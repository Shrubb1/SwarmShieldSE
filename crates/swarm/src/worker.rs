//! `swarm-worker` — the enforcement node. Owns one job's `Orchestrator`
//! (telemetry Agent + Firewall + stores), serves `Frame`s on a TCP
//! listener, and reports rules upstream to the swarm-orchestrator.
//!
//! Layout per connection: read frame → act → reply. Enforcement is
//! in-memory (`Firewall`'s RuleTable) — sub-microsecond, no proxy RTT.

use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

use snn_firewall::{MitigationRule, PolicySink};
use snn_runtime::{file_stores, FilePolicySink, JobSpec, Orchestrator};

use crate::proto::{read_frame, write_frame, Frame, Report};

/// Policy sink decorator: enforces into a `FilePolicySink` (what the
/// local proxy watches) AND reports each apply/revoke upstream.
struct ReportingSink {
    inner: FilePolicySink,
    reports: Sender<Report>,
    job_id: String,
}

impl PolicySink for ReportingSink {
    fn apply(&mut self, rule: &MitigationRule) -> io::Result<()> {
        self.inner.apply(rule)?;
        let _ = self.reports.send(Report::RuleApplied {
            job_id: self.job_id.clone(),
            rule: rule.clone(),
        });
        Ok(())
    }
    fn revoke(&mut self, rule_id: u64) -> io::Result<()> {
        self.inner.revoke(rule_id)?;
        let _ = self.reports.send(Report::RuleRevoked {
            job_id: self.job_id.clone(),
            rule_id,
        });
        Ok(())
    }
}

pub struct WorkerConfig {
    pub job: JobSpec,
    /// Dir for checkpoint stores (`{id}:telemetry`/`{id}:firewall` files).
    pub store_dir: PathBuf,
    /// Dir for `policy.json` (the proxy's watched config).
    pub policy_dir: PathBuf,
    /// swarm-orchestrator address; `None` = standalone (no upstream).
    pub upstream: Option<SocketAddr>,
    /// Report every detection upstream? Noisy — default false (rules only).
    pub report_detections: bool,
}

/// Reporter thread: opens a short-lived upstream connection per report.
/// Best-effort — a dead orchestrator never blocks enforcement.
fn spawn_reporter(upstream: SocketAddr) -> Sender<Report> {
    let (tx, rx) = mpsc::channel::<Report>();
    thread::spawn(move || {
        while let Ok(report) = rx.recv() {
            if let Ok(mut s) = TcpStream::connect(upstream) {
                let _ = write_frame(&mut s, &Frame::Report(report));
            }
        }
    });
    tx
}

/// Blocking serve loop. `stop` flips it to drain + exit.
pub fn run_worker(
    listener: TcpListener,
    cfg: WorkerConfig,
    stop: Arc<AtomicBool>,
) -> io::Result<()> {
    let reports = match cfg.upstream {
        Some(addr) => spawn_reporter(addr),
        None => {
            let (tx, _rx) = mpsc::channel::<Report>();
            tx
        }
    };

    let job_id = cfg.job.job_id.clone();
    let sink_job = job_id.clone();
    let report_tx = reports.clone();
    let policy_dir = cfg.policy_dir.clone();
    let mut orch = Orchestrator::new(
        cfg.store_dir.join("jobs"),
        Box::new(file_stores(cfg.store_dir.join("stores"))),
        Box::new(move |_: &JobSpec| {
            Box::new(ReportingSink {
                inner: FilePolicySink::new(policy_dir.clone()),
                reports: report_tx.clone(),
                job_id: sink_job.clone(),
            }) as Box<dyn PolicySink>
        }),
    );
    orch.register(cfg.job.clone())?;
    // Greeting upstream (registration marker; harmless if upstream is down).
    if cfg.upstream.is_some() {
        let _ = reports.send(Report::Heartbeat {
            job_id: job_id.clone(),
            samples: 0,
        });
    }

    // Single-job engine behind a mutex — per-conn threads serialize on
    // it. A poisoned lock must not kill the node.
    let orch = Arc::new(Mutex::new(orch));
    let report_detections = cfg.report_detections;

    listener.set_nonblocking(true)?;
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                // Windows: accepted sockets inherit the listener's
                // nonblocking flag — force blocking before framed I/O.
                let _ = stream.set_nonblocking(false);
                let (orch, reports, job_id) = (orch.clone(), reports.clone(), job_id.clone());
                thread::spawn(move || {
                    handle_conn(&mut stream, &orch, &job_id, &reports, report_detections)
                });
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(std::time::Duration::from_millis(2));
            }
            Err(e) => return Err(e),
        }
    }
    let mut eng = orch.lock().unwrap_or_else(|e| e.into_inner());
    eng.flush()
}

fn handle_conn(
    stream: &mut TcpStream,
    orch: &Mutex<Orchestrator>,
    job_id: &str,
    reports: &Sender<Report>,
    report_detections: bool,
) {
    while let Ok(Some(frame)) = read_frame(stream) {
        let mut eng = orch.lock().unwrap_or_else(|e| e.into_inner());
        let reply = match frame {
            Frame::Event(ev) => match eng.ingest(job_id, &ev) {
                Ok(v) => Some(Frame::Verdict(v)),
                Err(e) => Some(Frame::Err(e.to_string())),
            },
            Frame::Sample(s) => match eng.telemetry(job_id, &s) {
                Ok(d) => {
                    if report_detections {
                        let _ = reports.send(Report::Detection {
                            job_id: job_id.into(),
                            detection: Box::new(d.clone()),
                        });
                    }
                    Some(Frame::Detection(Box::new(d)))
                }
                Err(e) => Some(Frame::Err(e.to_string())),
            },
            Frame::Ping => Some(Frame::Pong),
            Frame::Flush => {
                let _ = eng.flush();
                Some(Frame::Pong)
            }
            Frame::Shutdown => Some(Frame::Pong),
            _ => None,
        };
        drop(eng);
        if let Some(r) = reply {
            if write_frame(stream, &r).is_err() {
                return;
            }
        }
    }
}
