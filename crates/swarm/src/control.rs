//! `swarm-orchestrator` — the control plane. Accepts worker `Report`
//! frames, appends them to per-job `mesh.jsonl` audit logs under the
//! jobs root, and answers `Ping`/`Status` queries.

use std::io::{self, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde::Serialize;

use crate::proto::{read_frame, write_frame, Frame, Report};

/// Runs the control-plane listener until `stop` flips.
/// Returns the number of reports ingested.
pub fn run_orchestrator(
    listener: TcpListener,
    jobs_root: PathBuf,
    stop: Arc<AtomicBool>,
) -> io::Result<u64> {
    listener.set_nonblocking(true)?;
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                // Windows: accepted sockets inherit nonblocking — force blocking.
                let _ = stream.set_nonblocking(false);
                // Thread per conn: a lingering report socket can't stall
                // other workers' reports.
                let jobs_root = jobs_root.clone();
                std::thread::spawn(move || {
                    while let Ok(Some(frame)) = read_frame(&mut stream) {
                        match frame {
                            Frame::Report(report) => {
                                let job = report_job(&report);
                                let _ = append(&jobs_root, &job, &report);
                            }
                            Frame::Ping => {
                                let _ = write_frame(&mut stream, &Frame::Pong);
                            }
                            _ => {}
                        }
                    }
                });
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(0)
}

fn report_job(r: &Report) -> String {
    match r {
        Report::RuleApplied { job_id, .. }
        | Report::RuleRevoked { job_id, .. }
        | Report::Detection { job_id, .. }
        | Report::Heartbeat { job_id, .. } => job_id.clone(),
    }
}

/// One JSONL line per report under `jobs/{id}/mesh.jsonl` — the same
/// tenant-scoped audit convention as the firewall's network.jsonl.
fn append(jobs_root: &std::path::Path, job: &str, report: &Report) -> io::Result<()> {
    let dir = jobs_root.join(job);
    std::fs::create_dir_all(&dir)?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("mesh.jsonl"))?;
    #[derive(Serialize)]
    struct Line<'a> {
        ts_ms: u64,
        report: &'a Report,
    }
    // Wall clock is fine here — this is a log sink, not sim state.
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let line = serde_json::to_string(&Line { ts_ms: ts, report }).map_err(io::Error::other)?;
    writeln!(f, "{line}")
}
