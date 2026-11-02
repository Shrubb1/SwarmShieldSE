//! Mass adversarial stress: a live `swarm-worker` under concurrent
//! mixed attack traffic — floods, jittered beacons, modeless walks,
//! payload-fuzzed injections, and normals — measuring throughput and
//! verdict distribution over real sockets.

use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use snn_firewall::{channel_names, ConnEvent, EventMeta, FirewallPolicy, MitigationKind, Verdict};
use snn_mesh::DetectorConfig;
use snn_runtime::JobSpec;
use swarm::proto::{read_frame, write_frame, Frame};
use swarm::worker::{run_worker, WorkerConfig};

const TICK: u64 = 1000;

fn ev(ts: u64, src: IpAddr, payload: Option<Vec<u8>>) -> ConnEvent {
    ConnEvent {
        ts_ms: ts,
        tenant: "t-a".into(),
        src_ip: src,
        payload_bytes: 500,
        header_bytes: 400,
        meta: EventMeta::default(),
        payload: payload.map(|b| b.into_boxed_slice()),
    }
}

fn spec() -> JobSpec {
    JobSpec {
        job_id: "fuzz".into(),
        tenant: "t-a".into(),
        telemetry: DetectorConfig::for_metrics(&["latency_ms"]),
        firewall_detector: DetectorConfig {
            delta_threshold: 5.0,
            spike_current: 200.0,
            initial_weight: 80.0,
            window: 10,
            anomaly_threshold: 1,
            ..DetectorConfig::for_metrics(&channel_names())
        },
        firewall_policy: FirewallPolicy {
            anomaly_threshold: 2,
            action_ladder: vec![MitigationKind::Drop],
            ttl_ms: 5_000,
            cooldown_ms: 0,
            ..Default::default()
        },
        telemetry_baselines: vec![50.0],
        firewall_baselines: vec![
            10.0, 2.0, 5.0, 500.0, 400.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 10.0, 0.0, 0.0, 10.0,
        ],
        checkpoint_every: 10_000,
    }
}

#[test]
fn mass_adversarial_fuzz() {
    let root = std::env::temp_dir().join(format!("fuzz-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let cfg = WorkerConfig {
        job: spec(),
        store_dir: root.join("stores"),
        policy_dir: root.join("policy"),
        upstream: None,
        report_detections: false,
    };
    let w = thread::spawn(move || {
        let _ = run_worker(listener, cfg, stop2);
    });

    let total = 100_000usize;
    let threads_n = 8;
    let per = total / threads_n;
    let counts: Vec<Arc<AtomicUsize>> = (0..4).map(|_| Arc::new(AtomicUsize::new(0))).collect();
    let start = Instant::now();
    let mut handles = Vec::new();

    for t in 0..threads_n {
        let cs: Vec<Arc<AtomicUsize>> = counts.iter().map(Arc::clone).collect();
        handles.push(thread::spawn(move || {
            let mut c = TcpStream::connect(addr).unwrap();
            let atk = IpAddr::V4(Ipv4Addr::new(66, 6, 6, t as u8));
            let norm = IpAddr::V4(Ipv4Addr::new(10, 0, 0, (t as u8) + 1));
            let mut x = 0x9e3779b9u64 ^ t as u64;
            for i in 0..per {
                x ^= x << 13;
                x ^= x >> 7;
                let seq = (t * per + i) as u64;
                // Advancing sim time so windows keep finalizing.
                let ts = (seq / 10) * TICK + (seq % 10) * 90;
                let e = match i % 5 {
                    // Volumetric flood (2 per window per thread — mild)
                    0 => ev(ts, atk, None),
                    // Signature-injected payload
                    1 => ev(ts, atk, Some(b"GET /x?id=' union select pass --".to_vec())),
                    // Beacon-ish contact (regular-ish jitter)
                    2 => ev(50_000 + seq * 100 + (x % 40), norm, None),
                    // Modeless walk attacker (random gaps, sustained)
                    3 => ev(200_000 + seq * (1 + (x % 800)), atk, None),
                    // Normal traffic
                    _ => ev(ts, norm, None),
                };
                write_frame(&mut c, &Frame::Event(e)).unwrap();
                if let Ok(Some(Frame::Verdict(v))) = read_frame(&mut c) {
                    let idx = match v {
                        Verdict::Allow => 0,
                        Verdict::Denied { .. } => 1,
                        Verdict::RateLimited { .. } => 2,
                    };
                    cs[idx].fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let dur = start.elapsed();
    let allowed = counts[0].load(Ordering::Relaxed);
    let denied = counts[1].load(Ordering::Relaxed);
    let limited = counts[2].load(Ordering::Relaxed);
    let thr = (allowed + denied + limited) as f64 / dur.as_secs_f64();

    eprintln!("=== MASS FUZZ ===");
    eprintln!("events answered: {}", allowed + denied + limited);
    eprintln!("duration: {dur:?}  throughput: {thr:.0} ev/s");
    eprintln!("allow={allowed} denied={denied} rate_limited={limited}");

    stop.store(true, Ordering::Relaxed);
    let _ = TcpStream::connect(addr); // kick the accept loop
    let _ = w.join();

    assert!(allowed + denied + limited > 0, "no verdicts came back");
    assert!(thr > 1_000.0, "throughput collapsed: {thr:.0} ev/s");
}
