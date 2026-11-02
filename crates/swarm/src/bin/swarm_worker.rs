//! swarm-worker — enforcement node binary.
//!
//! swarm-worker --listen 127.0.0.1:9101 \
//!              --upstream 127.0.0.1:9000 \
//!              --job-id job7 --tenant t-a \
//!              --root ./mesh-data

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use snn_firewall::{channel_names, FirewallPolicy, MitigationKind};
use snn_mesh::DetectorConfig;
use snn_runtime::JobSpec;
use swarm::{run_worker, WorkerConfig};

fn arg(args: &[String], flag: &str, default: &str) -> String {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| default.into())
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let listen = arg(&args, "--listen", "127.0.0.1:9101");
    let upstream = arg(&args, "--upstream", "");
    let job_id = arg(&args, "--job-id", "job1");
    let tenant = arg(&args, "--tenant", "default");
    let root = PathBuf::from(arg(&args, "--root", "./mesh-data"));

    let spec = JobSpec {
        job_id: job_id.clone(),
        tenant,
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
            action_ladder: vec![
                MitigationKind::RateLimit { max_rps: 50.0 },
                MitigationKind::Drop,
                MitigationKind::Block,
            ],
            ttl_ms: 60_000,
            ..Default::default()
        },
        telemetry_baselines: vec![50.0],
        firewall_baselines: vec![
            10.0, 2.0, 5.0, 500.0, 400.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 10.0, 0.0, 0.0, 10.0,
        ],
        checkpoint_every: 100,
    };

    let cfg = WorkerConfig {
        job: spec,
        store_dir: root.join("stores"),
        policy_dir: root.join("policy"),
        upstream: upstream.parse::<std::net::SocketAddr>().ok(),
        report_detections: false,
    };

    let listener = TcpListener::bind(&listen)?;
    eprintln!("swarm-worker listening on {listen} (job {job_id})");

    let stop = Arc::new(AtomicBool::new(false));
    let s = stop.clone();
    let _ = std::thread::spawn(move || {
        let _ = std::io::stdin().read_line(&mut String::new());
        s.store(true, Ordering::Relaxed);
    });
    run_worker(listener, cfg, stop)
}
