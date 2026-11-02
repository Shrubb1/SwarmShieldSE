use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use snn_firewall::{channel_names, ConnEvent, FirewallPolicy, MitigationKind, Verdict};
use snn_mesh::DetectorConfig;
use snn_runtime::JobSpec;
use swarm::{read_frame, run_orchestrator, run_worker, write_frame, Frame, WorkerConfig};

const TICK: u64 = 1000;
const ATTACKER: IpAddr = IpAddr::V4(Ipv4Addr::new(66, 6, 6, 6));

fn ip(n: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
}

fn ev(ts: u64, src: IpAddr) -> ConnEvent {
    ConnEvent {
        ts_ms: ts,
        tenant: "t-a".into(),
        src_ip: src,
        payload_bytes: 500,
        header_bytes: 400,
        meta: Default::default(),
        payload: None,
    }
}

fn spec(id: &str) -> JobSpec {
    JobSpec {
        job_id: id.into(),
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
        checkpoint_every: 10,
    }
}

fn send_event(c: &mut TcpStream, e: &ConnEvent) -> Verdict {
    write_frame(c, &Frame::Event(e.clone())).unwrap();
    match read_frame(c).unwrap() {
        Some(Frame::Verdict(v)) => v,
        other => panic!("expected Verdict, got {other:?}"),
    }
}

fn normal_window(c: &mut TcpStream, w: u64) {
    for i in 0..5u8 {
        for k in 0..2u64 {
            send_event(c, &ev(w * TICK + (i as u64 * 2 + k) * 100, ip(i + 1)));
        }
    }
}

fn flood_window(c: &mut TcpStream, w: u64) -> Vec<Verdict> {
    (0..200u64)
        .map(|k| send_event(c, &ev(w * TICK + k * 4, ATTACKER)))
        .collect()
}

fn spawn_worker(
    root: &std::path::Path,
    upstream: Option<std::net::SocketAddr>,
    stop: Arc<AtomicBool>,
) -> (std::net::SocketAddr, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = WorkerConfig {
        job: spec("job7"),
        store_dir: root.join("stores"),
        policy_dir: root.join("policy"),
        upstream,
        report_detections: false,
    };
    let h = thread::spawn(move || {
        if let Err(e) = run_worker(listener, cfg, stop) {
            eprintln!("worker exited with error: {e:?}");
        }
    });
    (addr, h)
}

/// Full loop over real sockets: worker enforces, orchestrator audits.
#[test]
fn mesh_enforces_and_reports() {
    let root = std::env::temp_dir().join(format!("swarm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    // Control plane.
    let orch_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let orch_addr = orch_listener.local_addr().unwrap();
    let orch_stop = Arc::new(AtomicBool::new(false));
    let os = orch_stop.clone();
    let orch_root = root.join("jobs");
    let _orch = thread::spawn(move || run_orchestrator(orch_listener, orch_root, os));

    // Worker node.
    let w_stop = Arc::new(AtomicBool::new(false));
    let (w_addr, _w_handle) = spawn_worker(&root, Some(orch_addr), w_stop.clone());
    thread::sleep(Duration::from_millis(50)); // let listener come up

    // Client: normal warmup, then flood.
    let mut c = TcpStream::connect(w_addr).unwrap();
    for w in 0..10 {
        normal_window(&mut c, w);
    }
    // Eval lags a tick and detector spikes lag a step — the rule lands
    // while a *later* flood window's events are being inspected.
    let mut denied = flood_window(&mut c, 11);
    denied.extend(flood_window(&mut c, 12));
    denied.extend(flood_window(&mut c, 13));
    assert!(
        denied.iter().any(|v| matches!(v, Verdict::Denied { .. })),
        "worker never denied the flood"
    );

    // Policy file landed for the local proxy.
    let policy = root.join("policy/policy.json");
    assert!(wait_for(|| policy.exists()), "policy.json never written");
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&policy).unwrap()).unwrap();
    assert_eq!(doc["rules"][0]["subject"], "ip:66.6.6.6");

    // Rule report reached the control plane's per-job audit.
    let audit = root.join("jobs/job7/mesh.jsonl");
    assert!(
        wait_for(|| audit.exists()
            && std::fs::read_to_string(&audit)
                .unwrap()
                .contains("RuleApplied")),
        "no RuleApplied in control-plane audit"
    );

    std::fs::remove_dir_all(&root).ok();
}

/// Worker dies and respawns on the same stores: the live rule is still
/// enforced — learned memory crosses process boundaries.
#[test]
fn worker_reincarnation_keeps_enforcement() {
    let root = std::env::temp_dir().join(format!("swarm-re-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let stop1 = Arc::new(AtomicBool::new(false));
    let (a1, _h1) = spawn_worker(&root, None, stop1.clone());
    thread::sleep(Duration::from_millis(50));

    let mut c = TcpStream::connect(a1).unwrap();
    for w in 0..10 {
        normal_window(&mut c, w);
    }
    flood_window(&mut c, 11);
    flood_window(&mut c, 12);
    flood_window(&mut c, 13);
    drop(c);
    write_frame(&mut TcpStream::connect(a1).unwrap(), &Frame::Flush).unwrap();

    // Kill worker 1, respawn on same stores.
    stop1.store(true, Ordering::Relaxed);
    thread::sleep(Duration::from_millis(50));
    let stop2 = Arc::new(AtomicBool::new(false));
    let (a2, _h2) = spawn_worker(&root, None, stop2.clone());
    thread::sleep(Duration::from_millis(50));

    let mut c2 = TcpStream::connect(a2).unwrap();
    // Rule was created ~t=12000 with ttl 5000 → still live at t=16000.
    let v = send_event(&mut c2, &ev(16 * TICK, ATTACKER));
    assert!(
        matches!(v, Verdict::Denied { .. }),
        "reincarnated worker lost the rule"
    );

    stop2.store(true, Ordering::Relaxed);
    std::fs::remove_dir_all(&root).ok();
}

fn wait_for(mut f: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if f() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}
