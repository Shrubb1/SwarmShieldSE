//! Chaos: multi-node mesh under partitions, disconnects, and garbage.
//! Invariants: enforcement never depends on the control plane, reports
//! are best-effort, malformed input can't kill a worker.

use std::io::Write;
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

fn send(c: &mut TcpStream, e: &ConnEvent) -> Verdict {
    write_frame(c, &Frame::Event(e.clone())).unwrap();
    match read_frame(c).unwrap() {
        Some(Frame::Verdict(v)) => v,
        other => panic!("expected Verdict, got {other:?}"),
    }
}

fn normal_window(c: &mut TcpStream, w: u64) {
    for i in 0..5u8 {
        for k in 0..2u64 {
            send(c, &ev(w * TICK + (i as u64 * 2 + k) * 100, ip(i + 1)));
        }
    }
}

fn flood(c: &mut TcpStream, w: u64) -> Vec<Verdict> {
    (0..200u64)
        .map(|k| send(c, &ev(w * TICK + k * 4, ATTACKER)))
        .collect()
}

fn spawn_worker(
    job: &str,
    upstream: Option<std::net::SocketAddr>,
    stop: Arc<AtomicBool>,
) -> std::net::SocketAddr {
    let root = std::env::temp_dir().join(format!("swarm-chaos-{job}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = WorkerConfig {
        job: spec(job),
        store_dir: root.join("stores"),
        policy_dir: root.join("policy"),
        upstream,
        report_detections: false,
    };
    let name = job.to_string();
    thread::spawn(move || {
        if let Err(e) = run_worker(listener, cfg, stop) {
            eprintln!("worker {name} died: {e:?}");
        }
    });
    addr
}

fn dead_port() -> std::net::SocketAddr {
    // Bind then drop → guaranteed-closed port (upstream partition).
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
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

#[test]
fn chaos_partition_disconnect_and_garbage() {
    // Control plane.
    let orch_l = TcpListener::bind("127.0.0.1:0").unwrap();
    let orch_addr = orch_l.local_addr().unwrap();
    let orch_stop = Arc::new(AtomicBool::new(false));
    let orch_root = std::env::temp_dir().join(format!("swarm-chaos-orch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&orch_root);
    let os = orch_stop.clone();
    let rr = orch_root.clone();
    thread::spawn(move || run_orchestrator(orch_l, rr, os));

    // 3 workers: A+B report to the live orchestrator, C is partitioned.
    let sa = Arc::new(AtomicBool::new(false));
    let sb = Arc::new(AtomicBool::new(false));
    let sc = Arc::new(AtomicBool::new(false));
    let wa = spawn_worker("jobA", Some(orch_addr), sa.clone());
    let wb = spawn_worker("jobB", Some(orch_addr), sb.clone());
    let wc = spawn_worker("jobC", Some(dead_port()), sc.clone());
    thread::sleep(Duration::from_millis(80));

    let mut ca = TcpStream::connect(wa).unwrap();
    let mut cb = TcpStream::connect(wb).unwrap();
    let mut cc = TcpStream::connect(wc).unwrap();

    // Warmup everywhere.
    for w in 0..10 {
        normal_window(&mut ca, w);
        normal_window(&mut cb, w);
        normal_window(&mut cc, w);
    }

    // Flood A and C. C's upstream is dead — enforcement must not care.
    let mut va = flood(&mut ca, 11);
    va.extend(flood(&mut ca, 12));
    va.extend(flood(&mut ca, 13));
    let mut vc = flood(&mut cc, 11);
    vc.extend(flood(&mut cc, 12));
    vc.extend(flood(&mut cc, 13));
    assert!(
        va.iter().any(|v| matches!(v, Verdict::Denied { .. })),
        "A never denied"
    );
    assert!(
        vc.iter().any(|v| matches!(v, Verdict::Denied { .. })),
        "partitioned C lost enforcement"
    );

    // Chaos 1: garbage bytes on a fresh conn — worker must not die.
    let mut g = TcpStream::connect(wa).unwrap();
    g.write_all(&[0xDE, 0xAD, 0xBE, 0xEF, 0x41, 0x41]).unwrap();
    drop(g); // server should drop the conn, not crash
    let mut c2 = TcpStream::connect(wa).unwrap();
    assert_eq!(send(&mut c2, &ev(20 * TICK, ip(1))), Verdict::Allow);

    // Chaos 2: abrupt disconnect mid-flood — send, never read, close.
    let mut rude = TcpStream::connect(wb).unwrap();
    for k in 0..50u64 {
        let _ = write_frame(&mut rude, &Frame::Event(ev(14 * TICK + k * 4, ATTACKER)));
    }
    drop(rude);
    thread::sleep(Duration::from_millis(50));
    let mut c3 = TcpStream::connect(wb).unwrap();
    assert_eq!(send(&mut c3, &ev(21 * TICK, ip(1))), Verdict::Allow);

    // Control-plane audit: A's report landed; C's was dropped on the
    // partition (best-effort — enforcement doesn't wait on upstream).
    let audit_a = orch_root.join("jobA/mesh.jsonl");
    let audit_c = orch_root.join("jobC/mesh.jsonl");
    assert!(wait_for(|| audit_a.exists()
        && std::fs::read_to_string(&audit_a)
            .unwrap()
            .contains("RuleApplied")));
    assert!(
        !audit_c.exists(),
        "partitioned report should be lost, not queued"
    );

    sa.store(true, Ordering::Relaxed);
    sb.store(true, Ordering::Relaxed);
    sc.store(true, Ordering::Relaxed);
    orch_stop.store(true, Ordering::Relaxed);
}
