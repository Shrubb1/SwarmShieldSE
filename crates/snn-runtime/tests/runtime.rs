use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use snn_firewall::{
    channel_names, ConnEvent, FirewallPolicy, MitigationKind, MitigationRule, PolicySink,
    RuleSubject, Verdict,
};
use snn_mesh::{DetectorConfig, TelemetrySample};
use snn_runtime::{file_stores, JobSpec, JsonApi, Orchestrator};

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

/// A policy sink shared across orchestrator incarnations — stands in for
/// the proxy's persistent rule set (survives worker restarts).
#[derive(Clone, Default)]
struct SharedSink {
    applied: Arc<Mutex<Vec<MitigationRule>>>,
}

impl PolicySink for SharedSink {
    fn apply(&mut self, rule: &MitigationRule) -> std::io::Result<()> {
        self.applied.lock().unwrap().push(rule.clone());
        Ok(())
    }
    fn revoke(&mut self, rule_id: u64) -> std::io::Result<()> {
        self.applied.lock().unwrap().retain(|r| r.id != rule_id);
        Ok(())
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

fn normal_window(orch: &mut Orchestrator, job: &str, w: u64) {
    for i in 0..5u8 {
        for k in 0..2u64 {
            orch.ingest(job, &ev(w * TICK + (i as u64 * 2 + k) * 100, ip(i + 1)))
                .unwrap();
        }
    }
}

fn flood_window(orch: &mut Orchestrator, job: &str, w: u64) -> Vec<Verdict> {
    let mut out = Vec::new();
    for k in 0..200u64 {
        out.push(orch.ingest(job, &ev(w * TICK + k * 4, ATTACKER)).unwrap());
    }
    normal_window(orch, job, w);
    out
}

fn tempdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("snn-rt-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// Full pipeline: register → traffic → rule → flush → NEW orchestrator
/// on the same stores → the rule is still enforced and re-pushed.
#[test]
fn end_to_end_survives_orchestrator_restart() {
    let root = tempdir("e2e");
    std::fs::create_dir_all(&root).unwrap();
    let sink_log: Arc<Mutex<Vec<MitigationRule>>> = Arc::new(Mutex::new(Vec::new()));

    let make_orch = |root: &PathBuf, sink_log: &Arc<Mutex<Vec<MitigationRule>>>| {
        let log = sink_log.clone();
        Orchestrator::new(
            root.clone(),
            Box::new(file_stores(root.join("stores"))),
            Box::new(move |_: &JobSpec| {
                Box::new(SharedSink {
                    applied: log.clone(),
                }) as Box<dyn PolicySink>
            }),
        )
    };

    let mut orch = make_orch(&root, &sink_log);
    orch.register(spec("job7")).unwrap();

    // Warmup + telemetry baseline.
    for w in 0..10 {
        normal_window(&mut orch, "job7", w);
    }
    for seq in 0..20u64 {
        orch.telemetry(
            "job7",
            &TelemetrySample {
                seq,
                ts_ms: seq * 1000,
                values: vec![50.0],
            },
        )
        .unwrap();
    }

    // Flood → drop rule (verdicts lag one tick — the rule lands while
    // the following window's events are being inspected).
    flood_window(&mut orch, "job7", 10);
    let mut v = flood_window(&mut orch, "job7", 11);
    v.extend(flood_window(&mut orch, "job7", 12));
    assert!(v.iter().any(|x| matches!(x, Verdict::Denied { .. })));
    let rules = orch.active_rules("job7");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].subject, RuleSubject::Ip(ATTACKER));

    // Persist + kill the orchestrator entirely.
    orch.flush().unwrap();
    drop(orch);

    // New orchestrator, same stores: job restores with its brain intact —
    // the live rule is re-applied to the (fresh) sink.
    let mut orch2 = make_orch(&root, &sink_log);
    orch2.register(spec("job7")).unwrap();
    let rules2 = orch2.active_rules("job7");
    assert_eq!(rules2.len(), 1, "restored job lost its live rule");
    assert_eq!(rules2[0].subject, RuleSubject::Ip(ATTACKER));
    assert_eq!(
        orch2
            .job("job7")
            .unwrap()
            .telemetry
            .detector
            .samples_observed(),
        20,
        "telemetry memory was not restored"
    );

    // Enforcement still denies the attacker after the restart.
    let v = orch2.ingest("job7", &ev(13 * TICK, ATTACKER)).unwrap();
    assert!(matches!(v, Verdict::Denied { .. }));

    std::fs::remove_dir_all(&root).ok();
}

/// The JSON façade: register → ingest → status, all through strings.
#[test]
fn json_api_round_trip() {
    let root = tempdir("api");
    std::fs::create_dir_all(&root).unwrap();
    let sink_log: Arc<Mutex<Vec<MitigationRule>>> = Arc::new(Mutex::new(Vec::new()));
    let log = sink_log.clone();
    let orch = Orchestrator::new(
        root.clone(),
        Box::new(file_stores(root.join("stores"))),
        Box::new(move |_: &JobSpec| {
            Box::new(SharedSink {
                applied: log.clone(),
            }) as Box<dyn PolicySink>
        }),
    );
    let mut api = JsonApi::new(orch);

    let spec_json = serde_json::to_string(&spec("job9")).unwrap();
    api.register(&spec_json).unwrap();

    let ev_json = serde_json::to_string(&ev(1000, ip(1))).unwrap();
    let v: Verdict = serde_json::from_str(&api.ingest("job9", &ev_json).unwrap()).unwrap();
    assert_eq!(v, Verdict::Allow);

    let status: serde_json::Value = serde_json::from_str(&api.status("job9").unwrap()).unwrap();
    assert_eq!(status["job_id"], "job9");
    assert_eq!(status["tenant"], "t-a");

    assert!(api.status("nope").is_err());
    std::fs::remove_dir_all(&root).ok();
}
