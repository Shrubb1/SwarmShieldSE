use std::net::{IpAddr, Ipv4Addr};

use snn_firewall::{
    channel_names, AuditKind, Firewall, FirewallPolicy, JsonlAudit, MemoryAudit, MitigationKind,
    RecordingPolicySink, RuleSubject, RuleTable, Verdict,
};
use snn_mesh::DetectorConfig;

const TICK: u64 = 1000;
const ATTACKER: IpAddr = IpAddr::V4(Ipv4Addr::new(66, 6, 6, 6));

fn ip(n: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
}

fn mk_ev(ts: u64, src: IpAddr, payload: u32, header: u32) -> snn_firewall::ConnEvent {
    snn_firewall::ConnEvent {
        ts_ms: ts,
        tenant: "tenant-a".into(),
        src_ip: src,
        payload_bytes: payload,
        header_bytes: header,
        meta: Default::default(),
        payload: None,
    }
}

/// Detector tuned so a normal window is silent and any real delta fires.
fn det_cfg() -> DetectorConfig {
    DetectorConfig {
        delta_threshold: 5.0,
        spike_current: 200.0,
        initial_weight: 80.0,
        detector_neurons: 8,
        window: 10,
        anomaly_threshold: 1,
        ..DetectorConfig::for_metrics(&channel_names())
    }
}

/// Baseline matching `normal_window`: 10 ev/s, top src 2/s, 5 ips,
/// 500B payloads, 400B headers, no new sources.
fn baseline() -> [f32; 15] {
    [
        10.0, 2.0, 5.0, 500.0, 400.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 10.0, 0.0, 0.0, 10.0,
    ]
}

fn fw_with(policy: FirewallPolicy) -> Firewall<RecordingPolicySink, MemoryAudit> {
    Firewall::new(
        det_cfg(),
        policy,
        &baseline(),
        RecordingPolicySink::default(),
        MemoryAudit::new(),
    )
}

/// 10 events in window `w`: 2 per each of 5 source IPs.
fn normal_window<A: snn_firewall::AuditLog>(
    fw: &mut Firewall<RecordingPolicySink, A>,
    w: u64,
) -> Vec<Verdict> {
    let mut out = Vec::new();
    for i in 0..5u8 {
        for k in 0..2u64 {
            out.push(
                fw.inspect(&mk_ev(
                    w * TICK + (i as u64 * 2 + k) * 100,
                    ip(i + 1),
                    500,
                    400,
                ))
                .unwrap(),
            );
        }
    }
    out
}

/// `n` attacker events + the normal 10, all inside window `w`.
fn flood_window<A: snn_firewall::AuditLog>(
    fw: &mut Firewall<RecordingPolicySink, A>,
    w: u64,
    n: u64,
) -> Vec<Verdict> {
    let mut out = Vec::new();
    for k in 0..n {
        out.push(
            fw.inspect(&mk_ev(w * TICK + k * 4, ATTACKER, 500, 400))
                .unwrap(),
        );
    }
    out.extend(normal_window(fw, w));
    out
}

/// The core contract: an anomalous spike generates a dynamic Drop rule,
/// enforcement denies the attacker, and TTL expiry restores access.
#[test]
fn anomalous_spike_triggers_drop_rule() {
    let mut fw = fw_with(FirewallPolicy {
        anomaly_threshold: 2,
        action_ladder: vec![MitigationKind::Drop],
        ttl_ms: 5_000,
        cooldown_ms: 0,
        ..Default::default()
    });

    // Baseline warmup: 10 quiet windows, no rules, all allowed.
    for w in 0..10 {
        let vs = normal_window(&mut fw, w);
        assert!(vs.iter().all(|v| *v == Verdict::Allow), "w{w}: {vs:?}");
    }
    assert!(fw.sink_mut().applied.is_empty());

    // Flood windows 10-12; the rule appears once a flood window has been
    // scored (window is evaluated when the *next* window's first event
    // arrives, so denials show up a tick after the flood starts).
    flood_window(&mut fw, 10, 200);
    let mut denied = flood_window(&mut fw, 11, 200);
    denied.extend(flood_window(&mut fw, 12, 200));
    assert_eq!(fw.sink_mut().applied.len(), 1, "expected exactly one rule");
    let rule = fw.sink_mut().applied[0].clone();
    assert_eq!(rule.subject, RuleSubject::Ip(ATTACKER));
    assert_eq!(rule.kind, MitigationKind::Drop);
    assert!(rule.expires_ms > rule.created_ms, "rule must carry a TTL");

    // Attacker denied while rule lives; normals still pass.
    assert!(denied.iter().any(|v| matches!(v, Verdict::Denied { .. })));
    let v = fw
        .inspect(&mk_ev(13 * TICK + 500, ip(1), 500, 400))
        .unwrap();
    assert_eq!(v, Verdict::Allow);

    // Audit trail: evaluations + the mitigation record.
    assert!(fw.audit().anomaly_count() >= 1);
    assert_eq!(fw.audit().rules().len(), 1);

    // Attack stops. Recovery is itself anomalous to the delta encoder
    // (baseline learned ~200, traffic returns to 10 → down-spikes), so
    // further rules — Global this time — may appear. Drive normal traffic
    // until EVERY rule's TTL drains: the self-heal property.
    for w in 13..40 {
        normal_window(&mut fw, w);
        if fw.active_rules().is_empty() {
            break;
        }
    }
    assert!(fw.active_rules().is_empty(), "rules should have expired");
    assert!(fw.sink_mut().revoked.contains(&rule.id));

    // The previously-blocked attacker is admitted again — false positives
    // self-heal by construction.
    let v = fw.inspect(&mk_ev(20 * TICK, ATTACKER, 500, 400)).unwrap();
    assert_eq!(v, Verdict::Allow);
}

/// Repeat offenses walk the ladder: rate-limit → drop → block, with
/// exponentially growing TTLs. No rule stacking while one is live.
#[test]
fn escalation_ladder() {
    let mut fw = fw_with(FirewallPolicy {
        anomaly_threshold: 2,
        action_ladder: vec![
            MitigationKind::RateLimit { max_rps: 50.0 },
            MitigationKind::Drop,
            MitigationKind::Block,
        ],
        ttl_ms: 3_000,
        ttl_growth: 2.0,
        cooldown_ms: 0,
        ..Default::default()
    });

    for w in 0..10 {
        normal_window(&mut fw, w);
    }
    // Sustained flood past two rule lifetimes.
    for w in 10..26 {
        flood_window(&mut fw, w, 200);
    }

    let applied = fw.sink_mut().applied.clone();
    assert!(
        applied.len() >= 3,
        "expected >=3 escalating rules, got {}",
        applied.len()
    );
    assert_eq!(applied[0].kind, MitigationKind::RateLimit { max_rps: 50.0 });
    assert_eq!(applied[1].kind, MitigationKind::Drop);
    assert_eq!(applied[2].kind, MitigationKind::Block);
    assert_eq!(applied[0].expires_ms - applied[0].created_ms, 3_000);
    assert_eq!(applied[1].expires_ms - applied[1].created_ms, 6_000);
    assert_eq!(applied[2].expires_ms - applied[2].created_ms, 12_000);
    assert_eq!(applied[2].offense, 3);
}

/// Rate-limit rules meter rather than block.
#[test]
fn rate_limit_meters_traffic() {
    let mut fw = fw_with(FirewallPolicy {
        anomaly_threshold: 2,
        action_ladder: vec![MitigationKind::RateLimit { max_rps: 10.0 }],
        ttl_ms: 60_000,
        cooldown_ms: 0,
        ..Default::default()
    });

    for w in 0..10 {
        normal_window(&mut fw, w);
    }
    // Three flood windows: eval lags one tick, and detector spikes lag
    // one step, so the score lands on the second anomalous eval.
    flood_window(&mut fw, 10, 200);
    flood_window(&mut fw, 11, 200);
    flood_window(&mut fw, 12, 200);

    assert_eq!(fw.sink_mut().applied.len(), 1);
    assert!(matches!(
        fw.sink_mut().applied[0].kind,
        MitigationKind::RateLimit { .. }
    ));

    // Slow drip under the cap passes; a same-second burst is metered.
    let v = fw
        .inspect(&mk_ev(13 * TICK + 100, ATTACKER, 500, 400))
        .unwrap();
    assert_eq!(v, Verdict::Allow);
    let mut limited = 0;
    for k in 1..40u64 {
        if matches!(
            fw.inspect(&mk_ev(13 * TICK + 100 + k * 20, ATTACKER, 500, 400))
                .unwrap(),
            Verdict::RateLimited { .. }
        ) {
            limited += 1;
        }
    }
    assert!(limited > 10, "bucket should have metered, got {limited}");
}

/// Recovery down-spikes are logged as informational shifts, never
/// escalated — blocking the traffic that already left is a blackout.
#[test]
fn down_spike_recovery_is_informational() {
    let mut fw = fw_with(FirewallPolicy {
        anomaly_threshold: 2,
        action_ladder: vec![MitigationKind::Drop],
        ttl_ms: 5_000,
        cooldown_ms: 0,
        exempt_down_spikes: true,
        ..Default::default()
    });

    for w in 0..10 {
        normal_window(&mut fw, w);
    }
    flood_window(&mut fw, 10, 200);
    flood_window(&mut fw, 11, 200);
    flood_window(&mut fw, 12, 200);
    assert_eq!(fw.sink_mut().applied.len(), 1);

    // Flood ends: baseline ratcheted high → down-spike anomalies.
    // Exempted → no new rules; logged as DownShift instead.
    for w in 13..16 {
        normal_window(&mut fw, w);
    }
    assert_eq!(
        fw.sink_mut().applied.len(),
        1,
        "down-spike recovery should not produce new rules"
    );
    assert!(fw
        .audit()
        .records
        .iter()
        .any(|r| matches!(r.kind, AuditKind::DownShift { .. })));
}

/// A diffuse anomaly (no dominant source) produces a Global rule.
#[test]
fn diffuse_anomaly_yields_global_rule() {
    let mut fw = fw_with(FirewallPolicy {
        anomaly_threshold: 2,
        action_ladder: vec![MitigationKind::Drop],
        ttl_ms: 5_000,
        cooldown_ms: 0,
        ..Default::default()
    });

    for w in 0..10 {
        normal_window(&mut fw, w);
    }
    // Header-bomb from 20 distinct IPs: 1 event each, 50KB headers.
    // Anomalous (mean_header + uniq + new_src all move) but no src > 5%.
    for w in 10..14 {
        for i in 0..20u8 {
            fw.inspect(&mk_ev(w * TICK + i as u64 * 50, ip(100 + i), 500, 50_000))
                .unwrap();
        }
        normal_window(&mut fw, w);
    }

    let applied = fw.sink_mut().applied.clone();
    assert!(!applied.is_empty(), "expected a rule");
    assert_eq!(applied[0].subject, RuleSubject::Global);
}

/// The `/jobs/{id}/network` audit contract: every record lands as a JSONL
/// line under the job dir, tenant-scoped.
#[test]
fn audit_writes_tenant_scoped_jsonl() {
    let dir = std::env::temp_dir().join(format!("snn-fw-{}", std::process::id()));
    let audit = JsonlAudit::for_job(dir.join("jobs").join("7"), "tenant-a").unwrap();
    let mut fw = Firewall::new(
        det_cfg(),
        FirewallPolicy {
            anomaly_threshold: 1,
            action_ladder: vec![MitigationKind::Drop],
            ttl_ms: 5_000,
            cooldown_ms: 0,
            ..Default::default()
        },
        &baseline(),
        RecordingPolicySink::default(),
        audit,
    );

    for w in 0..5 {
        normal_window(&mut fw, w);
    }
    flood_window(&mut fw, 5, 200);
    flood_window(&mut fw, 6, 200);
    flood_window(&mut fw, 7, 200);

    let log = std::fs::read_to_string(dir.join("jobs/7/network.jsonl")).unwrap();
    let lines: Vec<serde_json::Value> = log
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(!lines.is_empty());
    assert!(lines.iter().all(|l| l["tenant"] == "tenant-a"));
    assert!(lines.iter().any(|l| l["kind"]["Mitigation"].is_object()));
    std::fs::remove_dir_all(&dir).ok();
}

/// Bit-identical determinism: same event stream, same verdict stream.
#[test]
fn firewall_is_deterministic() {
    let run = || {
        let mut fw = fw_with(FirewallPolicy {
            anomaly_threshold: 2,
            action_ladder: vec![MitigationKind::Drop],
            cooldown_ms: 0,
            ..Default::default()
        });
        let mut out = Vec::new();
        for w in 0..8 {
            out.extend(normal_window(&mut fw, w));
        }
        for w in 8..10 {
            out.extend(flood_window(&mut fw, w, 200));
        }
        for w in 10..14 {
            out.extend(normal_window(&mut fw, w));
        }
        out
    };
    assert_eq!(run(), run());
}

/// FeatureWindow correctness: bucket math, top-src attribution, new-src.
#[test]
fn feature_window_aggregates() {
    use snn_firewall::FeatureWindow;
    let mut win = FeatureWindow::new(1000);
    // Window [0,1000): 4 events, 3 from ip(9).
    for _ in 0..3 {
        assert!(win.observe(&mk_ev(10, ip(9), 300, 100)).is_none());
    }
    assert!(win.observe(&mk_ev(20, ip(1), 900, 300)).is_none());
    // First event of next window finalizes the previous one.
    let fv = win.observe(&mk_ev(1100, ip(1), 0, 0)).unwrap();
    assert_eq!(fv.start_ms, 0);
    assert_eq!(fv.values[0], 4.0); // req/s
    assert_eq!(fv.values[1], 3.0); // top src/s
    assert_eq!(fv.values[2], 2.0); // uniq
    assert_eq!(fv.values[3], 450.0); // mean payload (3*300 + 900)/4
    assert_eq!(fv.values[5], 2.0); // both ips are new
    assert_eq!(fv.top_src, Some((ip(9), 3)));
    // Second window: no new sources → new_src_rate 0.
    let fv = win.observe(&mk_ev(2100, ip(1), 0, 0)).unwrap();
    assert_eq!(fv.values[5], 0.0);
}

/// RuleTable enforcement: deny precedence and TTL reaping.
#[test]
fn rule_table_enforces_and_expires() {
    let mut rt = RuleTable::new();
    rt.insert(snn_firewall::MitigationRule {
        id: 1,
        subject: RuleSubject::Ip(ip(9)),
        kind: MitigationKind::Drop,
        created_ms: 0,
        expires_ms: 5_000,
        offense: 1,
        reason: "test".into(),
    });
    let ev = mk_ev(1000, ip(9), 0, 0);
    assert!(matches!(rt.check(&ev), Verdict::Denied { rule: 1 }));
    let other = mk_ev(1000, ip(1), 0, 0);
    assert_eq!(rt.check(&other), Verdict::Allow);

    assert!(rt.sweep(4_999).is_empty());
    let expired = rt.sweep(5_000);
    assert_eq!(expired.len(), 1);
    assert!(matches!(rt.check(&ev), Verdict::Allow));
}
