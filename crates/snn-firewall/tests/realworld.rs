//! Real-world tool profiles: the behavioral signature each tool emits —
//! not real binaries, but the patterns they actually produce — through
//! a live Firewall with the full detection stack enabled.

use std::net::{IpAddr, Ipv4Addr};

use snn_firewall::{
    channel_names, ConnEvent, EventMeta, Firewall, FirewallPolicy, MemoryAudit, MitigationKind,
    RecordingPolicySink, Verdict,
};
use snn_mesh::DetectorConfig;

const TICK: u64 = 1000;
const ATTACKER: IpAddr = IpAddr::V4(Ipv4Addr::new(66, 6, 6, 6));

fn ip(n: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
}

fn fw() -> Firewall<RecordingPolicySink, MemoryAudit> {
    let mut p = FirewallPolicy {
        anomaly_threshold: 2,
        action_ladder: vec![MitigationKind::Drop],
        ttl_ms: 5_000,
        cooldown_ms: 0,
        ..Default::default()
    };
    p.search.enabled = true;
    Firewall::new(
        DetectorConfig {
            delta_threshold: 5.0,
            spike_current: 200.0,
            initial_weight: 80.0,
            window: 10,
            anomaly_threshold: 1,
            ..DetectorConfig::for_metrics(&channel_names())
        },
        p,
        &[
            10.0, 2.0, 5.0, 500.0, 400.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 10.0, 0.0, 0.0, 10.0,
        ],
        RecordingPolicySink::default(),
        MemoryAudit::default(),
    )
}

fn ev(ts: u64, src: IpAddr) -> ConnEvent {
    ConnEvent {
        ts_ms: ts,
        tenant: "t-a".into(),
        src_ip: src,
        payload_bytes: 500,
        header_bytes: 400,
        meta: EventMeta::default(),
        payload: None,
    }
}

fn warm(f: &mut Firewall<RecordingPolicySink, MemoryAudit>, to: u64) {
    for w in 0..to {
        for i in 0..5u8 {
            for k in 0..2u64 {
                f.inspect(&ev(w * TICK + (i as u64 * 2 + k) * 100, ip(i + 1)))
                    .unwrap();
            }
        }
    }
}

// ----------------- sqlmap -----------------
// sqlmap: hundreds of obfuscated SQLi payloads, method=GET, path_len
// long, real URL-encoding + comment-splicing variants.
#[test]
fn sqlmap_profile_locked() {
    let mut f = fw();
    warm(&mut f, 10);
    let payloads = [
        "id=1' OR '1'='1",
        "id=1/**/OR/**/1=1--",
        "id=%27%20union%20select%201,2,3",
        "id=1' AND (SELECT 1 FROM users)--",
        "id=1;WAITFOR DELAY '0:0:5'--",
    ];
    let w = 11u64;
    let mut denied = 0;
    for (i, p) in payloads.iter().enumerate() {
        let mut e = ev(w * TICK + (i as u64) * 200, ATTACKER);
        e.meta.method = 1; // GET
        e.meta.path_len = p.len() as u16;
        e.payload = Some(p.as_bytes().to_vec().into_boxed_slice());
        match f.inspect(&e).unwrap() {
            Verdict::Denied { .. } | Verdict::RateLimited { .. } => denied += 1,
            _ => {}
        }
    }
    // sqlmap's signature hits should flag immediately — Denied or a
    // scout playbook rule quickly.
    assert!(denied >= 3, "sqlmap profile slipped: {denied}/5 denied");
}

// ----------------- nikto / dirb -----------------
// nikto: rapid file enumeration — hundreds of distinct paths/sec,
// mixed status errors (path_len varies, error_rate spikes).
#[test]
fn nikto_enumeration_caught() {
    let mut f = fw();
    warm(&mut f, 10);
    let rules_before = f.sink_mut().applied.len();
    for w in 11..15 {
        for k in 0..80u64 {
            let mut e = ev(w * TICK + k * 12, ATTACKER);
            e.meta.method = 1;
            e.meta.path_len = 8 + (k % 30) as u16; // varied paths
            e.meta.error = k % 3 == 0; // 404s
            f.inspect(&e).unwrap();
        }
    }
    let rules_after = f.sink_mut().applied.len();
    assert!(
        rules_after > rules_before,
        "rapid enumeration should trip a rule"
    );
}

// ----------------- slowloris -----------------
// slowloris: partial requests trickled — tiny payloads, huge gaps,
// held-open connections. Should trip SlowTick/profile/beacon paths.
#[test]
fn slowloris_pacing_flagged() {
    let mut f = fw();
    warm(&mut f, 10);
    // One attacker dripping 1-byte payloads at ~10s intervals.
    let rules_before = f.sink_mut().applied.len();
    for i in 0..20u64 {
        let mut e = ev(11_000 + i * 10_000, ATTACKER);
        e.payload_bytes = 1;
        e.meta.method = 1;
        // Normal traffic continues around it.
        for j in 0..5u8 {
            f.inspect(&ev(11_000 + i * 10_000 + j as u64 * 100, ip(j + 1)))
                .unwrap();
        }
        f.inspect(&e).unwrap();
    }
    let rules_after = f.sink_mut().applied.len();
    assert!(
        rules_after > rules_before,
        "slowloris drip should accumulate to a rule"
    );
}

// ----------------- full sweep -----------------
// All three simultaneously — the layered mesh catches every profile.
#[test]
fn combined_realworld_sweep() {
    let mut f = fw();
    warm(&mut f, 10);
    let sqlmap = IpAddr::V4(Ipv4Addr::new(66, 6, 6, 6));
    let nikto = IpAddr::V4(Ipv4Addr::new(66, 6, 6, 7));
    let loris = IpAddr::V4(Ipv4Addr::new(66, 6, 6, 8));
    let mut hits = 0;
    for w in 11..16 {
        // sqlmap: 5 sqli payloads/window
        for i in 0..5u64 {
            let mut e = ev(w * TICK + i * 200, sqlmap);
            e.payload = Some(b"' OR 1=1--".to_vec().into_boxed_slice());
            if matches!(
                f.inspect(&e).unwrap(),
                Verdict::Denied { .. } | Verdict::RateLimited { .. }
            ) {
                hits += 1;
            }
        }
        // nikto: 40 rapid enumerations/window
        for k in 0..40u64 {
            let mut e = ev(w * TICK + k * 24, nikto);
            e.meta.error = k % 4 == 0;
            f.inspect(&e).unwrap();
        }
        // loris: 2 events/window at huge internal gaps
        for k in 0..2u64 {
            let mut e = ev(w * TICK + k * 400, loris);
            e.payload_bytes = 1;
            f.inspect(&e).unwrap();
        }
        // normals keep flowing
        for i in 0..5u8 {
            for k in 0..2u64 {
                f.inspect(&ev(w * TICK + (i as u64 * 2 + k) * 100, ip(i + 1)))
                    .unwrap();
            }
        }
    }
    eprintln!(
        "combined hits={} applied={}",
        hits,
        f.sink_mut().applied.len()
    );
    assert!(
        f.sink_mut().applied.len() >= 2,
        "realworld sweep under-enforced"
    );
}
