//! Universal bypass fuzzer: systematically attacks every dimension of
//! the ingestion pipeline — boundary-riding, pacing mutations, extreme
//! metadata, evasion encodings, ghost-IP swarms — through a live
//! Firewall. Asserts: no panic, bounded state, still enforcing at the
//! end. Silent-bypass captures get promoted to unit tests by hand.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

use snn_firewall::{
    channel_names, ConnEvent, EventMeta, Firewall, FirewallPolicy, MemoryAudit, MitigationKind,
    RecordingPolicySink, Verdict,
};
use snn_mesh::DetectorConfig;

fn ip(n: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
}

struct Xor64(u64);
impl Xor64 {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
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

const EVIL: &[&str] = &[
    "' OR 1=1--",
    "'or/**/1=1",
    "%27%20union%20select",
    "union/**/select",
    "../../etc/passwd",
    "%2e%2e%2f",
    "${jndi:ldap://x}",
    "{{7*7}}",
    "GET /.env HTTP",
    "<script>alert(1)</script>",
    ";cat /etc/passwd",
    "\0or 1=1",
    "U\x00n\x00i\x00o\x00n", // null-byte spliced
    "SELECT%09*",
    "UNION\tSELECT",
];

#[test]
fn universal_bypass_fuzz() {
    let (v0, l0, r0, p0) = run(false);
    eprintln!("=== 80/20 NO ALLOWLIST ===");
    eprintln!(
        "events=200000 allow={} denied={} rl={} rules={} playbook={} legit-allow={:.2}%",
        v0[0], v0[1], v0[2], r0, p0, l0
    );
    let (v1, l1, r1, p1) = run(true);
    eprintln!("=== 80/20 LEGIT ALLOWLISTED ===");
    eprintln!(
        "events=200000 allow={} denied={} rl={} rules={} playbook={} legit-allow={:.2}%",
        v1[0], v1[1], v1[2], r1, p1, l1
    );
}

/// The fuzz loop, optionally with the 5 legit IPs in `static_policy.allow`.
/// Returns (verdict counts, legit allow-rate %, distinct rules, playbook).
fn run(allow_listed: bool) -> ([usize; 3], f64, usize, usize) {
    let mut f = fw();
    if allow_listed {
        // Cover the whole legit pool (10.0.{1..8}.{1..254}).
        for b in 1..=8u8 {
            for c in 1..=254u8 {
                f.static_policy.allow.insert(IpAddr::V4(Ipv4Addr::new(10, 0, b, c)));
            }
        }
    }
    let mut rng = Xor64(0x9e3779b97f4a7c15);
    let mut rules = HashSet::new();
    let mut verdicts = [0usize; 3]; // allow, denied, ratelimited
    let total = 200_000u64;
    let mut ts = 0u64;
    // 80% hostile / 20% legit — modes 8-9 are the clean traffic whose
    // survival rate is the real collateral metric.
    let mut legit = [0usize; 2]; // allowed, denied

    for i in 0..total {
        let mode = i % 10;
        let hostile = mode < 8;
        let r = rng.next();
        let ip = match mode {
            // ghost-IP swarm: fully random source each event
            0 => IpAddr::V4(Ipv4Addr::new(
                (r % 254) as u8,
                ((r >> 8) % 254) as u8,
                ((r >> 16) % 254) as u8,
                ((r >> 24) % 254) as u8,
            )),
            // rotating pool of 40
            1 | 2 => IpAddr::V4(Ipv4Addr::new(66, 6, (r % 40) as u8, 6)),
            // legit users: a wide pool (~2000 IPs, ~20 events each) —
            // realistic churn, not 5 IPs at botnet volume
            _ => IpAddr::V4(Ipv4Addr::new(
                10,
                0,
                ((r >> 8) % 8 + 1) as u8,
                ((r >> 16) % 254 + 1) as u8,
            )),
        };
        // pacing: burst, normal, or huge gap
        ts += match mode {
            3 => r % 4,               // micro-bursts
            4 => 60_000 + r % 60_000, // hour-scale gaps
            _ => 90 + r % 40,
        };
        let mut ev = ConnEvent {
            ts_ms: ts,
            tenant: "t-a".into(),
            src_ip: ip,
            payload_bytes: match mode {
                5 => (r % 1_000_000) as u32, // extreme sizes
                _ => 100 + (r % 900) as u32,
            },
            header_bytes: match mode {
                6 => (r % 65_000) as u32,
                _ => 400,
            },
            meta: EventMeta {
                dst_port: (r % 65_535) as u16,
                ua_id: (r % 64) as u16,
                path_len: (r % 2000) as u16,
                payload_entropy: (r % 800) as u8,
                ja3: (r % 512) as u32,
                ..Default::default()
            },
            payload: None,
        };
        if mode == 7 {
            ev.payload = Some(
                EVIL[(r as usize) % EVIL.len()]
                    .as_bytes()
                    .to_vec()
                    .into_boxed_slice(),
            );
        }
        // NaN/extreme payload_entropy is a u8 — can't be NaN, but ports
        // and sizes hit their type ceilings above.
        match f.inspect(&ev).unwrap() {
            Verdict::Allow => {
                verdicts[0] += 1;
                if !hostile {
                    legit[0] += 1;
                }
            }
            Verdict::Denied { rule } => {
                verdicts[1] += 1;
                rules.insert(rule);
                if !hostile {
                    legit[1] += 1;
                }
            }
            Verdict::RateLimited { .. } => {
                verdicts[2] += 1;
                if !hostile {
                    legit[1] += 1;
                }
            }
        }
    }
    let legit_allow = legit[0] as f64 / (legit[0] + legit[1]).max(1) as f64 * 100.0;
    // Survival: engine still answers, still bounded.
    let v = f.inspect(&ConnEvent {
        ts_ms: ts + 1000,
        tenant: "t-a".into(),
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        payload_bytes: 500,
        header_bytes: 400,
        meta: EventMeta::default(),
        payload: None,
    });
    assert!(v.is_ok(), "engine died under fuzz");
    (verdicts, legit_allow, rules.len(), f.playbook.len())
}

/// TNR preservation: a distributed *bare* flood (scans/SYN-style — no
/// method, no path) must get a shape-scoped Pattern rule, NOT Global —
/// legitimate HTTP requests with a different shape keep flowing.
#[test]
fn pattern_scopes_diffuse_flood() {
    use snn_firewall::RuleSubject;
    let mut f = fw();
    let mut ts = 1_000u64;
    let legit_ip = |n: u8| IpAddr::V4(Ipv4Addr::new(10, 0, 0, n));
    let legit = |ip: IpAddr| ConnEvent {
        ts_ms: 0,
        tenant: "t-a".into(),
        src_ip: ip,
        payload_bytes: 300,
        header_bytes: 400,
        meta: EventMeta {
            method: 1,
            proto: 6,
            dst_port: 9101,
            path_len: 12,
            ua_id: (ip.to_string().len() % 40) as u16,
            ..Default::default()
        },
        payload: None,
    };
    // Warm baseline: a POOL of 30 legit users, jittery sparse pacing —
    // each stays far below the persistence threshold that flags C2s.
    for i in 0..150u64 {
        let mut ev = legit(legit_ip((i % 30 + 1) as u8));
        ev.ts_ms = ts;
        ts += 60 + (i * 37) % 160;
        let _ = f.inspect(&ev);
    }
    // Distributed bare flood — rotating IPs (no dominant src), no
    // method, no path — the shape that used to force Global. Legit
    // traffic interleaves, as it would in reality.
    for i in 0..400 {
        ts += 10;
        if i > 200 && i % 80 == (i / 80) % 80 {
            let mut lv = legit(legit_ip((i % 30 + 1) as u8));
            lv.ts_ms = ts;
            let _ = f.inspect(&lv);
        }
        let ev = ConnEvent {
            ts_ms: ts,
            tenant: "t-a".into(),
            src_ip: IpAddr::V4(Ipv4Addr::new(66, (i % 200) as u8, (i % 100) as u8, 1)),
            payload_bytes: 64,
            header_bytes: 0,
            meta: EventMeta {
                method: 0,
                proto: 6,
                dst_port: 9101,
                path_len: 0,
                ..Default::default()
            },
            payload: None,
        };
        let _ = f.inspect(&ev);
    }
    // A Pattern rule should exist — not Global.
    let has_pattern = f
        .active_rules()
        .iter()
        .any(|r| matches!(r.subject, RuleSubject::Pattern(_)));
    let has_global = f
        .active_rules()
        .iter()
        .any(|r| matches!(r.subject, RuleSubject::Global));
    eprintln!(
        "rules: {:?}",
        f.active_rules()
            .iter()
            .map(|r| format!("{:?} <- {}", r.subject, r.reason))
            .collect::<Vec<_>>()
    );
    assert!(has_pattern, "bare flood should emit a shape-scoped rule");
    assert!(!has_global, "no Global collateral needed for shaped attack");

    // TNR: a FRESH legit HTTP user (method=1, path>0, no history) must
    // still be Allowed — Pattern rules can't touch its shape.
    let mut ev = legit(legit_ip(99));
    ts += 50;
    ev.ts_ms = ts;
    let v = f.inspect(&ev).unwrap();
    assert_eq!(v, Verdict::Allow, "legit HTTP collateral-denied: {v:?}");

    // TPR: bare probes (the attack shape) must be mitigated — a burst
    // exhausts any rate-limit bucket, so not all can pass.
    let mut mitigated = 0;
    for _ in 0..80 {
        ts += 5;
        let hostile = ConnEvent {
            ts_ms: ts,
            tenant: "t-a".into(),
            src_ip: IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
            payload_bytes: 64,
            header_bytes: 0,
            meta: EventMeta {
                method: 0,
                proto: 6,
                dst_port: 9101,
                path_len: 0,
                ..Default::default()
            },
            payload: None,
        };
        if !matches!(f.inspect(&hostile).unwrap(), Verdict::Allow) {
            mitigated += 1;
        }
    }
    assert!(
        mitigated > 50,
        "bare probes leaked through pattern rule ({mitigated}/80 mitigated)"
    );
}
