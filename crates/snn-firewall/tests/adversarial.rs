//! Red-team suite: known evasion classes run against the live engine.
//! Each test is either DEFENDED (assert protection works) or DOCUMENTED
//! (asserts the current behavior at a known boundary so it can't
//! silently regress).

use std::net::{IpAddr, Ipv4Addr};

use snn_firewall::{
    channel_names, Beacons, ConnEvent, EventMeta, EventSource, Firewall, FirewallPolicy,
    MemoryAudit, MetaWindow, MitigationKind, PcapSource, RecordingPolicySink, RuleSubject, Scout,
    Signatures, SlowTick, Verdict,
};
use snn_mesh::{Detector, DetectorConfig, TelemetrySample};

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
        meta: EventMeta::default(),
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

// ----------------- EVASION: threshold riding -----------------
// Attacker sustains exactly +threshold/sec — strict `>` means the delta
// path never fires. DEFENDED by the slow layer: sustained drift trips
// SlowTick's slow-mean (zero-variance floor included).
#[test]
fn threshold_rider_caught_by_slow_layer() {
    let mut det = Detector::new(
        DetectorConfig {
            delta_threshold: 5.0,
            ..DetectorConfig::for_metrics(&["req"])
        },
        &[10.0],
    );
    // Exactly +5.0 — the strict-inequality hole is real:
    let d = det.observe(&TelemetrySample {
        seq: 1,
        ts_ms: 0,
        values: vec![15.0],
    });
    assert_eq!(
        d.input_spikes, 0,
        "boundary-riding should be invisible to delta"
    );

    // ...but sustained +5 IS a slow-mean drift — the layered design's
    // backstop for exactly this hole.
    let mut slow = SlowTick::new(60, 2.0, 1);
    for _ in 0..120 {
        slow.push(&fv(&[10.0]));
    }
    let mut hits = Vec::new();
    for _ in 0..120 {
        hits.extend(slow.push(&fv(&[15.0])));
    }
    assert!(
        hits.contains(&0),
        "sustained threshold-riding escaped the slow layer"
    );
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

// ----------------- EVASION: signature munging -----------------
// Comment-splicing, URL-encoding, case-mixing — all decoded/normalized.
#[test]
fn signature_evasion_variants_caught() {
    assert_eq!(
        Signatures::scan(b"'or/**/1=1--") & 1,
        1,
        "comment splice evaded"
    );
    assert_eq!(
        Signatures::scan(b"%27%20or%201%3D1") & 1,
        1,
        "url-encode evaded"
    );
    assert_eq!(Signatures::scan(b"UNION/**/SELECT") & 1, 1);
    assert_eq!(
        Signatures::scan(b"%2e%2e%2fetc%2fpasswd") & 4,
        4,
        "encoded traversal"
    );
    assert_eq!(
        Signatures::scan("'.oR 1=1--".as_bytes()) & 1,
        1,
        "case-mix evaded"
    );
}

// ----------------- EVASION: rotating sources -----------------
// Fast rotation → new_src_rate catches. Slow rotation (4 new IPs/win)
// sits under the default threshold → silent. The per-metric override
// flags the TRANSITION — but note the adaptive baseline absorbs any
// sustained signal within ~ceil(diff/thr) evals, so the honest contract
// is "catches what the default can't see," not "perma-alerts."
#[test]
fn slow_rotation_scan_needs_threshold_override() {
    let mk = || {
        Detector::new(
            DetectorConfig {
                delta_threshold: 5.0,
                spike_current: 200.0,
                initial_weight: 80.0,
                window: 10,
                anomaly_threshold: 1,
                ..DetectorConfig::for_metrics(&channel_names())
            },
            &[
                // window metrics (0-5), meta (6-14), jitter(15) last
                10.0, 2.0, 5.0, 500.0, 400.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 10.0, 0.0, 0.0,
                10.0, 0.0,
            ],
        )
    };
    let mut default_det = mk();
    let mut override_det = mk();
    override_det.set_metric_threshold(5, 1.5);

    // Same transition, both detectors: new_src jumps 0→4.
    let sample = |seq| TelemetrySample {
        seq,
        ts_ms: seq * TICK,
        values: vec![
            14.0, 2.0, 9.0, 500.0, 400.0, 4.0, 0.0, 0.0, 0.0, 0.0, 0.0, 10.0, 0.0, 0.0, 10.0,
            0.0,
        ],
    };
    let d0 = default_det.observe(&sample(0));
    let d1 = override_det.observe(&sample(0));
    assert_eq!(d0.input_spikes, 0, "4<5 should be invisible by default");
    assert!(
        d1.input_spikes > 0 && d1.anomaly,
        "hair-trigger override didn't flag the scan transition"
    );

    // DOCUMENTED: the adaptive baseline absorbs sustained signal —
    // within ~3 evals the new rate becomes "normal." That's the delta
    // encoder working as designed (transitions, not states).
    let mut tail_spikes = 0;
    for seq in 1..8u64 {
        tail_spikes += override_det.observe(&sample(seq)).input_spikes;
    }
    assert!(
        tail_spikes <= 2,
        "sustained signal should be absorbed, got {tail_spikes} extra spikes"
    );
}

// ----------------- EVASION: window-boundary splitting -----------------
// Burst straddles the tick boundary — both halves still look anomalous.
#[test]
fn boundary_split_burst_still_flags() {
    let mut f = fw();
    for w in 0..10 {
        normal_window(&mut f, w);
    }
    // 100 events in last 400ms of w10 + 100 in first 400ms of w11 —
    // instantaneous 250/s but ~125/window → each window still 12× base.
    for k in 0..200u64 {
        f.inspect(&ev(10 * TICK + 600 + k * 4, ATTACKER)).unwrap();
    }
    for i in 0..5u8 {
        f.inspect(&ev(11 * TICK + i as u64 * 100, ip(i + 1)))
            .unwrap();
    }
    assert!(!f.sink_mut().applied.is_empty(), "boundary-split evaded");
}

// ----------------- EVASION: rule-table games -----------------
// TTL expiry + immediate resume: cooldown can defer re-ruling —
// DOCUMENTED tradeoff (offense counter still escalates the NEXT rule).
#[test]
fn post_expiry_resume_documented() {
    let mut f = fw();
    for w in 0..10 {
        normal_window(&mut f, w);
    }
    for w in 11..14 {
        for k in 0..200u64 {
            f.inspect(&ev(w * TICK + k * 4, ATTACKER)).unwrap();
        }
    }
    assert!(!f.sink_mut().applied.is_empty());
}

// ----------------- EVASION: resource exhaustion -----------------
// Unique-IP storm: profiles/beacons capped at 10k — no OOM, no hang.
// Note the storm itself IS an attack (new_src explosion) → rules and
// Denied verdicts are correct; the assertion is that the engine stays
// responsive and bounded afterward.
#[test]
fn unique_ip_storm_bounded() {
    let mut f = fw();
    for k in 0..20_000u64 {
        let src = IpAddr::V4(Ipv4Addr::new(200, (k >> 8) as u8, (k & 255) as u8, 1));
        f.inspect(&ev(k, src)).unwrap();
    }
    assert!(
        !f.sink_mut().applied.is_empty(),
        "20k unique sources should trip new_src detection"
    );
    // Engine still answers verdicts afterward (no panic/hang).
    let _v = f.inspect(&ev(21_000, ip(1))).unwrap();
}

// ----------------- EVASION: disorder -----------------
// Out-of-order + duplicate events must not panic or corrupt verdicts.
#[test]
fn out_of_order_events_safe() {
    let mut f = fw();
    normal_window(&mut f, 0);
    normal_window(&mut f, 2);
    // Late arrival for window 0 — after window 2 already flowed.
    let v = f.inspect(&ev(100, ip(1))).unwrap();
    assert!(matches!(
        v,
        Verdict::Allow | Verdict::Denied { .. } | Verdict::RateLimited { .. }
    ));
    let v2 = f.inspect(&ev(100, ip(1))).unwrap(); // exact duplicate
    assert!(matches!(
        v2,
        Verdict::Allow | Verdict::Denied { .. } | Verdict::RateLimited { .. }
    ));
}

// ----------------- EVASION: cadence tricks -----------------
// Fully random gaps → DOCUMENTED no-flag (information-theory boundary:
// a modeless walk is noise).
#[test]
fn random_walk_beacon_documented() {
    let mut b = Beacons::new(0.15, 6);
    let mut ts = 0u64;
    // Deterministic pseudo-random gaps, full-spectrum spread.
    let mut x = 0x9e3779b9u64;
    for _ in 0..200 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        ts += 1 + (x % 900);
        assert!(b.observe(&ev(ts, ip(1))).is_none());
    }
}

// ----------------- EVASION: meta trust -----------------
// Producer sets dst_port — port-spread keeps entropy low.
#[test]
fn port_spread_entropy_normal() {
    let mut mw = MetaWindow::default();
    for p in 0..50u16 {
        let mut e = ev(0, ip(1));
        e.meta.dst_port = p;
        mw.observe(&e);
    }
    let v = mw.values();
    // 50 distinct ports → high entropy — a scanner's signal, honestly.
    assert!(v[0] > 400.0, "port spread should register as scan");
}

// ----------------- EVASION: modeless walks -----------------
// DOCUMENTED blind spot: a modeless walk — uniform jitter over ANY
// band — is indistinguishable from noise. CV finds no regularity, the
// histogram finds no mode, and "bounded range" alone can't separate
// attack-jitter from noise (verified: every ratio-based persistence
// heuristic false-flags unbounded traffic). Caught only if the walk
// also trips a volume/source channel — defense-in-depth, not a single
// detector.
#[test]
fn modeless_walk_documented_blind_spot() {
    let mut b = Beacons::new(0.15, 6);
    let mut ts = 0u64;
    let mut x = 0x2545f4914f6cdd1du64;
    // Bounded band [100,300] — no dominant mode.
    for _ in 0..30 {
        x ^= x << 13;
        x ^= x >> 7;
        ts += 100 + (x % 200);
        assert!(b.observe(&ev(ts, ip(1))).is_none());
    }
    // Unbounded [1,900] — same story, wider band.
    for _ in 0..200 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        ts += 1 + (x % 900);
        assert!(b.observe(&ev(ts, ip(1))).is_none());
    }
}

// ----------------- EVASION: meta lying -----------------
// Producer says sig_hits=0 while the payload contains SQLi — the
// engine scans attached bytes itself and the lie dies.
#[test]
fn engine_side_payload_scan_beats_lying_producer() {
    let mut mw = MetaWindow::default();
    let mut e = ev(0, ip(1));
    e.meta.sig_hits = 0; // producer claims clean
    e.payload = Some(
        b"GET /x?id=' union select pass --"
            .to_vec()
            .into_boxed_slice(),
    );
    mw.observe(&e);
    let v = mw.values();
    assert!(
        (v[7] - 100.0).abs() < 1e-4,
        "engine-side scan should catch the hidden signature"
    );
    // Entropy also computed in-engine, not trusted.
    assert!(v[6] > 0.0, "entropy should be engine-computed");
}

// New signature categories: JNDI, template injection, secret probes.
#[test]
fn signature_new_categories() {
    assert_eq!(Signatures::scan(b"${jndi:ldap://evil/x}") & 32, 32);
    assert_eq!(Signatures::scan(b"{{7*7}}") & 64, 64);
    assert_eq!(Signatures::scan(b"GET /.env HTTP") & 128, 128);
    assert_eq!(Signatures::scan(b"GET /.git/config") & 128, 128);
}

// ----------------- Scout layer -----------------
// Modeless random-walk beacon: invisible to Beacons (documented) but
// Scout's Persistence counts sustained contacts — the walk can't hide
// its VOLUME of check-ins even with fully random gaps.
#[test]
fn scout_persistence_catches_modeless_walk() {
    let mut s = Scout::new();
    s.persistence.threshold = 10; // lower bar for test speed
    let mut ts = 0u64;
    let mut x = 0x9e3779b9u64;
    let mut peak = 0f32;
    for _ in 0..40 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        ts += 1 + (x % 900);
        peak = peak.max(s.observe(&ev(ts, ip(1))).unwrap_or(0.0));
    }
    assert!(
        peak > 0.3,
        "scout should flag sustained random check-ins, got {peak}"
    );
}

// Scout decays suspicion for quiet sources — a one-off probe doesn't
// leave a permanent stain.
#[test]
fn scout_decays_quiet_sources() {
    let mut s = Scout::new();
    let mut e = ev(0, ip(1));
    e.payload = Some(b"GET /x union select pass --".to_vec().into_boxed_slice());
    let hot = s.observe(&e).unwrap_or(0.0);
    assert!(hot >= s.sig_weight, "sig hit should spike suspicion");
    for t in 1..60 {
        s.observe(&ev(t * 1000, ip(1)));
    }
    assert!(
        s.suspicion(ip(1)) < 0.1,
        "quiet source should decay back to clean"
    );
}

// Scout escalation → real Ip rule through the shared emit path.
#[test]
fn scout_flag_emits_ip_rule() {
    let mut f = fw();
    f.scout.flag_at = 0.5;
    f.scout.persistence.threshold = 5;
    for w in 0..10 {
        normal_window(&mut f, w);
    }
    // Suspicious payload-carrying talker, sustained contact.
    for w in 10..20 {
        let mut e = ev(w * TICK, ATTACKER);
        e.payload = Some(b"union select".to_vec().into_boxed_slice());
        f.inspect(&e).unwrap();
        for i in 0..5u8 {
            for k in 0..2u64 {
                f.inspect(&ev(w * TICK + (i as u64 * 2 + k) * 100, ip(i + 1)))
                    .unwrap();
            }
        }
    }
    assert!(
        f.sink_mut()
            .applied
            .iter()
            .any(|r| r.reason.contains("scout")),
        "scout flag should emit an Ip rule"
    );
}

// ----------------- Reference anchor -----------------
// The adaptive baseline absorbs a slow walk — but the frozen reference
// can't. ref_drift trips a rule where delta-blindness would otherwise
// absorb the sustained shift.
#[test]
fn reference_anchor_catches_absorbed_walk() {
    let mut det = Detector::new(
        DetectorConfig {
            delta_threshold: 5.0,
            spike_current: 200.0,
            initial_weight: 80.0,
            window: 10,
            anomaly_threshold: 1,
            ..DetectorConfig::for_metrics(&["req"])
        },
        &[10.0],
    );
    // Sustained +40 — adaptive absorbs it in ~8 evals; reference stays.
    let mut drifts = Vec::new();
    for seq in 0..12u64 {
        drifts.push(
            det.observe(&TelemetrySample {
                seq,
                ts_ms: seq * 1000,
                values: vec![50.0],
            })
            .reference_drift,
        );
    }
    assert!(
        drifts.iter().all(|&d| d >= 40.0 - 1e-4),
        "reference drift should track |observed - anchor| exactly"
    );
}

// ----------------- Mitigation search: minimal sufficient -----------------
// 60 req/s attacker: RL{50} lets ~all through (no hits, no metric drop)
// → escalate to RL{10} → ~50 denied/sec accumulate hits → confirmed →
// probe DOWN to RL{50} → metric still hot (arrivals continue) →
// descend-fail → revert. Playbook must learn RateLimit{10} — the
// minimal sufficient fix, not the harshest.
#[test]
fn search_learns_minimal_sufficient_fix() {
    let mut f = fw();
    f.policy.search.enabled = true;
    f.policy.search.confirm_hits = 40;
    for w in 0..10 {
        normal_window(&mut f, w);
    }
    // Sustained 60 events/window from the attacker.
    for w in 10..26 {
        for k in 0..60u64 {
            f.inspect(&ev(w * TICK + k * 15, ATTACKER)).unwrap();
        }
    }
    // Dominant channel for a single-IP flood is top_src_rate (idx 1) —
    // the attacker's own rate deviates furthest from baseline.
    let learned = f
        .playbook
        .get(&format!("{:?}:1", RuleSubject::Ip(ATTACKER)))
        .cloned();
    assert_eq!(
        learned,
        Some(MitigationKind::RateLimit { max_rps: 10.0 }),
        "search should converge on the minimal sufficient rung"
    );
}

// Playbook replay: second attack of the same shape skips the whole
// search and lands the learned fix instantly.
#[test]
fn playbook_replays_learned_fix() {
    let mut f = fw();
    f.policy.search.enabled = true;
    f.policy.search.confirm_hits = 40;
    for w in 0..10 {
        normal_window(&mut f, w);
    }
    for w in 10..26 {
        for k in 0..60u64 {
            f.inspect(&ev(w * TICK + k * 15, ATTACKER)).unwrap();
        }
    }
    assert!(!f.playbook.is_empty(), "search never confirmed");
    // Dampen the scout layer for this test — we want the playbook
    // replay specifically, not persistence-suspicion containment.
    f.scout.flag_at = 99.0;
    // Let rules drain — the grown TTL tail (offense^growth) means the
    // last rule can live ~40s; drain past it, then re-attack same shape.
    for w in 26..62 {
        normal_window(&mut f, w);
    }
    // Bursts at random window offsets — in-burst gaps stay under the
    // beacon floor, boundary gaps vary per window, no cadence survives:
    // only the detector → playbook replay path can fire.
    let mut x = 0x2545f4914f6cdd1du64;
    for w in 62..72 {
        x ^= x << 13;
        x ^= x >> 7;
        let off = x % 300;
        for k in 0..40u64 {
            f.inspect(&ev(w * TICK + off + k * 20, ATTACKER)).unwrap();
        }
    }
    let replayed = f
        .sink_mut()
        .applied
        .iter()
        .any(|r| r.reason.starts_with("playbook fix:"));
    assert!(
        replayed,
        "second attack should hit the learned fix directly"
    );
}

// ----------------- Live pcap replay -----------------
// A real libpcap binary (Wireshark-format bytes) carrying a SYN-flood
// + SQLi-in-TCP-payload attack is parsed by PcapSource and driven
// through the engine — the file → parse → ConnEvent → rule path is
// the same one a live WinDivert/tcpdump feed would take.
fn pcap_pkt(src: [u8; 4], dst_port: u16, payload: &[u8], ts_sec: u32) -> Vec<u8> {
    let ip_total = 20 + 20 + payload.len() as u16;
    let frame_len = 14 + ip_total as usize;
    let mut rec = Vec::with_capacity(16 + frame_len);
    rec.extend(ts_sec.to_le_bytes());
    rec.extend(0u32.to_le_bytes()); // usec
    rec.extend((frame_len as u32).to_le_bytes());
    rec.extend((frame_len as u32).to_le_bytes());
    // Ethernet
    rec.extend([0xaa; 6]);
    rec.extend([0xbb; 6]);
    rec.extend(0x0800u16.to_be_bytes());
    // IPv4 header (20B): ver/ihl, tos, len, id, frag, ttl, proto, csum, src, dst
    rec.push(0x45);
    rec.push(0);
    rec.extend(ip_total.to_be_bytes());
    rec.extend(0u16.to_be_bytes()); // id
    rec.extend(0u16.to_be_bytes()); // frag
    rec.push(64); // ttl
    rec.push(6); // proto TCP
    rec.extend(0u16.to_be_bytes()); // csum
    rec.extend(src);
    rec.extend([10, 0, 0, 1]);
    // TCP header (20B): src port, dst port, seq, ack, flags, win, csum, urg
    rec.extend(0u16.to_be_bytes());
    rec.extend(dst_port.to_be_bytes());
    rec.extend([0; 16]);
    rec.extend(payload);
    rec
}

#[test]
fn real_pcap_binary_replays_attacks() {
    // Assemble a valid libpcap file: global header + records.
    let mut file = Vec::new();
    file.extend([0xd4, 0xc3, 0xb2, 0xa1]); // LE magic
    file.extend(2u16.to_le_bytes());
    file.extend(4u16.to_le_bytes());
    file.extend(0i32.to_le_bytes());
    file.extend(0u32.to_le_bytes());
    file.extend(65535u32.to_le_bytes());
    file.extend(1u32.to_le_bytes()); // Ethernet

    let atk = [66, 6, 6, 6];
    let _nrm = [10, 0, 0, 1];
    // 15s of normal traffic (1s ticks), then a 200-pkt/sec SYN flood
    // on the same source, then 5 SQLi-in-TCP payloads.
    for w in 0..10u32 {
        for i in 1..=5u8 {
            for _k in 0..2u32 {
                file.extend(pcap_pkt([10, 0, 0, i], 443, b"GET / HTTP/1.1", w));
            }
        }
    }
    for w in 11..14u32 {
        for k in 0..200u32 {
            file.extend(pcap_pkt(atk, 80 + (k % 30) as u16, b"", w));
        }
    }
    for (i, p) in [
        b"GET /?id=' OR 1=1--".as_slice(),
        b"GET /?x=${jndi:ldap://e}".as_slice(),
    ]
    .iter()
    .enumerate()
    {
        file.extend(pcap_pkt(atk, 443, p, 15 + i as u32 / 2));
    }
    // Normals keep flowing.
    for w in 15..18u32 {
        for i in 1..=5u8 {
            for _k in 0..2u32 {
                file.extend(pcap_pkt([10, 0, 0, i], 443, b"GET /ok", w));
            }
        }
    }

    let mut src = PcapSource::open(std::io::Cursor::new(file)).expect("bad pcap");
    let mut f = fw();
    let mut events = 0usize;
    while let Some(ev) = src.next_event() {
        events += 1;
        f.inspect(&ev).unwrap();
    }
    eprintln!(
        "pcap events={} applied={}",
        events,
        f.sink_mut().applied.len()
    );
    assert!(events >= 620, "pcap parser lost packets: {events}");
    assert!(
        !f.sink_mut().applied.is_empty(),
        "pcap-driven attack never tripped a rule"
    );
}

// ----------------- Kill-chain prediction -----------------
// recon (unusual ports) → enumeration (errors) → exploit: the rule
// must exist BEFORE the sqli event — pre-emption, not reaction.
#[test]
fn killchain_predicts_and_preempts() {
    let mut f = fw();
    // Dampen the faster detectors — this test isolates the kill-chain
    // predictor specifically; other tests cover their paths.
    f.policy.anomaly_threshold = 999;
    f.policy.ref_drift_threshold = 9e9;
    f.scout.flag_at = 99.0;
    for w in 0..10 {
        normal_window(&mut f, w);
    }
    // Stage 0: one probe per window — every detector stays under
    // threshold; only the kill-chain tracker sees the sequence.
    for (i, p) in [22u16, 23, 3389, 5432].iter().enumerate() {
        let mut e = ev(11_000 + i as u64 * 2000, ATTACKER);
        e.meta.dst_port = *p;
        f.inspect(&e).unwrap();
    }
    // Stage 1: sparse enumeration. The FIRST stage-1 event completes
    // recon+enum → predicted rule before any channel goes anomalous.
    for k in 0..6u64 {
        let mut e = ev(19_000 + k * 500, ATTACKER);
        e.meta.dst_port = 443;
        e.meta.error = true;
        e.meta.path_len = 70;
        f.inspect(&e).unwrap();
    }
    let pre = f
        .sink_mut()
        .applied
        .iter()
        .filter(|r| r.reason.starts_with("predicted kill-chain"))
        .count();
    // Stage 2: the actual exploit payload — should be denied by the
    // ALREADY-LIVE predicted rule.
    let mut sqli = ev(23_000, ATTACKER);
    sqli.payload = Some(b"' OR 1=1--".to_vec().into_boxed_slice());
    let v = f.inspect(&sqli).unwrap();
    eprintln!("pre-emptive rules={} verdict={:?}", pre, v);
    assert!(pre >= 1, "kill-chain never predicted");
    assert!(
        matches!(v, Verdict::Denied { .. } | Verdict::RateLimited { .. }),
        "predicted attacker slipped the exploit"
    );
    // The denying rule must predate the sqli event (created < t=17000).
    let rule_ms = f
        .sink_mut()
        .applied
        .iter()
        .filter(|r| r.reason.starts_with("predicted kill-chain"))
        .map(|r| r.created_ms)
        .min();
    assert!(rule_ms.is_some_and(|t| t < 23_000));
}

// ----------------- Actor fingerprint / IP rotation -----------------
// Attacker flagged under IP A, rotates to IP B with the same ja3+ua —
// B must be denied on event one, no re-learning needed.
#[test]
fn fingerprint_beats_ip_rotation() {
    let mut f = fw();
    f.scout.flag_at = 99.0; // isolate the identity path
    f.policy.anomaly_threshold = 999;
    f.policy.ref_drift_threshold = 9e9;
    for w in 0..10 {
        normal_window(&mut f, w);
    }
    let ja3 = 0x0123_4567u32;
    let ua = 42u16;
    // Attack under IP A: sqli payload → signature flag → fingerprint.
    let mut a = ev(11_000, ATTACKER);
    a.meta.ja3 = ja3;
    a.meta.ua_id = ua;
    a.payload = Some(b"' OR 1=1--".to_vec().into_boxed_slice());
    f.inspect(&a).unwrap();
    // Rotate to IP B — same fingerprint, first event, benign payload.
    let ip_b = IpAddr::V4(Ipv4Addr::new(66, 6, 6, 9));
    let mut b = ev(12_000, ip_b);
    b.meta.ja3 = ja3;
    b.meta.ua_id = ua;
    let v = f.inspect(&b).unwrap();
    let fp_rules = f
        .sink_mut()
        .applied
        .iter()
        .filter(|r| r.reason.starts_with("actor fingerprint match"))
        .count();
    eprintln!("fp rules={} verdict={:?}", fp_rules, v);
    assert!(fp_rules >= 1, "rotation not flagged");
    assert!(matches!(
        v,
        Verdict::Denied { .. } | Verdict::RateLimited { .. }
    ));
    // Sanity: a DIFFERENT fingerprint on IP C is untouched.
    let ip_c = IpAddr::V4(Ipv4Addr::new(66, 6, 6, 10));
    let mut c = ev(13_000, ip_c);
    c.meta.ja3 = 0xdead_beef;
    c.meta.ua_id = 7;
    assert_eq!(f.inspect(&c).unwrap(), Verdict::Allow);
}

// ----------------- Soft allowlist: observe, don't block -----------------
// An allowlisted IP attacking stays Allowed (no collateral lockout) but
// every flag lands as an audit Alert — a turned insider can't move
// silently.
#[test]
fn allowlisted_attacker_is_alerted_not_denied() {
    let mut f = fw();
    f.static_policy.allow.insert(ATTACKER);
    f.scout.flag_at = 99.0;
    for w in 0..10 {
        normal_window(&mut f, w);
    }
    // The trusted source turns hostile — a short sqli burst across
    // windows so evals finalize and flags actually reach emit().
    for i in 0..6u64 {
        let mut e = ev(11_000 + i * 800, ATTACKER);
        e.payload = Some(b"' OR 1=1--".to_vec().into_boxed_slice());
        let v = f.inspect(&e).unwrap();
        assert_eq!(
            v,
            Verdict::Allow,
            "allowlisted traffic must never hard-block"
        );
    }
    // But the flag was logged as an Alert, not silently dropped.
    let alerts = f
        .audit()
        .records
        .iter()
        .filter(|r| matches!(r.kind, snn_firewall::AuditKind::Alert { .. }))
        .count();
    eprintln!("alerts={}", alerts);
    assert!(alerts >= 1, "allowlisted attack went unobserved");
}
