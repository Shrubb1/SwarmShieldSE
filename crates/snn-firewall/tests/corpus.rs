//! Evasion regression corpus — every bypass ever found lives here
//! forever. `CAUGHT` strings must ALWAYS flag (regressions fail the
//! suite); `KNOWN_GAP` strings document the current honest frontier —
//! each one is a future hardening target, not a secret.

use snn_firewall::Signatures;

/// Bypasses we've killed — must never regress.
const CAUGHT: &[&str] = &[
    // comment-splice
    "1/**/union/**/select/**/user",
    "'/**/or/**/'1'='1",
    // + for space
    ";+cat+/etc/shadow",
    "1+union+select+user",
    // null-byte padding (NUL-strip + comment→space catches the real form)
    "x\x00'/**/or/**/'1'='1\x00x",
    "x\x00' or '1'='1\x00x",
    // double percent-encoding — `%2527%2520...` → `'`+space → `' or '`
    "%2527%2520or%2520%25271%2527=%25271",
    // mixed-case after decode
    "%3c%73%43%52%69%50%54%3e%41%6c%65%52%54%28%31%29%3c%2f%73%43%52%49%70%54%3e",
    // leet-speak (the big win — was ~16% of all evasions)
    "${jnd1:ldap://x/}",
    "cmd.3x3 /c wh0am1",
    "1gn0r3%20pr3v10us%201nstruct10ns",
    "1+un10n+s3l3ct+us3r",
    "IGN0r3%20PREV1OUs%20INSTruCt1ONS",
];

/// Documented frontiers — known gaps, each a future target. Keeping
/// them here makes the suite's coverage honest instead of pretending
/// they're caught.
const KNOWN_GAP: &[&str] = &[
    // triple+/nested encode + leet layers stacked — each layer alone is
    // caught; the full stack needs recursive-until-stable normalization
    // which currently caps at 2 passes.
];

#[test]
fn corpus_known_bypasses_stay_dead() {
    for s in CAUGHT {
        assert_ne!(
            Signatures::scan(s.as_bytes()),
            0,
            "regression: {s:?} slipped back through"
        );
    }
}

/// Gap strings SHOULD evade today — the moment one starts catching,
/// flip it into CAUGHT (the harness forces honest bookkeeping).
#[test]
fn corpus_known_gaps_track_frontier() {
    for s in KNOWN_GAP {
        assert_eq!(
            Signatures::scan(s.as_bytes()),
            0,
            "unexpected catch: {s:?} — move it into CAUGHT"
        );
    }
}

/// Smuggling/charset bypasses — `scan_smuggling` must catch these.
#[test]
fn corpus_smuggling_stay_dead() {
    // TE.CL: Content-Length + Transfer-Encoding together
    assert_ne!(
        Signatures::scan_smuggling(
            "POST /x HTTP/1.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"
        ),
        0
    );
    // Conflicting duplicate Content-Length
    assert_ne!(
        Signatures::scan_smuggling(
            "POST /x HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 99\r\n\r\n"
        ),
        0
    );
    // UTF-7 charset confusion
    assert_ne!(
        Signatures::scan_smuggling("GET /x HTTP/1.1\r\nContent-Type: text/plain; charset=utf-7\r\n\r\n"),
        0
    );
    // Overlong encoding marker
    assert_ne!(
        Signatures::scan_smuggling("GET /%c0%ae/etc/passwd HTTP/1.1\r\n\r\n"),
        0
    );
    // JSON duplicate-key pollution
    assert_ne!(
        Signatures::scan_smuggling(r#"{"a":1,"a":2}"#),
        0
    );
    // TRACE verb (XST)
    assert_ne!(
        Signatures::scan_smuggling("TRACE / HTTP/1.1\r\nHost: x\r\n\r\n"),
        0
    );
    // WebSocket covert-channel upgrade
    assert_ne!(
        Signatures::scan_smuggling(
            "GET / HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
        ),
        0
    );
}


#[test]
fn sig_hit_denies_instantly() {
    let baselines = vec![0.0f32; 16];
    let mut fw = snn_firewall::Firewall::new(
        snn_mesh::DetectorConfig::for_metrics(&snn_firewall::channel_names()),
        snn_firewall::FirewallPolicy::default(),
        &baselines,
        snn_firewall::RecordingPolicySink::default(),
        snn_firewall::MemoryAudit::new(),
    );
    let mut ev = snn_firewall::ConnEvent {
        ts_ms: 1_700_000_000_000, tenant: "t".into(), src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(1,2,3,4)),
        payload_bytes: 50, header_bytes: 50, meta: Default::default(),
        payload: Some(b"GET /x=<script>alert(1)</script> HTTP/1.0".to_vec().into_boxed_slice()),
    };
    let v = fw.inspect(&ev).unwrap();
    assert!(matches!(v, snn_firewall::Verdict::Denied{..}), "sig hit must deny");
}
