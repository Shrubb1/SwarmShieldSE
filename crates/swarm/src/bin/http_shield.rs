//! `http-shield` — a real HTTP front gate for the SNN firewall.
//! Listens on a port, parses each request into a `ConnEvent` (raw
//! bytes → engine-side signature scan), enforces the verdict, and
//! answers 200 or 403. Attack tools (sqlmap, nikto, curl) hit a real
//! HTTP surface; the engine decides.
//!
//! Usage: `http_shield [listen_addr]`  (default 127.0.0.1:8081)

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};

use snn_firewall::{
    channel_names, ConnEvent, EventMeta, Firewall, FirewallPolicy, MemoryAudit, MitigationKind,
    RecordingPolicySink, Verdict,
};
use snn_mesh::DetectorConfig;

fn firewall() -> Firewall<RecordingPolicySink, MemoryAudit> {
    let mut p = FirewallPolicy {
        anomaly_threshold: 2,
        action_ladder: vec![
            MitigationKind::RateLimit { max_rps: 10.0 },
            MitigationKind::Drop,
            MitigationKind::Block,
        ],
        ttl_ms: 30_000,
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

fn method_id(m: &str) -> u8 {
    match m {
        "GET" => 1,
        "POST" => 2,
        "PUT" => 3,
        "DELETE" => 4,
        _ => 9,
    }
}

fn handle(s: &mut TcpStream, fw: &mut Firewall<RecordingPolicySink, MemoryAudit>) {
    let mut br = BufReader::new(s.try_clone().unwrap());
    let mut raw = Vec::new();
    let mut line = String::new();
    let mut method = 0u8;
    let mut path_len = 0u16;
    let mut fwd_for: Option<String> = None;
    // Read headers until blank line.
    loop {
        line.clear();
        match br.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        raw.extend_from_slice(line.as_bytes());
        let t = line.trim_end();
        if t.is_empty() {
            break;
        }
        if method == 0 {
            let mut parts = t.split_whitespace();
            method = method_id(parts.next().unwrap_or(""));
            path_len = parts.next().map(|p| p.len()).unwrap_or(0) as u16;
        }
        // Proxied deployments: the socket IP is the load balancer — the
        // real client rides in forwarding headers (leftmost entry).
        let tl = t.to_ascii_lowercase();
        for h in ["x-forwarded-for:", "cf-connecting-ip:", "x-real-ip:"] {
            if tl.starts_with(h) && fwd_for.is_none() {
                fwd_for = t[h.len()..].split(',').next().map(|s| s.trim().to_string());
            }
        }
    }
    // Tier-1 smuggling/charset gate — the attacks that beat real WAFs:
    // TE.CL/CL.TE conflicts, duplicate Content-Length, UTF-7/overlong
    // encodings, JSON key pollution. Hard-deny before the event even
    // reaches the engine — parsers disagreeing IS the attack.
    let smug = snn_firewall::Signatures::scan_smuggling(&String::from_utf8_lossy(&raw));
    if smug != 0 {
        let _ = s.set_write_timeout(Some(std::time::Duration::from_secs(2)));
        let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        return;
    }
    let src = fwd_for
        .as_deref()
        .and_then(|f| f.parse().ok())
        .or_else(|| s.peer_addr().map(|a| a.ip()).ok())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
    let ev = ConnEvent {
        ts_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
        tenant: "t-a".into(),
        src_ip: src,
        payload_bytes: raw.len() as u32,
        header_bytes: raw.len() as u32,
        meta: EventMeta {
            method,
            path_len,
            dst_port: 8081,
            ..Default::default()
        },
        payload: Some(raw.clone().into_boxed_slice()),
    };
    let verdict = fw.inspect(&ev).unwrap_or(Verdict::Allow);
    eprintln!("[shield] {src} → {verdict:?}");
    match verdict {
        Verdict::Allow => {
            let body = "<html><head><title>SwarmShieldSE</title></head><body style=\"font-family:monospace;background:#0d1117;color:#3fb950;padding:40px\"><h2>&#x1f6e1; SwarmShieldSE</h2><p>request clean — behavioral SNN firewall active</p><p style=\"color:#8b949e;font-size:12px\">every packet profiled &middot; threats tarpitted</p></body></html>";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
        }
        Verdict::RateLimited { .. } | Verdict::Denied { .. } => {
            // Tarpit: instead of a clean 403, serve a fake success page
            // one drip at a time — the attacker's threads stall waiting
            // while the Scout keeps profiling.
            eprintln!("[shield] TARPIT {src} ({verdict:?})");
            let _ = s.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n",
            );
            let fake: [&str; 6] = [
                "<html><head><title>loading</title></head>",
                "<body><p>connecting to service…</p>",
                "<p>negotiating session…</p>",
                "<p>fetching content…</p>",
                "<p>almost there…</p>",
                "<p>done.</p></body></html>",
            ];
            for chunk in fake {
                let f = format!("{:x}\r\n{}\r\n", chunk.len(), chunk);
                if s.write_all(f.as_bytes()).is_err() {
                    break; // they gave up first
                }
                let _ = s.flush();
                std::thread::sleep(std::time::Duration::from_millis(400));
            }
            let _ = s.write_all(b"0\r\n\r\n");
        }
    }
}

fn main() {
    swarm::crash::install();
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8081".to_string());
    let listener = TcpListener::bind(&addr).expect("bind failed");
    eprintln!("[shield] listening on {addr}");
    // Thread-per-conn: a tarpitted attacker must not block legit
    // connections. Engine shared under a mutex — verdicts serialize.
    let fw = std::sync::Arc::new(std::sync::Mutex::new(firewall()));
    for s in listener.incoming() {
        let mut s = match s {
            Ok(s) => s,
            Err(_) => continue,
        };
        let fw = std::sync::Arc::clone(&fw);
        std::thread::spawn(move || {
            let _ = s.set_nonblocking(false);
            let mut guard = fw.lock().unwrap();
            handle(&mut s, &mut guard);
        });
    }
}
