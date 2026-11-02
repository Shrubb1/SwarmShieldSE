//! `sys-proxy` — system-wide protection without drivers: an HTTP CONNECT
//! proxy. Set it as the OS/browser proxy and every proxy-respecting app's
//! traffic flows through the engine — the same way corporate proxies work.
//!
//! CONNECT host:443 → engine sees the hostname (block/flag by domain)
//! plus the byte stream (rate/cadence/entropy — beacons don't need
//! plaintext). Inside TLS we can't read content without a MITM cert —
//! behavioral channels carry the load. That's the honest limit.
//!
//! Usage: `sys_proxy [listen]`  (default 127.0.0.1:9090)

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
        &[10.0, 2.0, 5.0, 500.0, 400.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 10.0, 0.0, 0.0, 10.0],
        RecordingPolicySink::default(),
        MemoryAudit::default(),
    )
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Deny a CONNECT politely at the proxy layer (client sees a real error,
/// not a hung socket — tarpit semantics don't fit CONNECT).
fn tarpit_hold(s: &mut TcpStream, host: &str) {
    eprintln!("[sysproxy] HOLD {host} — connection kept open, no data");
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    let mut b = [0u8; 512];
    for _ in 0..40 {
        let _ = s.read(&mut b);
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn handle(client: TcpStream, fw: &Arc<Mutex<Firewall<RecordingPolicySink, MemoryAudit>>>) {
    let src = client
        .peer_addr()
        .map(|a| a.ip())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let mut br = BufReader::new(client.try_clone().unwrap());
    // First line: CONNECT host:port HTTP/1.1   (or plain GET for http)
    let mut line = String::new();
    if br.read_line(&mut line).is_err() {
        return;
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 || !parts[0].eq_ignore_ascii_case("CONNECT") {
        // Plain HTTP proxy form: GET http://host/path — minimal support:
        // forward raw via the same relay after resolving host header.
        let _ = client.shutdown(std::net::Shutdown::Both);
        return;
    }
    let target = parts[1].to_string();
    // Drain remaining headers.
    let mut host_hdr = String::new();
    loop {
        line.clear();
        match br.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let t = line.trim_end();
        if t.is_empty() {
            break;
        }
        if t.to_ascii_lowercase().starts_with("host:") {
            host_hdr = t[5..].trim().to_string();
        }
    }
    let host = if host_hdr.is_empty() {
        target.clone()
    } else {
        host_hdr
    };
    // The CONNECT request itself is an event — hostname-level intel.
    let ev = ConnEvent {
        ts_ms: now_ms(),
        tenant: "t-a".into(),
        src_ip: src,
        payload_bytes: host.len() as u32,
        header_bytes: line.len() as u32,
        meta: EventMeta {
            dst_port: target.rsplit(':').next().and_then(|p| p.parse().ok()).unwrap_or(443),
            path_len: host.len() as u16,
            proto: 6,
            ..Default::default()
        },
        payload: Some(host.as_bytes().to_vec().into_boxed_slice()),
    };
    let v = fw.lock().unwrap().inspect(&ev).unwrap_or(Verdict::Allow);
    if !matches!(v, Verdict::Allow) {
        eprintln!("[sysproxy] {src} → {host}  {v:?}");
        tarpit_hold(&mut client.try_clone().unwrap(), &host);
        return;
    }
    println!("[conn] {src} → {host}");
    let mut upstream = match TcpStream::connect(&target) {
        Ok(u) => u,
        Err(_) => {
            let _ = client.try_clone().unwrap().write_all(
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n",
            );
            return;
        }
    };
    let _ = client.try_clone().unwrap().write_all(
        b"HTTP/1.1 200 Connection established\r\n\r\n",
    );
    // Bytes the BufReader pre-read past the CONNECT headers (e.g. a
    // TLS ClientHello in the same segment) must go upstream or the
    // handshake dies.
    let leftover = br.buffer().to_vec();
    if !leftover.is_empty() && upstream.write_all(&leftover).is_err() {
        return;
    }

    // Two blocking pumps — the alternating-timeout loop was too fragile
    // for real TLS handshakes.
    let mut c2u_client = client.try_clone().unwrap();
    let mut c2u_upstream = upstream.try_clone().unwrap();
    let mut u2c_upstream = upstream;
    let mut u2c_client = client;
    let host_c = host.clone();
    let fw_c = Arc::clone(fw);
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match c2u_client.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    let chunk = &buf[..n];
                    let ev = ConnEvent {
                        ts_ms: now_ms(),
                        tenant: "t-a".into(),
                        src_ip: src,
                        payload_bytes: n as u32,
                        header_bytes: 0,
                        meta: EventMeta {
                            dst_port: 443,
                            proto: 6,
                            ..Default::default()
                        },
                        payload: Some(chunk.to_vec().into_boxed_slice()),
                    };
                    let v = fw_c
                        .lock()
                        .unwrap()
                        .inspect(&ev)
                        .unwrap_or(Verdict::Allow);
                    match v {
                        Verdict::Allow => {
                            if c2u_upstream.write_all(chunk).is_err() {
                                return;
                            }
                        }
                        _ => {
                            eprintln!("[sysproxy] {src} → {host_c} mid-stream {v:?}");
                            tarpit_hold(&mut c2u_client, &host_c);
                            return;
                        }
                    }
                }
            }
        }
    });
    // upstream → client pump in this thread.
    let mut buf = [0u8; 8192];
    loop {
        match u2c_upstream.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if u2c_client.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
        }
    }
}

fn main() {
    let listen = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9090".to_string());
    println!("SwarmShieldSE system proxy on {listen}");
    println!("  set it as the OS/browser proxy → all app traffic inspected");
    let listener = TcpListener::bind(&listen).expect("bind failed");
    let fw = Arc::new(Mutex::new(firewall()));
    for s in listener.incoming().flatten() {
        let fw = Arc::clone(&fw);
        std::thread::spawn(move || handle(s, &fw));
    }
}
