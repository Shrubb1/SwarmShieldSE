//! `universal-gateway` — Layer-4 shield: transparent TCP relay in front
//! of ANY service (database, game server, SSH, custom protocol).
//! Every client→server chunk becomes a `ConnEvent` and goes through the
//! same engine: rate/size/cadence/signatures are protocol-agnostic.
//! Allow → forward upstream; Denied/RateLimited → L4 tarpit: the socket
//! stays open but only drips garbage — the attacker hangs on a live
//! connection that never answers. Thread-per-conn; engine under mutex.
//!
//! Usage: `universal_gateway <listen> <target>`
//!   universal_gateway 0.0.0.0:9101 127.0.0.1:3306

use std::io::{Read, Write};
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

/// L4 tarpit: hold the socket, drip garbage — the attacker's client
/// waits on a live connection that never completes its protocol.
fn tarpit(s: &mut TcpStream) {
    eprintln!("[gateway] TARPIT");
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buf = [0u8; 512];
    for _ in 0..40 {
        let _ = s.write_all(b"...");
        let _ = s.flush();
        // If they send more, it's more evidence — drain it silently.
        let _ = s.read(&mut buf);
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn handle(
    mut client: TcpStream,
    target: &str,
    listen_port: u16,
    fw: &Arc<Mutex<Firewall<RecordingPolicySink, MemoryAudit>>>,
) {
    let src = client
        .peer_addr()
        .map(|a| a.ip())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let mut upstream = match TcpStream::connect(target) {
        Ok(u) => u,
        Err(_) => return,
    };
    let _ = client.set_read_timeout(Some(Duration::from_millis(100)));
    let mut buf = [0u8; 8192];

    loop {
        match client.read(&mut buf) {
            Ok(0) => return,                    // client closed
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // idle gap — drain upstream->client meanwhile
            }
            Err(_) => return,
            Ok(n) => {
                let chunk = &buf[..n];
                let ev = ConnEvent {
                    ts_ms: now_ms(),
                    tenant: "t-a".into(),
                    src_ip: src,
                    payload_bytes: n as u32,
                    header_bytes: 0,
                    meta: EventMeta {
                        dst_port: listen_port,
                        proto: 6,
                        ..Default::default()
                    },
                    payload: Some(chunk.to_vec().into_boxed_slice()),
                };
                let verdict = fw
                    .lock()
                    .unwrap()
                    .inspect(&ev)
                    .unwrap_or(Verdict::Allow);
                match verdict {
                    Verdict::Allow => {
                        if upstream.write_all(chunk).is_err() {
                            return;
                        }
                    }
                    _ => {
                        eprintln!("[gateway] {verdict:?} on {src}");
                        tarpit(&mut client);
                        return;
                    }
                }
            }
        }
        // upstream → client relay (non-blocking read)
        let _ = upstream.set_read_timeout(Some(Duration::from_millis(0)));
        match upstream.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => {
                if client.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
            Err(_) => {}
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let listen = args
        .next()
        .unwrap_or_else(|| "127.0.0.1:9101".to_string());
    let target = args
        .next()
        .unwrap_or_else(|| "127.0.0.1:3306".to_string());
    let listen_port = listen
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(9101);
    let listener = TcpListener::bind(&listen).expect("bind failed");
    eprintln!("[gateway] {listen} → {target} (L4 shield active)");
    let fw = Arc::new(Mutex::new(firewall()));
    for s in listener.incoming() {
        let s = match s {
            Ok(s) => s,
            Err(_) => continue,
        };
        let fw = Arc::clone(&fw);
        let target = target.clone();
        std::thread::spawn(move || handle(s, &target, listen_port, &fw));
    }
}
