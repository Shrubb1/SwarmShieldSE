//! `swarmshield` — the consumer runner: one terminal, live plain-English
//! feed of what the firewall sees and does. Protects ANY TCP service.
//!
//! Usage:
//!   swarmshield <listen:target> [more listen:target ...]
//!   swarmshield 9101:8081 3307:3306
//!   (defaults: 9101:8081)

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use snn_firewall::{
    channel_names, AuditKind, ConnEvent, EventMeta, Firewall, FirewallPolicy, MemoryAudit,
    MitigationKind, RecordingPolicySink, Verdict,
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

/// Turn a rule's technical reason into a plain sentence anyone gets.
fn explain(reason: &str) -> &'static str {
    if reason.contains("beacon") {
        "is checking in on a schedule — like malware phoning home"
    } else if reason.contains("kill-chain") {
        "is snooping around like an attacker setting up — stopped early"
    } else if reason.contains("fingerprint") {
        "is the same attacker on a new address — recognized and blocked"
    } else if reason.contains("scout") {
        "is acting suspicious — watching closely"
    } else if reason.contains("playbook") {
        "matched a known attack — hit with the fix that worked before"
    } else if reason.contains("search") {
        "triggered a defense — trying the right fix for this attack"
    } else if reason.contains("baseline") || reason.contains("slow") {
        "is behaving strangely compared to normal traffic"
    } else if reason.contains("sig") || reason.contains("injection") {
        "tried to sneak in malicious code (like a database attack)"
    } else if reason.contains("static") || reason.contains("blocklist") {
        "is on the blocklist — known bad actor"
    } else if reason.contains("Global") {
        "caused a flood — everything's being temporarily shielded"
    } else {
        "is doing something abnormal — blocked to be safe"
    }
}

fn say(quiet: bool, ip: std::net::IpAddr, kind: &str, msg: &str) {
    if quiet && kind == "ok" {
        return;
    }
    let tag = match kind {
        "ok" => "  ok ",
        "watch" => "watch",
        "slow" => "slow!",
        "trap" => "TRAP ",
        _ => "  ?? ",
    };
    println!("[{tag}] {ip} {msg}");
}

/// L4 tarpit with friendly narration.
fn tarpit(s: &mut TcpStream, ip: std::net::IpAddr) {
    say(false, ip, "trap", "→ stuck in the tar — wasting their time on a fake connection");
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buf = [0u8; 512];
    for _ in 0..40 {
        let _ = s.write_all(b"...");
        let _ = s.flush();
        let _ = s.read(&mut buf);
        std::thread::sleep(Duration::from_millis(500));
    }
    println!("[done] {ip} gave up or finished in the trap");
}

fn handle(
    mut client: TcpStream,
    target: &str,
    listen_port: u16,
    quiet: bool,
    fw: &Arc<Mutex<Firewall<RecordingPolicySink, MemoryAudit>>>,
    audit_prev: &Arc<Mutex<usize>>,
) {
    let src = client
        .peer_addr()
        .map(|a| a.ip())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let mut upstream = match TcpStream::connect(target) {
        Ok(u) => u,
        Err(_) => {
            say(false, src, "??", "→ can't reach the protected service right now");
            return;
        }
    };
    let _ = client.set_read_timeout(Some(Duration::from_millis(100)));
    let mut buf = [0u8; 8192];
    let mut explained = false;

    loop {
        match client.read(&mut buf) {
            Ok(0) => return,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
            {
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
                        if !explained {
                            say(quiet, src, "ok", "— looks normal, let them through");
                            explained = true;
                        }
                        if upstream.write_all(chunk).is_err() {
                            return;
                        }
                    }
                    Verdict::RateLimited { .. } => {
                        say(false, src, "slow", "→ sending too fast — slowing them down");
                        tarpit(&mut client, src);
                        return;
                    }
                    Verdict::Denied { .. } => {
                        tarpit(&mut client, src);
                        return;
                    }
                }
            }
        }
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
        // Show any new findings the engine logged — in plain words.
        {
            let g = fw.lock().unwrap();
            let recs = g.audit().records.len();
            let mut prev = audit_prev.lock().unwrap();
            for r in g.audit().records[*prev..].iter() {
                let src = r.src.map(|i| i.to_string()).unwrap_or_else(|| "someone".into());
                match &r.kind {
                    AuditKind::Mitigation { rule } => {
                        println!("[ !! ] {src} {}", explain(&rule.reason));
                        println!("       → action: {}", action_words(&rule.kind));
                    }
                    AuditKind::Alert { reason } => {
                        println!("[warn] {src} (trusted) {}", explain(reason));
                    }
                    AuditKind::DownShift { .. } => {}
                    _ => {}
                }
            }
            *prev = recs;
        }
    }
}

fn action_words(kind: &MitigationKind) -> &'static str {
    match kind {
        MitigationKind::RateLimit { .. } => "slowed down",
        MitigationKind::Drop => "blocked",
        MitigationKind::Block => "blocked hard",
    }
}

/// First-run disclosure — the user sees exactly what the software does
/// before it does anything. Consent is remembered via a marker file.
fn consent() -> bool {
    let marker = std::env::var("USERPROFILE")
        .map(|p| format!("{p}\\.swarmshield-consent"))
        .unwrap_or_else(|_| ".swarmshield-consent".into());
    if std::path::Path::new(&marker).exists() {
        return true;
    }
    println!("=============================================================");
    println!("  SwarmShieldSE — what this software does:");
    println!("   • runs a local network guard in the background");
    println!("   • watches traffic you point it at for attacks");
    println!("   • slows down / traps / blocks what's hostile");
    println!("   • learns your normal traffic IN MEMORY ONLY —");
    println!("     nothing is saved, nothing is sent anywhere");
    println!("   • optional: pulls a shared blocklist from the web");
    println!("     (download only — your data never uploads)");
    println!("  Type YES to run: ");
    println!("=============================================================");
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    if input.trim().eq_ignore_ascii_case("yes") {
        let _ = std::fs::write(&marker, "consented\n");
        true
    } else {
        println!("  not consented — exiting without running anything");
        false
    }
}

/// Optional privacy-first update: pull a shared blocklist file from a
/// URL every N minutes — download-only, no telemetry uploads. Requires
/// a real endpoint URL; skipped silently when unset/failed.
fn update_loop(fw: Arc<Mutex<Firewall<RecordingPolicySink, MemoryAudit>>>) {
    let url = match std::env::var("SWARM_FEED") {
        Ok(u) if !u.is_empty() => u,
        _ => return, // no feed configured — skip entirely
    };
    std::thread::spawn(move || loop {
        if let Ok(lines) = fetch_blocklist(&url) {
            if !lines.is_empty() {
                let n = lines.len();
                let mut g = fw.lock().unwrap();
                let added = g.import_blocklist(lines.into_iter());
                if added > 0 {
                    println!("[feed] {added}/{n} blocklist entries loaded");
                }
            }
        }
        std::thread::sleep(Duration::from_secs(3600 * 4));
    });
}

/// Minimal http:// GET → blocklist lines (one IP per line, `#` ok).
/// Pure std, no deps — download only, nothing uploads.
fn fetch_blocklist(url: &str) -> std::io::Result<Vec<String>> {
    let host = url
        .strip_prefix("http://")
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();
    let path = url
        .splitn(4, '/')
        .nth(3)
        .map(|s| format!("/{s}"))
        .unwrap_or_else(|| "/".into());
    let mut s = TcpStream::connect(&host)?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    write!(s, "GET {path} HTTP/1.0\r\nHost: {host}\r\n\r\n")?;
    let mut body = String::new();
    s.read_to_string(&mut body)?;
    // Split headers from body.
    let start = body.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    Ok(body[start..]
        .lines()
        .map(str::to_string)
        .collect())
}

fn main() {
    if !consent() {
        return;
    }
    let pairs: Vec<String> = std::env::args().skip(1).filter(|a| a != "-q").collect();
    let quiet = std::env::args().any(|a| a == "-q");
    let pairs = if pairs.is_empty() {
        vec!["9101:8081".to_string()]
    } else {
        pairs
    };
    println!("=============================================================");
    println!("  SwarmShieldSE — live protection");
    println!("  watching {} service(s); this feed says what's happening", pairs.len());
    println!("  [-q for quiet mode: only show threats]");
    println!("=============================================================");
    let fw = Arc::new(Mutex::new(firewall()));
    update_loop(Arc::clone(&fw));
    let audit_prev = Arc::new(Mutex::new(0usize));
    for pair in pairs {
        let mut it = pair.split(':');
        let (lp, tp) = match (it.next(), it.next(), it.next()) {
            (Some(a), Some(b), Some(c)) => (format!("{a}:{b}"), c.to_string()),
            (Some(a), Some(b), None) => (format!("0.0.0.0:{a}"), format!("127.0.0.1:{b}")),
            _ => {
                eprintln!("bad rule '{pair}' — use listen:target");
                continue;
            }
        };
        let listen_port = tp.parse().unwrap_or(9101);
        println!("  • guarding {lp} → {tp}");
        let fw = Arc::clone(&fw);
        let prev = Arc::clone(&audit_prev);
        std::thread::spawn(move || {
            let listener = TcpListener::bind(&lp).expect("bind failed");
            for s in listener.incoming().flatten() {
                let fw = Arc::clone(&fw);
                let prev = Arc::clone(&prev);
                let tp = tp.clone();
                std::thread::spawn(move || handle(s, &tp, listen_port, quiet, &fw, &prev));
            }
        });
    }
    println!("=============================================================");
    // Keep main alive — workers run in threads.
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
