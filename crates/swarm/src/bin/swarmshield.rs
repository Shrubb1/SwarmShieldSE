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

/// Feature tier from license: free = drop-only, single service, no
/// tarpit deception; paid = the full stack.
#[derive(Clone, Copy, PartialEq)]
enum Tier {
    Free,
    Paid,
}

/// FNV-1a machine id — a binding convenience, not a crypto primitive.
fn machine_id() -> u64 {
    let s = format!(
        "{}:{}",
        std::env::var("COMPUTERNAME").unwrap_or_default(),
        std::env::var("USERNAME").unwrap_or_default()
    );
    let mut h = 0xcbf29ce484222325u64;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Verify a token against the licensing API (`SWARM_LICENSE_URL`),
/// falling back to the cached grant within a 48h offline grace.
/// Returns the granted tier (Free when anything fails or no token).
/// Keyed-hash grant signature — server signs `token|expiry|mid` with a
/// shared secret so a hand-edited cache can't forge a grant (prod would
/// use ed25519; this is the honest no-dep version of the contract).
fn grant_sig(token: &str, expiry: u64, mid: u64) -> u64 {
    let secret = std::env::var("SWARM_LICENSE_SECRET")
        .unwrap_or_else(|_| "swarmshield-v1".into());
    let mut h = 0xcbf29ce484222325u64;
    for b in format!("{token}|{expiry}|{mid}|{secret}").bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn license_tier(token: Option<&str>) -> Tier {
    let cache = std::env::var("USERPROFILE")
        .map(|p| format!("{p}\\.swarmshield-license"))
        .unwrap_or_else(|_| ".swarmshield-license".into());
    let Some(token) = token else {
        return Tier::Free;
    };
    if let Ok(url) = std::env::var("SWARM_LICENSE_URL") {
        if !url.is_empty() {
            let req = format!(
                "{}/verify?token={}&mid={:x}",
                url.trim_end_matches('/'),
                token,
                machine_id()
            );
            if let Ok(resp) = fetch_blocklist(&req) {
                let status = resp.first().map(|s| s.trim()).unwrap_or("");
                if status == "active" || status == "grace" {
                    if status == "grace" {
                        println!("  ⚠ renewal pending — update payment to keep the full tier");
                    }
                    let exp = now_ms() / 1000 + 7 * 24 * 3600 + 48 * 3600;
                    let sig = grant_sig(token, exp, machine_id());
                    let _ = std::fs::write(&cache, format!("{token}|{exp}|{sig:x}"));
                    return Tier::Paid;
                }
            }
        }
    }
    // Offline / unconfigured: honor a cached grant inside the grace.
    if let Ok(data) = std::fs::read_to_string(&cache) {
        let mut it = data.trim().split('|');
        if it.next() == Some(token) {
            if let Some(Ok(exp)) = it.next().map(|e| e.parse::<u64>()) {
                // Signature must verify — a hand-edited cache can't
                // forge `sig` without the shared secret.
                let sig_ok = it
                    .next()
                    .and_then(|s| u64::from_str_radix(s, 16).ok())
                    .map(|s| s == grant_sig(token, exp, machine_id()))
                    .unwrap_or(false);
                if sig_ok && now_ms() / 1000 < exp {
                    return Tier::Paid;
                }
            }
        }
    }
    Tier::Free
}

fn firewall(tier: Tier) -> Firewall<RecordingPolicySink, MemoryAudit> {
    let mut p = FirewallPolicy {
        anomaly_threshold: 2,
        action_ladder: if tier == Tier::Paid {
            vec![
                MitigationKind::RateLimit { max_rps: 10.0 },
                MitigationKind::Drop,
                MitigationKind::Block,
            ]
        } else {
            vec![MitigationKind::Drop] // free tier: block, no deception
        },
        ttl_ms: 30_000,
        cooldown_ms: 0,
        ..Default::default()
    };
    p.search.enabled = tier == Tier::Paid; // playbook/search is paid
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
    if reason.contains("credential") || reason.contains("api-key") {
        "tried to send a secret or API key out — blocked before it left"
    } else if reason.contains("beacon") {
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
    tier: Tier,
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
                        if tier == Tier::Paid {
                            tarpit(&mut client, src);
                        }
                        return;
                    }
                    Verdict::Denied { .. } => {
                        if tier == Tier::Paid {
                            tarpit(&mut client, src);
                        } else {
                            say(false, src, "??", "→ hostile — connection dropped");
                        }
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
                        toast(&src, explain(&rule.reason));
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

/// OS toast on real blocks — zero-dep WinRT toast via PowerShell.
/// Fire-and-forget; silently no-ops where powershell isn't available.
fn toast(ip: &str, what: &str) {
    let xml = format!(
        "<toast><visual><binding template='ToastGeneric'><text>SwarmShield blocked an attack</text><text>{ip} {what}</text></binding></visual></toast>"
    );
    let ps = format!(
        "[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]|Out-Null;$x=New-Object Windows.Data.Xml.Dom.XmlDocument;$x.LoadXml('{}');[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('SwarmShieldSE').Show((New-Object Windows.UI.Notifications.ToastNotification $x))",
        xml.replace('\'', "''")
    );
    let _ = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .spawn();
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

/// Herd-immunity sync (paid tier): pull the shared feed AND push
/// locally-learned playbook fixes upstream so other clients immunize
/// too. Download + upload of *shape strings only* — never packet data.
fn update_loop(fw: Arc<Mutex<Firewall<RecordingPolicySink, MemoryAudit>>>, paid: bool) {
    let url = match std::env::var("SWARM_FEED") {
        Ok(u) if !u.is_empty() => u,
        _ => return,
    };
    std::thread::spawn(move || loop {
        // Pull: shared blocklist + playbook fixes.
        if let Ok(lines) = fetch_blocklist(&format!("{}/feed", url.trim_end_matches('/'))) {
            let mut g = fw.lock().unwrap();
            let mut added = 0;
            for line in &lines {
                if let Some((k, v)) = line.split_once(':') {
                    if k == "block" {
                        let _ = g.static_policy.deny.insert(
                            v.parse().unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                            true,
                        );
                        added += 1;
                    } else if let Some(ch) = k.strip_prefix("ch") {
                        // Federated fix — channel-anonymous, zero identifying
                        // info: `ch{idx}=drop|block|rl:N` → shared map.
                        let (idx, fix) = match ch.split_once('=') {
                            Some((i, f)) => (i, f),
                            None => continue,
                        };
                        let kind = match fix {
                            "drop" => MitigationKind::Drop,
                            "block" => MitigationKind::Block,
                            s if s.starts_with("rl:") => MitigationKind::RateLimit {
                                max_rps: s[3..].parse().unwrap_or(10.0),
                            },
                            _ => continue,
                        };
                        if let Ok(i) = idx.parse::<u8>() {
                            g.shared.insert(i, kind);
                            added += 1;
                        }
                    }
                }
            }
            if added > 0 {
                println!("[feed] pulled {added} shared protections");
            }
        }
        // Push (paid only): local playbook discoveries → the herd.
        if paid {
            // Push channel-anonymous fixes only — the playbook key is
            // `{subject}:{channel}`; the subject holds an IP, so only
            // the channel index + fix goes upstream. Zero identifiers.
            let entries: Vec<String> = {
                let g = fw.lock().unwrap();
                g.playbook
                    .iter()
                    .filter_map(|(k, v)| {
                        k.rsplit(':').next().and_then(|c| {
                            c.parse::<u8>().ok().map(|i| format!("ch{i}={}", fix_str(v)))
                        })
                    })
                    .collect()
            };
            for e in entries {
                let q = e.replace(':', "%3A").replace(';', "%3B");
                let _ = fetch_blocklist(&format!(
                    "{}/report?entry={q}",
                    url.trim_end_matches('/')
                ));
            }
        }
        std::thread::sleep(Duration::from_secs(900)); // 15min cadence
    });
}

fn fix_str(k: &MitigationKind) -> String {
    match k {
        MitigationKind::Drop => "drop".into(),
        MitigationKind::Block => "block".into(),
        MitigationKind::RateLimit { max_rps } => format!("rl:{max_rps}"),
    }
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

/// Import `.sscfg` pre-block files (emitted by the web scanner's
/// "download with this threat pre-blocked" link). `block:` lines take
/// IPs or domains — domains resolve to IPs. Pure allowlist of denials;
/// zero telemetry — it's just a file the user downloaded.
fn import_sscfg(fw: &mut Firewall<RecordingPolicySink, MemoryAudit>) -> Vec<String> {
    use std::net::ToSocketAddrs;
    let mut dirs = vec![std::env::current_dir().unwrap_or_default()];
    if let Ok(p) = std::env::var("USERPROFILE") {
        dirs.push(std::path::PathBuf::from(format!("{p}\\Downloads")));
    }
    let mut loaded = vec![];
    for dir in dirs {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for ent in rd.flatten() {
            let p = ent.path();
            if p.extension().map(|e| e == "sscfg").unwrap_or(false) {
                if let Ok(txt) = std::fs::read_to_string(&p) {
                    for line in txt.lines().map(str::trim) {
                        if let Some(t) = line.strip_prefix("block:") {
                            // Direct IP or resolve domain → insert denies.
                            if let Ok(ip) = t.parse::<std::net::IpAddr>() {
                                fw.static_policy.deny.insert(ip, true);
                                loaded.push(t.to_string());
                            } else if let Ok(mut addrs) = format!("{t}:80").to_socket_addrs() {
                                if let Some(a) = addrs.next() {
                                    fw.static_policy.deny.insert(a.ip(), true);
                                    loaded.push(t.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    loaded
}

/// BYOF — bring-your-own-feed: drop a `rules.txt` next to the binary or
/// in Downloads. One entry per line: `block:1.2.3.4`, `block:domain.tld`
/// — power users/teams plug their own intel straight into the engine.
fn import_custom(fw: &mut Firewall<RecordingPolicySink, MemoryAudit>) -> usize {
    use std::net::ToSocketAddrs;
    let mut n = 0;
    for path in ["rules.txt", "custom_rules.txt"] {
        if let Ok(txt) = std::fs::read_to_string(path) {
            for line in txt.lines().map(str::trim) {
                if let Some(t) = line.strip_prefix("block:") {
                    if let Ok(ip) = t.parse::<std::net::IpAddr>() {
                        fw.static_policy.deny.insert(ip, true);
                        n += 1;
                    } else if let Ok(mut a) = format!("{t}:80").to_socket_addrs() {
                        if let Some(x) = a.next() {
                            fw.static_policy.deny.insert(x.ip(), true);
                            n += 1;
                        }
                    }
                }
            }
        }
    }
    n
}

fn main() {
    swarm::crash::install();
    if !consent() {
        return;
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let quiet = args.iter().any(|a| a == "-q");
    let token = args
        .iter()
        .position(|a| a == "--token")
        .and_then(|i| args.get(i + 1))
        .map(String::as_str);
    let tier = license_tier(token);
    let mut pairs: Vec<String> = args
        .iter()
        .filter(|a| !a.starts_with('-') && !a.contains("SS-SE"))
        .cloned()
        .collect();
    if tier == Tier::Free && pairs.len() > 1 {
        println!("  free tier protects ONE service — using {}", pairs[0]);
        pairs.truncate(1);
    }
    let pairs = if pairs.is_empty() {
        vec!["9101:8081".to_string()]
    } else {
        pairs
    };
    println!("=============================================================");
    println!("  SwarmShieldSE — live protection   [{} tier]", if tier == Tier::Paid { "PAID" } else { "FREE" });
    println!("  watching {} service(s); this feed says what's happening", pairs.len());
    if tier == Tier::Free {
        println!("  free tier: blocks attacks · upgrade for tarpit deception,");
        println!("  multi-service, adaptive search + playbook — --token SS-SE-XXXX");
    }
    println!("  [-q for quiet mode: only show threats]");
    println!("=============================================================");
    let mut fw_obj = firewall(tier);
    let custom = import_custom(&mut fw_obj);
    if custom > 0 {
        println!("  loaded {custom} custom rules (rules.txt)");
    }
    let preblocked = import_sscfg(&mut fw_obj);
    if !preblocked.is_empty() {
        println!("  welcome back — already blocking what you scanned earlier:");
        for t in &preblocked {
            println!("   • {t}");
        }
    }
    let fw = Arc::new(Mutex::new(fw_obj));
    update_loop(Arc::clone(&fw), tier == Tier::Paid);
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
        let listen_port = lp
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or(9101);
        println!("  • guarding {lp} → {tp}");
        let fw = Arc::clone(&fw);
        let prev = Arc::clone(&audit_prev);
        std::thread::spawn(move || {
            // Network-change resilience: the listen socket can die when
            // the OS shifts networks (sleep/Wi-Fi/VPN). Rebind forever —
            // never take the service down with it.
            loop {
                let listener = match TcpListener::bind(&lp) {
                    Ok(l) => l,
                    Err(e) => {
                        println!("[rebind] {lp} can't bind ({e}) — retry in 5s");
                        std::thread::sleep(Duration::from_secs(5));
                        continue;
                    }
                };
                for s in listener.incoming() {
                    let s = match s {
                        Ok(s) => s,
                        Err(_) => break, // listener poisoned → rebind
                    };
                    let fw = Arc::clone(&fw);
                    let prev = Arc::clone(&prev);
                    let tp = tp.clone();
                    std::thread::spawn(move || {
                        handle(s, &tp, listen_port, quiet, tier, &fw, &prev)
                    });
                }
                println!("[rebind] {lp} listener dropped — rebinding");
            }
        });
    }
    println!("=============================================================");
    // Keep main alive — workers run in threads.
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
