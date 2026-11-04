//! `dns-guard` — local DNS forwarder + exfil detector.
//! Point the system resolver at 127.0.0.1:53 → every app on the machine
//! reveals every domain it touches. Exfil shows up as long labels,
//! high entropy, weird label counts, beacon-y rates. Clean queries
//! forward upstream untouched; flagged ones get a plain log + NXDOMAIN.
//!
//! Usage: `dns_guard [listen_addr] [upstream_addr]`
//!   default 127.0.0.1:53 → upstream 1.1.1.1:53

use std::net::UdpSocket;
use std::time::Duration;

/// Parse the qname out of a DNS query — label-length-walk until 0x00.
fn qname(pkt: &[u8]) -> Option<String> {
    if pkt.len() < 12 {
        return None;
    }
    let mut name = String::new();
    let mut i = 12;
    loop {
        let len = *pkt.get(i)? as usize;
        if len == 0 {
            break;
        }
        i += 1;
        let end = i.checked_add(len)?;
        if end > pkt.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(&pkt[i..end]));
        i = end;
    }
    Some(name)
}

/// Is the domain shaped like exfil / a C2 / DGA?
/// Long labels, high entropy, many labels, hex/base64-y, or known-sus.
fn flag(name: &str) -> Option<String> {
    let low = name.to_lowercase();
    // Ad/tracker network — blocked at the lookup, ad never loads.
    if swarm::adblock::is_ad(&low) {
        return Some(format!("ad/tracker domain '{low}'"));
    }
    // Known-real infra — Discord/CDN hash-y names pass clean, the
    // DGA/entropy checks below don't run on them.
    if swarm::adblock::is_safe(&low) {
        return None;
    }
    let labels: Vec<&str> = low.split('.').collect();
    let longest = labels.iter().map(|l| l.len()).max().unwrap_or(0);
    if longest > 40 {
        return Some(format!("longest label {longest} chars — exfil-shaped"));
    }
    if labels.len() > 6 {
        return Some(format!("{} labels — deep subdomain chain", labels.len()));
    }
    // Shannon-ish entropy on the full name — encoded payloads are dense.
    let mut freq = [0u32; 256];
    for b in low.bytes() {
        freq[b as usize] += 1;
    }
    let n = low.len() as f64;
    let mut e = 0.0f64;
    for f in freq.iter().filter(|&&f| f > 0) {
        let p = *f as f64 / n;
        e -= p * p.log2();
    }
    if e > 4.2 && low.len() > 40 {
        return Some(format!("entropy {e:.1} — encoded payload in the name"));
    }
    // DGA-shaped: long consonant-heavy pseudo-random string before TLD.
    let head = labels.first().copied().unwrap_or("");
    if head.len() >= 16
        && head.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !head.bytes().any(|b| matches!(b, b'a' | b'e' | b'i' | b'o' | b'u'))
    {
        return Some(format!("consonant-dense '{head}' — DGA-shaped"));
    }
    None
}

fn main() {
    let listen = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:53".into());
    let upstream = std::env::args().nth(2).unwrap_or_else(|| "1.1.1.1:53".into());
    let sock = UdpSocket::bind(&listen).unwrap_or_else(|e| {
        eprintln!("dns_guard: can't bind {listen}: {e}");
        std::process::exit(1);
    });
    let _ = sock.set_read_timeout(Some(Duration::from_secs(10)));
    let up = UdpSocket::bind("0.0.0.0:0").unwrap();
    eprintln!("dns_guard on {listen} → forwarding clean to {upstream}");
    let mut buf = [0u8; 2048];
    loop {
        let Ok((n, src)) = sock.recv_from(&mut buf) else {
            continue;
        };
        let pkt = &buf[..n];
        match qname(pkt).and_then(|q| flag(&q).map(|why| (q, why))) {
            Some((name, why)) => {
                eprintln!("[BLOCK] {src} asked for {name} — {why}");
                // Log to the feed file — the app merges this into the
                // live view so ad-blocks are visible to the user.
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(r"C:\ProgramData\SwarmShieldSE\ads_log.txt")
                {
                    use std::io::Write;
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let _ = writeln!(f, "[{ts}] AD-BLOCKED {name} — {why}");
                }
                // NXDOMAIN-ish reply: copy header, set RCODE=3, zero answers.
                let mut resp = pkt.to_vec();
                if resp.len() >= 4 {
                    resp[2] |= 0x80; // QR response
                    resp[3] = (resp[3] & 0xF0) | 0x03; // RCODE NXDOMAIN
                }
                let _ = sock.send_to(&resp, src);
            }
            None => {
                let _ = up.send_to(pkt, &upstream);
                let mut rbuf = [0u8; 4096];
                // Timeout — a dropped upstream reply must not hang the
                // whole forwarder. 3s cap, client just times out.
                let _ = up.set_read_timeout(Some(std::time::Duration::from_secs(3)));
                if let Ok((rn, _)) = up.recv_from(&mut rbuf) {
                    let _ = sock.send_to(&rbuf[..rn], src);
                }
            }
        }
    }
}
