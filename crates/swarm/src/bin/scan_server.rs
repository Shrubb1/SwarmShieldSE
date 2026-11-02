//! `scan-server` — free, no-login dropbox scanner for the public site.
//! Uploads scan IN MEMORY — bytes never touch disk. Limits: 25MB cap,
//! extension filter, 10 scans/min/IP. Heuristics only — honest verdicts,
//! not an antivirus engine.
//!
//!   GET /            → dropzone page
//!   POST /scan       → multipart file → verdict report (HTML)
//!   GET /link?url=   → header/redirect inspection (no JS, no download)
//!
//! Usage: `scan_server [listen]`  (default 0.0.0.0:9200)

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use snn_firewall::Signatures;

const MAX_BYTES: usize = 25 * 1024 * 1024;
const PAGE: &str = r#"<!DOCTYPE html><html><head><meta charset="utf-8">
<title>SwarmShieldSE — free scanner</title>
<style>body{font-family:system-ui;background:#0d1117;color:#e6edf3;max-width:640px;margin:40px auto;padding:0 20px}
.card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:20px;margin:16px 0}
input,button{padding:10px;border-radius:8px;border:1px solid #30363d;background:#0d1117;color:#e6edf3}
button{background:#238636;border:0;cursor:pointer}.muted{color:#8b949e;font-size:13px}</style></head><body>
<h1>🛡 SwarmShieldSE scanner</h1>
<div class="card"><h3>Drop a suspicious file</h3>
<form method="post" action="/scan" enctype="multipart/form-data">
<input type="file" name="f" required><button type="submit">Scan</button></form>
<p class="muted">scanned in memory — nothing is stored · 25MB max · 10/min</p></div>
<div class="card"><h3>Check a suspicious link</h3>
<form method="get" action="/link"><input name="url" style="width:70%" placeholder="https://…" required>
<button type="submit">Check</button></form>
<p class="muted">headers only — we never run or download the payload</p></div>
<p class="muted">Want this automatic? <a href="/" style="color:#3fb950">SwarmShieldSE blocks threats before they land.</a></p>
</body></html>"#;

fn now_s() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Entropy + printable ratio of a byte slice.
fn shape(b: &[u8]) -> (f32, f32) {
    let mut freq = [0u64; 256];
    for &x in b {
        freq[x as usize] += 1;
    }
    let n = b.len() as f32;
    let mut e = 0f32;
    let mut printable = 0u64;
    for &x in b {
        if (32..127).contains(&x) || x == 9 || x == 10 || x == 13 {
            printable += 1;
        }
    }
    for f in freq.iter().filter(|&&f| f > 0) {
        let p = *f as f32 / n;
        e -= p * p.log2();
    }
    (e, printable as f32 / n)
}

/// Heuristic verdict on file bytes — honest, not an AV engine.
fn scan_bytes(name: &str, b: &[u8]) -> String {
    let mut flags: Vec<String> = vec![];
    let sigs = Signatures::scan(b);
    if sigs != 0 {
        flags.push(format!("matches known attack patterns (mask {sigs:#x})"));
    }
    let (entropy, printable) = shape(b);
    if entropy > 7.2 && b.len() > 4096 {
        flags.push(format!("very high entropy ({entropy:.1} bits/byte) — packed or encrypted"));
    } else if entropy > 6.5 && printable < 0.3 {
        flags.push(format!("obfuscated-looking ({entropy:.1} bits, {}% text)", (printable * 100.0) as u8));
    }
    let text = String::from_utf8_lossy(&b[..b.len().min(1 << 20)]);
    let low = text.to_lowercase();
    if b.starts_with(b"MZ") {
        for bad in [
            "createremotethread", "virtualalloc", "writeprocessmemory",
            "powershell -enc", "rundll32", "regsvr32 /s /u",
        ] {
            if low.contains(bad) {
                flags.push(format!("contains suspicious API call '{bad}'"));
            }
        }
        flags.push("Windows executable (MZ) — treat with care".into());
    }
    if !b.starts_with(b"MZ") && printable > 0.7 {
        for bad in [
            "eval(", "wscript.shell", "powershell -e", "frombase64string",
            "invoke-expression", "certutil -decode",
        ] {
            if low.contains(bad) {
                flags.push(format!("script contains '{bad}'"));
            }
        }
    }
    let verdict = if flags.is_empty() {
        "looks clean".to_string()
    } else if sigs != 0 || low.contains("createremotethread") || low.contains("wscript.shell") {
        format!("⚠ suspicious — {}", flags.join("; "))
    } else {
        format!("⚠ notable traits — {}", flags.join("; "))
    };
    format!(
        "<div class='card'><h3>{name}</h3><p>{} bytes · entropy {entropy:.2} · {}</p><p>{verdict}</p></div>",
        b.len(),
        if sigs != 0 { "signature match" } else { "no known signatures" },
    )
}

/// Minimal multipart extract — first file part's bytes + filename.
fn parse_multipart<'a>(body: &'a [u8], boundary: &str) -> Option<(String, &'a [u8])> {
    let body_s = String::from_utf8_lossy(body);
    let delim = format!("--{boundary}");
    let mut name = "upload".to_string();
    for part in body_s.split(&delim) {
        if let Some(fnpos) = part.find("filename=\"") {
            let rest = &part[fnpos + 10..];
            if let Some(end) = rest.find('"') {
                name = rest[..end].rsplit(['\\', '/']).next().unwrap_or("upload").to_string();
            }
            if let Some(start) = part.find("\r\n\r\n") {
                let content = &part[start + 4..];
                // Trim the closing boundary tail.
                let content = content.trim_end_matches(|c| c == '\r' || c == '\n' || c == '-');
                let start_idx = body_s.find(part).unwrap_or(0) + start + 4;
                let end_idx = start_idx + content.len();
                if end_idx <= body.len() {
                    return Some((name, &body[start_idx..end_idx]));
                }
            }
        }
    }
    None
}

/// Link check: headers-only fetch (HEAD-ish GET, no body), 1 redirect.
fn check_link(url: &str) -> String {
    let mut flags = vec![];
    let url_l = url.to_lowercase();
    let host = url_l
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split(['/', '?', ':'])
        .next()
        .unwrap_or("")
        .to_string();
    if host.is_empty() {
        return "can't parse that URL".into();
    }
    if host.chars().all(|c| c.is_ascii_digit() || c == '.') {
        flags.push("bare IP address (no domain) — classic malware host".to_string());
    }
    if host.contains("xn--") {
        flags.push("punycode domain — possible lookalike".to_string());
    }
    if url_l.contains('@') || url_l.matches('.').count() > 4 {
        flags.push("weird URL structure (deep subdomains or @ tricks)".to_string());
    }
    // Header-only fetch — never the payload.
    let target = if url_l.starts_with("https://") { format!("{host}:443") } else { format!("{host}:80") };
    let is_https = url_l.starts_with("https://");
    let fetch_note = if is_https {
        flags.push("https — can't inspect headers without TLS (by design)".to_string());
        "TLS-protected, not fetched".to_string()
    } else if let Ok(mut s) = std::net::TcpStream::connect(&target) {
        let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(6)));
        let path = url_l[url_l.find(host.as_str()).map(|i| i + host.len()).unwrap_or(0)..]
            .split(['?', '#'])
            .next()
            .unwrap_or("/")
            .to_string();
        let path = if path.is_empty() { "/".into() } else { path };
        let _ = write!(s, "GET {path} HTTP/1.0\r\nHost: {host}\r\nRange: bytes=0-0\r\n\r\n");
        let mut resp = String::new();
        let _ = s.take(4096).read_to_string(&mut resp);
        if let Some(code) = resp.split_whitespace().nth(1) {
            format!("server answered HTTP {code}")
        } else {
            "server answered".to_string()
        }
    } else {
        flags.push("host unreachable — dead or fake domain".to_string());
        "unreachable".to_string()
    };
    let verdict = if flags.is_empty() {
        "looks okay".to_string()
    } else {
        format!("⚠ notable — {}", flags.join("; "))
    };
    // The bridge: flagged links get a one-click "pre-block this in the
    // desktop app" cfg download — zero telemetry, just a blocklist file.
    let cta = if flags.is_empty() {
        String::new()
    } else {
        format!(
            "<p><a href='/shieldcfg?host={host}' style='color:#3fb950'>\
             → download SwarmShieldSE with this threat pre-blocked (.sscfg)</a></p>"
        )
    };
    format!(
        "<div class='card'><h3>{url}</h3><p>host: {host} · {fetch_note}</p><p>{verdict}</p>{cta}</div>"
    )
}

fn resp(page: &str) -> String {
    format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}", page.len(), page)
}

/// Serve a file from `site/` (or SWARM_SITE_DIR) — makes the scanner
/// server one-origin: `/`, `/signup`, `/download/*` + the scan endpoints.
fn serve_file(s: &mut std::net::TcpStream, rel: &str) -> bool {
    let base = std::env::var("SWARM_SITE_DIR").unwrap_or_else(|_| "site".into());
    let rel = rel.trim_start_matches('/');
    let rel = if rel.is_empty() { "index.html" } else { rel };
    // no traversal
    if rel.contains("..") {
        return false;
    }
    let path = format!("{base}/{rel}");
    let Ok(bytes) = std::fs::read(&path) else {
        return false;
    };
    let ct = if rel.ends_with(".html") {
        "text/html"
    } else if rel.ends_with(".zip") {
        "application/octet-stream"
    } else if rel.ends_with(".css") {
        "text/css"
    } else {
        "application/octet-stream"
    };
    let _ = write!(
        s,
        "HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {}\r\n\r\n",
        bytes.len()
    );
    let _ = s.write_all(&bytes);
    true
}

fn handle(mut s: std::net::TcpStream, limits: &Mutex<HashMap<std::net::IpAddr, (u32, Instant)>>) {
    let ip = s.peer_addr().map(|a| a.ip()).unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    // Rate limit: 10 scans/min/IP.
    {
        let mut m = limits.lock().unwrap();
        let e = m.entry(ip).or_insert((0, Instant::now()));
        if e.1.elapsed().as_secs() > 60 {
            *e = (0, Instant::now());
        }
        e.0 += 1;
        if e.0 > 10 {
            let _ = write!(s, "{}", resp("<h3>rate limit — 10 scans/min. SwarmShield Desktop has no limit.</h3>"));
            return;
        }
    }
    let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let mut head = Vec::with_capacity(8192);
    let mut tmp = [0u8; 8192];
    // Read headers.
    let mut content_len = 0usize;
    let mut boundary = String::new();
    loop {
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                head.extend_from_slice(&tmp[..n]);
                let txt = String::from_utf8_lossy(&head);
                if let Some(pos) = txt.find("\r\n\r\n") {
                    for line in txt[..pos].lines() {
                        let l = line.to_lowercase();
                        if l.starts_with("content-length:") {
                            content_len = l[15..].trim().parse().unwrap_or(0);
                        }
                        if l.contains("boundary=") {
                            boundary = line.split("boundary=").nth(1).unwrap_or("").trim().to_string();
                        }
                    }
                    break;
                }
                if head.len() > 8192 {
                    return;
                }
            }
        }
    }
    let header_end = String::from_utf8_lossy(&head).find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    let req_line = String::from_utf8_lossy(&head[..header_end]).lines().next().unwrap_or("").to_string();
    let path = req_line.split_whitespace().nth(1).unwrap_or("/").to_string();

    // Site routing: real files first (index.html, signup.html,
    // download/*), dropzone fallback when site/ isn't deployed.
    if path == "/signup" || path == "/signup.html" {
        if serve_file(&mut s, "signup.html") {
            return;
        }
    } else if path == "/viz" || path == "/viz.html" {
        if serve_file(&mut s, "viz.html") {
            return;
        }
    } else if path == "/viz2" || path == "/viz2.html" {
        if serve_file(&mut s, "viz2.html") {
            return;
        }
    } else if path.starts_with("/download/") {
        if serve_file(&mut s, &path) {
            return;
        }
    } else if req_line.starts_with("GET / ") || path == "/" {
        if !serve_file(&mut s, "index.html") {
            let _ = write!(s, "{}", resp(PAGE));
        }
        return;
    }
    if path.starts_with("/link") {
        let url = path.split("url=").nth(1).unwrap_or("").replace("%3A", ":").replace("%2F", "/");
        let _ = write!(s, "{}", resp(&format!("{PAGE}{}", check_link(&url))));
        return;
    }
    if path.starts_with("/shieldcfg") {
        let host = path.split("host=").nth(1).unwrap_or("").trim().to_string();
        let body = format!("# SwarmShieldSE pre-block config\nblock:{host}\n");
        let _ = write!(
            s,
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"swarmshield.sscfg\"\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        return;
    }
    if path.starts_with("/scan") {
        if content_len > MAX_BYTES {
            let _ = write!(s, "{}", resp("<h3>over 25MB — SwarmShield Desktop scans anything, unlimited.</h3>"));
            return;
        }
        // Read the body — in memory, never disk.
        let mut body = head.split_off(header_end);
        while body.len() < content_len {
            match s.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => body.extend_from_slice(&tmp[..n]),
                Err(_) => break,
            }
        }
        let report = if body.len() > MAX_BYTES {
            "<h3>over 25MB — SwarmShield Desktop scans anything, unlimited.</h3>".to_string()
        } else if boundary.is_empty() {
            "<h3>couldn't parse the upload</h3>".to_string()
        } else {
            match parse_multipart(&body, &boundary) {
                Some((name, bytes)) => {
                    let ext = name.rsplit('.').next().unwrap_or("").to_lowercase();
                    if !matches!(ext.as_str(), "exe" | "zip" | "rar" | "msi" | "js" | "py" | "pdf" | "bat" | "ps1" | "dll" | "txt" | "") {
                        format!("<h3>{ext} not a supported scan type — try an executable, script, archive, or document.</h3>")
                    } else {
                        scan_bytes(&name, bytes)
                    }
                }
                None => "<h3>couldn't find a file in that upload</h3>".to_string(),
            }
        };
        let _ = write!(s, "{}", resp(&format!("{PAGE}{report}")));
        return;
    }
    let _ = write!(s, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
}

fn main() {
    swarm::crash::install();
    let listen = std::env::args().nth(1).unwrap_or_else(|| "0.0.0.0:9200".into());
    println!("scan server on {listen} — free dropbox, no login");
    let limits = Arc::new(Mutex::new(HashMap::new()));
    for s in TcpListener::bind(&listen).unwrap().incoming().flatten() {
        let limits = Arc::clone(&limits);
        std::thread::spawn(move || handle(s, &limits));
    }
    let _ = now_s();
}
