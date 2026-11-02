//! Privacy-preserving crash reporting: a panic hook that strips file
//! paths, IPs, and payload data, then posts a minimal anonymous ping
//! `{panic line, version, OS}` to `SWARM_CRASH_URL`. Never touches
//! packet data or user info — just the crash itself.

use std::io::Write;
use std::net::TcpStream;
use std::panic;
use std::time::Duration;

fn sanitize(s: &str) -> String {
    // Strip paths → keep just `file.rs:line`; drop anything IP-looking
    // or longer than a panic summary needs.
    let mut out = String::with_capacity(s.len().min(200));
    for (i, word) in s.split_whitespace().enumerate() {
        if i > 24 {
            break;
        }
        let w = if word.contains('\\') || word.contains('/') {
            word.rsplit(['\\', '/']).next().unwrap_or(word)
        } else if word.parse::<std::net::IpAddr>().is_ok() {
            "[ip]"
        } else {
            word
        };
        out.push_str(w);
        out.push(' ');
    }
    out.trim_end().to_string()
}

fn report(msg: &str) {
    let Ok(url) = std::env::var("SWARM_CRASH_URL") else {
        return; // no endpoint → silent
    };
    if url.is_empty() {
        return;
    }
    let body = format!(
        "{{\"panic\":\"{}\",\"version\":\"{}\",\"os\":\"{}_{}\"}}",
        msg.replace('"', "'").chars().take(160).collect::<String>(),
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
    );
    let host = url
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("");
    let path = url.splitn(4, '/').nth(3).map(|s| format!("/{s}")).unwrap_or("/".into());
    if let Ok(mut s) = TcpStream::connect(host) {
        let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = write!(
            s,
            "POST {path} HTTP/1.0\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
    }
}

/// Install the hook — call at the top of `main` in every long-lived bin.
pub fn install() {
    let prev = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "panic".into());
        let loc = info
            .location()
            .map(|l| format!(" {}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_default();
        report(&sanitize(&format!("{msg}{loc}")));
        prev(info); // still print the real backtrace locally
    }));
}
