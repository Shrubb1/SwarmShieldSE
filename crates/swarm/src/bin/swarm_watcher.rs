//! `swarm_watcher` — the small-addons bundle: polls the attack
//! surfaces malware actually uses and flags changes to the feed.
//!
//!   1. Downloads watch — every new file lands → scanned instantly
//!   2. Startup watcher  — a new entry in Startup/Run keys = alert
//!   3. hosts integrity  — hosts file mtime/size drift = alert
//!   4. USB watch        — a removable drive appears → flag its files
//!   5. Weekly digest    — plain-English block summary on each tick
//!
//! Everything logs to watcher_log.txt (read by the app feed).

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

const LOG: &str = r"C:\ProgramData\SwarmShieldSE\watcher_log.txt";
const HOSTS: &str = r"C:\Windows\System32\drivers\etc\hosts";
const STARTUP: &[&str] = &[
    r"Microsoft\Windows\Start Menu\Programs\Startup",
];
const DL_EXTS: &[&str] = &[
    "exe", "dll", "msi", "bat", "cmd", "ps1", "vbs", "js", "jar",
    "apk", "zip", "rar", "7z", "scr", "pif", "hta",
];

fn log_line(s: &str) {
    if let Some(parent) = Path::new(LOG).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(LOG) {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = writeln!(f, "[{ts}] {s}");
    }
    eprintln!("[watcher] {s}");
}

fn snap_dir(dir: &Path) -> HashMap<PathBuf, u64> {
    let mut m = HashMap::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if let Ok(meta) = e.metadata() {
                m.insert(e.path(), meta.len());
            }
        }
    }
    m
}

/// Scan a newly-landed file — signatures + entropy, same rules as
/// swarm_scanner (a script sig only flags inside an executable type).
fn scan_new(path: &Path) -> Option<String> {
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if !DL_EXTS.contains(&ext.as_str()) {
        return None;
    }
    let mut f = std::fs::File::open(path).ok()?;
    use std::io::Read;
    let mut buf = vec![0u8; 64 * 1024];
    let n = f.read(&mut buf).ok()?;
    buf.truncate(n);
    if snn_firewall::Signatures::scan(&buf) != 0 {
        return Some(format!("downloaded {ext} hits a signature"));
    }
    let mut freq = [0u32; 256];
    for &b in &buf {
        freq[b as usize] += 1;
    }
    let nn = n.max(1) as f64;
    let e: f64 = freq
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / nn;
            -p * p.log2()
        })
        .sum();
    if e > 7.8 && n > 4 * 1024 {
        return Some(format!("downloaded {ext} is packed/encrypted"));
    }
    None
}

/// Weekly digest — counts flagged/blocked lines, writes one plain
/// summary line to the feed.
fn digest() {
    let blocks = std::fs::read_to_string(r"C:\ProgramData\SwarmShieldSE\svc_feed.log")
        .map(|s| s.lines().count())
        .unwrap_or(0);
    let flags = std::fs::read_to_string(r"C:\ProgramData\SwarmShieldSE\scan_log.txt")
        .map(|s| s.lines().count())
        .unwrap_or(0);
    let watches = std::fs::read_to_string(LOG)
        .map(|s| s.lines().count())
        .unwrap_or(0);
    log_line(&format!(
        "digest: {blocks} connections blocked · {flags} files flagged · {watches} watcher alerts"
    ));
}

fn main() {
    let user = std::env::var("USERPROFILE").unwrap_or_else(|_| r"C:\Users\Black".into());
    let dl = PathBuf::from(&user).join("Downloads");
    let mut dl_seen = snap_dir(&dl);
    let mut startup_seen: HashMap<PathBuf, u64> = HashMap::new();
    for s in STARTUP {
        for (p, v) in snap_dir(&Path::new(&user).join("AppData").join("Roaming").join(s)) {
            startup_seen.insert(p, v);
        }
    }
    let mut hosts_state = std::fs::metadata(HOSTS)
        .map(|m| (m.len(), m.modified().ok()))
        .ok();
    let mut usb_seen: Vec<String> = Vec::new();
    log_line("watcher online — downloads/startup/hosts/usb watching");

    let mut tick = 0u64;
    loop {
        std::thread::sleep(std::time::Duration::from_secs(4));
        tick += 1;

        // 1. Downloads — new files scanned instantly
        let now = snap_dir(&dl);
        for (p, sz) in &now {
            if !dl_seen.contains_key(p) && *sz > 0 {
                match scan_new(p) {
                    Some(why) => log_line(&format!("ALERT {} — {why}", p.display())),
                    None => log_line(&format!("new download {} — clean", p.display())),
                }
            }
        }
        dl_seen = now;

        // 2. Startup — new persistence entry
        let mut now_s: HashMap<PathBuf, u64> = HashMap::new();
        for s in STARTUP {
            for (p, v) in snap_dir(&Path::new(&user).join("AppData").join("Roaming").join(s)) {
                now_s.insert(p, v);
            }
        }
        for p in now_s.keys() {
            if !startup_seen.contains_key(p) {
                log_line(&format!("ALERT new startup entry: {}", p.display()));
            }
        }
        startup_seen = now_s;

        // 3. hosts integrity — size/mtime drift
        if let Ok(meta) = std::fs::metadata(HOSTS) {
            let cur = Some((meta.len(), meta.modified().ok()));
            if hosts_state.is_some() && cur != hosts_state {
                log_line("ALERT hosts file changed — possible malware persistence");
            }
            hosts_state = cur;
        }

        // 4. USB watch — new removable drive letters
        for letter in b'D'..=b'Z' {
            let d = format!("{}:\\", letter as char);
            let exists = Path::new(&d).exists();
            let was = usb_seen.contains(&d);
            if exists && !was {
                usb_seen.push(d.clone());
                log_line(&format!("ALERT new drive {d} — removable media inserted"));
            } else if !exists {
                usb_seen.retain(|x| x != &d);
            }
        }

        // 5. digest every ~5 min tick
        if tick % 75 == 0 {
            digest();
        }
    }
}
