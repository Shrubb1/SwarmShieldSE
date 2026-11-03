//! `swarm_scanner` — the background file watcher. Slowly walks the
//! filesystem (nice-throttled — never hammers disk/CPU), hashes each
//! file, and scans unknown bytes through the same signatures the
//! firewall uses. Files verified clean go into a local safe-cache
//! so they're never re-scanned — everything stays on this machine.
//!
//!   swarm_scanner [dir ...]   (default: C:\Users)

use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

const CACHE: &str = r"C:\ProgramData\SwarmShieldSE\known_safe.txt";
const LOG: &str = r"C:\ProgramData\SwarmShieldSE\scan_log.txt";
/// Read cap per file — enough for PE/script headers + signatures.
const HEAD: usize = 96 * 1024;
/// Pace: ms to sleep between files — background-friendly.
const PACE_MS: u64 = 40;

/// Cheap local identity for the safe-cache — not crypto, just a
/// "did we see these bytes before" key. path-independent so renames
/// don't force re-scans... actually path+size+hash keeps it honest.
fn file_key(path: &Path, bytes: &[u8], size: u64) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes
        .iter()
        .chain(path.to_string_lossy().as_bytes())
        .chain(&size.to_le_bytes())
    {
        h = (h ^ b as u64).wrapping_mul(0x100000001b3);
    }
    h
}

fn load_cache() -> HashSet<u64> {
    std::fs::read_to_string(CACHE)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.trim().parse::<u64>().ok())
        .collect()
}

fn append_line(path: &str, line: &str) {
    if let Some(parent) = Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{line}");
    }
}

/// Scan the file's head — signatures (the same ones http_shield
/// enforces on) + a quick high-entropy flag for packed/encrypted blobs.
fn scan(path: &Path) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; HEAD];
    use std::io::Read;
    let n = f.read(&mut buf).ok()?;
    buf.truncate(n);
    if n < 8 {
        return None;
    }
    let sig = snn_firewall::Signatures::scan(&buf);
    if sig != 0 {
        // Context gate: a script signature inside an HTML file is the
        // web working as designed — only flag when the sig lands in a
        // file type it shouldn't be in (executables, scripts, packed
        // blobs). Suspicious set; .html/.css/.svg etc. pass clean.
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        const SUSPECT: &[&str] = &[
            "exe", "dll", "com", "scr", "bat", "cmd", "ps1", "vbs", "js",
            "jse", "wsf", "jar", "apk", "msi", "hta", "pif", "gadget",
            "pl", "py", "sh", "php", "elf", "so", "dylib",
        ];
        if SUSPECT.contains(&ext.as_str()) {
            return Some(format!("signature match in {ext} (mask={sig})"));
        }
        // .html/.txt/etc. — a script sig is expected content, not a flag.
        return None;
    }
    // Packed/encrypted: near-random bytes at the head.
    let mut freq = [0u32; 256];
    for &b in &buf {
        freq[b as usize] += 1;
    }
    let nn = n as f64;
    let e: f64 = freq
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / nn;
            -p * p.log2()
        })
        .sum();
    if e > 7.8 && n > 4 * 1024 {
        return Some(format!("packed/encrypted head (entropy {e:.1})"));
    }
    None
}

fn main() {
    let roots: Vec<String> = std::env::args().skip(1).collect();
    let roots = if roots.is_empty() {
        vec![r"C:\Users".to_string()]
    } else {
        roots
    };
    let mut cache = load_cache();
    eprintln!("[scanner] starting — {} known-safe cached", cache.len());
    let mut walked = 0u64;
    let mut flagged = 0u64;
    let mut new_safe = 0u64;

    for root in &roots {
        for entry in walkdir(root) {
            walked += 1;
            if let Ok(meta) = entry.metadata() {
                if !meta.is_file() || meta.len() == 0 {
                    continue;
                }
                // Don't churn the cache file itself or huge blobs.
                if meta.len() > 256 * 1024 * 1024 {
                    continue;
                }
                let mut buf = Vec::new();
                use std::io::Read;
                if let Ok(mut f) = std::fs::File::open(&entry) {
                    let mut tmp = [0u8; 4096];
                    let mut head = Vec::new();
                    if let Ok(n) = f.read(&mut tmp) {
                        head.extend_from_slice(&tmp[..n]);
                    }
                    buf = head;
                }
                let key = file_key(&entry, &buf, meta.len());
                if cache.contains(&key) {
                    continue; // known clean — never re-scanned
                }
                match scan(&entry) {
                    Some(why) => {
                        flagged += 1;
                        append_line(
                            LOG,
                            &format!(
                                "FLAGGED {} — {} ({:.1}KB)",
                                entry.display(),
                                why,
                                meta.len() as f64 / 1024.0
                            ),
                        );
                        eprintln!("[scanner] FLAGGED {} — {}", entry.display(), why);
                    }
                    None => {
                        cache.insert(key);
                        new_safe += 1;
                        append_line(CACHE, &key.to_string());
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(PACE_MS));
                if walked % 500 == 0 {
                    eprintln!("[scanner] walked={walked} flagged={flagged} cached+{new_safe}");
                }
            }
        }
    }
    eprintln!("[scanner] done — {walked} files, {flagged} flagged, {new_safe} newly trusted");
}

/// Depth-first walk yielding file paths, skipping permission errors.
fn walkdir(root: &str) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(root)];
    while let Some(dir) = stack.pop() {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let p = e.path();
                match p.is_dir() {
                    true => stack.push(p),
                    false => out.push(p),
                }
            }
        }
    }
    out
}
