//! Production extensions, kept separate from the core SNN loop:
//! - `StaticPolicy`: explicit allow/deny primitives before behavior.
//! - `SlowTick`: low-and-slow detector — aggregates feature deltas over a
//!   long window (statistical, deterministic; complements delta-mod SNN).
//! - `SourceProfiles`: per-IP rate baselines — rotating-botnet blind spot.
//! - `MetaWindow`: extra channels from `EventMeta` (port entropy, error
//!   rate, proto mix) — additive alongside the core 6.
//! - `EventSource`/`JsonlSource`: ingestion seam for real packet feeds.

use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, Read};
use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

use crate::event::{ConnEvent, EventMeta, FeatureVector};
use crate::policy::Verdict;

// ---------- 1. Static policy layer ----------

/// Explicit allow/deny primitives checked before behavioral enforcement.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StaticPolicy {
    pub allow: std::collections::HashSet<IpAddr>,
    pub deny: std::collections::HashMap<IpAddr, bool>,
}

impl StaticPolicy {
    /// `Some(verdict)` short-circuits the engine; `None` defers to behavior.
    pub fn verdict(&self, ip: IpAddr) -> Option<Verdict> {
        if self.deny.contains_key(&ip) {
            // rule 0 is reserved — real rules start at 1.
            Some(Verdict::Denied { rule: 0 })
        } else if self.allow.contains(&ip) {
            Some(Verdict::Allow)
        } else {
            None
        }
    }

    /// Reputation feed: import a blocklist — one IP per line, `#`
    /// comments and blanks ignored. Returns entries added.
    pub fn import_blocklist(&mut self, lines: impl Iterator<Item = String>) -> usize {
        let mut n = 0;
        for line in lines {
            let s = line.split('#').next().unwrap_or("").trim();
            if let Ok(ip) = s.parse::<IpAddr>() {
                self.deny.insert(ip, true);
                n += 1;
            }
        }
        n
    }
}

// ---------- 2. Slow tick: low-and-slow detection ----------

/// Aggregates fast-window vectors over `slow_len` ticks; flags any channel
/// whose slow-mean deviates `slow_z`× stddev from the learned slow baseline.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlowTick {
    pub slow_len: usize,
    pub slow_z: f32,
    acc: Vec<f32>,
    n: usize,
    /// Per-channel (mean, var, count) — online.
    stats: Vec<(f32, f32, u64)>,
    buf: VecDeque<Vec<f32>>,
    channels: usize,
}

impl SlowTick {
    pub fn new(slow_len: usize, slow_z: f32, channels: usize) -> Self {
        Self {
            slow_len,
            slow_z,
            acc: vec![0.0; channels],
            n: 0,
            stats: vec![(0.0, 0.0, 0); channels],
            buf: VecDeque::new(),
            channels,
        }
    }

    /// Feed a fast-window vector; returns channels anomalous at slow scale.
    pub fn push(&mut self, fv: &FeatureVector) -> Vec<usize> {
        for (i, v) in fv.values.iter().enumerate().take(self.channels) {
            self.acc[i] += v;
        }
        self.buf.push_back(fv.values.clone());
        self.n += 1;
        if self.buf.len() > self.slow_len {
            let old = self.buf.pop_front().unwrap();
            for (i, v) in old.iter().enumerate().take(self.acc.len()) {
                self.acc[i] -= v;
            }
        }
        if self.n < self.slow_len {
            return Vec::new();
        }
        // Slow-mean per channel vs rolling stats.
        let mut hit = Vec::new();
        for i in 0..self.channels.min(fv.values.len()) {
            let m = self.acc[i] / self.buf.len().max(1) as f32;
            let (mean, var, cnt) = &mut self.stats[i];
            *cnt += 1;
            if *cnt > 4 {
                // Need a baseline first. σ floored at 1 — a perfectly
                // flat baseline (sd≈0) can't hide sustained drift.
                let sd = (*var / (*cnt - 1) as f32).max(0.0).sqrt().max(1.0);
                if (m - *mean).abs() > self.slow_z * sd {
                    hit.push(i);
                }
            }
            // Welford update on slow-mean.
            let d = m - *mean;
            *mean += d / *cnt as f32;
            *var += d * (m - *mean);
        }
        hit
    }
}

// ---------- 3. Per-source micro-profiles ----------

/// Per-IP event-rate baseline (mean/var online). Flags an IP whose rate
/// deviates `z`× σ — catches rotating botnets where no single source
/// dominates the *aggregate* window.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceProfiles {
    pub z: f32,
    pub cap: usize,
    map: HashMap<IpAddr, (u32, f32, f32, u64)>, // cur, mean, var, cnt
    tick_ms: u64,
    cur_start: u64,
}

impl SourceProfiles {
    pub fn new(z: f32, cap: usize, tick_ms: u64) -> Self {
        Self {
            z,
            cap,
            map: HashMap::new(),
            tick_ms,
            cur_start: 0,
        }
    }

    /// Feed one event; returns `Some(ip)` the moment an IP's per-tick rate
    /// breaches its own baseline.
    pub fn observe(&mut self, ev: &ConnEvent) -> Option<IpAddr> {
        let start = ev.ts_ms - (ev.ts_ms % self.tick_ms);
        let mut hit = None;
        if self.cur_start != 0 && start != self.cur_start {
            hit = self.roll();
            self.cur_start = start;
        } else if self.cur_start == 0 {
            self.cur_start = start;
        }
        if !self.map.contains_key(&ev.src_ip) && self.map.len() >= self.cap {
            return hit; // LRU-lite: cap reached, skip new talkers
        }
        self.map.entry(ev.src_ip).or_insert((0, 0.0, 0.0, 0)).0 += 1;
        hit
    }

    /// Tick end: update baselines, flag outliers.
    fn roll(&mut self) -> Option<IpAddr> {
        let mut flag: Option<(IpAddr, f32)> = None;
        for (ip, (cur, mean, var, cnt)) in self.map.iter_mut() {
            let m = *cur as f32;
            *cnt += 1;
            if *cnt > 4 {
                // σ floored at 1 event — a perfectly-steady IP that
                // suddenly bursts must still flag (sd≈0 else kills it).
                let sd = (*var / (*cnt - 1) as f32).max(0.0).sqrt().max(1.0);
                if (m - *mean) > self.z * sd {
                    let keep = flag.is_none_or(|(_, b)| m - *mean > b);
                    if keep {
                        flag = Some((*ip, m - *mean));
                    }
                }
            }
            let d = m - *mean;
            *mean += d / *cnt as f32;
            *var += d * (m - *mean);
            *cur = 0;
        }
        flag.map(|(ip, _)| ip)
    }

    /// Is `ip`'s OWN traffic anomalous right now — its current tick
    /// count vs its learned baseline? The TNR guard: being present in a
    /// bad window ≠ being the attacker; only self-deviation earns a rule.
    pub fn anomalous(&self, ip: &IpAddr) -> bool {
        let Some((cur, mean, var, cnt)) = self.map.get(ip) else {
            return false;
        };
        if *cnt < 4 {
            return false; // not enough history to know "their" normal
        }
        let sd = (*var / (*cnt - 1) as f32).max(0.0).sqrt().max(1.0);
        (*cur as f32 - *mean) > self.z * sd
    }
}

// ---------- 4. Meta channels ----------

/// Extra per-tick features from `EventMeta`: port entropy, error ratio,
/// TCP share — appended to the core feature vector for the detector.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MetaWindow {
    ports: HashMap<u16, u32>,
    uas: std::collections::HashSet<u16>,
    ja3s: std::collections::HashSet<u32>,
    /// Distributed-scan correlation: distinct srcs sharing one request
    /// shape (port, method, path-len). One event per IP per day stays
    /// invisible to every rate channel — the shared shape doesn't.
    by_shape: HashMap<(u16, u8, u16), std::collections::HashSet<IpAddr>>,
    errors: u32,
    tcp: u32,
    verbs: u32,
    path_sum: u64,
    pent_sum: u64,
    sig: u32,
    total: u32,
}

impl MetaWindow {
    pub fn observe(&mut self, ev: &ConnEvent) {
        self.total += 1;
        if ev.meta.proto == 6 {
            self.tcp += 1;
        }
        if ev.meta.error {
            self.errors += 1;
        }
        if matches!(ev.meta.method, 2..=4) {
            self.verbs += 1; // POST/PUT/DELETE
        }
        self.uas.insert(ev.meta.ua_id);
        self.ja3s.insert(ev.meta.ja3);
        self.path_sum += ev.meta.path_len as u64;
        // Engine-side scan when payload bytes are attached — producer
        // meta can't lie about entropy or signatures.
        match &ev.payload {
            Some(bytes) => {
                self.pent_sum += Signatures::shannon(bytes) as u64;
                if Signatures::scan(bytes) != 0 {
                    self.sig += 1;
                }
            }
            None => {
                self.pent_sum += ev.meta.payload_entropy as u64;
                if ev.meta.sig_hits != 0 {
                    self.sig += 1;
                }
            }
        }
        *self.ports.entry(ev.meta.dst_port).or_insert(0) += 1;
        self.by_shape
            .entry((ev.meta.dst_port, ev.meta.method, ev.meta.path_len))
            .or_default()
            .insert(ev.src_ip);
    }

    /// Max distinct sources sharing any one request shape — a
    /// distributed scan's fingerprint. Legit traffic fans out; a
    /// coordinated scan converges on identical shape.
    pub fn shared_shape_srcs(&self) -> usize {
        self.by_shape
            .values()
            .map(|s| s.len())
            .max()
            .unwrap_or(0)
    }

    /// Channels 7–15 — all ×100 so the shared delta threshold fires.
    pub fn values(&self) -> [f32; 9] {
        let n = self.total.max(1) as f32;
        let ent = self
            .ports
            .values()
            .map(|&c| {
                let p = c as f32 / n;
                -p * p.log2()
            })
            .sum::<f32>();
        [
            ent * 100.0,
            self.errors as f32 / n * 100.0,
            self.tcp as f32 / n * 100.0,
            self.verbs as f32 / n * 100.0,
            self.path_sum as f32 / n,
            self.uas.len() as f32 / n * 100.0,
            self.pent_sum as f32 / n,
            self.sig as f32 / n * 100.0,
            self.ja3s.len() as f32 / n * 100.0,
        ]
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Inter-arrival regularity per source — uniform gaps mean machine
/// traffic (beacons/C2), not humans. Coefficient of variation of gap
/// times drops below `cv` once `min_cnt` gaps are seen.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Beacons {
    pub cv: f32,
    pub min_cnt: u64,
    /// Dominant-bucket share for the jitter-resistant path.
    pub share: f32,
    /// Max tracked sources — a unique-IP flood can't exhaust memory.
    pub cap: usize,
    map: HashMap<IpAddr, (u64, f32, f32, u64)>, // last_ts, mean, var, cnt
    hist: HashMap<IpAddr, GapHist>,
}

/// Signature patterns — producer-side content scan; only the bitmask
/// crosses the wire. Pure substring matching, case-insensitive.
pub struct Signatures;

impl Signatures {
    /// Scan payload bytes → bitmask: 1=SQLi, 2=XSS, 4=traversal,
    /// 8=cmd-injection, 16=scanner UA. Matches on the raw text AND a
    /// normalized form (C-comments stripped, %XX-decoded, whitespace
    /// collapsed) — `'or/**/1=1` and `%27%20or%201=1` can't slide past.
    pub fn scan(payload: &[u8]) -> u16 {
        let raw = String::from_utf8_lossy(&payload[..payload.len().min(4096)]).to_lowercase();
        // Two passes: the second catches double-encoded payloads
        // (%25%33 → after pass 1 → %3 → pass 2 decodes fully).
        let norm = Self::normalize(&Self::normalize(&raw)).to_lowercase();
        // Leet-folded shadow: matches disguised variants (`jnd1`, `cmd.3x3`)
        // without corrupting the real payload's matching.
        let leet = Self::leetfold(&norm);
        let mut hits = 0u16;
        for (bit, pats) in Self::TABLE {
            if pats
                .iter()
                .any(|p| raw.contains(p) || norm.contains(p) || leet.contains(p))
            {
                hits |= bit;
            }
        }
        hits
    }

    /// Leet-speak fold: 1→i, 3→e, 0→o, 5→s, 7→t, 4→a. Attackers use
    /// these to dodge literal matches — folding normalizes them back.
    /// Runs on a SEPARATE shadow of the payload (not mixed into the main
    /// normalized form, so legit `1=1`-style math isn't corrupted).
    fn leetfold(s: &str) -> String {
        s.chars()
            .map(|c| match c {
                '1' => 'i',
                '3' => 'e',
                '0' => 'o',
                '5' => 's',
                '7' => 't',
                '4' => 'a',
                _ => c,
            })
            .collect()
    }

    /// Request-smuggling + charset-confusion detection on raw headers.
    /// These are the attacks that beat real WAFs — two parsers disagree
    /// on where the body starts, or an odd encoding smuggles bytes past.
    /// Returns a bitmask: 512 smuggling, 1024 charset, 2048 json-pollution.
    pub fn scan_smuggling(raw_headers: &str) -> u16 {
        let h = raw_headers.to_lowercase();
        let mut hits = 0u16;
        let cl = h.matches("content-length:").count();
        let te_chunked = h.contains("transfer-encoding:") && h.contains("chunked");
        // TE.CL / CL.TE: both present → parsers disagree on body bounds.
        if cl > 0 && te_chunked {
            hits |= 512;
        }
        // Conflicting duplicate Content-Length (a CL.CL smuggle variant).
        if cl > 1 {
            let mut vals = std::collections::HashSet::new();
            for line in h.lines() {
                if let Some(v) = line.trim().strip_prefix("content-length:") {
                    vals.insert(v.trim().to_string());
                }
            }
            if vals.len() > 1 {
                hits |= 512;
            }
        }
        // Charset confusion: utf-7 marker, utf-16le, overlong %c0%ae,
        // raw C0/C1 lead bytes that decode past UTF-8 validators.
        if h.contains("charset=utf-7")
            || h.contains("charset=utf-16")
            || h.contains("%c0%ae")
            || h.contains("%e0%80%ae")
            || raw_headers.bytes().any(|b| b == 0xc0 || b == 0xc1)
        {
            hits |= 1024;
        }
        // Verb anomalies — TRACE/TRACK echo back request contents
        // (XST attack); CONNECT outside a proxy context is tunnel abuse.
        let first = h.lines().next().unwrap_or("");
        if first.starts_with("trace ") || first.starts_with("track ") {
            hits |= 4096;
        }
        // WebSocket/upgrade covert-channel attempt — a legit app doesn't
        // upgrade to a raw tunnel mid-session.
        if h.contains("upgrade:") && (h.contains("websocket") || h.contains("connect")) {
            hits |= 4096;
        }
        // Oversized header block — buffer-abuse / smuggling padding.
        if raw_headers.len() > 16_384 {
            hits |= 4096;
        }
        // JSON pollution: same key twice in one object body fragment.
        if h.contains('{') {
            let mut keys = std::collections::HashMap::new();
            for (i, c) in h.char_indices() {
                if c != '"' {
                    continue;
                }
                if let Some(k) = h[i + 1..].split('"').next() {
                    if !k.is_empty() && k.len() < 40 && h[i + 1 + k.len()..].starts_with("\":") {
                        *keys.entry(k.to_string()).or_insert(0u8) += 1;
                    }
                }
            }
            if keys.values().any(|&c| c > 1) {
                hits |= 2048;
            }
        }
        hits
    }

    /// Defeats the classic evasions: strip `/* */` comments, %-decode,
    /// collapse runs of whitespace to a single space.
    fn normalize(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let b = s.as_bytes();
        let mut i = 0;
        let mut last_ws = false;
        while i < b.len() {
            // `/* */` → space (token splicing becomes `; cat`, not `;cat`)
            if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
                if let Some(end) = s[i + 2..].find("*/") {
                    i += 2 + end + 2;
                    if !last_ws {
                        out.push(' ');
                        last_ws = true;
                    }
                    continue;
                }
            }
            // %XX → decoded byte
            if b[i] == b'%'
                && i + 2 < b.len()
                && b[i + 1].is_ascii_hexdigit()
                && b[i + 2].is_ascii_hexdigit()
            {
                let h = u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap_or(b'%');
                out.push(h as char);
                i += 3;
                last_ws = false;
                continue;
            }
            // `+` → space (query-string convention); `\x00` → drop
            // (null-padding evasion).
            if b[i] == b'+' {
                if !last_ws {
                    out.push(' ');
                    last_ws = true;
                }
                i += 1;
                continue;
            }
            if b[i] == 0 {
                i += 1;
                continue;
            }
            if b[i].is_ascii_whitespace() {
                if !last_ws {
                    out.push(' ');
                    last_ws = true;
                }
                i += 1;
                continue;
            }
            out.push(b[i] as char);
            last_ws = false;
            i += 1;
        }
        out
    }

    const TABLE: &'static [(u16, &'static [&'static str])] = &[
        (
            1,
            &[
                "' or '",
                " or 1=1",
                "1=1", // tautology survives comment-splicing & encoding
                "union select",
                "union/**/select",
                "drop table",
                "'; --",
                "exec xp_",
            ],
        ),
        (
            2,
            &["<script", "javascript:", "onerror=", "onload=", "alert("],
        ),
        (
            4,
            &["../", "..\\", "%2e%2e", "etc/passwd", "boot.ini", "win.ini"],
        ),
        (
            8,
            &[
                "; cat ",
                "| nc ",
                "`id`",
                "$(id",
                "cmd.exe",
                "/bin/sh",
                "/bin/bash",
                "powershell",
            ],
        ),
        (
            16,
            &[
                "sqlmap",
                "nikto",
                "nmap",
                "masscan",
                "hydra",
                "gobuster",
                "dirbuster",
            ],
        ),
        (
            32, // JNDI / log4shell-class lookups
            &[
                "${jndi:",
                "jndi:ldap",
                "jndi:rmi",
                "jndi:dns",
                "${lower:",
                "${env:",
            ],
        ),
        (
            64, // credential/key material leaving the machine (agent guardrail)
            &[
                "sk-",
                "ghp_",
                "gho_",
                "akia",
                "xoxb-",
                "aiza",
                "-----begin",
                "private key",
                "api_key",
                "apikey",
                "bearer eyj",
            ],
        ),
        (
            128, // prompt-injection / agent-hijack markers
            &[
                "ignore previous instructions",
                "ignore all previous",
                "disregard previous",
                "reveal your system prompt",
                "developer mode enabled",
                "dan mode",
            ],
        ),
        (
            256, // industry-standard test files (EICAR)
            &["eicar-standard-antivirus-test-file"],
        ),
        (
            64, // template / expression injection
            &[
                "{{7*7}}", "${7*7}", "{{config", "{{self.", "eval(", "popen(",
            ],
        ),
        (
            128, // sensitive-path / secret probing
            &[
                "/.env",
                "/.git/",
                ".aws/credentials",
                "/wp-admin",
                "id_rsa",
                ".ssh/",
            ],
        ),
    ];

    /// Shannon entropy of bytes → ×100 u8 (for the payload_ent channel).
    pub fn shannon(data: &[u8]) -> u8 {
        if data.is_empty() {
            return 0;
        }
        let mut hist = [0u32; 256];
        for &b in &data[..data.len().min(4096)] {
            hist[b as usize] += 1;
        }
        let n = data.len().min(4096) as f32;
        let e: f32 = hist
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f32 / n;
                -p * p.log2()
            })
            .sum();
        (e * 100.0) as u8
    }
}

/// Second beacon path: linear 50ms gap histogram. Jittered beacons
/// still land most gaps in ≤2 adjacent buckets — CV evasion can't hide
/// the mode. (Log2 buckets failed here: their exponential width
/// clusters uniform-random gaps into the top buckets → false flag.)
/// `last` is the most recent gap's bucket: a flag requires the cadence
/// to still be happening NOW, not a stale pattern from old traffic.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct GapHist {
    buckets: [u32; 32],
    last: usize,
    /// Consecutive gaps in adjacent buckets — the cadence must be
    /// CURRENT, not residue from old traffic. One outlier breaks it.
    streak: u32,
}

impl GapHist {
    fn push(&mut self, gap_ms: u64) {
        let b = (gap_ms / 50).min(31) as usize;
        self.streak = if b == self.last || b == self.last + 1 || b + 1 == self.last {
            self.streak + 1
        } else {
            1
        };
        self.last = b;
        self.buckets[b] += 1;
    }
    /// True when ≥share of gaps sit in ≤2 adjacent buckets AND the last
    /// `min_cnt` gaps ran consecutively in-band — stale cadence can't
    /// flag on residue alone.
    fn flag(&self, share: f32, min_cnt: u32) -> bool {
        let total: u32 = self.buckets.iter().sum();
        if total == 0 || self.streak < min_cnt {
            return false;
        }
        let (bi, best) = (0..31)
            .map(|i| (i, self.buckets[i] + self.buckets[i + 1]))
            .max_by_key(|x| x.1)
            .unwrap();
        best as f32 / total as f32 >= share && (self.last == bi || self.last == bi + 1)
    }
}

impl Beacons {
    /// `share`: fraction of gaps that must sit in ≤2 adjacent log2
    /// buckets for the jitter-resistant path to flag.
    pub fn new(cv: f32, min_cnt: u64) -> Self {
        Self {
            cv,
            min_cnt,
            share: 0.7,
            cap: 10_000,
            map: HashMap::new(),
            hist: HashMap::new(),
        }
    }

    /// `Some(ip)` when a source's inter-arrival times turn suspiciously
    /// regular — strict CV for clean beacons, dominant-bucket for
    /// jittered ones.
    pub fn observe(&mut self, ev: &ConnEvent) -> Option<IpAddr> {
        if !self.map.contains_key(&ev.src_ip) && self.map.len() >= self.cap {
            return None; // table full — skip new talkers (same bound as SourceProfiles)
        }
        let (last, mean, var, cnt) = self.map.entry(ev.src_ip).or_insert((0, 0.0, 0.0, 0));
        if *last == 0 {
            *last = ev.ts_ms;
            return None;
        }
        let gap = ev.ts_ms.saturating_sub(*last) as f32;
        // Sub-`min_gap` spacing = burst-internal, not cadence — floods
        // are rate-channel territory. Update last_ts so the post-burst
        // gap measures from burst end, but feed no cadence stats.
        if gap < 50.0 {
            *last = ev.ts_ms;
            return None;
        }
        *last = ev.ts_ms;
        *cnt += 1;
        self.hist
            .entry(ev.src_ip)
            .or_insert_with(|| GapHist {
                buckets: [0; 32],
                last: 0,
                streak: 0,
            })
            .push(gap as u64);
        let d = gap - *mean;
        *mean += d / *cnt as f32;
        *var += d * (gap - *mean);
        if *cnt >= self.min_cnt && *mean > f32::EPSILON {
            let sd = (*var / (*cnt - 1) as f32).max(0.0).sqrt();
            if sd / *mean < self.cv {
                return Some(ev.src_ip);
            }
            // Jittered path: ≥share of gaps in ≤2 adjacent buckets AND
            // the current gap continues the cadence (not a stale tail).
            if *cnt >= self.min_cnt * 2
                && self
                    .hist
                    .get(&ev.src_ip)
                    .is_some_and(|h| h.flag(self.share, self.min_cnt as u32))
            {
                return Some(ev.src_ip);
            }
        }
        None
    }
}

// ---------- 5. Real ingest seam ----------

/// Any source of `ConnEvent`s — pcap/WinDivert adapters implement this.
pub trait EventSource {
    fn next_event(&mut self) -> Option<ConnEvent>;
}

/// Replay a JSONL file of `ConnEvent`s — real capture files, testable.
pub struct JsonlSource<R: BufRead>(pub R);

impl<R: BufRead> EventSource for JsonlSource<R> {
    fn next_event(&mut self) -> Option<ConnEvent> {
        let mut line = String::new();
        match self.0.read_line(&mut line) {
            Ok(0) | Err(_) => None,
            Ok(_) => serde_json::from_str(&line).ok(),
        }
    }
}

/// Replay a libpcap capture: global header + per-packet records →
/// Ethernet/IPv4/TCP → `ConnEvent`. Pure parser, zero deps — the same
/// binary format Wireshark/tcpdump produce.
pub struct PcapSource<R: Read> {
    r: R,
    eof: bool,
}

impl<R: Read> PcapSource<R> {
    /// Returns `None` on a bad/unsupported capture header.
    pub fn open(mut r: R) -> Option<Self> {
        let mut gh = [0u8; 24];
        r.read_exact(&mut gh).ok()?;
        // LE magic only (d4 c3 b2 a1); network must be Ethernet (1).
        let magic_ok = gh[0..4] == [0xd4, 0xc3, 0xb2, 0xa1];
        let network_ok = u32::from_le_bytes(gh[20..24].try_into().ok()?) == 1;
        (magic_ok && network_ok).then_some(Self { r, eof: false })
    }
}

impl<R: Read> EventSource for PcapSource<R> {
    fn next_event(&mut self) -> Option<ConnEvent> {
        if self.eof {
            return None;
        }
        let mut rh = [0u8; 16];
        if self.r.read_exact(&mut rh).is_err() {
            self.eof = true;
            return None;
        }
        let (ts_sec, ts_usec, incl) = (
            u32::from_le_bytes(rh[0..4].try_into().unwrap()),
            u32::from_le_bytes(rh[4..8].try_into().unwrap()),
            u32::from_le_bytes(rh[8..12].try_into().unwrap()) as usize,
        );
        let mut pkt = vec![0u8; incl];
        if self.r.read_exact(&mut pkt).is_err() || incl < 14 + 20 {
            self.eof = true;
            return None;
        }
        // Ethernet → IPv4 → TCP; skip anything else (non-TCP traffic
        // is out of scope for this event model).
        if u16::from_be_bytes([pkt[12], pkt[13]]) != 0x0800 {
            return self.next_event();
        }
        let ip = &pkt[14..];
        let ihl = ((ip[0] & 0x0f) as usize) * 4;
        if ip.len() < ihl + 20 || ip[9] != 6 {
            return self.next_event();
        }
        let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
        let tcp = &ip[ihl..];
        if tcp.len() < 20 {
            return self.next_event();
        }
        let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
        let tcp_hl = ((tcp[12] >> 4) as usize) * 4;
        let payload = &tcp[tcp_hl.min(tcp.len())..];
        Some(ConnEvent {
            ts_ms: ts_sec as u64 * 1000 + ts_usec as u64 / 1000,
            tenant: "t-a".into(),
            src_ip: IpAddr::V4(src),
            payload_bytes: payload.len() as u32,
            header_bytes: (ihl + tcp_hl) as u32,
            meta: EventMeta {
                dst_port,
                proto: 6,
                ..Default::default()
            },
            payload: if payload.is_empty() {
                None
            } else {
                Some(payload.to_vec().into_boxed_slice())
            },
        })
    }
}
