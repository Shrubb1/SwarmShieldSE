//! Gateway-side observation: raw connection events → metric vectors.
//!
//! The proxy calls [`FeatureWindow::observe`] once per connection event.
//! Events are bucketed into fixed `tick_ms` windows; when an event arrives
//! past the current window's end, the completed window is finalized into a
//! [`FeatureVector`] — the numeric sample the SNN detector consumes —
//! plus attribution data telling the policy engine *who* drove the window.
//!
//! Quiet policy: windows with zero events are never emitted. A silent
//! gateway is not scored — otherwise every quiet period would read as a
//! down-spike anomaly. Low-but-nonzero rates stay in the baseline.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// One connection-level observation from the gateway/proxy.
/// Fields are metadata only — payload contents are never inspected.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConnEvent {
    /// Event time in ms. All firewall logic keys off this field — no
    /// wall clock anywhere in the engine.
    pub ts_ms: u64,
    /// Tenant/job scope for tenant-scoped audit (`jobs/{id}` style).
    pub tenant: String,
    /// Source of the connection.
    pub src_ip: IpAddr,
    /// Request payload size in bytes (0 for a bare SYN/HEAD).
    pub payload_bytes: u32,
    /// Total header size in bytes.
    pub header_bytes: u32,
    /// Optional port/proto/error metadata — defaults keep old wire
    /// peers working.
    #[serde(default)]
    pub meta: EventMeta,
    /// Optional raw payload bytes. When present the ENGINE computes
    /// entropy + signature hits itself — producer meta can't lie.
    /// Skipped on the wire when absent (most events carry none).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Box<[u8]>>,
}

/// Metric channels emitted per tick, in `FeatureVector::values` order.
/// Keep this aligned with `FeatureWindow::finalize` — and with the
/// `DetectorConfig::metrics` names produced by `channel_names()`.
pub const CHANNELS: usize = 6;

pub fn channel_names() -> Vec<&'static str> {
    vec![
        "req_rate",      // events/sec across all sources
        "top_src_rate",  // events/sec from the single busiest source
        "uniq_srcs",     // distinct source IPs in the window
        "mean_payload",  // mean payload bytes per event
        "mean_header",   // mean header bytes per event
        "new_src_rate",  // first-seen sources/sec (scan/probe signal)
        "port_entropy",  // dst-port entropy ×100 (port-scan signal)
        "error_rate",    // errored conns ÷ total ×100
        "tcp_share",     // TCP fraction ×100 (proto-mix shift)
        "post_share",    // POST/PUT/DELETE fraction ×100 (write-verb shift)
        "mean_path",     // mean request-path length ×100
        "ua_diversity",  // distinct UA buckets ÷ events ×100 (UA rotation)
        "payload_ent",   // mean payload entropy ×100 (payload scan signal)
        "sig_rate",      // signature-hit fraction ×100 (content attacks)
        "ja3_diversity", // distinct TLS fingerprints ÷ events ×100
    ]
}

/// One finalized window: detector input + attribution.
#[derive(Clone, Debug)]
pub struct FeatureVector {
    /// Window start (ms) — becomes `TelemetrySample::ts_ms`.
    pub start_ms: u64,
    /// Metrics aligned to `channel_names()`.
    pub values: Vec<f32>,
    /// `(ip, event_count)` of the busiest source this window, if any —
    /// the candidate subject for a targeted mitigation rule.
    pub top_src: Option<(IpAddr, u32)>,
}

#[derive(Default)]
struct TickAgg {
    events: u32,
    payload_bytes: u64,
    header_bytes: u64,
    by_src: HashMap<IpAddr, u32>,
    new_srcs: u32,
}

/// Buckets `ConnEvent`s into fixed windows and finalizes them on demand.
pub struct FeatureWindow {
    tick_ms: u64,
    /// Start time of the window currently accumulating. `None` until the
    /// first event arrives — the clock is event-driven, not wall-driven.
    cur_start: Option<u64>,
    cur: TickAgg,
    /// Sources seen across all windows — drives the `new_src_rate` metric.
    seen: HashSet<IpAddr>,
}

impl FeatureWindow {
    pub fn new(tick_ms: u64) -> Self {
        Self {
            tick_ms: tick_ms.max(1),
            cur_start: None,
            cur: TickAgg::default(),
            seen: HashSet::new(),
        }
    }

    /// Record `ev`. Returns the finalized [`FeatureVector`] when `ev`
    /// closed the previous window (i.e. `ev` starts a later tick), else
    /// `None`. The returned vector describes the *completed* window —
    /// `ev` itself belongs to the new one.
    pub fn observe(&mut self, ev: &ConnEvent) -> Option<FeatureVector> {
        let start = match self.cur_start {
            Some(s) => s,
            None => {
                let s = ev.ts_ms / self.tick_ms * self.tick_ms;
                self.cur_start = Some(s);
                s
            }
        };
        let finalized = if ev.ts_ms >= start + self.tick_ms {
            let v = self.finalize(start);
            // Align the new window to the tick grid containing `ev`.
            self.cur_start = Some(ev.ts_ms / self.tick_ms * self.tick_ms);
            Some(v)
        } else {
            None
        };

        self.accumulate(ev);
        finalized
    }

    fn accumulate(&mut self, ev: &ConnEvent) {
        self.cur.events += 1;
        self.cur.payload_bytes += ev.payload_bytes as u64;
        self.cur.header_bytes += ev.header_bytes as u64;
        *self.cur.by_src.entry(ev.src_ip).or_insert(0) += 1;
        if self.seen.insert(ev.src_ip) {
            self.cur.new_srcs += 1;
        }
    }

    fn finalize(&mut self, start: u64) -> FeatureVector {
        let agg = std::mem::take(&mut self.cur);
        let secs = self.tick_ms as f32 / 1000.0;
        let n = agg.events.max(1) as f32;
        let top_src = agg
            .by_src
            .iter()
            .max_by_key(|(_, &c)| c)
            .map(|(&ip, &c)| (ip, c));
        FeatureVector {
            start_ms: start,
            values: vec![
                agg.events as f32 / secs,
                top_src.map(|(_, c)| c).unwrap_or(0) as f32 / secs,
                agg.by_src.len() as f32,
                agg.payload_bytes as f32 / n,
                agg.header_bytes as f32 / n,
                agg.new_srcs as f32 / secs,
            ],
            top_src,
        }
    }

    /// Flush a partially-filled window (e.g. on shutdown). Returns `None`
    /// if nothing accumulated.
    pub fn flush(&mut self) -> Option<FeatureVector> {
        self.cur_start
            .take()
            .filter(|_| self.cur.events > 0)
            .map(|start| self.finalize(start))
    }
}

/// Port/protocol/error fields — optional, serde-defaulted so old wire
/// peers keep working. Carried on `ConnEvent::meta`.
#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct EventMeta {
    #[serde(default)]
    pub dst_port: u16,
    /// 6=TCP, 17=UDP, 0=unknown.
    #[serde(default)]
    pub proto: u8,
    #[serde(default)]
    pub error: bool,
    /// HTTP-ish method: 0 none, 1 GET, 2 POST, 3 PUT, 4 DELETE, 9 other.
    #[serde(default)]
    pub method: u8,
    /// Request path length in bytes (0 when not HTTP).
    #[serde(default)]
    pub path_len: u16,
    /// UA-string bucket id — diversity of values signals UA rotation.
    #[serde(default)]
    pub ua_id: u16,
    /// Shannon entropy of the first N payload bytes ×100 (producer-
    /// computed — the engine never sees payload content).
    #[serde(default)]
    pub payload_entropy: u8,
    /// Signature bitmask from `Signatures::scan` (producer-side):
    /// 1=SQLi, 2=XSS, 4=traversal, 8=cmd-injection, 16=scanner UA.
    #[serde(default)]
    pub sig_hits: u16,
    /// TLS fingerprint bucket (JA3/JA4 hash, producer-computed).
    /// Diversity of values = fingerprint rotation.
    #[serde(default)]
    pub ja3: u32,
}
