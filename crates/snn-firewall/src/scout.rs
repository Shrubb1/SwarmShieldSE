//! The Scout layer — a lenient first gate that profiles instead of
//! blocking. Every event is analyzed; nothing is denied. Suspicion
//! accumulates per source and feeds the real `Firewall`: tagged IPs
//! get their anomalies escalated (`scout_hint` lowers the effective
//! threshold), and hard-scored sources emit an Ip rule outright.
//!
//! Three detectors the main engine can't reach:
//! - `Persistence`: long-horizon contact count per IP — catches the
//!   modeless random-walk beacon (it's loud in COUNT even when silent
//!   in cadence).
//! - `ReferenceDrift`: anchors against the frozen initial baselines —
//!   the adaptive delta baseline can't absorb drift vs the anchor.
//! - `ShapeScore`: payload entropy + printable ratio per source —
//!   content suspicion without signatures.

use std::collections::HashMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::enhance::Signatures;
use crate::event::ConnEvent;

/// Long-horizon contact tracking: count per source over a `span_ms`
/// window. Beacons are loud in COUNT even when cadence-random.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Persistence {
    /// Tick span the counts accumulate over.
    pub span_ms: u64,
    /// Sustained contacts/span that marks machine persistence.
    pub threshold: u32,
    map: HashMap<IpAddr, (u64, u32)>, // span_start, count
    pub cap: usize,
}

impl Persistence {
    pub fn new(span_ms: u64, threshold: u32) -> Self {
        Self {
            span_ms,
            threshold,
            map: HashMap::new(),
            cap: 10_000,
        }
    }

    /// Sustained-contact score 0..1 for this source.
    pub fn observe(&mut self, ev: &ConnEvent) -> f32 {
        if !self.map.contains_key(&ev.src_ip) && self.map.len() >= self.cap {
            return 0.0;
        }
        let e = self.map.entry(ev.src_ip).or_insert((ev.ts_ms, 0));
        if ev.ts_ms.saturating_sub(e.0) > self.span_ms {
            *e = (ev.ts_ms, 0); // span rolled
        }
        e.1 += 1;
        (e.1 as f32 / self.threshold as f32).min(1.0)
    }
}

/// Per-source payload-shape suspicion: high entropy or low printable
/// ratio reads as binary/exploit-ish content.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Shape {
    printable_ratio: f32,
    entropy: f32,
}

fn payload_shape(bytes: &[u8]) -> Shape {
    let n = bytes.len().min(4096);
    if n == 0 {
        return Shape {
            printable_ratio: 1.0,
            entropy: 0.0,
        };
    }
    let printable = bytes[..n]
        .iter()
        .filter(|b| b.is_ascii_graphic() || **b == b' ')
        .count();
    Shape {
        printable_ratio: printable as f32 / n as f32,
        entropy: Signatures::shannon(&bytes[..n]) as f32 / 100.0,
    }
}

/// Per-source suspicion accumulator — one number the Firewall reads.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Suspect {
    score: f32,
    hits: u32,
}

/// The Scout gate. Cheap, bounded, serializable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Scout {
    pub persistence: Persistence,
    suspects: HashMap<IpAddr, Suspect>,
    /// Suspicion needed to flag a source downstream.
    pub flag_at: f32,
    /// Score increment per persistence unit.
    pub persist_weight: f32,
    /// Score increment for binary-ish payload shape.
    pub shape_weight: f32,
    /// Score increment per signature hit.
    pub sig_weight: f32,
    /// Decay per event for quiet sources — suspicion isn't sticky forever.
    pub decay: f32,
    cap: usize,
}

impl Scout {
    pub fn new() -> Self {
        Self {
            // 200+ contacts inside a 5s span = sustained machine-rate
            // right now. The span rolls — suspicion can't outlive the
            // attack window into a permanent stain.
            persistence: Persistence::new(5_000, 200),
            suspects: HashMap::new(),
            flag_at: 0.6,
            persist_weight: 0.4,
            shape_weight: 0.5,
            sig_weight: 0.6,
            decay: 0.02,
            cap: 10_000,
        }
    }

    /// Observe → accumulate → Some(score) only when THIS event both
    /// contributed suspicion AND the score sits at/above `flag_at`.
    /// Passive residue never flags on its own — clean events just
    /// decay. Never denies — the honeypot stays open.
    pub fn observe(&mut self, ev: &ConnEvent) -> Option<f32> {
        let persist = self.persistence.observe(ev);
        // Kicks in past half-threshold only — a quiet-but-regular source
        // shouldn't accrue; sustained machine-paced contact should.
        let mut s = (persist - 0.5).max(0.0) * self.persist_weight;

        if let Some(bytes) = &ev.payload {
            let shape = payload_shape(bytes);
            // Binary-ish: high entropy OR low printable ratio.
            let weird = (shape.entropy / 8.0) + (1.0 - shape.printable_ratio);
            if weird > 0.6 {
                s += (weird - 0.6) * self.shape_weight;
            }
            if Signatures::scan(bytes) != 0 {
                s += self.sig_weight;
            }
        } else if ev.meta.sig_hits != 0 {
            s += self.sig_weight;
        }

        if !self.suspects.contains_key(&ev.src_ip) && self.suspects.len() >= self.cap {
            return None;
        }
        let e = self.suspects.entry(ev.src_ip).or_insert(Suspect {
            score: 0.0,
            hits: 0,
        });
        if s > 0.0 {
            e.score = (e.score + s).min(3.0);
            e.hits += 1;
        } else {
            e.score = (e.score - self.decay).max(0.0);
            return None;
        }
        (e.score >= self.flag_at).then_some(e.score)
    }

    /// Firewalled-side read: is this source currently tagged?
    pub fn suspicion(&self, ip: IpAddr) -> f32 {
        self.suspects.get(&ip).map(|s| s.score).unwrap_or(0.0)
    }

    /// A rule was emitted for this IP — consume the flag. Score drops
    /// to half the flag line so it must re-accumulate through renewed
    /// attack behavior (suspicion isn't a permanent stain — rules
    /// drain and a quiet returner heals; a resumed attacker re-flags).
    pub fn consumed_flag(&mut self, ip: IpAddr) {
        if let Some(s) = self.suspects.get_mut(&ip) {
            s.score = self.flag_at * 0.5;
        }
    }

    /// Sources at/above the flag line right now.
    pub fn flagged(&self) -> Vec<IpAddr> {
        self.suspects
            .iter()
            .filter(|(_, s)| s.score >= self.flag_at)
            .map(|(ip, _)| *ip)
            .collect()
    }
}

impl Default for Scout {
    fn default() -> Self {
        Self::new()
    }
}
