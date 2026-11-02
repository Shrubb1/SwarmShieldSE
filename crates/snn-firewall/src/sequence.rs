//! Kill-chain prediction: attackers follow stages —
//!   0 recon (port probes, unusual dst_ports)
//!   1 enumeration (rapid varied paths / error harvest)
//!   2 exploit (signature hit / anomalous payload)
//! A source seen at stages 0 AND 1 within `window_ms` is predicted to
//! strike at stage 2 — the firewall can pre-empt before the payload
//! ever arrives. Bounded per-IP state, deterministic, serialized.

use std::collections::HashMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::event::ConnEvent;

const COMMON_PORTS: &[u16] = &[80, 443, 8080];

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Chain {
    stages: u8,    // bit0..2 = stage seen
    first_ms: u64, // when stage 0/1 first recorded
}

/// Per-IP kill-chain tracker.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SequenceTracker {
    map: HashMap<IpAddr, Chain>,
    pub window_ms: u64,
    cap: usize,
}

impl Default for SequenceTracker {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
            window_ms: 60_000,
            cap: 10_000,
        }
    }
}

impl SequenceTracker {
    /// Classify this event's stage and fold it into the chain.
    /// Returns `true` when stages 0+1 are both fresh within the window —
    /// the exploit is predicted imminent.
    pub fn observe(&mut self, ev: &ConnEvent, sig_hit: bool) -> bool {
        if !self.map.contains_key(&ev.src_ip) && self.map.len() >= self.cap {
            return false;
        }
        let stage = if sig_hit {
            2
        } else if !COMMON_PORTS.contains(&ev.meta.dst_port) {
            0 // probing unusual ports
        } else if ev.meta.error || ev.meta.path_len > 60 {
            1 // enumeration / error harvest
        } else {
            return false; // ordinary traffic — no chain signal
        };
        let c = self.map.entry(ev.src_ip).or_insert(Chain {
            stages: 0,
            first_ms: ev.ts_ms,
        });
        // A chain that sat idle past the window is a fresh sequence.
        if ev.ts_ms.saturating_sub(c.first_ms) > self.window_ms {
            c.stages = 0;
            c.first_ms = ev.ts_ms;
        }
        let was_pre = c.stages & 0b011 != 0b011;
        c.stages |= 1 << stage;
        // Predicted exploit: both earlier stages present, and this event
        // isn't itself the exploit (we predict BEFORE stage 2 lands).
        was_pre && c.stages & 0b011 == 0b011 && stage != 2
    }

    /// Forget a source (post-mitigation self-heal).
    pub fn reset(&mut self, ip: IpAddr) {
        self.map.remove(&ip);
    }
}
