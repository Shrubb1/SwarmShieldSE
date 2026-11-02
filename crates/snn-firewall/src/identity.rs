//! Actor fingerprinting — beats IP rotation. `ja3`+`ua_id` identify the
//! actor regardless of `src_ip`; once any IP under a fingerprint is
//! flagged, new IPs with the same fingerprint inherit the flag — the
//! rotate-and-retry gambit fails on event one.
//! Only fingerprinted when `ja3 != 0` — TLS-less traffic has no stable
//! identity and sharing fingerprints there would false-positive NATs.

use std::collections::HashMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::event::ConnEvent;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Actor {
    flagged: bool,
    ips: Vec<IpAddr>, // bounded — rotation tracking, cap implicit via map cap
    last_ms: u64,
}

/// fingerprint-keyed actor registry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityMap {
    map: HashMap<u64, Actor>,
    cap: usize,
    max_ips: usize,
}

impl Default for IdentityMap {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
            cap: 10_000,
            max_ips: 64,
        }
    }
}

impl IdentityMap {
    /// `Some(fp)` when the event carries a usable fingerprint.
    fn fp(ev: &ConnEvent) -> Option<u64> {
        (ev.meta.ja3 != 0).then_some((ev.meta.ja3 as u64) << 16 | ev.meta.ua_id as u64)
    }

    /// Observe an event: returns `true` when this fingerprint is ALREADY
    /// flagged from other IPs — the new source inherits suspicion.
    /// `flagged_now`: this event independently triggered a detector.
    pub fn observe(&mut self, ev: &ConnEvent, flagged_now: bool) -> bool {
        let fp = match Self::fp(ev) {
            Some(f) => f,
            None => return false,
        };
        if !self.map.contains_key(&fp) && self.map.len() >= self.cap {
            return false;
        }
        let a = self.map.entry(fp).or_insert(Actor {
            flagged: false,
            ips: Vec::new(),
            last_ms: ev.ts_ms,
        });
        a.last_ms = ev.ts_ms;
        if !a.ips.contains(&ev.src_ip) && a.ips.len() < self.max_ips {
            a.ips.push(ev.src_ip);
        }
        if flagged_now {
            a.flagged = true;
        }
        // Known-bad actor on a source it wasn't seen under before, or a
        // flagged actor continuing — either way this event is suspect.
        a.flagged && (a.ips.len() > 1 || flagged_now)
    }
}
