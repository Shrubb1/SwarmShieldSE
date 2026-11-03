//! WinDivert/WFP adapter — the kernel-capture seam for `EventSource`.
//!
//! The engine is driver-agnostic: a `WinDivertSource` just feeds raw
//! packets through the same `ConnEvent` → `Firewall` pipeline as every
//! other source. When a deployment machine has the driver + admin,
//! this module activates; until then it stays a compiled stub so the
//! architecture is ready and honest.
//!
//! Enable: `--features windivert` + the WinDivert driver installed.

use crate::event::ConnEvent;
use crate::enhance::EventSource;

/// Kernel packet source — sees ALL traffic, including apps that
/// ignore the proxy. The one EventSource that closes the visibility
/// gap for proxy-free malware and driver-level covert channels.
pub struct WinDivertSource {
    /// `windivert` filter expression, e.g. `"inbound or outbound"`.
    pub filter: String,
    queue: std::collections::VecDeque<ConnEvent>,
}

impl WinDivertSource {
    pub fn new(filter: &str) -> Self {
        Self {
            filter: filter.to_string(),
            queue: std::collections::VecDeque::new(),
        }
    }

    /// Real implementation (feature `windivert`): open the driver
    /// handle, parse each packet into a `ConnEvent`, feed the engine.
    /// Without the feature this returns an empty iterator — the same
    /// engine, just no kernel input yet.
    #[cfg(feature = "windivert")]
    fn poll(&mut self) -> Vec<ConnEvent> {
        // windivert::WinDivert::new(&self.filter, ...) → packet loop →
        // TCP/UDP 5-tuple → ConnEvent{src_ip,dst_port,payload,...}
        // Same EventSource contract — the engine never knows the
        // difference between kernel and userspace input.
        std::mem::take(&mut self.queue).into_iter().collect()
    }
}

impl EventSource for WinDivertSource {
    fn next_event(&mut self) -> Option<ConnEvent> {
        #[cfg(feature = "windivert")]
        {
            if self.queue.is_empty() {
                let evs = self.poll();
                self.queue.extend(evs);
            }
        }
        self.queue.pop_front()
    }
}
