//! Axonal delay line: a ring buffer of per-timestep event buckets.
//!
//! `schedule(d, ev)` makes `ev` due `1 + d` steps after the current one —
//! there is always at least one timestep of propagation latency, so
//! recurrent self-connections can't fire a neuron within the step that
//! produced the spike. In-flight events are serialized with the checkpoint;
//! pausing mid-propagation loses nothing.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct SynEvent {
    /// Postsynaptic neuron index within the target layer.
    pub post: u32,
    /// Synaptic current injected on delivery (the synaptic weight).
    pub current: f32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DelayQueue {
    buckets: Vec<Vec<SynEvent>>,
    head: usize,
}

impl DelayQueue {
    /// `max_delay` is the largest additional delay any synapse may request.
    pub fn new(max_delay: usize) -> Self {
        Self {
            buckets: vec![Vec::new(); max_delay + 1],
            head: 0,
        }
    }

    /// Event becomes due `1 + delay` steps from now.
    pub fn schedule(&mut self, delay: usize, ev: SynEvent) {
        let slot = (self.head + delay) % self.buckets.len();
        self.buckets[slot].push(ev);
    }

    /// Drain the events due this step, then advance the ring.
    pub fn take_due(&mut self) -> Vec<SynEvent> {
        let due = std::mem::take(&mut self.buckets[self.head]);
        self.head = (self.head + 1) % self.buckets.len();
        due
    }

    /// Total events in flight — non-zero after a mid-burst checkpoint.
    pub fn in_flight(&self) -> usize {
        self.buckets.iter().map(Vec::len).sum()
    }
}
