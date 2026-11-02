//! `snn-learn` — local online plasticity.
//!
//! Trace-based pairwise STDP. Each neuron keeps one exponential trace
//! (`x' = -x/tau`, bumped by 1 on its own spikes). Weight updates happen at
//! spike events:
//!
//! - pre spike `i` → for each outgoing synapse: `w -= a_minus * post_trace[j]` (LTD)
//! - post spike `j` → for each incoming synapse: `w += a_plus * pre_trace[i]` (LTP)
//!
//! Ordering inside a step is fixed (decay → LTD/pre → LTP/post) so the
//! rule is deterministic even when pre and post fire simultaneously.
//! Traces are serializable — the "memory" of recent firing survives
//! checkpoints like the weights themselves.
//!
//! The learner sits *outside* the network: it observes each `SpikeFrame`
//! and mutates `Connection::synapses` in place. Core stays pure
//! simulation; learning is opt-in per connection.

use serde::{Deserialize, Serialize};
use snn_core::{Network, SparseSynapses, SpikeFrame};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StdpParams {
    /// LTP amplitude applied per unit pre-trace on a post spike.
    pub a_plus: f32,
    /// LTD amplitude applied per unit post-trace on a pre spike.
    pub a_minus: f32,
    /// Pre-trace time constant (ms).
    pub tau_plus: f32,
    /// Post-trace time constant (ms).
    pub tau_minus: f32,
    /// Hard weight bounds — plasticity can never push past these.
    pub w_min: f32,
    pub w_max: f32,
}

impl Default for StdpParams {
    /// Slightly LTD-dominant, a common stable choice.
    fn default() -> Self {
        Self {
            a_plus: 0.01,
            a_minus: 0.0105,
            tau_plus: 20.0,
            tau_minus: 20.0,
            w_min: 0.0,
            w_max: 1.0,
        }
    }
}

/// STDP state bound to one `Connection`. Traces are per-neuron in the
/// connection's pre/post layers — O(neurons) memory, independent of the
/// number of synapses.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StdpLearner {
    pub params: StdpParams,
    /// Index into `Network::connections`.
    pub connection: usize,
    /// Layer ids, cached so `apply` doesn't have to look them up.
    pub pre_layer: usize,
    pub post_layer: usize,
    pre_trace: Vec<f32>,
    post_trace: Vec<f32>,
}

impl StdpLearner {
    pub fn new(
        connection: usize,
        pre_layer: usize,
        post_layer: usize,
        pre_size: usize,
        post_size: usize,
        params: StdpParams,
    ) -> Self {
        Self {
            params,
            connection,
            pre_layer,
            post_layer,
            pre_trace: vec![0.0; pre_size],
            post_trace: vec![0.0; post_size],
        }
    }

    /// Wire a learner to `net.connections[connection]` with `params`.
    pub fn for_connection(net: &Network, connection: usize, params: StdpParams) -> Self {
        let conn = &net.connections[connection];
        Self::new(
            connection,
            conn.pre,
            conn.post,
            conn.synapses.pre_size(),
            conn.synapses.post_size(),
            params,
        )
    }

    /// One timestep of plasticity against the spikes just emitted.
    ///
    /// Order: decay both traces → process pre spikes (LTD + pre bump) →
    /// process post spikes (LTP + post bump). A simultaneous pre/post pair
    /// therefore sees the already-bumped pre-trace for LTP — a documented
    /// convention, kept fixed for determinism.
    pub fn apply(&mut self, dt: f32, frame: &SpikeFrame, syn: &mut SparseSynapses) {
        let p = &self.params;
        let decay_pre = (-dt / p.tau_plus).exp();
        let decay_post = (-dt / p.tau_minus).exp();
        for x in &mut self.pre_trace {
            *x *= decay_pre;
        }
        for x in &mut self.post_trace {
            *x *= decay_post;
        }

        for &i in frame.layer(self.pre_layer) {
            let i = i as usize;
            for k in syn.row_range(i) {
                let j = syn.post_of(k) as usize;
                syn.add_weight(k, -p.a_minus * self.post_trace[j], p.w_min, p.w_max);
            }
            self.pre_trace[i] += 1.0;
        }

        for &j in frame.layer(self.post_layer) {
            let j = j as usize;
            for k in syn.incoming_range(j) {
                let i = syn.incoming_pre(k) as usize;
                let s = syn.incoming_syn(k);
                syn.add_weight(s, p.a_plus * self.pre_trace[i], p.w_min, p.w_max);
            }
            self.post_trace[j] += 1.0;
        }
    }

    pub fn pre_traces(&self) -> &[f32] {
        &self.pre_trace
    }

    pub fn post_traces(&self) -> &[f32] {
        &self.post_trace
    }
}

/// Apply every learner against the frame just produced by `net.step()`.
/// Convenience for the standard loop:
///
/// ```ignore
/// let frame = net.step();
/// snn_learn::apply_all(&mut learners, &frame, &mut net);
/// ```
pub fn apply_all(learners: &mut [StdpLearner], frame: &SpikeFrame, net: &mut Network) {
    let dt = net.dt;
    for l in learners {
        l.apply(dt, frame, &mut net.connections[l.connection].synapses);
    }
}
