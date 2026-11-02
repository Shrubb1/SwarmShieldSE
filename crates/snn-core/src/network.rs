//! The hybrid clock-driven simulation loop.
//!
//! Each `step` is one fixed `dt` (ms) and proceeds in a fixed order:
//!
//! 1. **Deliver** — drain due delay-queue events into postsynaptic input
//!    accumulators.
//! 2. **Integrate** — update every neuron in parallel (`rayon`), collect
//!    spikes. `par_iter_mut` touches disjoint neurons, so results are
//!    identical to sequential execution.
//! 3. **Propagate** — for each firing presynaptic neuron, walk its CSR row
//!    and schedule `(post, weight)` events into the connection's delay ring.
//! 4. **Clear** — input accumulators are zeroed; synaptic currents are
//!    impulse-like, not persistent.
//!
//! Given the same injected currents, a run is bit-for-bit deterministic:
//! layout is sorted, iteration order is fixed, and no RNG lives in core.

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::delay::{DelayQueue, SynEvent};
use crate::neuron::{IzhikevichNeuron, LifNeuron, Neuron, NeuronModel};
use crate::synapse::SparseSynapses;

/// A homogeneous population of neurons.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Layer {
    pub name: String,
    pub neurons: Vec<Neuron>,
}

impl Layer {
    /// `n` LIF neurons cloned from `template` (params shared, state fresh).
    pub fn lif(name: impl Into<String>, n: usize, template: &LifNeuron) -> Self {
        Self {
            name: name.into(),
            neurons: vec![Neuron::Lif(template.clone()); n],
        }
    }

    /// `n` Izhikevich neurons cloned from `template`.
    pub fn izhikevich(name: impl Into<String>, n: usize, template: &IzhikevichNeuron) -> Self {
        Self {
            name: name.into(),
            neurons: vec![Neuron::Izhikevich(template.clone()); n],
        }
    }

    pub fn size(&self) -> usize {
        self.neurons.len()
    }

    pub fn membranes(&self) -> Vec<f32> {
        self.neurons.iter().map(|n| n.membrane()).collect()
    }
}

/// A directed synaptic projection `pre` layer → `post` layer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Connection {
    pub pre: usize,
    pub post: usize,
    pub synapses: SparseSynapses,
    queue: DelayQueue,
}

/// The spikes emitted by one `Network::step`, indexed by layer id.
/// Each inner vec holds neuron indices in ascending order.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SpikeFrame {
    pub spikes: Vec<Vec<u32>>,
}

impl SpikeFrame {
    pub fn layer(&self, id: usize) -> &[u32] {
        &self.spikes[id]
    }

    pub fn total(&self) -> usize {
        self.spikes.iter().map(Vec::len).sum()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Network {
    pub layers: Vec<Layer>,
    pub connections: Vec<Connection>,
    /// Per-layer synaptic input accumulators for the current step.
    inputs: Vec<Vec<f32>>,
    pub dt: f32,
    pub step_count: u64,
}

impl Network {
    pub fn new(dt: f32) -> Self {
        Self {
            layers: Vec::new(),
            connections: Vec::new(),
            inputs: Vec::new(),
            dt,
            step_count: 0,
        }
    }

    pub fn add_layer(&mut self, layer: Layer) -> usize {
        self.inputs.push(vec![0.0; layer.size()]);
        self.layers.push(layer);
        self.layers.len() - 1
    }

    /// Wire `pre` → `post` with `(pre_idx, post_idx, weight, delay)` edges.
    /// Returns the connection id.
    pub fn connect(&mut self, pre: usize, post: usize, edges: &[(u32, u32, f32, u16)]) -> usize {
        let synapses =
            SparseSynapses::from_edges(self.layers[pre].size(), self.layers[post].size(), edges);
        let queue = DelayQueue::new(synapses.max_delay() as usize);
        self.connections.push(Connection {
            pre,
            post,
            synapses,
            queue,
        });
        self.connections.len() - 1
    }

    /// Add external current into a layer's input accumulator for the
    /// *next* `step` only. Call once per step before `step()`.
    pub fn inject(&mut self, layer: usize, currents: &[f32]) {
        assert_eq!(
            currents.len(),
            self.inputs[layer].len(),
            "input length must match layer size"
        );
        for (acc, &c) in self.inputs[layer].iter_mut().zip(currents) {
            *acc += c;
        }
    }

    /// Advance the simulation one `dt`. Returns which neurons spiked.
    pub fn step(&mut self) -> SpikeFrame {
        // 1. Deliver due synaptic events.
        for conn in &mut self.connections {
            let due = conn.queue.take_due();
            let post_inputs = &mut self.inputs[conn.post];
            for ev in due {
                post_inputs[ev.post as usize] += ev.current;
            }
        }

        // 2. Integrate neurons in parallel; spikes collected in index order.
        let mut frame = SpikeFrame {
            spikes: Vec::with_capacity(self.layers.len()),
        };
        for (li, layer) in self.layers.iter_mut().enumerate() {
            let input = &self.inputs[li];
            let dt = self.dt;
            let spikes: Vec<u32> = layer
                .neurons
                .par_iter_mut()
                .enumerate()
                .filter_map(|(i, n)| n.step(input[i], dt).then_some(i as u32))
                .collect();
            frame.spikes.push(spikes);
        }

        // 3. Propagate spikes through CSR rows into delay queues.
        for conn in &mut self.connections {
            for &pre in &frame.spikes[conn.pre] {
                for k in conn.synapses.row_range(pre as usize) {
                    let ev = SynEvent {
                        post: conn.synapses.post_of(k),
                        current: conn.synapses.weight(k),
                    };
                    conn.queue.schedule(conn.synapses.delay(k) as usize, ev);
                }
            }
        }

        // 4. Zero accumulators for next step.
        for buf in &mut self.inputs {
            buf.fill(0.0);
        }

        self.step_count += 1;
        frame
    }

    /// Events currently in flight across all connections (diagnostics;
    /// should be preserved across checkpoints).
    pub fn in_flight(&self) -> usize {
        self.connections.iter().map(|c| c.queue.in_flight()).sum()
    }
}
