//! `snn-core` — hybrid clock-driven spiking neural network simulation.
//!
//! Fixed-`dt` neuron updates (rayon-parallel), event-driven spike delivery
//! through CSR synapses with per-synapse axonal delays. All state is
//! `serde`-serializable for checkpointing.

pub mod delay;
pub mod network;
pub mod neuron;
pub mod synapse;

pub use delay::{DelayQueue, SynEvent};
pub use network::{Connection, Layer, Network, SpikeFrame};
pub use neuron::{IzhikevichNeuron, LifNeuron, Neuron, NeuronModel};
pub use synapse::SparseSynapses;
