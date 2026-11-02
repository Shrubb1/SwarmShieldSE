//! Neuron dynamics.
//!
//! All models expose one operation: integrate a synaptic input current for one
//! fixed timestep `dt` (milliseconds) and report whether a spike was emitted.
//! State is kept in plain fields so every model is `serde`-serializable —
//! membrane potential and refractory counters are part of the network's
//! persistent memory, not scratch state.

use serde::{Deserialize, Serialize};

/// Per-timestep neuron dynamics. `step` returns `true` on spike emission.
pub trait NeuronModel {
    /// Integrate one timestep of `dt` ms with synaptic input current `i_syn`.
    fn step(&mut self, i_syn: f32, dt: f32) -> bool;
    /// Return to resting state (does not clear learned structure, only dynamics).
    fn reset(&mut self);
    /// Current membrane potential.
    fn membrane(&self) -> f32;
}

/// Leaky integrate-and-fire neuron.
///
/// `dv/dt = (v_rest - v + r_in * i_syn) / tau_m`, Euler-integrated.
/// On `v >= v_th`: emit spike, reset to `v_reset`, hold for
/// `refractory_steps` timesteps.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LifNeuron {
    pub v: f32,
    pub tau_m: f32,
    pub v_rest: f32,
    pub v_th: f32,
    pub v_reset: f32,
    pub r_in: f32,
    pub refractory_steps: u32,
    ref_count: u32,
}

impl LifNeuron {
    pub fn new(
        tau_m: f32,
        v_rest: f32,
        v_th: f32,
        v_reset: f32,
        r_in: f32,
        refractory_steps: u32,
    ) -> Self {
        Self {
            v: v_rest,
            tau_m,
            v_rest,
            v_th,
            v_reset,
            r_in,
            refractory_steps,
            ref_count: 0,
        }
    }

    /// Reasonable defaults: 10 ms membrane, -65 mV rest, -50 mV threshold.
    pub fn default_params() -> Self {
        Self::new(10.0, -65.0, -50.0, -65.0, 1.0, 2)
    }
}

impl NeuronModel for LifNeuron {
    fn step(&mut self, i_syn: f32, dt: f32) -> bool {
        if self.ref_count > 0 {
            self.ref_count -= 1;
            self.v = self.v_reset;
            return false;
        }
        self.v += (dt / self.tau_m) * (self.v_rest - self.v + self.r_in * i_syn);
        if self.v >= self.v_th {
            self.v = self.v_reset;
            self.ref_count = self.refractory_steps;
            return true;
        }
        false
    }

    fn reset(&mut self) {
        self.v = self.v_rest;
        self.ref_count = 0;
    }

    fn membrane(&self) -> f32 {
        self.v
    }
}

/// Izhikevich neuron — two-dimensional model capable of bursting, chattering,
/// and adaptation depending on `(a, b, c, d)`.
///
/// `v' = 0.04v² + 5v + 140 - u + i`
/// `u' = a(bv - u)`
/// spike at `v >= v_peak` → `v = c`, `u += d`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IzhikevichNeuron {
    pub v: f32,
    pub u: f32,
    pub a: f32,
    pub b: f32,
    pub c: f32,
    pub d: f32,
    pub v_peak: f32,
}

impl IzhikevichNeuron {
    pub fn new(a: f32, b: f32, c: f32, d: f32) -> Self {
        let v = -65.0;
        Self {
            v,
            u: b * v,
            a,
            b,
            c,
            d,
            v_peak: 30.0,
        }
    }

    /// Regular spiking (excitatory cortical-like).
    pub fn regular_spiking() -> Self {
        Self::new(0.02, 0.2, -65.0, 8.0)
    }

    /// Intrinsically bursting.
    pub fn bursting() -> Self {
        Self::new(0.02, 0.2, -55.0, 4.0)
    }

    /// Fast spiking (inhibitory interneuron-like).
    pub fn fast_spiking() -> Self {
        Self::new(0.1, 0.2, -65.0, 2.0)
    }
}

impl NeuronModel for IzhikevichNeuron {
    fn step(&mut self, i_syn: f32, dt: f32) -> bool {
        // Two half-steps keep Euler stable at dt = 1 ms near the spike upstroke.
        for _ in 0..2 {
            self.v += 0.5 * dt * (0.04 * self.v * self.v + 5.0 * self.v + 140.0 - self.u + i_syn);
        }
        self.u += dt * self.a * (self.b * self.v - self.u);
        if self.v >= self.v_peak {
            self.v = self.c;
            self.u += self.d;
            return true;
        }
        false
    }

    fn reset(&mut self) {
        self.v = -65.0;
        self.u = self.b * self.v;
    }

    fn membrane(&self) -> f32 {
        self.v
    }
}

/// Concrete neuron storage. Layers are homogeneous in practice but the enum
/// keeps `Layer` serializable and dispatch static (no trait objects, so
/// checkpoints stay plain data).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Neuron {
    Lif(LifNeuron),
    Izhikevich(IzhikevichNeuron),
}

impl NeuronModel for Neuron {
    fn step(&mut self, i_syn: f32, dt: f32) -> bool {
        match self {
            Neuron::Lif(n) => n.step(i_syn, dt),
            Neuron::Izhikevich(n) => n.step(i_syn, dt),
        }
    }

    fn reset(&mut self) {
        match self {
            Neuron::Lif(n) => n.reset(),
            Neuron::Izhikevich(n) => n.reset(),
        }
    }

    fn membrane(&self) -> f32 {
        match self {
            Neuron::Lif(n) => n.membrane(),
            Neuron::Izhikevich(n) => n.membrane(),
        }
    }
}
