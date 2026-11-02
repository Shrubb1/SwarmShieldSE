//! Sparse synaptic connectivity.
//!
//! Weights live in a hand-rolled CSR layout rather than inside `sprs`'s matrix
//! type for two reasons: STDP needs in-place weight mutation by synapse index
//! (sprs views make that awkward), and each synapse carries an aligned axonal
//! delay that has no place in a pure matrix. `to_csr` still produces a
//! `sprs::CsMat` for matvec-style propagation or external tooling.
//!
//! A CSC transpose index (`t_indptr`/`t_syn`/`t_pre`) is kept alongside the CSR
//! so post-before-pre STDP lookups are O(in-degree), not O(nnz).

use serde::{Deserialize, Serialize};
use std::ops::Range;

/// Sparse directed synapses in CSR form, with a CSC transpose index.
///
/// `delay` is measured in simulation timesteps *beyond* the mandatory
/// one-step propagation latency: `delay == 0` delivers the postsynaptic
/// current on the timestep after the presynaptic spike.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SparseSynapses {
    pre_size: usize,
    post_size: usize,
    // CSR: row = presynaptic neuron.
    indptr: Vec<usize>,
    post: Vec<u32>,
    weight: Vec<f32>,
    delay: Vec<u16>,
    // CSC transpose: maps postsynaptic neuron -> synapse indices.
    t_indptr: Vec<usize>,
    t_pre: Vec<u32>,
    t_syn: Vec<u32>,
    max_delay: u16,
}

impl SparseSynapses {
    /// Build from `(pre, post, weight, delay)` edges. Edges are sorted by
    /// `(pre, post)` so the layout — and everything derived from it — is
    /// deterministic regardless of input order.
    pub fn from_edges(pre_size: usize, post_size: usize, edges: &[(u32, u32, f32, u16)]) -> Self {
        let mut e = edges.to_vec();
        e.sort_by_key(|&(p, q, _, _)| (p, q));

        let mut indptr = vec![0usize; pre_size + 1];
        let mut t_indptr = vec![0usize; post_size + 1];
        for &(p, q, _, _) in &e {
            indptr[p as usize + 1] += 1;
            t_indptr[q as usize + 1] += 1;
        }
        for i in 0..pre_size {
            indptr[i + 1] += indptr[i];
        }
        for i in 0..post_size {
            t_indptr[i + 1] += t_indptr[i];
        }

        let post: Vec<u32> = e.iter().map(|x| x.1).collect();
        let weight: Vec<f32> = e.iter().map(|x| x.2).collect();
        let delay: Vec<u16> = e.iter().map(|x| x.3).collect();
        let max_delay = delay.iter().copied().max().unwrap_or(0);

        // Transpose: stable sort of synapse indices by postsynaptic target.
        let mut order: Vec<u32> = (0..e.len() as u32).collect();
        order.sort_by_key(|&k| post[k as usize]);
        let t_syn = order;
        let t_pre: Vec<u32> = t_syn.iter().map(|&k| e[k as usize].0).collect();

        Self {
            pre_size,
            post_size,
            indptr,
            post,
            weight,
            delay,
            t_indptr,
            t_pre,
            t_syn,
            max_delay,
        }
    }

    pub fn pre_size(&self) -> usize {
        self.pre_size
    }

    pub fn post_size(&self) -> usize {
        self.post_size
    }

    pub fn nnz(&self) -> usize {
        self.weight.len()
    }

    pub fn max_delay(&self) -> u16 {
        self.max_delay
    }

    /// Synapse-index range of `pre`'s outgoing row.
    pub fn row_range(&self, pre: usize) -> Range<usize> {
        self.indptr[pre]..self.indptr[pre + 1]
    }

    /// Postsynaptic target of synapse `k`.
    pub fn post_of(&self, k: usize) -> u32 {
        self.post[k]
    }

    /// Range into the transpose index listing synapses arriving at `post`.
    pub fn incoming_range(&self, post: usize) -> Range<usize> {
        self.t_indptr[post]..self.t_indptr[post + 1]
    }

    /// Presynaptic source of the k-th incoming synapse entry.
    pub fn incoming_pre(&self, k: usize) -> u32 {
        self.t_pre[k]
    }

    /// Synapse index of the k-th incoming synapse entry.
    pub fn incoming_syn(&self, k: usize) -> usize {
        self.t_syn[k] as usize
    }

    pub fn weight(&self, k: usize) -> f32 {
        self.weight[k]
    }

    pub fn delay(&self, k: usize) -> u16 {
        self.delay[k]
    }

    pub fn weights(&self) -> &[f32] {
        &self.weight
    }

    /// `w += delta`, clamped to `[w_min, w_max]`. Single entry point for
    /// plasticity so bounds enforcement can't be bypassed.
    pub fn add_weight(&mut self, k: usize, delta: f32, w_min: f32, w_max: f32) {
        self.weight[k] = (self.weight[k] + delta).clamp(w_min, w_max);
    }

    /// Dense/CSR view as a `sprs` matrix for matvec propagation or analysis.
    pub fn to_csr(&self) -> sprs::CsMat<f32> {
        let mut t = sprs::TriMat::new((self.pre_size, self.post_size));
        for pre in 0..self.pre_size {
            for k in self.row_range(pre) {
                t.add_triplet(pre, self.post[k] as usize, self.weight[k]);
            }
        }
        t.to_csr()
    }
}
