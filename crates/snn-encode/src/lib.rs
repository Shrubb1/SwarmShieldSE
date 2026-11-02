//! Telemetry → spike-train encoders.
//!
//! Two converter families for streaming metrics (proxy latency, error
//! rates, worker health):
//!
//! - [`PoissonEncoder`]: rate coding — a normalized signal level becomes a
//!   Bernoulli spike probability per `dt`. Seeded, so replays are identical.
//! - [`DeltaModulator`]: temporal coding — spikes only on *change*, the
//!   natural fit for anomaly detection: a quiet metric produces a silent
//!   channel, a regime shift produces a burst.
//!
//! Both are `serde`-serializable, so encoder state (Poisson RNG position,
//! delta baselines) is checkpointed along with the network — required for
//! bit-identical resume.

use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};

/// Bernoulli-process rate encoder: channel `i` fires with probability
/// `rate_hz[i] * dt / 1000` each step, emitting `current` on a spike.
///
/// Not serialized in checkpoints (`StdRng` has no serde impl): recreate
/// with the same `seed` to continue an identical spike sequence from its
/// start. For mid-run bit-identical resume use [`DeltaModulator`], whose
/// state is plain data.
#[derive(Clone, Debug)]
pub struct PoissonEncoder {
    rates_hz: Vec<f32>,
    current: f32,
    seed: u64,
    rng: StdRng,
}

impl PoissonEncoder {
    /// `seed` pins the spike sequence — same seed + same rate updates =
    /// same spike train, across processes and reboots.
    pub fn new(rates_hz: Vec<f32>, current: f32, seed: u64) -> Self {
        Self {
            rates_hz,
            current,
            seed,
            rng: StdRng::seed_from_u64(seed),
        }
    }

    /// Restart the stream at `seed` (or the original seed if unchanged).
    pub fn reseed(&mut self, seed: u64) {
        self.seed = seed;
        self.rng = StdRng::seed_from_u64(seed);
    }

    pub fn channels(&self) -> usize {
        self.rates_hz.len()
    }

    /// Re-target channels from normalized telemetry in `[0, 1]`:
    /// `rate_i = clamp(x_i) * max_hz`.
    pub fn set_rates_normalized(&mut self, normalized: &[f32], max_hz: f32) {
        assert_eq!(normalized.len(), self.rates_hz.len());
        for (r, &x) in self.rates_hz.iter_mut().zip(normalized) {
            *r = x.clamp(0.0, 1.0) * max_hz;
        }
    }

    /// Raw Hz version for callers that do their own scaling.
    pub fn set_rates_hz(&mut self, rates_hz: &[f32]) {
        assert_eq!(rates_hz.len(), self.rates_hz.len());
        self.rates_hz.copy_from_slice(rates_hz);
    }

    /// Produce one step of input currents (feed to `Network::inject`).
    pub fn encode(&mut self, dt: f32) -> Vec<f32> {
        self.rates_hz
            .iter()
            .map(|&r| {
                let p = (r * dt / 1000.0).clamp(0.0, 1.0);
                if self.rng.random::<f32>() < p {
                    self.current
                } else {
                    0.0
                }
            })
            .collect()
    }
}

/// Delta modulation: emits an "up" spike when a channel rises more than
/// `threshold` above its baseline, a "down" spike when it falls more than
/// `threshold` below. The baseline ratchets one threshold per emitted
/// spike, so sustained ramps produce a spike *rate* proportional to the
/// slope — and step changes produce a burst proportional to their size.
///
/// Typically wired as two input channels per metric (up/down), which gives
/// the SNN a signed view of metric motion.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeltaModulator {
    baseline: Vec<f32>,
    threshold: f32,
    current: f32,
    /// Per-channel threshold overrides; 0 or missing = use `threshold`.
    /// E.g. hair-trigger `new_src_rate` while `req_rate` stays calm.
    per_metric: Vec<f32>,
}

/// One step of delta-modulated output.
#[derive(Clone, Debug, Default)]
pub struct DeltaFrame {
    /// Currents for the "increase" channel.
    pub up: Vec<f32>,
    /// Currents for the "decrease" channel.
    pub down: Vec<f32>,
}

impl DeltaModulator {
    /// Baselines start at `initial` — pass current metric values at
    /// construction so startup doesn't register as one giant delta.
    pub fn new(initial: &[f32], threshold: f32, current: f32) -> Self {
        Self {
            baseline: initial.to_vec(),
            threshold,
            current,
            per_metric: Vec::new(),
        }
    }

    /// Override the delta threshold for one metric channel.
    pub fn set_threshold(&mut self, metric: usize, v: f32) {
        if metric >= self.per_metric.len() {
            self.per_metric.resize(self.baseline.len(), 0.0);
        }
        self.per_metric[metric] = v;
    }

    #[inline]
    fn thr(&self, i: usize) -> f32 {
        self.per_metric
            .get(i)
            .copied()
            .filter(|&v| v > 0.0)
            .unwrap_or(self.threshold)
    }

    pub fn channels(&self) -> usize {
        self.baseline.len()
    }

    /// Reseed baselines (e.g. after a known-good deploy resets the regime).
    pub fn reset_baseline(&mut self, values: &[f32]) {
        assert_eq!(values.len(), self.baseline.len());
        self.baseline.copy_from_slice(values);
    }

    /// Current learned baseline per channel — what "normal" looks like.
    pub fn baselines(&self) -> &[f32] {
        &self.baseline
    }

    pub fn encode(&mut self, values: &[f32]) -> DeltaFrame {
        assert_eq!(values.len(), self.baseline.len());
        let mut frame = DeltaFrame {
            up: vec![0.0; values.len()],
            down: vec![0.0; values.len()],
        };
        for (i, &v) in values.iter().enumerate() {
            let diff = v - self.baseline[i];
            let thr = self.thr(i);
            if diff > thr {
                frame.up[i] = self.current;
                self.baseline[i] += thr;
            } else if diff < -thr {
                frame.down[i] = self.current;
                self.baseline[i] -= thr;
            }
        }
        frame
    }
}
