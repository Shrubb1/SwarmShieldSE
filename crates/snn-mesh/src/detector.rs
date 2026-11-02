//! The anomaly detector: telemetry samples in, `Detection` events out.
//!
//! Wiring: each metric owns two input neurons — `2i` (up channel) and
//! `2i+1` (down channel) — delta-modulated against a learned baseline.
//! Every input neuron projects to every detector neuron; STDP adapts the
//! projection online, so repeated anomaly signatures are learned and fire
//! the detector *faster* over time (the "routing adaptation" memory).
//!
//! `observe(sample)` is one telemetry tick: encode → inject → simulate
//! `steps_per_sample` timesteps → apply STDP → update the rolling score.
//! No RNG anywhere — the same stream always produces the same detections.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use snn_core::{Layer, LifNeuron, Network};
use snn_encode::DeltaModulator;
use snn_io::Checkpoint;
use snn_learn::{apply_all, StdpLearner, StdpParams};

/// One telemetry tick from the orchestrator/worker stream.
/// `values[i]` is metric `config.metrics[i]` at this tick.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TelemetrySample {
    /// Monotonic sequence number from the producer.
    pub seq: u64,
    /// Wall/logical timestamp of the sample (ms since epoch or tick).
    pub ts_ms: u64,
    /// Metric values, aligned to `DetectorConfig::metrics`.
    pub values: Vec<f32>,
}

/// What the detector concluded about one sample.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Detection {
    /// Echo of `TelemetrySample::seq`.
    pub seq: u64,
    /// Input-layer spikes this tick (delta events that fired).
    pub input_spikes: u32,
    /// Input spikes on "up" channels (increase over baseline).
    pub up_spikes: u32,
    /// Input spikes on "down" channels (decrease vs baseline). A purely
    /// down-driven anomaly is a regime drop-off, not an inbound threat —
    /// the firewall uses this to exempt recovery shifts from escalation.
    pub down_spikes: u32,
    /// Consecutive evals (including this one) with no up-channel activity.
    /// Covers refractory gaps and silent evals carrying detector echo:
    /// `>= 2` means the anomaly contains no recent inbound-volume signal.
    pub up_free_streak: u32,
    /// max |observed - reference| — drift vs the frozen anchor baseline.
    /// The adaptive encoder can absorb a slow walk; this can't.
    pub reference_drift: f32,
    /// Detector-layer spikes this tick.
    pub detector_spikes: u32,
    /// Rolling sum of detector spikes over the last `window` samples —
    /// the anomaly score the control plane consumes.
    pub score: u32,
    /// `score >= anomaly_threshold`.
    pub anomaly: bool,
    /// Largest `|value - baseline|` across metrics, pre-encode.
    pub max_deviation: f32,
    /// Baseline (learned "normal") for each metric after this sample.
    pub baselines: Vec<f32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetectorConfig {
    /// Metric names; index `i` maps to input channels `2i`/`2i+1`.
    pub metrics: Vec<String>,
    /// Delta threshold: a metric must move more than this from its
    /// baseline to emit a spike. Same for every metric — the encoder can
    /// be rebuilt with per-metric thresholds later without API change.
    pub delta_threshold: f32,
    /// Current injected on an encoder spike. ~200 fires the input neuron
    /// immediately; smaller values require coincidence.
    pub spike_current: f32,
    /// Initial input→detector synapse weight.
    pub initial_weight: f32,
    /// Detector-layer population size.
    pub detector_neurons: usize,
    /// Sim timesteps per telemetry sample. Step 0 receives the encoded
    /// input; remaining steps settle propagation (delays, refractory).
    pub steps_per_sample: usize,
    /// Rolling window length, in samples, for the anomaly score.
    pub window: usize,
    /// Detector spikes within `window` that flag an anomaly.
    pub anomaly_threshold: u32,
    /// STDP rule for the input→detector projection.
    pub stdp: StdpParams,
    /// Sim timestep (ms).
    pub dt: f32,
}

impl DetectorConfig {
    pub fn for_metrics(metrics: &[&str]) -> Self {
        Self {
            metrics: metrics.iter().map(|s| s.to_string()).collect(),
            ..Self::default()
        }
    }
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            metrics: Vec::new(),
            delta_threshold: 5.0,
            spike_current: 200.0,
            initial_weight: 80.0,
            detector_neurons: 8,
            steps_per_sample: 1,
            window: 20,
            anomaly_threshold: 2,
            stdp: StdpParams {
                w_min: 0.0,
                w_max: 200.0,
                ..Default::default()
            },
            dt: 1.0,
        }
    }
}

/// Aux slot name in [`Checkpoint::aux`] holding encoder state.
const AUX_ENCODER: &str = "encoder";
/// Aux slot name holding this detector's rolling score state.
const AUX_DETECTOR: &str = "detector";

/// Serializable detector bookkeeping (rolling window + sample counter +
/// up-spike recency for directional anomaly semantics).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct DetectorState {
    history: VecDeque<u32>,
    score: u32,
    samples: u64,
    /// Evals since the last up-channel spike. >=2 ⇒ no recent
    /// inbound-volume signal behind the current score.
    up_free_streak: u32,
    /// Per-metric rebound flags: a down-spike's return-to-baseline is
    /// the same event's second half — the next up-spike on that metric
    /// counts as down-direction, not new attack evidence.
    rebound: Vec<bool>,
    /// Frozen anchor baselines — the adaptive encoder absorbs slow
    /// walks, but `|observed - reference|` can't be absorbed.
    reference: Vec<f32>,
}

pub struct Detector {
    net: Network,
    learners: Vec<StdpLearner>,
    encoder: DeltaModulator,
    metrics: Vec<String>,
    steps_per_sample: usize,
    window: usize,
    anomaly_threshold: u32,
    state: DetectorState,
}

impl Detector {
    /// Build a fresh detector. `initial_baselines` should be current metric
    /// values (or known-good values); otherwise startup registers as one
    /// giant delta burst.
    pub fn new(config: DetectorConfig, initial_baselines: &[f32]) -> Self {
        assert_eq!(
            config.metrics.len(),
            initial_baselines.len(),
            "one baseline per metric"
        );
        let m = config.metrics.len();

        let mut net = Network::new(config.dt);
        let input = net.add_layer(Layer::lif(
            "telemetry-in",
            2 * m,
            &LifNeuron::default_params(),
        ));
        let det = net.add_layer(Layer::lif(
            "detector",
            config.detector_neurons,
            &LifNeuron::default_params(),
        ));

        // Dense input→detector, delay 0: every channel can excite every
        // detector neuron; STDP carves out which channels actually matter.
        let mut edges = Vec::with_capacity(2 * m * config.detector_neurons);
        for pre in 0..(2 * m) {
            for post in 0..config.detector_neurons {
                edges.push((pre as u32, post as u32, config.initial_weight, 0));
            }
        }
        let conn = net.connect(input, det, &edges);
        let learner = StdpLearner::for_connection(&net, conn, config.stdp.clone());

        Self {
            net,
            learners: vec![learner],
            encoder: DeltaModulator::new(
                initial_baselines,
                config.delta_threshold,
                config.spike_current,
            ),
            metrics: config.metrics,
            steps_per_sample: config.steps_per_sample.max(1),
            window: config.window.max(1),
            anomaly_threshold: config.anomaly_threshold,
            state: DetectorState {
                reference: initial_baselines.to_vec(),
                ..Default::default()
            },
        }
    }

    /// Feed one telemetry tick through the SNN.
    pub fn observe(&mut self, sample: &TelemetrySample) -> Detection {
        assert_eq!(
            sample.values.len(),
            self.metrics.len(),
            "sample must align with configured metrics"
        );

        // Deviation is measured against the pre-encode baseline — the
        // baseline ratchets during encode.
        let max_deviation = sample
            .values
            .iter()
            .zip(self.encoder.baselines())
            .map(|(v, b)| (v - b).abs())
            .fold(0.0f32, f32::max);

        // Drift vs the frozen anchor — the adaptive baseline can't
        // absorb this: slow walks stay visible forever.
        let reference_drift = sample
            .values
            .iter()
            .zip(self.state.reference.iter())
            .map(|(v, r)| (v - r).abs())
            .fold(0.0f32, f32::max);

        let frame = self.encoder.encode(&sample.values);

        // Channel layout: 2i = up_i, 2i+1 = down_i.
        let mut currents = vec![0.0f32; 2 * self.metrics.len()];
        for i in 0..self.metrics.len() {
            currents[2 * i] = frame.up[i];
            currents[2 * i + 1] = frame.down[i];
        }

        // Step 0 gets the encoded input; further steps settle.
        let mut input_spikes = 0u32;
        let mut up_spikes = 0u32;
        let mut down_spikes = 0u32;
        let mut detector_spikes = 0u32;
        for s in 0..self.steps_per_sample {
            if s == 0 {
                self.net.inject(0, &currents);
            }
            let f = self.net.step();
            apply_all(&mut self.learners, &f, &mut self.net);
            if s == 0 {
                input_spikes = f.layer(0).len() as u32;
                // Channel layout: even index = up, odd = down. An
                // up-spike on a metric with a pending rebound flag is
                // recovery swing, not new attack evidence.
                if self.state.rebound.len() < self.metrics.len() {
                    self.state.rebound.resize(self.metrics.len(), false);
                }
                for &i in f.layer(0) {
                    let metric = (i / 2) as usize;
                    if i % 2 == 0 {
                        if self.state.rebound[metric] {
                            self.state.rebound[metric] = false;
                            down_spikes += 1;
                        } else {
                            up_spikes += 1;
                        }
                    } else {
                        down_spikes += 1;
                        self.state.rebound[metric] = true;
                    }
                }
            }
            detector_spikes += f.layer(1).len() as u32;
        }

        // Rolling score window + up-spike recency. Input spikes count
        // too: a lone channel firing can't always drive a detector
        // neuron (2+ concurrent channels needed), yet a sustained
        // single-channel breach IS anomaly evidence — persistence is
        // what separates it from one-off noise.
        let contribution = detector_spikes + input_spikes;
        self.state.history.push_back(contribution);
        self.state.score += contribution;
        if self.state.history.len() > self.window {
            self.state.score -= self.state.history.pop_front().unwrap_or(0);
        }
        self.state.up_free_streak = if up_spikes > 0 {
            0
        } else {
            self.state.up_free_streak + 1
        };
        self.state.samples += 1;

        Detection {
            seq: sample.seq,
            input_spikes,
            up_spikes,
            down_spikes,
            up_free_streak: self.state.up_free_streak,
            reference_drift,
            detector_spikes,
            score: self.state.score,
            anomaly: self.state.score >= self.anomaly_threshold,
            max_deviation,
            baselines: self.encoder.baselines().to_vec(),
        }
    }

    pub fn samples_observed(&self) -> u64 {
        self.state.samples
    }

    /// Per-metric delta threshold override — e.g. hair-trigger
    /// `new_src_rate` while `req_rate` stays calm.
    pub fn set_metric_threshold(&mut self, metric: usize, v: f32) {
        self.encoder.set_threshold(metric, v);
    }

    /// Everything needed for bit-identical resume: SNN + STDP traces +
    /// encoder baselines + rolling score state.
    pub fn checkpoint(&self) -> std::io::Result<Checkpoint> {
        let mut ck = Checkpoint::capture(&self.net, &self.learners);
        ck.set_aux(AUX_ENCODER, &self.encoder)?;
        ck.set_aux(AUX_DETECTOR, &self.state)?;
        Ok(ck)
    }

    /// Rebuild a detector from a checkpoint produced by [`Self::checkpoint`].
    /// `config` supplies topology/policy (must match the checkpointed one).
    pub fn from_checkpoint(config: DetectorConfig, ck: Checkpoint) -> std::io::Result<Self> {
        // Extract aux slots before restore() consumes the checkpoint.
        let encoder = ck.get_aux::<DeltaModulator>(AUX_ENCODER)?;
        let state = ck.get_aux::<DetectorState>(AUX_DETECTOR)?;

        // Rebuild a shell for config-derived fields, then overwrite state.
        let baselines = vec![0.0f32; config.metrics.len()];
        let mut det = Self::new(config, &baselines);
        let (net, learners) = ck.restore()?;
        det.net = net;
        det.learners = learners;
        if let Some(enc) = encoder {
            det.encoder = enc;
        }
        if let Some(st) = state {
            det.state = st;
        }
        Ok(det)
    }

    /// Read-only view for diagnostics/Wasm bridge.
    pub fn network(&self) -> &Network {
        &self.net
    }
}
