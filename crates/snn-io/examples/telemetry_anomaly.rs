//! End-to-end Phase 1 demo: a latency metric is delta-encoded into
//! up/down spike channels, driven through an STDP-learning SNN, then
//! checkpointed and resumed mid-stream with bit-identical output.
//!
//! Phase 2 replaces `synthetic_latency` with the mesh telemetry stream and
//! `to_bytes` with a Postgres `bytea` write — the SNN side doesn't change.
//!
//! Run: `cargo run -p snn-io --example telemetry_anomaly`

use snn_core::{Layer, LifNeuron, Network};
use snn_encode::DeltaModulator;
use snn_io::{from_bytes, to_bytes, Checkpoint};
use snn_learn::{apply_all, StdpLearner, StdpParams};

/// Fake p99-latency stream (ms): flat 50, a slow ramp (normal drift),
/// then a step to 200 (anomaly), then recovery.
fn synthetic_latency(t: usize) -> f32 {
    match t {
        0..=199 => 50.0,
        200..=399 => 50.0 + 0.05 * (t - 200) as f32,
        400..=599 => 200.0,
        _ => 50.0,
    }
}

fn build() -> (Network, Vec<StdpLearner>, DeltaModulator) {
    let mut net = Network::new(1.0);
    // Two input channels per metric: [up, down].
    let input = net.add_layer(Layer::lif("metric", 2, &LifNeuron::default_params()));
    let detector = net.add_layer(Layer::lif("detector", 4, &LifNeuron::default_params()));
    let conn = net.connect(
        input,
        detector,
        &[
            (0, 0, 150.0, 0),
            (0, 1, 100.0, 0),
            (0, 2, 60.0, 1),
            (1, 1, 100.0, 0),
            (1, 3, 150.0, 0),
        ],
    );
    let params = StdpParams {
        w_min: 0.0,
        w_max: 200.0,
        ..Default::default()
    };
    let learner = StdpLearner::for_connection(&net, conn, params);
    // Threshold 5 ms: only deviations worth caring about spike.
    // Current 200: a single delta-spike fires the input channel same-step.
    let encoder = DeltaModulator::new(&[synthetic_latency(0)], 5.0, 200.0);
    (net, vec![learner], encoder)
}

fn run(
    net: &mut Network,
    learners: &mut [StdpLearner],
    enc: &mut DeltaModulator,
    from: usize,
    to: usize,
) {
    for t in from..to {
        let frame = enc.encode(&[synthetic_latency(t)]);
        // One metric → two input channels: [up, down].
        net.inject(0, &[frame.up[0], frame.down[0]]);
        let spikes = net.step();
        apply_all(learners, &spikes, net);
        let in_fired = spikes.layer(0).len();
        let det_fired = spikes.layer(1).len();
        if in_fired > 0 || det_fired > 0 {
            println!(
                "t={t:>4}  metric={:>6.1}  input={in_fired}  detector={det_fired}",
                synthetic_latency(t)
            );
        }
    }
}

fn main() {
    let (mut net, mut learners, mut enc) = build();

    println!("--- first half (baseline + drift) ---");
    run(&mut net, &mut learners, &mut enc, 0, 400);

    let bytes = to_bytes(&Checkpoint::capture(&net, &learners)).unwrap();
    println!(
        "--- checkpointed {} bytes; simulating reboot ---",
        bytes.len()
    );

    let (mut net, mut learners) = from_bytes(&bytes).unwrap().restore().unwrap();
    println!("--- second half (anomaly at t=400) ---");
    run(&mut net, &mut learners, &mut enc, 400, 800);

    println!("final weights: {:?}", net.connections[0].synapses.weights());
}
