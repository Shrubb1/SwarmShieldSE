use snn_core::{Layer, LifNeuron, Network};
use snn_io::{from_bytes, to_bytes, Checkpoint};
use snn_learn::{apply_all, StdpLearner, StdpParams};

/// Build a small deterministic system: 3 LIF -> 3 LIF, mixed delays,
/// one STDP learner on the projection.
fn build() -> (Network, Vec<StdpLearner>) {
    let mut net = Network::new(1.0);
    let a = net.add_layer(Layer::lif("telemetry", 3, &LifNeuron::default_params()));
    let b = net.add_layer(Layer::lif("anomaly", 3, &LifNeuron::default_params()));
    let c = net.connect(
        a,
        b,
        &[
            (0, 0, 30.0, 0),
            (0, 1, 10.0, 2),
            (1, 1, 30.0, 1),
            (2, 2, 30.0, 0),
            (2, 0, 10.0, 3),
        ],
    );
    let learner = StdpLearner::for_connection(&net, c, StdpParams::default());
    (net, vec![learner])
}

fn run(net: &mut Network, learners: &mut [StdpLearner], steps: usize) -> Vec<Vec<Vec<u32>>> {
    (0..steps)
        .map(|_| {
            net.inject(0, &[20.0, 15.0, 18.0]);
            let f = net.step();
            apply_all(learners, &f, net);
            f.spikes
        })
        .collect()
}

/// The core memory guarantee: checkpoint mid-run, restore, continue —
/// the spike train must be identical to an uninterrupted run, including
/// learned weights and in-flight delayed spikes.
#[test]
fn checkpoint_resume_is_bit_identical() {
    // Uninterrupted reference run.
    let (mut ref_net, mut ref_l) = build();
    let reference = run(&mut ref_net, &mut ref_l, 100);
    let ref_weights: Vec<f32> = ref_net.connections[0].synapses.weights().to_vec();

    // Interrupted run: 50 steps, serialize, restore, 50 more.
    let (mut net, mut learners) = build();
    let mut interrupted = run(&mut net, &mut learners, 50);
    let bytes = to_bytes(&Checkpoint::capture(&net, &learners)).unwrap();
    let (mut net2, mut learners2) = from_bytes(&bytes).unwrap().restore().unwrap();
    assert_eq!(net2.step_count, 50);
    interrupted.extend(run(&mut net2, &mut learners2, 50));

    assert_eq!(interrupted, reference, "resume diverged from reference run");
    assert_eq!(
        net2.connections[0].synapses.weights(),
        ref_weights.as_slice(),
        "learned weights diverged"
    );
}

#[test]
fn checkpoint_preserves_in_flight_spikes() {
    let (mut net, mut learners) = build();
    // Drive until something is guaranteed in flight (delays up to 4 steps).
    let mut saw_flight = false;
    for _ in 0..30 {
        net.inject(0, &[20.0, 15.0, 18.0]);
        let f = net.step();
        apply_all(&mut learners, &f, &mut net);
        if net.in_flight() > 0 {
            saw_flight = true;
            let bytes = to_bytes(&Checkpoint::capture(&net, &learners)).unwrap();
            let (net2, _) = from_bytes(&bytes).unwrap().restore().unwrap();
            assert_eq!(net2.in_flight(), net.in_flight());
        }
    }
    assert!(saw_flight, "test never produced an in-flight spike");
}

#[test]
fn version_mismatch_is_rejected() {
    let (net, learners) = build();
    let mut ck = Checkpoint::capture(&net, &learners);
    ck.version = 999;
    let bytes = to_bytes(&ck).unwrap();
    let err = from_bytes(&bytes).unwrap().restore().unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn file_round_trip() {
    let (net, learners) = build();
    let path = std::env::temp_dir().join(format!("snn-ck-{}.bin", std::process::id()));
    snn_io::save(&Checkpoint::capture(&net, &learners), &path).unwrap();
    let ck = snn_io::load(&path).unwrap();
    let (net2, _) = ck.restore().unwrap();
    assert_eq!(net2.layers.len(), 2);
    assert_eq!(net2.connections[0].synapses.nnz(), 5);
    std::fs::remove_file(&path).ok();
}
