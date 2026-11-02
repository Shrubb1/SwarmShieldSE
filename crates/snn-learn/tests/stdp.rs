use snn_core::{SparseSynapses, SpikeFrame};
use snn_learn::{StdpLearner, StdpParams};

fn syn() -> SparseSynapses {
    SparseSynapses::from_edges(1, 1, &[(0, 0, 0.5, 0)])
}

fn frame(pre: &[u32], post: &[u32]) -> SpikeFrame {
    SpikeFrame {
        spikes: vec![pre.to_vec(), post.to_vec()],
    }
}

fn learner() -> StdpLearner {
    StdpLearner::new(0, 0, 1, 1, 1, StdpParams::default())
}

#[test]
fn causal_pairing_potentiates() {
    let mut s = syn();
    let mut l = learner();
    // Pre at t, post 5 steps later: classic LTP window.
    l.apply(1.0, &frame(&[0], &[]), &mut s);
    for _ in 0..4 {
        l.apply(1.0, &frame(&[], &[]), &mut s);
    }
    l.apply(1.0, &frame(&[], &[0]), &mut s);
    // w += a_plus * exp(-5/tau_plus) ≈ 0.01 * 0.7788 ≈ 0.5078
    assert!(s.weight(0) > 0.5, "w={} should have grown", s.weight(0));
    assert!(s.weight(0) < 0.52, "w={} grew too much", s.weight(0));
}

#[test]
fn anticausal_pairing_depresses() {
    let mut s = syn();
    let mut l = learner();
    // Post first, pre 5 steps later: LTD.
    l.apply(1.0, &frame(&[], &[0]), &mut s);
    for _ in 0..4 {
        l.apply(1.0, &frame(&[], &[]), &mut s);
    }
    l.apply(1.0, &frame(&[0], &[]), &mut s);
    assert!(s.weight(0) < 0.5, "w={} should have shrunk", s.weight(0));
}

#[test]
fn weights_stay_within_bounds() {
    let mut s = syn();
    let mut l = learner();
    // Hammer LTP: interleave pre/post spikes every step.
    for _ in 0..2000 {
        l.apply(1.0, &frame(&[0], &[0]), &mut s);
    }
    assert!(s.weight(0) <= 1.0);
    // And LTD to the floor.
    let mut l2 = StdpLearner::new(
        0,
        0,
        1,
        1,
        1,
        StdpParams {
            a_plus: 0.0,
            a_minus: 1.0,
            ..Default::default()
        },
    );
    l2.apply(1.0, &frame(&[], &[0]), &mut s); // arm post trace
    for _ in 0..50 {
        l2.apply(1.0, &frame(&[0], &[]), &mut s);
    }
    assert!(s.weight(0) >= 0.0);
}

#[test]
fn traces_decay_and_bump() {
    let mut s = syn();
    let mut l = learner();
    l.apply(1.0, &frame(&[0], &[]), &mut s);
    assert_eq!(l.pre_traces()[0], 1.0);
    l.apply(1.0, &frame(&[], &[]), &mut s);
    let expected = (-1.0f32 / 20.0).exp();
    assert!((l.pre_traces()[0] - expected).abs() < 1e-6);
}
