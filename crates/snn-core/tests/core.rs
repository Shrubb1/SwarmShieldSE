use snn_core::delay::{DelayQueue, SynEvent};
use snn_core::{IzhikevichNeuron, Layer, LifNeuron, Network, NeuronModel, SparseSynapses};

/// Constant current I=20 into the default LIF: v_inf = -65 + 20 = -45.
/// Discrete Euler with (dt/tau)=0.1 gives v_k = -45 - 20*0.9^k.
/// v_k >= -50 first at k=14. After a spike, 2 refractory steps, then the
/// same 14-step climb: spikes land at 14, 30, 46, ...
#[test]
fn lif_spike_timing_is_exact() {
    let mut n = LifNeuron::default_params();
    let mut steps = Vec::new();
    for s in 1..=48u32 {
        if n.step(20.0, 1.0) {
            steps.push(s);
        }
    }
    assert_eq!(steps, vec![14, 30, 46]);
}

#[test]
fn lif_refractory_blocks_integration() {
    let mut n = LifNeuron::default_params();
    for _ in 0..14 {
        n.step(20.0, 1.0); // spike on last call
    }
    // Two refractory steps: huge current cannot fire it.
    assert!(!n.step(1e6, 1.0));
    assert!(!n.step(1e6, 1.0));
}

#[test]
fn izhikevich_regular_spiking_fires() {
    let mut n = IzhikevichNeuron::regular_spiking();
    let count = (0..1000).filter(|_| n.step(10.0, 1.0)).count();
    // 1 s of sim at I=10 should produce a healthy regular-spiking train.
    assert!(count > 3, "expected a spike train, got {count}");
}

#[test]
fn csr_layout_and_lookup() {
    let edges = [
        (1, 0, 0.5, 0),
        (0, 2, 1.5, 3),
        (0, 0, 2.5, 1),
        (1, 2, 3.5, 0),
    ];
    let s = SparseSynapses::from_edges(2, 3, &edges);
    assert_eq!(s.nnz(), 4);
    // Sorted by (pre, post): pre0 -> {0:w2.5,d1}, {2:w1.5,d3}; pre1 -> {0,2}.
    assert_eq!(s.row_range(0).collect::<Vec<_>>(), vec![0, 1]);
    assert_eq!(s.row_range(1).collect::<Vec<_>>(), vec![2, 3]);
    assert_eq!(s.post_of(0), 0);
    assert_eq!(s.weight(0), 2.5);
    assert_eq!(s.delay(1), 3);
    assert_eq!(s.max_delay(), 3);
    // Transpose: post2 receives synapses 1 (from pre0) and 3 (from pre1).
    let incoming: Vec<(u32, usize)> = s
        .incoming_range(2)
        .map(|k| (s.incoming_pre(k), s.incoming_syn(k)))
        .collect();
    assert_eq!(incoming, vec![(0, 1), (1, 3)]);
}

#[test]
fn add_weight_clamps() {
    let s_edges = [(0u32, 0u32, 0.5f32, 0u16)];
    let mut s = SparseSynapses::from_edges(1, 1, &s_edges);
    s.add_weight(0, 10.0, 0.0, 1.0);
    assert_eq!(s.weight(0), 1.0);
    s.add_weight(0, -10.0, 0.0, 1.0);
    assert_eq!(s.weight(0), 0.0);
}

#[test]
fn to_csr_produces_correct_sprs_matrix() {
    let edges = [(0, 1, 2.0, 0), (2, 0, 3.0, 1), (2, 1, -1.0, 0)];
    let s = SparseSynapses::from_edges(3, 2, &edges);
    let m = s.to_csr();
    assert_eq!(m.shape(), (3, 2));
    assert_eq!(m.get(0, 1), Some(&2.0));
    assert_eq!(m.get(2, 0), Some(&3.0));
    assert_eq!(m.get(2, 1), Some(&-1.0));
    assert_eq!(m.get(0, 0), None);
}

#[test]
fn delay_queue_delivers_after_one_plus_d() {
    let mut q = DelayQueue::new(3);
    q.schedule(
        0,
        SynEvent {
            post: 9,
            current: 1.0,
        },
    );
    q.schedule(
        2,
        SynEvent {
            post: 8,
            current: 2.0,
        },
    );
    assert_eq!(q.in_flight(), 2);

    let d0 = q.take_due(); // step boundary 1
    assert_eq!(
        d0,
        vec![SynEvent {
            post: 9,
            current: 1.0
        }]
    );
    assert!(q.take_due().is_empty());
    let d2 = q.take_due();
    assert_eq!(
        d2,
        vec![SynEvent {
            post: 8,
            current: 2.0
        }]
    );
    assert_eq!(q.in_flight(), 0);
}

/// Two-layer feed-forward: drive layer 0 hard; a strong synapse (delay 0)
/// should make the postsynaptic neuron fire exactly one step later.
#[test]
fn network_propagates_spike_with_one_step_latency() {
    let mut net = Network::new(1.0);
    let l0 = net.add_layer(Layer::lif("in", 1, &LifNeuron::default_params()));
    let l1 = net.add_layer(Layer::lif("out", 1, &LifNeuron::default_params()));
    net.connect(l0, l1, &[(0, 0, 200.0, 0)]);

    let mut pre_spike_at = None;
    let mut post_spike_at = None;
    for step in 1..=20u64 {
        net.inject(l0, &[20.0]);
        let f = net.step();
        if pre_spike_at.is_none() && !f.layer(l0).is_empty() {
            pre_spike_at = Some(step);
        }
        if post_spike_at.is_none() && !f.layer(l1).is_empty() {
            post_spike_at = Some(step);
        }
    }
    assert_eq!(pre_spike_at, Some(14));
    assert_eq!(post_spike_at, Some(15));
}

/// Same construction, same inputs → identical frames, twice in a row.
#[test]
fn network_is_deterministic() {
    fn run() -> Vec<Vec<Vec<u32>>> {
        let mut net = Network::new(1.0);
        let a = net.add_layer(Layer::lif("a", 3, &LifNeuron::default_params()));
        let b = net.add_layer(Layer::lif("b", 3, &LifNeuron::default_params()));
        net.connect(a, b, &[(0, 0, 30.0, 0), (1, 1, 30.0, 2), (2, 2, 30.0, 1)]);
        (0..60)
            .map(|_| {
                net.inject(a, &[20.0, 15.0, 18.0]);
                net.step().spikes
            })
            .collect()
    }
    assert_eq!(run(), run());
}
