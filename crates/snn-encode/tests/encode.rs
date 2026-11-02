use snn_encode::{DeltaModulator, PoissonEncoder};

#[test]
fn poisson_is_seed_deterministic() {
    let mut a = PoissonEncoder::new(vec![50.0; 8], 5.0, 42);
    let mut b = PoissonEncoder::new(vec![50.0; 8], 5.0, 42);
    for _ in 0..100 {
        assert_eq!(a.encode(1.0), b.encode(1.0));
    }
}

#[test]
fn poisson_respects_rate_bounds() {
    let mut silent = PoissonEncoder::new(vec![0.0; 4], 5.0, 1);
    let mut saturated = PoissonEncoder::new(vec![100_000.0; 4], 5.0, 1);
    for _ in 0..50 {
        assert_eq!(silent.encode(1.0), vec![0.0; 4]);
        assert_eq!(saturated.encode(1.0), vec![5.0; 4]);
    }
}

#[test]
fn poisson_normalized_rates() {
    let mut e = PoissonEncoder::new(vec![0.0; 3], 1.0, 7);
    e.set_rates_normalized(&[0.5, 1.5, -0.5], 200.0);
    // Clamped: 100 Hz, 200 Hz, 0 Hz.
    let mut c = PoissonEncoder::new(vec![0.0; 3], 1.0, 7);
    c.set_rates_hz(&[100.0, 200.0, 0.0]);
    assert_eq!(e.encode(1.0), c.encode(1.0));
}

#[test]
fn delta_modulator_spikes_on_change() {
    let mut d = DeltaModulator::new(&[0.0, 0.0], 0.25, 4.0);
    // Flat → silent.
    let f = d.encode(&[0.0, 0.0]);
    assert_eq!(f.up, vec![0.0; 2]);
    assert_eq!(f.down, vec![0.0; 2]);
    // +0.3 on ch0 → up spike; -0.3 on ch1 → down spike.
    let f = d.encode(&[0.3, -0.3]);
    assert_eq!(f.up[0], 4.0);
    assert_eq!(f.down[0], 0.0);
    assert_eq!(f.up[1], 0.0);
    assert_eq!(f.down[1], 4.0);
    // Baseline ratcheted: another +0.3 is only +0.05 over the new baseline.
    let f = d.encode(&[0.3, -0.3]);
    assert_eq!(f.up[0], 0.0);
}

#[test]
fn delta_modulator_ramp_produces_rate() {
    let mut d = DeltaModulator::new(&[0.0], 0.5, 1.0);
    // Steady +1.0/step ramp → exactly one up-spike per step.
    for i in 1..=10 {
        let f = d.encode(&[i as f32]);
        assert_eq!(f.up[0], 1.0, "step {i}");
    }
}
