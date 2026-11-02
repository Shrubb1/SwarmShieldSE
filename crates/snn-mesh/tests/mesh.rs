use std::sync::mpsc;
use std::thread;

use snn_mesh::{
    run_worker, Agent, Detection, Detector, DetectorConfig, MemoryStore, TelemetrySample,
};

fn config() -> DetectorConfig {
    DetectorConfig {
        window: 10,
        anomaly_threshold: 1,
        ..DetectorConfig::for_metrics(&["latency_ms"])
    }
}

fn sample(seq: u64, values: &[f32]) -> TelemetrySample {
    TelemetrySample {
        seq,
        ts_ms: seq * 1000,
        values: values.to_vec(),
    }
}

#[test]
fn flat_stream_stays_silent() {
    let mut det = Detector::new(config(), &[50.0]);
    for seq in 0..200 {
        let d = det.observe(&sample(seq, &[50.0]));
        assert!(!d.anomaly);
        assert_eq!(d.input_spikes, 0);
        assert_eq!(d.score, 0);
    }
}

#[test]
fn step_change_is_flagged_and_remembered() {
    let mut det = Detector::new(config(), &[50.0]);
    let mut flagged = 0;
    for seq in 0..100u64 {
        let v = if seq >= 50 { 200.0 } else { 50.0 };
        if det.observe(&sample(seq, &[v])).anomaly {
            flagged += 1;
        }
    }
    assert!(flagged > 0, "regime shift produced no anomaly");
    // Baseline learned the new regime: it ratchets until the residual is
    // within one delta threshold (5.0), then stops.
    let last = det.observe(&sample(100, &[200.0]));
    assert!((last.baselines[0] - 200.0).abs() <= 5.0);
    // And is silent once learned — the baseline IS the memory.
    assert_eq!(last.input_spikes, 0);
}

#[test]
fn same_stream_same_detections() {
    let stream: Vec<f32> = (0..300)
        .map(|t| if (150..200).contains(&t) { 300.0 } else { 50.0 })
        .collect();
    let run = || {
        let mut det = Detector::new(config(), &[50.0]);
        stream
            .iter()
            .enumerate()
            .map(|(i, &v)| det.observe(&sample(i as u64, &[v])))
            .collect::<Vec<Detection>>()
    };
    assert_eq!(run(), run());
}

#[test]
fn agent_resume_continues_identically() {
    let store_a = MemoryStore::new();
    let stream: Vec<f32> = (0..80)
        .map(|t| if t >= 60 { 120.0 } else { 50.0 })
        .collect();

    // Reference: uninterrupted run.
    let mut ref_agent = Agent::open(MemoryStore::new(), config(), &[50.0]).unwrap();
    ref_agent.checkpoint_every = 10;
    let reference: Vec<Detection> = stream
        .iter()
        .enumerate()
        .map(|(i, &v)| ref_agent.observe(&sample(i as u64, &[v])).unwrap())
        .collect();

    // Interrupted: 40 samples, drop agent, reopen on same store, continue.
    let mut interrupted = Vec::new();
    {
        let mut agent = Agent::open(&store_a, config(), &[50.0]).unwrap();
        agent.checkpoint_every = 10;
        for (i, &v) in stream.iter().enumerate().take(40) {
            interrupted.push(agent.observe(&sample(i as u64, &[v])).unwrap());
        }
        agent.flush().unwrap();
    }
    {
        let mut agent = Agent::open(&store_a, config(), &[50.0]).unwrap();
        agent.checkpoint_every = 10;
        for (i, &v) in stream.iter().enumerate().skip(40) {
            interrupted.push(agent.observe(&sample(i as u64, &[v])).unwrap());
        }
    }

    assert_eq!(interrupted.len(), reference.len());
    for (a, b) in interrupted.iter().zip(&reference) {
        assert_eq!(
            (a.input_spikes, a.detector_spikes, a.score, a.anomaly),
            (b.input_spikes, b.detector_spikes, b.score, b.anomaly),
            "diverged at seq {}",
            a.seq
        );
    }
}

#[test]
fn worker_threads_samples_in_detections_out() {
    let (tx_in, rx_in) = mpsc::channel::<TelemetrySample>();
    let (tx_out, rx_out) = mpsc::channel::<Detection>();
    let mut agent = Agent::open(MemoryStore::new(), config(), &[50.0]).unwrap();

    let handle = thread::spawn(move || run_worker(&mut agent, &rx_in, &tx_out).unwrap());

    for seq in 0..50u64 {
        let v = if seq >= 25 { 300.0 } else { 50.0 };
        tx_in.send(sample(seq, &[v])).unwrap();
    }
    drop(tx_in); // producer shutdown → worker flushes + exits

    let processed = handle.join().unwrap();
    assert_eq!(processed, 50);
    let detections: Vec<Detection> = rx_out.try_iter().collect();
    assert_eq!(detections.len(), 50);
    assert!(detections.iter().any(|d| d.anomaly));
}

#[test]
fn file_store_round_trip() {
    use snn_mesh::FileStore;
    let path = std::env::temp_dir().join(format!("snn-mesh-{}.bin", std::process::id()));
    let store = FileStore::new(&path);
    {
        let mut agent = Agent::open(&store, config(), &[50.0]).unwrap();
        agent.observe(&sample(0, &[51.0])).unwrap();
        agent.flush().unwrap();
    }
    {
        let mut agent = Agent::open(&store, config(), &[50.0]).unwrap();
        assert_eq!(agent.detector.samples_observed(), 1);
        agent.observe(&sample(1, &[51.0])).unwrap();
        assert_eq!(agent.detector.samples_observed(), 2);
    }
    std::fs::remove_file(&path).ok();
}

/// Compile-time contract: the detector crosses thread boundaries
/// (one worker per thread) and shares immutably where needed.
#[test]
fn detector_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Detector>();
    assert_send_sync::<MemoryStore>();
}
