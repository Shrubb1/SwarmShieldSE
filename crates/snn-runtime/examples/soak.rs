//! Soak + throughput harness — run with `--release` for real numbers.
//! cargo run -p snn-runtime --release --example soak

use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use snn_firewall::{
    channel_names, ConnEvent, FirewallPolicy, MitigationKind, MitigationRule, PolicySink, Verdict,
};
use snn_mesh::{DetectorConfig, TelemetrySample};
use snn_runtime::{file_stores, JobSpec, Orchestrator};

const TICK: u64 = 1000;
/// Stable population: 5 IPs, 2 events each per window — matches the
/// seeded baseline so warmup converges instead of perma-alerting.
const NORMAL_IPS: u8 = 5;

#[derive(Clone, Default)]
struct NullSink;
impl PolicySink for NullSink {
    fn apply(&mut self, _r: &MitigationRule) -> std::io::Result<()> {
        Ok(())
    }
    fn revoke(&mut self, _id: u64) -> std::io::Result<()> {
        Ok(())
    }
}

fn ev(ts: u64, src: IpAddr, payload: u32) -> ConnEvent {
    ConnEvent {
        ts_ms: ts,
        tenant: "soak".into(),
        src_ip: src,
        payload_bytes: payload,
        header_bytes: 400,
        meta: Default::default(),
        payload: None,
    }
}

fn spec() -> JobSpec {
    JobSpec {
        job_id: "soak".into(),
        tenant: "soak".into(),
        telemetry: DetectorConfig::for_metrics(&["latency_ms"]),
        firewall_detector: DetectorConfig {
            delta_threshold: 5.0,
            spike_current: 200.0,
            initial_weight: 80.0,
            window: 10,
            anomaly_threshold: 1,
            ..DetectorConfig::for_metrics(&channel_names())
        },
        firewall_policy: FirewallPolicy {
            anomaly_threshold: 2,
            action_ladder: vec![
                MitigationKind::RateLimit { max_rps: 50.0 },
                MitigationKind::Drop,
                MitigationKind::Block,
            ],
            ttl_ms: 30_000,
            cooldown_ms: 10_000,
            ..Default::default()
        },
        telemetry_baselines: vec![50.0],
        firewall_baselines: vec![
            10.0, 2.0, 5.0, 500.0, 400.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 10.0, 0.0, 0.0, 10.0,
        ],
        checkpoint_every: 500,
    }
}

fn main() {
    let root = std::env::temp_dir().join(format!("snn-soak-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let store_root = root.join("stores");

    let mut orch = Orchestrator::new(
        root.join("jobs"),
        Box::new(file_stores(store_root.clone())),
        Box::new(|_: &JobSpec| Box::new(NullSink) as Box<dyn PolicySink>),
    );
    orch.register(spec()).unwrap();

    // 1-hour simulated soak: rotating normal traffic + telemetry tick,
    // floods at t=1800s and t=3000s.
    let mut events = 0u64;
    let mut denied = 0u64;
    let mut limited = 0u64;
    let mut rules_seen = 0usize;
    let wall = Instant::now();

    for w in 0..3600u64 {
        // Normal traffic: 10 events/window, 2 per stable IP.
        for k in 0..10u64 {
            let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, (k % NORMAL_IPS as u64) as u8 + 1));
            let payload = 495 + ((w * 7 + k * 13) % 10) as u32;
            match orch
                .ingest("soak", &ev(w * TICK + k * 100, src, payload))
                .unwrap()
            {
                Verdict::Denied { .. } => denied += 1,
                Verdict::RateLimited { .. } => limited += 1,
                _ => {}
            }
            events += 1;
        }
        // Flood windows.
        if (1800..1804).contains(&w) || (3000..3002).contains(&w) {
            for k in 0..200u64 {
                match orch
                    .ingest(
                        "soak",
                        &ev(w * TICK + k * 5, "66.6.6.6".parse().unwrap(), 500),
                    )
                    .unwrap()
                {
                    Verdict::Denied { .. } => denied += 1,
                    Verdict::RateLimited { .. } => limited += 1,
                    _ => {}
                }
                events += 1;
            }
        }
        // Telemetry sample per window.
        orch.telemetry(
            "soak",
            &TelemetrySample {
                seq: w,
                ts_ms: w * TICK,
                values: vec![50.0 + (w % 300) as f32 * 0.01],
            },
        )
        .unwrap();
        if w % 600 == 0 {
            let t = Instant::now();
            orch.flush().unwrap();
            rules_seen = rules_seen.max(orch.active_rules("soak").len());
            eprintln!("w{w}: flush in {:?}", t.elapsed());
        }
    }

    let elapsed = wall.elapsed();
    let rules = orch.active_rules("soak");
    let ck_bytes = std::fs::read_dir(&store_root)
        .unwrap()
        .map(|e| e.unwrap().metadata().unwrap().len())
        .sum::<u64>();

    println!("\n=== soak results ===");
    println!("wall time:      {:?}", elapsed);
    println!(
        "events:         {events} ({:.0} ev/s)",
        events as f64 / elapsed.as_secs_f64()
    );
    println!("denied:         {denied}");
    println!("rate-limited:   {limited}");
    println!("peak live rules:{rules_seen}");
    println!("live rules end: {}", rules.len());
    println!("ckpt bytes:     {ck_bytes}");
    println!(
        "sim steps:      {}",
        orch.job("soak")
            .unwrap()
            .telemetry
            .detector
            .network()
            .step_count
    );
    std::fs::remove_dir_all(&root).ok();
}
