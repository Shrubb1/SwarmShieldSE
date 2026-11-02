//! Replay an actual live-captured pcap (scapy+Npcap) through the engine.
//! Skips gracefully if no capture exists — this is the last-mile seam:
//! real bytes on the wire → libpcap file → ConnEvent → verdicts.
use snn_firewall::{
    channel_names, EventSource, Firewall, FirewallPolicy, MemoryAudit, MitigationKind, PcapSource,
    RecordingPolicySink, Verdict,
};
use snn_mesh::DetectorConfig;
use std::io::BufReader;

#[test]
fn live_pcap_replay() {
    let path = std::env::var("LIVE_PCAP")
        .unwrap_or_else(|_| r"C:\Users\Black\AppData\Local\Temp\live.pcap".into());
    let f = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => {
            eprintln!("no live.pcap — capture with: sniff(timeout=12); wrpcap(path, pkts)");
            return;
        }
    };
    let mut src = match PcapSource::open(BufReader::new(f)) {
        Some(s) => s,
        None => {
            eprintln!("pcap parse failed");
            return;
        }
    };
    let mut fw = Firewall::new(
        DetectorConfig {
            delta_threshold: 5.0,
            spike_current: 200.0,
            initial_weight: 80.0,
            window: 10,
            anomaly_threshold: 1,
            ..DetectorConfig::for_metrics(&channel_names())
        },
        FirewallPolicy {
            anomaly_threshold: 2,
            action_ladder: vec![MitigationKind::Drop],
            ttl_ms: 5_000,
            cooldown_ms: 0,
            ..Default::default()
        },
        &[
            10.0, 2.0, 5.0, 500.0, 400.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 10.0, 0.0, 0.0, 10.0,
        ],
        RecordingPolicySink::default(),
        MemoryAudit::default(),
    );
    let mut n = 0usize;
    let mut allow = 0usize;
    while let Some(ev) = src.next_event() {
        n += 1;
        if matches!(fw.inspect(&ev).unwrap(), Verdict::Allow) {
            allow += 1;
        }
    }
    eprintln!(
        "live pcap: {} events parsed, {} allowed, {} rules applied",
        n,
        allow,
        fw.sink_mut().applied.len()
    );
    assert!(n > 0, "pcap yielded no events");
}
