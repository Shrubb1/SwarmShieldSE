//! Native tests for `WasmShim` — the wasm bindings are a thin re-export
//! of this surface, so coverage here covers the JS-visible contract.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use snn_firewall::{channel_names, ConnEvent, FirewallPolicy, MitigationRule, PolicySink};
use snn_mesh::{CheckpointStore, DetectorConfig, MemoryStore};
use snn_runtime::{JobSpec, JsonApi, Orchestrator};
use snn_wasm::{api_version, WasmShim};

#[derive(Clone, Default)]
struct SharedSink {
    applied: Arc<Mutex<Vec<MitigationRule>>>,
}

impl PolicySink for SharedSink {
    fn apply(&mut self, rule: &MitigationRule) -> std::io::Result<()> {
        self.applied.lock().unwrap().push(rule.clone());
        Ok(())
    }
    fn revoke(&mut self, rule_id: u64) -> std::io::Result<()> {
        self.applied.lock().unwrap().retain(|r| r.id != rule_id);
        Ok(())
    }
}

fn shim() -> WasmShim {
    let orch = Orchestrator::new(
        PathBuf::from("/snn-test"),
        Box::new(|_name: &str| Box::new(MemoryStore::new()) as Box<dyn CheckpointStore>),
        Box::new(|_spec: &JobSpec| Box::new(SharedSink::default()) as Box<dyn PolicySink>),
    );
    WasmShim::new(JsonApi::new(orch))
}

#[test]
fn register_ingest_status_over_json() {
    let mut s = shim();
    let spec = JobSpec {
        job_id: "j1".into(),
        tenant: "t".into(),
        telemetry: DetectorConfig::for_metrics(&["m"]),
        firewall_detector: DetectorConfig::for_metrics(&channel_names()),
        firewall_policy: FirewallPolicy::default(),
        telemetry_baselines: vec![0.0],
        firewall_baselines: vec![
            10.0, 2.0, 5.0, 500.0, 400.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 10.0, 0.0, 0.0, 10.0,
        ],
        checkpoint_every: 100,
    };
    s.register(&serde_json::to_string(&spec).unwrap()).unwrap();

    let ev = ConnEvent {
        ts_ms: 1000,
        tenant: "t".into(),
        src_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        payload_bytes: 500,
        header_bytes: 400,
        meta: Default::default(),
        payload: None,
    };
    let v: serde_json::Value = serde_json::from_str(
        &s.ingest("j1", &serde_json::to_string(&ev).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(v, "Allow");

    let status: serde_json::Value = serde_json::from_str(&s.status("j1").unwrap()).unwrap();
    assert_eq!(status["job_id"], "j1");

    assert!(s.ingest("missing", "{}").is_err());
    assert!(!api_version().is_empty());
}
