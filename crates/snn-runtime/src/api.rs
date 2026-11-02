//! JSON façade over [`Orchestrator`] — the Wasm/IPC boundary.
//!
//! Every method takes/returns JSON strings so a `wasm_bindgen` wrapper,
//! an FFI shim, or a plain TCP/stdio worker can sit in front without
//! knowing Rust types. Errors are returned as strings (the boundary is
//! text anyway); callers that care can match on them.
//!
//! ```ignore
//! let mut api = JsonApi::new(orch);
//! api.register(&spec_json)?;
//! let verdict_json = api.ingest("job7", &event_json)?;
//! ```

use serde::{Deserialize, Serialize};

use snn_firewall::{ConnEvent, Verdict};
use snn_mesh::TelemetrySample;

use crate::orchestrator::{JobSpec, Orchestrator};

/// Status payload for `status` — what a dashboard/policy endpoint wants.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobStatus {
    pub job_id: String,
    pub tenant: String,
    pub telemetry_samples: u64,
    pub active_rules: Vec<snn_firewall::MitigationRule>,
}

pub struct JsonApi {
    pub orch: Orchestrator,
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

impl JsonApi {
    pub fn new(orch: Orchestrator) -> Self {
        Self { orch }
    }

    /// `register(JobSpec)` → `null` or error string.
    pub fn register(&mut self, spec_json: &str) -> Result<String, String> {
        let spec: JobSpec = serde_json::from_str(spec_json).map_err(err)?;
        self.orch.register(spec).map_err(err)?;
        Ok("null".into())
    }

    /// `ingest(job_id, ConnEvent)` → `Verdict`.
    pub fn ingest(&mut self, job_id: &str, ev_json: &str) -> Result<String, String> {
        let ev: ConnEvent = serde_json::from_str(ev_json).map_err(err)?;
        let v: Verdict = self.orch.ingest(job_id, &ev).map_err(err)?;
        serde_json::to_string(&v).map_err(err)
    }

    /// `telemetry(job_id, TelemetrySample)` → `Detection`.
    pub fn telemetry(&mut self, job_id: &str, sample_json: &str) -> Result<String, String> {
        let s: TelemetrySample = serde_json::from_str(sample_json).map_err(err)?;
        let d = self.orch.telemetry(job_id, &s).map_err(err)?;
        serde_json::to_string(&d).map_err(err)
    }

    /// `status(job_id)` → `JobStatus`.
    pub fn status(&self, job_id: &str) -> Result<String, String> {
        let job = self
            .orch
            .job(job_id)
            .ok_or_else(|| format!("no job '{job_id}'"))?;
        let status = JobStatus {
            job_id: job.spec.job_id.clone(),
            tenant: job.spec.tenant.clone(),
            telemetry_samples: job.telemetry.detector.samples_observed(),
            active_rules: self.orch.active_rules(job_id),
        };
        serde_json::to_string(&status).map_err(err)
    }

    /// `flush()` → `null`. Periodic + shutdown persistence.
    pub fn flush(&mut self) -> Result<String, String> {
        self.orch.flush().map_err(err)?;
        Ok("null".into())
    }
}
