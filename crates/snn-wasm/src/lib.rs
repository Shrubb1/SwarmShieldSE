//! `snn-wasm` — browser/edge shim over `snn-runtime`'s [`JsonApi`].
//!
//! [`WasmShim`] is plain Rust — a constructor-injected orchestrator plus
//! pass-through methods — so the whole surface is unit-testable natively.
//! `mod bindings` (wasm32 only) exposes the same methods through
//! `wasm_bindgen` as `SnnFirewall` for JS/TS callers:
//!
//! ```ts
//! const fw = new SnnFirewall();
//! fw.register(specJson);
//! const verdict = JSON.parse(fw.ingest("job7", eventJson));
//! ```

use serde_json::json;
use snn_runtime::JsonApi;

/// Native-side wrapper: every method is JSON-string in/out, exactly what
/// the wasm bindings re-export.
pub struct WasmShim {
    api: JsonApi,
}

impl WasmShim {
    pub fn new(api: JsonApi) -> Self {
        Self { api }
    }

    pub fn register(&mut self, spec_json: &str) -> Result<String, String> {
        self.api.register(spec_json)
    }

    pub fn ingest(&mut self, job_id: &str, ev_json: &str) -> Result<String, String> {
        self.api.ingest(job_id, ev_json)
    }

    pub fn telemetry(&mut self, job_id: &str, sample_json: &str) -> Result<String, String> {
        self.api.telemetry(job_id, sample_json)
    }

    pub fn status(&self, job_id: &str) -> Result<String, String> {
        self.api.status(job_id)
    }

    pub fn flush(&mut self) -> Result<String, String> {
        self.api.flush()
    }
}

#[cfg(target_arch = "wasm32")]
mod bindings {
    use std::path::PathBuf;
    use std::sync::Mutex;

    use wasm_bindgen::prelude::*;

    use snn_firewall::{PolicySink, RecordingPolicySink};
    use snn_mesh::MemoryStore;
    use snn_runtime::JobSpec;

    use super::WasmShim;

    /// Browser-facing handle. Uses in-memory stores and a recording sink
    /// by default — swap factories for IndexedDB/OPFS-backed persistence
    /// when wiring to a real host.
    #[wasm_bindgen]
    pub struct SnnFirewall {
        shim: Mutex<WasmShim>,
    }

    #[wasm_bindgen]
    impl SnnFirewall {
        #[wasm_bindgen(constructor)]
        pub fn new() -> Self {
            let api = snn_runtime::JsonApi::new(snn_runtime::Orchestrator::new(
                PathBuf::from("/snn"),
                Box::new(|_name: &str| {
                    Box::new(MemoryStore::new()) as Box<dyn snn_mesh::CheckpointStore>
                }),
                Box::new(|_spec: &JobSpec| {
                    Box::new(RecordingPolicySink::default()) as Box<dyn PolicySink>
                }),
            ));
            Self {
                shim: Mutex::new(WasmShim::new(api)),
            }
        }

        pub fn register(&self, spec_json: &str) -> Result<String, JsError> {
            self.shim
                .lock()
                .map_err(|_| JsError::new("poisoned"))?
                .register(spec_json)
                .map_err(|e| JsError::new(&e))
        }

        pub fn ingest(&self, job_id: &str, ev_json: &str) -> Result<String, JsError> {
            self.shim
                .lock()
                .map_err(|_| JsError::new("poisoned"))?
                .ingest(job_id, ev_json)
                .map_err(|e| JsError::new(&e))
        }

        pub fn telemetry(&self, job_id: &str, sample_json: &str) -> Result<String, JsError> {
            self.shim
                .lock()
                .map_err(|_| JsError::new("poisoned"))?
                .telemetry(job_id, sample_json)
                .map_err(|e| JsError::new(&e))
        }

        pub fn status(&self, job_id: &str) -> Result<String, JsError> {
            self.shim
                .lock()
                .map_err(|_| JsError::new("poisoned"))?
                .status(job_id)
                .map_err(|e| JsError::new(&e))
        }

        pub fn flush(&self) -> Result<String, JsError> {
            self.shim
                .lock()
                .map_err(|_| JsError::new("poisoned"))?
                .flush()
                .map_err(|e| JsError::new(&e))
        }
    }
}

// Re-export nothing on native — bindings module is wasm-only.

/// Version probe for JS hosts to sanity-check ABI drift.
pub fn api_version() -> String {
    serde_json::to_string(&json!({ "api": env!("CARGO_PKG_VERSION") })).unwrap_or_default()
}
