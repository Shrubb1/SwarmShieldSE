//! `snn-runtime` — the tenant/job-scoped orchestrator layer.
//!
//! ```text
//!                ┌─────────────── Orchestrator ───────────────┐
//!  ConnEvent ──> │ job firewall ──> rules → sink   audit.jsonl │
//!  Telemetry ──> │ job agent    ──> detection  checkpoint ────│─> Store
//!                └────────────────────────────────────────────┘
//!
//! - [`orchestrator`]: `JobSpec` → `Job` registry, ingest routing, flush.
//! - [`api`]: JSON string façade — the Wasm/IPC integration surface.

pub mod api;
pub mod orchestrator;
pub mod sinks;

pub use api::{JobStatus, JsonApi};
pub use orchestrator::{file_stores, Job, JobSpec, Orchestrator, SinkFactory, StoreFactory};
pub use sinks::{FilePolicySink, PolicyDocument, ProxyRule};

#[cfg(feature = "http-sink")]
pub use sinks::HttpPolicySink;
