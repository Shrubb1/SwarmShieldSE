//! `swarm` — live mesh nodes.
//!
//! - `swarm-worker` ([`worker`]): TCP listener → `Orchestrator` (telemetry
//!   Agent + Firewall) → `Verdict`/`Detection` replies; rules pushed to a
//!   `FilePolicySink` (`policy.json` for the local proxy) and reported
//!   upstream.
//! - `swarm-orchestrator` ([`control`]): accepts `Report` frames →
//!   `jobs/{id}/mesh.jsonl` audit.
//! - [`proto`]: length-prefixed JSON frames, same serde types as JsonApi.

pub mod control;
pub mod crash;
pub mod proto;
pub mod worker;

pub use control::run_orchestrator;
pub use proto::{read_frame, write_frame, Frame, Report};
pub use worker::{run_worker, WorkerConfig};
