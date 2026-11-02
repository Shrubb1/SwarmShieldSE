//! `snn-mesh` — Phase 2 integration layer.
//!
//! Sits between the mesh telemetry stream and the SNN crates:
//!
//! ```text
//! telemetry ──> TelemetrySample ──> [Detector: encode→SNN→STDP]
//!                                        │
//!                                        ├─> Detection (score, anomaly)
//!                                        │
//!                              every N samples
//!                                        ▼
//!                              Checkpoint ──> CheckpointStore
//!                                        (File / Postgres bytea / Memory)
//! ```
//!
//! - [`detector`]: the anomaly detector + config + event types.
//! - [`store`]: persistence backends for SNN memory.
//! - [`agent`]: detector + store + checkpoint policy (what workers hold).
//! - [`worker`]: reference channel-based worker loop.

pub mod agent;
pub mod detector;
pub mod store;
pub mod worker;

pub use agent::Agent;
pub use detector::{Detection, Detector, DetectorConfig, TelemetrySample};
pub use store::{CheckpointStore, FileStore, MemoryStore};
pub use worker::run_worker;

#[cfg(feature = "postgres-store")]
pub use store::PostgresStore;
