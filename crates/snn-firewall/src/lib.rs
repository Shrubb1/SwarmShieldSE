//! `snn-firewall` — autonomous behavioral firewall on top of the SNN
//! anomaly detector.
//!
//! ```text
//! ConnEvent ──> FeatureWindow ──> Detector (snn-mesh) ──> anomaly?
//!                  (1s buckets)        (delta enc → SNN)      │
//!                        │                                    ▼
//!                        │                    MitigationRule { subject, kind,
//!                        │                                   TTL }
//!                        │                          ┌─────────┴─────────┐
//!                        ▼                          ▼                   ▼
//!                  Verdict check             RuleTable (local)   PolicySink
//!                                            enforcement         (proxy push)
//!                        └────────────────> AuditLog (tenant-scoped)
//! ```
//!
//! Everything is deterministic: the only clock is `ConnEvent::ts_ms`.

pub mod audit;
pub mod engine;
pub mod enhance;
pub mod event;
pub mod policy;
pub mod scout;

pub use scout::{Persistence, Scout};

pub use enhance::PcapSource;
pub mod identity;
pub mod sequence;
pub use identity::IdentityMap;
pub use sequence::SequenceTracker;

pub use enhance::{
    Beacons, EventSource, JsonlSource, MetaWindow, Signatures, SlowTick, SourceProfiles,
    StaticPolicy,
};

pub use audit::{
    downshift_record, eval_record, mitigation_record, AuditKind, AuditLog, AuditRecord, JsonlAudit,
    MemoryAudit,
};
pub use engine::{Firewall, FirewallPolicy, FirewallSnapshot};
pub use event::{channel_names, ConnEvent, EventMeta, FeatureVector, FeatureWindow, CHANNELS};
pub use policy::{
    MitigationKind, MitigationRule, PolicySink, RecordingPolicySink, RuleSubject, RuleTable,
    Verdict,
};
