//! Tenant-scoped audit for every firewall decision.
//!
//! Three record kinds: `Evaluation` (per finalized window — score, verdict
//! context), `Mitigation` (rule pushed downstream), `Expiry` (rule TTL
//! elapsed, rule revoked). Everything is plain serde structs so the same
//! log can feed the `/jobs/{id}/network` audit path, a file, or a stream.

use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::policy::{MitigationRule, RuleSubject};

/// What the engine recorded.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum AuditKind {
    /// A scored window: the SNN's verdict on observed traffic.
    Evaluation {
        score: u32,
        anomaly: bool,
        max_deviation: f32,
    },
    /// A mitigation rule was generated and pushed downstream.
    Mitigation { rule: MitigationRule },
    /// A rule's TTL elapsed and it was revoked.
    Expiry { rule_id: u64 },
    /// Informational regime drop-off: anomaly driven purely by
    /// down-spikes (volume collapsing vs baseline). Logged, never
    /// escalated — blocking "traffic that left" is a self-inflicted
    /// blackout.
    DownShift { score: u32, max_deviation: f32 },
    /// An allowlisted source was flagged — observe-only: the trusted IP
    /// is never ruled, but a turned insider can't move silently either.
    Alert { reason: String },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub ts_ms: u64,
    /// Tenant/job scope — the `jobs/{id}` of `/jobs/{id}/network` logging.
    pub tenant: String,
    /// Source the record concerns (attributed IP for mitigations).
    pub src: Option<IpAddr>,
    pub kind: AuditKind,
}

/// Type-erased audit log for heterogenous per-job writers.
impl AuditLog for Box<dyn AuditLog> {
    fn record(&mut self, rec: AuditRecord) {
        (**self).record(rec)
    }
}

/// Sink for audit records. Implemented by the mesh's job-scoped log
/// writer; `MemoryAudit`/`JsonlAudit` cover tests and local runs.
pub trait AuditLog: Send {
    fn record(&mut self, rec: AuditRecord);
}

/// In-memory audit — tests, and a buffer fronting a real writer.
#[derive(Default)]
pub struct MemoryAudit {
    pub records: Vec<AuditRecord>,
}

impl MemoryAudit {
    pub fn new() -> Self {
        Self::default()
    }

    /// All generated rules, in order.
    pub fn rules(&self) -> Vec<&MitigationRule> {
        self.records
            .iter()
            .filter_map(|r| match &r.kind {
                AuditKind::Mitigation { rule } => Some(rule),
                _ => None,
            })
            .collect()
    }

    pub fn anomaly_count(&self) -> usize {
        self.records
            .iter()
            .filter(|r| matches!(&r.kind, AuditKind::Evaluation { anomaly: true, .. }))
            .count()
    }
}

impl AuditLog for MemoryAudit {
    fn record(&mut self, rec: AuditRecord) {
        self.records.push(rec);
    }
}

/// Append-only JSONL file — one line per record, matching the
/// `jobs/{job_id}/network` convention: point it at the job's directory
/// and records land in `<dir>/network.jsonl`.
pub struct JsonlAudit {
    path: PathBuf,
    tenant: String,
}

impl JsonlAudit {
    /// `job_dir` is e.g. `/jobs/42`; records append to
    /// `/jobs/42/network.jsonl` tagged with `tenant`.
    pub fn for_job(
        job_dir: impl Into<PathBuf>,
        tenant: impl Into<String>,
    ) -> std::io::Result<Self> {
        let dir = job_dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self {
            path: dir.join("network.jsonl"),
            tenant: tenant.into(),
        })
    }
}

impl AuditLog for JsonlAudit {
    fn record(&mut self, rec: AuditRecord) {
        let rec = AuditRecord {
            tenant: self.tenant.clone(),
            ..rec
        };
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            if let Ok(line) = serde_json::to_string(&rec) {
                let _ = writeln!(f, "{line}");
            }
        }
    }
}

/// Convenience: pull the subject out of a rule for `AuditRecord::src`.
pub fn rule_src(rule: &MitigationRule) -> Option<IpAddr> {
    match &rule.subject {
        RuleSubject::Ip(ip) => Some(*ip),
        _ => None,
    }
}

/// Convenience for building an evaluation record.
pub fn eval_record(
    ts_ms: u64,
    tenant: impl Into<String>,
    src: Option<IpAddr>,
    score: u32,
    anomaly: bool,
    max_deviation: f32,
) -> AuditRecord {
    AuditRecord {
        ts_ms,
        tenant: tenant.into(),
        src,
        kind: AuditKind::Evaluation {
            score,
            anomaly,
            max_deviation,
        },
    }
}

/// Convenience for building a mitigation record.
pub fn mitigation_record(
    ts_ms: u64,
    tenant: impl Into<String>,
    rule: MitigationRule,
) -> AuditRecord {
    AuditRecord {
        ts_ms,
        tenant: tenant.into(),
        src: rule_src(&rule),
        kind: AuditKind::Mitigation { rule },
    }
}

/// Convenience for building an informational down-shift record.
pub fn downshift_record(
    ts_ms: u64,
    tenant: impl Into<String>,
    src: Option<IpAddr>,
    score: u32,
    max_deviation: f32,
) -> AuditRecord {
    AuditRecord {
        ts_ms,
        tenant: tenant.into(),
        src,
        kind: AuditKind::DownShift {
            score,
            max_deviation,
        },
    }
}
