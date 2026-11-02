//! The orchestrator: a registry of tenant/job-scoped SNN subsystems.
//!
//! Each [`JobSpec`] spawns a [`Job`] holding:
//! - `telemetry` — an `snn_mesh::Agent` (generic-metric anomaly detector +
//!   periodic checkpointing), backed by a per-job [`CheckpointStore`],
//! - `firewall` — an `snn_firewall::Firewall` (connection-event inspection
//!   + mitigation rules), auditing into `jobs/{id}/network.jsonl`,
//! - `fw_store` — where the firewall's [`FirewallSnapshot`] is persisted
//!   on `flush` (and re-applied to the sink on restore).
//!
//! Everything downstream is injected: stores come from a [`StoreFactory`],
//! proxy pushes from a [`SinkFactory`]. In tests both are in-memory; in
//! the mesh they become Postgres rows and the proxy policy adapter.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use snn_firewall::{
    AuditLog, Firewall, FirewallPolicy, FirewallSnapshot, JsonlAudit, MitigationRule, PolicySink,
    Verdict,
};
use snn_mesh::{Agent, CheckpointStore, Detection, DetectorConfig, FileStore, TelemetrySample};

/// Everything needed to bring up one job.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobSpec {
    pub job_id: String,
    pub tenant: String,
    /// Generic telemetry detector config (metrics → anomaly score).
    pub telemetry: DetectorConfig,
    /// Firewall detector config — metrics must match
    /// `snn_firewall::channel_names()`.
    pub firewall_detector: DetectorConfig,
    pub firewall_policy: FirewallPolicy,
    /// Seed baselines for the telemetry detector (one per metric).
    pub telemetry_baselines: Vec<f32>,
    /// Seed baselines for the firewall feature channels.
    pub firewall_baselines: Vec<f32>,
    /// Telemetry checkpoint cadence, in samples.
    pub checkpoint_every: u64,
}

/// Produces a namespaced checkpoint backend per job component
/// (e.g. `"job7:telemetry"` → Postgres row name / file `job7_telemetry.ckpt`).
pub trait StoreFactory: Send + Sync {
    fn store(&self, name: &str) -> Box<dyn CheckpointStore>;
}

impl<F> StoreFactory for F
where
    F: Fn(&str) -> Box<dyn CheckpointStore> + Send + Sync,
{
    fn store(&self, name: &str) -> Box<dyn CheckpointStore> {
        self(name)
    }
}

/// `FileStore` factory rooted at `dir`, one file per store name.
pub fn file_stores(dir: PathBuf) -> impl StoreFactory {
    move |name: &str| {
        let safe: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        Box::new(FileStore::new(dir.join(format!("{safe}.ckpt")))) as Box<dyn CheckpointStore>
    }
}

/// Produces the per-job downstream policy sink.
pub trait SinkFactory: Send + Sync {
    fn sink(&self, spec: &JobSpec) -> Box<dyn PolicySink>;
}

impl<F> SinkFactory for F
where
    F: Fn(&JobSpec) -> Box<dyn PolicySink> + Send + Sync,
{
    fn sink(&self, spec: &JobSpec) -> Box<dyn PolicySink> {
        self(spec)
    }
}

/// One tenant/job: telemetry agent + firewall + firewall persistence.
pub struct Job {
    pub spec: JobSpec,
    pub telemetry: Agent<Box<dyn CheckpointStore>>,
    pub firewall: Firewall<Box<dyn PolicySink>, Box<dyn AuditLog>>,
    fw_store: Box<dyn CheckpointStore>,
}

pub struct Orchestrator {
    jobs_root: PathBuf,
    stores: Box<dyn StoreFactory>,
    sinks: Box<dyn SinkFactory>,
    jobs: HashMap<String, Job>,
}

impl Orchestrator {
    /// `jobs_root` is the audit/checkpoint root — job `id` writes to
    /// `jobs_root/id/network.jsonl` plus store files.
    pub fn new(
        jobs_root: PathBuf,
        stores: Box<dyn StoreFactory>,
        sinks: Box<dyn SinkFactory>,
    ) -> Self {
        Self {
            jobs_root,
            stores,
            sinks,
            jobs: HashMap::new(),
        }
    }

    /// Bring up a job: restore-or-init telemetry agent and firewall,
    /// create its audit dir, wire its sink.
    pub fn register(&mut self, spec: JobSpec) -> io::Result<()> {
        let job_dir = self.jobs_root.join(&spec.job_id);
        let audit: Box<dyn AuditLog> =
            Box::new(JsonlAudit::for_job(&job_dir, spec.tenant.clone())?);

        let mut telemetry = Agent::open(
            self.stores.store(&format!("{}:telemetry", spec.job_id)),
            spec.telemetry.clone(),
            &spec.telemetry_baselines,
        )?;
        telemetry.checkpoint_every = spec.checkpoint_every;

        let fw_store = self.stores.store(&format!("{}:firewall", spec.job_id));
        let sink = self.sinks.sink(&spec);
        let firewall = match fw_store.load()? {
            Some(bytes) => {
                let snap: FirewallSnapshot = bincode::deserialize(&bytes)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                Firewall::restore(
                    spec.firewall_detector.clone(),
                    spec.firewall_policy.clone(),
                    snap,
                    sink,
                    audit,
                )?
            }
            None => Firewall::new(
                spec.firewall_detector.clone(),
                spec.firewall_policy.clone(),
                &spec.firewall_baselines,
                sink,
                audit,
            ),
        };

        self.jobs.insert(
            spec.job_id.clone(),
            Job {
                spec,
                telemetry,
                firewall,
                fw_store,
            },
        );
        Ok(())
    }

    /// Route one connection event to a job's firewall.
    pub fn ingest(&mut self, job_id: &str, ev: &snn_firewall::ConnEvent) -> io::Result<Verdict> {
        self.job_mut(job_id)?.firewall.inspect(ev)
    }

    /// Route one telemetry sample to a job's detector agent.
    pub fn telemetry(&mut self, job_id: &str, s: &TelemetrySample) -> io::Result<Detection> {
        self.job_mut(job_id)?.telemetry.observe(s)
    }

    /// Persist everything: telemetry checkpoints + firewall snapshots.
    /// Call on a timer (checkpoint cadence is the agent's concern) and on
    /// shutdown.
    pub fn flush(&mut self) -> io::Result<()> {
        for job in self.jobs.values_mut() {
            job.telemetry.flush()?;
            let snap = job.firewall.snapshot()?;
            let bytes = bincode::serialize(&snap)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            job.fw_store.save(&bytes, snap.detector.step_count)?;
        }
        Ok(())
    }

    /// Live mitigation rules for a job (status/policy endpoint payload).
    pub fn active_rules(&self, job_id: &str) -> Vec<MitigationRule> {
        self.jobs
            .get(job_id)
            .map(|j| j.firewall.active_rules().into_iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn job(&self, job_id: &str) -> Option<&Job> {
        self.jobs.get(job_id)
    }

    fn job_mut(&mut self, job_id: &str) -> io::Result<&mut Job> {
        self.jobs
            .get_mut(job_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no job '{job_id}'")))
    }
}
