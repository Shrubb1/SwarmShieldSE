//! Concrete [`PolicySink`] adapters — where mitigation rules actually land.
//!
//! - [`FilePolicySink`]: rewrites an atomic `policy.json` per job — the
//!   classic watched-config contract for sidecar proxies (the fetch layer
//!   polls or watches the file; no push protocol needed).
//! - `HttpPolicySink` (feature `http-sink`): REST push — `PUT /rules/{id}`
//!   on apply, `DELETE /rules/{id}` on revoke, against the proxy's live
//!   policy endpoint. Hot-reloading without restart by definition.
//!
//! `ProxyRule` is the on-the-wire schema both adapters share: deliberately
//! proxy-agnostic (subject + action + expiry), mapping 1:1 from
//! `MitigationRule`.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use snn_firewall::{MitigationKind, MitigationRule, PolicySink, RuleSubject};

/// Proxy-facing rule schema — what the fetch policy layer consumes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProxyRule {
    pub id: u64,
    /// `"ip:1.2.3.4"`, `"tenant:t-a"`, or `"global"`.
    pub subject: String,
    /// `"rate_limit"`, `"drop"`, or `"block"`.
    pub action: String,
    /// Present when `action == "rate_limit"`.
    pub max_rps: Option<f32>,
    pub expires_ms: u64,
    pub reason: String,
}

impl From<&MitigationRule> for ProxyRule {
    fn from(r: &MitigationRule) -> Self {
        let (action, max_rps) = match r.kind {
            MitigationKind::RateLimit { max_rps } => ("rate_limit", Some(max_rps)),
            MitigationKind::Drop => ("drop", None),
            MitigationKind::Block => ("block", None),
        };
        let subject = match &r.subject {
            RuleSubject::Ip(ip) => format!("ip:{ip}"),
            RuleSubject::Tenant(t) => format!("tenant:{t}"),
            RuleSubject::Global => "global".into(),
        };
        Self {
            id: r.id,
            subject,
            action: action.into(),
            max_rps,
            expires_ms: r.expires_ms,
            reason: r.reason.clone(),
        }
    }
}

/// The whole policy document a file-watching proxy reads.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolicyDocument {
    pub version: u32,
    /// Event-clock ms of the last rule change.
    pub generated_ms: u64,
    pub rules: Vec<ProxyRule>,
}

/// Writes the active rule set to `<dir>/policy.json` atomically
/// (tmp + rename) on every apply/revoke.
pub struct FilePolicySink {
    path: PathBuf,
    rules: BTreeMap<u64, ProxyRule>,
    last_ms: u64,
}

impl FilePolicySink {
    /// `dir` is the watched directory — e.g. the job's policy volume.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            path: dir.into().join("policy.json"),
            rules: BTreeMap::new(),
            last_ms: 0,
        }
    }

    fn write(&self) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let doc = PolicyDocument {
            version: 1,
            generated_ms: self.last_ms,
            rules: self.rules.values().cloned().collect(),
        };
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&doc)?)?;
        std::fs::rename(&tmp, &self.path)
    }
}

impl PolicySink for FilePolicySink {
    fn apply(&mut self, rule: &MitigationRule) -> io::Result<()> {
        self.rules.insert(rule.id, ProxyRule::from(rule));
        self.last_ms = self.last_ms.max(rule.created_ms);
        self.write()
    }

    fn revoke(&mut self, rule_id: u64) -> io::Result<()> {
        self.rules.remove(&rule_id);
        self.write()
    }
}

/// REST-push sink: `PUT {base}/rules/{id}` with the `ProxyRule` body on
/// apply, `DELETE {base}/rules/{id}` on revoke. 2xx = success; anything
/// else surfaces as an `io::Error` so the engine can log the failed push.
#[cfg(feature = "http-sink")]
pub struct HttpPolicySink {
    base_url: String,
}

#[cfg(feature = "http-sink")]
impl HttpPolicySink {
    /// `base_url` like `http://proxy-mesh.internal:8080` (no trailing /).
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
        }
    }
}

#[cfg(feature = "http-sink")]
impl PolicySink for HttpPolicySink {
    fn apply(&mut self, rule: &MitigationRule) -> io::Result<()> {
        let resp = ureq::put(format!("{}/rules/{}", self.base_url, rule.id))
            .send_json(ProxyRule::from(rule))
            .map_err(io::Error::other)?;
        if !(200..300).contains(&resp.status().as_u16()) {
            return Err(io::Error::other(format!(
                "policy push failed: HTTP {}",
                resp.status()
            )));
        }
        Ok(())
    }

    fn revoke(&mut self, rule_id: u64) -> io::Result<()> {
        let resp = ureq::delete(format!("{}/rules/{}", self.base_url, rule_id))
            .call()
            .map_err(io::Error::other)?;
        // 404 is fine — downstream already forgot it.
        if !(200..300).contains(&resp.status().as_u16()) && resp.status().as_u16() != 404 {
            return Err(io::Error::other(format!(
                "policy revoke failed: HTTP {}",
                resp.status()
            )));
        }
        Ok(())
    }
}
