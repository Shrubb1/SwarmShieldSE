//! Mitigation rules: generated on anomaly, enforced in-line, always TTL'd.
//!
//! Every rule carries `expires_ms` — there is no API for a permanent rule.
//! A false positive therefore self-heals: the worst case is a bounded
//! outage for one subject, never a permanent lockout.
//!
//! Two enforcement surfaces:
//! - [`RuleTable`]: the in-process hot path the engine checks on every
//!   event (deny / rate-limit token bucket).
//! - [`PolicySink`]: the seam for pushing rules to the *external* fetch/
//!   proxy policy layer — the orchestrator's adapter implements this and
//!   receives apply/revoke without restarts.

use std::collections::HashMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::event::ConnEvent;

/// What a mitigation rule does to matching traffic.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum MitigationKind {
    /// Token-bucket cap: at most `max_rps` events/sec pass.
    RateLimit { max_rps: f32 },
    /// Drop matching connections at the proxy layer.
    Drop,
    /// Full block: connection refused before any processing.
    Block,
}

/// Who a rule matches. Broader than a single IP when attribution is weak.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleSubject {
    Ip(IpAddr),
    Tenant(String),
    /// Applies to all traffic — last resort when no single source dominates.
    Global,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MitigationRule {
    pub id: u64,
    pub subject: RuleSubject,
    pub kind: MitigationKind,
    pub created_ms: u64,
    /// Mandatory expiry — enforced by `RuleTable::sweep`.
    pub expires_ms: u64,
    /// Offense count that produced this rule (1 = first strike).
    pub offense: u32,
    /// Human/log-readable reason incl. the anomaly score that triggered it.
    pub reason: String,
}

/// Verdict for one connection event.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Verdict {
    Allow,
    /// Passed a rate-limit gate? No — rejected by it.
    RateLimited {
        rule: u64,
    },
    Denied {
        rule: u64,
    },
}

struct ActiveRule {
    rule: MitigationRule,
    // Token bucket state for RateLimit enforcement.
    tokens: f32,
    last_refill_ms: u64,
    /// Events this rule has enforced against — live proof a mitigation
    /// is working while the attack is still running.
    hit_count: u64,
}

/// Live enforcement set. Rules are matched per event; expired rules are
/// reaped by `sweep` — nothing here outlives its TTL.
#[derive(Default)]
pub struct RuleTable {
    rules: HashMap<u64, ActiveRule>,
}

impl RuleTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, rule: MitigationRule) {
        let tokens = match rule.kind {
            MitigationKind::RateLimit { max_rps } => max_rps,
            _ => 0.0,
        };
        self.rules.insert(
            rule.id,
            ActiveRule {
                rule,
                tokens,
                last_refill_ms: 0,
                hit_count: 0,
            },
        );
    }

    pub fn remove(&mut self, id: u64) -> Option<MitigationRule> {
        self.rules.remove(&id).map(|a| a.rule)
    }

    pub fn get(&self, id: u64) -> Option<&MitigationRule> {
        self.rules.get(&id).map(|a| &a.rule)
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Is there already a live rule on this subject? Stops rule stacking.
    /// Remove the live rule on `subject` (search-path candidate
    /// replacement). Returns it so the caller can revoke downstream.
    pub fn remove_subject(&mut self, subject: &RuleSubject) -> Option<MitigationRule> {
        let id = self
            .rules
            .iter()
            .find(|(_, r)| &r.rule.subject == subject)
            .map(|(id, _)| *id)?;
        self.rules.remove(&id).map(|e| e.rule)
    }

    pub fn has_subject(&self, subject: &RuleSubject) -> bool {
        self.rules.values().any(|a| &a.rule.subject == subject)
    }

    /// Total enforcement hits on rules covering `subject` — the
    /// search path's live "the fix is working" signal.
    pub fn hits_for(&self, subject: &RuleSubject) -> u64 {
        self.rules
            .values()
            .filter(|a| &a.rule.subject == subject)
            .map(|a| a.hit_count)
            .sum()
    }

    /// First matching rule decides; precedence Block/Drop over RateLimit
    /// is implicit (we scan all matches and take the harshest verdict).
    pub fn check(&mut self, ev: &ConnEvent) -> Verdict {
        let mut rate_verdict = None;
        for a in self.rules.values_mut() {
            let matches = match &a.rule.subject {
                RuleSubject::Ip(ip) => *ip == ev.src_ip,
                RuleSubject::Tenant(t) => *t == ev.tenant,
                RuleSubject::Global => true,
            };
            if !matches {
                continue;
            }
            match a.rule.kind {
                MitigationKind::Drop | MitigationKind::Block => {
                    a.hit_count += 1;
                    return Verdict::Denied { rule: a.rule.id };
                }
                MitigationKind::RateLimit { max_rps } => {
                    // Refill lazily from the event clock.
                    let elapsed_s = (ev.ts_ms.saturating_sub(a.last_refill_ms)) as f32 / 1000.0;
                    a.last_refill_ms = ev.ts_ms;
                    a.tokens = (a.tokens + elapsed_s * max_rps).min(max_rps);
                    if a.tokens >= 1.0 {
                        a.tokens -= 1.0; // passes the bucket
                    } else {
                        a.hit_count += 1;
                        rate_verdict = Some(a.rule.id);
                    }
                }
            }
        }
        rate_verdict
            .map(|rule| Verdict::RateLimited { rule })
            .unwrap_or(Verdict::Allow)
    }

    /// Remove and return rules whose TTL has passed at `now_ms`.
    pub fn sweep(&mut self, now_ms: u64) -> Vec<MitigationRule> {
        let expired: Vec<u64> = self
            .rules
            .iter()
            .filter(|(_, a)| now_ms >= a.rule.expires_ms)
            .map(|(id, _)| *id)
            .collect();
        expired
            .into_iter()
            .filter_map(|id| self.remove(id))
            .collect()
    }
}

/// Type-erased sink — orchestrator jobs can each carry a different
/// downstream adapter.
impl PolicySink for Box<dyn PolicySink> {
    fn apply(&mut self, rule: &MitigationRule) -> std::io::Result<()> {
        (**self).apply(rule)
    }
    fn revoke(&mut self, rule_id: u64) -> std::io::Result<()> {
        (**self).revoke(rule_id)
    }
}

/// External policy push seam — implemented by the proxy/fetch adapter in
/// the orchestrator. `apply` must take effect without a service restart.
pub trait PolicySink: Send + Sync {
    fn apply(&mut self, rule: &MitigationRule) -> std::io::Result<()>;
    fn revoke(&mut self, rule_id: u64) -> std::io::Result<()>;
}

/// Test/dev sink: records every call. Also useful as an audit cross-check.
#[derive(Default)]
pub struct RecordingPolicySink {
    pub applied: Vec<MitigationRule>,
    pub revoked: Vec<u64>,
    /// Inject failures to exercise error paths.
    pub fail_next: bool,
}

impl PolicySink for RecordingPolicySink {
    fn apply(&mut self, rule: &MitigationRule) -> std::io::Result<()> {
        if self.fail_next {
            self.fail_next = false;
            return Err(std::io::Error::other("injected sink failure"));
        }
        self.applied.push(rule.clone());
        Ok(())
    }

    fn revoke(&mut self, rule_id: u64) -> std::io::Result<()> {
        self.revoked.push(rule_id);
        Ok(())
    }
}
