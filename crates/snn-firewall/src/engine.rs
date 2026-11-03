//! The behavioral firewall engine — the closed loop.
//!
//! Per [`ConnEvent`] (`inspect`):
//! 1. sweep expired rules (TTL is the false-positive safety valve),
//! 2. enforce: check the event against live rules → possible `Denied`,
//! 3. bucket it into the feature window; on window close, score it
//!    through the SNN detector,
//! 4. on anomaly: generate a TTL'd mitigation rule — attributed to the
//!    dominant source when it carries ≥ `attribution_min_share` of the
//!    window, else `Global` — enforce locally, push downstream via
//!    `PolicySink`, and audit everything.
//!
//! Repeat anomalies from the same subject walk up `action_ladder`
//! (rate-limit → drop → block) with TTLs scaled by `ttl_growth`, inside a
//! per-subject `cooldown_ms` so one bad burst can't spam rules.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use snn_io::Checkpoint;
use snn_mesh::{Detection, Detector, DetectorConfig, TelemetrySample};

use crate::audit::{
    downshift_record, eval_record, mitigation_record, rule_src, AuditKind, AuditLog, AuditRecord,
};
use crate::enhance::Signatures;
use crate::enhance::{Beacons, MetaWindow, SlowTick, SourceProfiles, StaticPolicy};
use crate::event::{ConnEvent, FeatureVector, FeatureWindow, CHANNELS};
use crate::identity::IdentityMap;
use crate::policy::{
    MitigationKind, MitigationRule, PolicySink, RuleSubject, RuleTable, ShapePattern, Verdict,
};
use crate::scout::Scout;
use crate::sequence::SequenceTracker;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FirewallPolicy {
    /// Detector score at/above which remediation triggers.
    pub anomaly_threshold: u32,
    /// Offense ladder: first anomaly uses index 0, repeats escalate.
    pub action_ladder: Vec<MitigationKind>,
    /// Base rule lifetime (ms). Multiplied by `ttl_growth`^(offense-1).
    pub ttl_ms: u64,
    pub ttl_growth: f32,
    /// Minimum ms between new rules against the same subject.
    pub cooldown_ms: u64,
    /// Window share (0..1) the top source must hold to get a targeted
    /// rule; below it the rule is Global.
    pub attribution_min_share: f32,
    /// Exempt anomalies driven purely by down-spikes (volume collapse vs
    /// baseline) from remediation — they're logged as informational
    /// `DownShift` records. Blocking recovery traffic is a self-inflicted
    /// blackout; inbound floods (any up-spike present) still escalate
    /// normally.
    #[serde(default = "default_true")]
    pub exempt_down_spikes: bool,
    /// |current - reference baseline| that trips a rule. The adaptive
    /// delta baseline absorbs slow walks; the frozen anchor can't.
    #[serde(default = "default_ref_drift")]
    pub ref_drift_threshold: f32,
    /// Feedback-driven mitigation search — try ordered candidates,
    /// measure next windows, keep the fix that actually drops the
    /// anomaly, and learn it into `playbook` for instant reuse.
    #[serde(default)]
    pub search: SearchPolicy,
    /// Feature window length (ms).
    pub tick_ms: u64,
}

fn default_true() -> bool {
    true
}

fn default_ref_drift() -> f32 {
    30.0
}

/// Ordered candidate mitigations the search iterates until the anomaly
/// actually drops — canary-first, never invents actions outside the
/// `MitigationKind` set. `enabled` is opt-in to keep the classic ladder
/// as the default path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SearchPolicy {
    pub enabled: bool,
    /// Tried in order until the flagged metric clears.
    pub candidates: Vec<MitigationKind>,
    /// Windows a candidate gets to prove itself before advancing.
    pub eval_windows: u32,
    /// Rule hits that confirm a candidate mid-attack — enforcement
    /// working on live traffic is proof, the anomaly needn't stop.
    pub confirm_hits: u64,
}

impl Default for SearchPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            candidates: vec![
                MitigationKind::RateLimit { max_rps: 50.0 },
                MitigationKind::RateLimit { max_rps: 10.0 },
                MitigationKind::Drop,
                MitigationKind::Block,
            ],
            eval_windows: 1,
            confirm_hits: 50,
        }
    }
}

/// Active search state for one attack shape.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct SearchStep {
    idx: usize,
    kind: MitigationKind,
    waited: u32,
    /// Flagged metric's value when the search began — improvement vs
    /// this is the metric-side confirmation.
    start_val: f32,
    /// After a candidate confirms, probe DOWNWARD for the minimal
    /// sufficient mitigation (weakest rung that still contains).
    descending: bool,
}

impl Default for FirewallPolicy {
    fn default() -> Self {
        Self {
            anomaly_threshold: 2,
            action_ladder: vec![
                MitigationKind::RateLimit { max_rps: 50.0 },
                MitigationKind::Drop,
                MitigationKind::Block,
            ],
            ttl_ms: 60_000,
            ttl_growth: 2.0,
            cooldown_ms: 30_000,
            attribution_min_share: 0.3,
            exempt_down_spikes: true,
            ref_drift_threshold: 30.0,
            search: SearchPolicy::default(),
            tick_ms: 1000,
        }
    }
}

pub struct Firewall<P: PolicySink, A: AuditLog> {
    detector: Detector,
    window: FeatureWindow,
    /// Engine policy — pub for tests/operator tuning (search, drift).
    pub policy: FirewallPolicy,
    rules: RuleTable,
    sink: P,
    audit: A,
    next_rule_id: u64,
    /// Per-subject offense count + last-rule timestamp (cooldown).
    subjects: HashMap<RuleSubject, (u32, u64)>,
    /// Ambiguous-attribution watchlist: an unattributed window's
    /// dominant source is *watched*, not ruled — it graduates to a real
    /// `Ip` rule only on repeat appearance. Hostile sources persist;
    /// a legit top_src misattribution is a one-off. Map: ip →
    /// (strikes, last_ms).
    watch: HashMap<IpAddr, (u8, u64)>,
    /// Tenant attributed to the current window (last event seen).
    tenant: String,
    sample_seq: u64,
    /// Explicit allow/deny primitives — checked before behavior.
    pub static_policy: StaticPolicy,
    /// Per-IP rate baselines — rotating-botnet blind spot.
    profiles: SourceProfiles,
    /// Port entropy / error rate / proto mix (log + inspectable).
    meta_win: MetaWindow,
    /// Long-window drift detector — catches low-and-slow attacks the
    /// delta encoder misses.
    slow: SlowTick,
    /// Inter-arrival regularity per source — beacons/C2 cadence.
    beacons: Beacons,
    /// Lenient scanner layer — profiles every event, never denies;
    /// flagged sources earn real rules.
    pub scout: Scout,
    /// Kill-chain predictor: recon+enumeration within a window predicts
    /// the exploit → pre-empt before the payload arrives.
    pub tracker: SequenceTracker,
    /// Actor fingerprints (ja3+ua) — flags transfer across IP rotation.
    pub identity: IdentityMap,
    /// Active mitigation searches, keyed by attack-shape
    /// (`subject:metric`) — search-and-verify, not blind escalation.
    search: HashMap<String, SearchStep>,
    /// Learned fixes: shape → the mitigation that cleared the anomaly.
    /// Survives restarts via `FirewallSnapshot` — instant replay on
    /// re-attack without re-searching.
    pub playbook: HashMap<String, MitigationKind>,
    /// Federated fixes: channel-indexed fixes learned by OTHER clients
    /// (zero-knowledge — the channel carries no identifying info).
    /// Consulted between the local playbook and a fresh search.
    pub shared: HashMap<u8, MitigationKind>,
    /// Borderline-anomaly strikes per subject — repeat borderline evals
    /// within 60s graduate to a real remediation (attacks persist,
    /// one-off borderlines don't).
    strikes: HashMap<String, (u32, u64)>,
    /// Learned-benign reputation: sources present in clean windows earn
    /// trust (0-5). Reputation ONLY shields against ambiguous window
    /// attribution (watch/strike paths) — explicit evidence (signatures,
    /// kill-chains, fingerprints, scout flags) still rules instantly.
    /// A real user accumulates innocence; an attacker never lingers
    /// benignly long enough.
    rep: HashMap<IpAddr, u8>,
}

impl<P: PolicySink, A: AuditLog> Firewall<P, A> {
    /// `initial_baselines` seeds the detector's delta baselines — pass
    /// observed normal values or startup registers as one anomaly burst.
    /// Baseline order must match `crate::event::channel_names()`.
    pub fn new(
        detector_config: DetectorConfig,
        policy: FirewallPolicy,
        initial_baselines: &[f32],
        sink: P,
        audit: A,
    ) -> Self {
        let tick_ms = policy.tick_ms;
        // Channel set can grow (jitter added as values[6]) — pad a
        // shorter baseline slice with zeros instead of asserting out.
        let mut baselines = initial_baselines.to_vec();
        baselines.resize(detector_config.metrics.len(), 0.0);
        Self {
            detector: Detector::new(detector_config, &baselines),
            window: FeatureWindow::new(policy.tick_ms),
            policy,
            rules: RuleTable::new(),
            sink,
            audit,
            next_rule_id: 1,
            subjects: HashMap::new(),
            watch: HashMap::new(),
            tenant: String::new(),
            sample_seq: 0,
            static_policy: StaticPolicy::default(),
            profiles: SourceProfiles::new(3.0, 10_000, tick_ms),
            meta_win: MetaWindow::default(),
            slow: SlowTick::new(60, 2.5, CHANNELS),
            beacons: Beacons::new(0.15, 6),
            scout: Scout::new(),
            tracker: SequenceTracker::default(),
            identity: IdentityMap::default(),
            search: HashMap::new(),
            playbook: HashMap::new(),
            shared: HashMap::new(),
            strikes: HashMap::new(),
            rep: HashMap::new(),
        }
    }

    /// Per-metric delta threshold override — e.g. hair-trigger
    /// `new_src_rate` (metric 5) while `req_rate` stays calm.
    pub fn set_metric_threshold(&mut self, metric: usize, v: f32) {
        self.detector.set_metric_threshold(metric, v);
    }

    /// Reputation feed: import one-IP-per-line blocklists into the
    /// static deny layer. Returns entries added.
    pub fn import_blocklist(&mut self, lines: impl Iterator<Item = String>) -> usize {
        self.static_policy.import_blocklist(lines)
    }

    /// Ingest one gateway event; returns the enforcement verdict.
    pub fn inspect(&mut self, ev: &ConnEvent) -> io::Result<Verdict> {
        self.tenant = ev.tenant.clone();

        // 1. TTL sweep — expiry revokes downstream too.
        for rule in self.rules.sweep(ev.ts_ms) {
            self.sink.revoke(rule.id)?;
            self.audit.record(AuditRecord {
                ts_ms: ev.ts_ms,
                tenant: ev.tenant.clone(),
                src: rule_src(&rule),
                kind: AuditKind::Expiry { rule_id: rule.id },
            });
        }

        // 2. Static policy: deny short-circuits; allow is SOFT — the
        // source still feeds every detector, but flags become audit
        // alerts instead of rules. A trusted IP turning hostile is
        // seen, not blindly passed.
        if self.static_policy.deny.contains_key(&ev.src_ip) {
            return Ok(Verdict::Denied { rule: 0 });
        }
        let soft = self.static_policy.allow.contains(&ev.src_ip);

        // 3. Enforce against live rules — soft sources are enforcement-
        // exempt but fully observed.
        let mut verdict = self.rules.check(ev);
        if soft && !matches!(verdict, Verdict::Allow) {
            verdict = Verdict::Allow;
        }

        // Meta + per-IP profile + beacon tracking see every event.
        self.meta_win.observe(ev);
        let profile_hit = self.profiles.observe(ev);
        let beacon_hit = self.beacons.observe(ev);
        // Scout layer: silent profiling — suspicion feeds enforcement.
        let scout_hit = self.scout.observe(ev);
        let mut ruled_now = false;
        // Kill-chain: classify stage; recon+enum inside the window →
        // the exploit is predicted → pre-empt BEFORE it lands.
        let sig_mask = ev
            .payload
            .as_deref()
            .map(|p| Signatures::scan(p))
            .unwrap_or(0);
        let sig_hit = sig_mask != 0;
        // Agent guardrail: credential/key material leaving the machine
        // gets an immediate rule — a secret should never exfiltrate.
        if sig_mask & 64 != 0 {
            ruled_now |= self.emit(
                RuleSubject::Ip(ev.src_ip),
                "credential/api-key material in outbound data".to_string(),
                ev.ts_ms,
            )?;
        }
        // Attack-class signatures (SQLi/XSS/traversal/shell/scanner/JNDI
        // — bits 1-32) are ground truth: one malicious request denies,
        // no volume needed. Signatures enforce, they don't just score.
        if sig_mask & 63 != 0 {
            // Hard Drop — not the offense ladder: a signature is proof,
            // the triggering request itself must not pass.
            ruled_now |= self.emit_with(
                RuleSubject::Ip(ev.src_ip),
                Some(MitigationKind::Drop),
                "malicious payload signature".to_string(),
                ev.ts_ms,
            )?;
        }
        let predicted = self.tracker.observe(ev, sig_hit);
        // Actor fingerprint: a flagged ja3+ua on a NEW source IP is a
        // rotation — flag it on event one, no re-learning needed.
        let actor_flagged = self.identity.observe(ev, sig_hit || predicted);

        // 4. Feature windowing; a finalized window gets scored.
        if let Some(fv) = self.window.observe(ev) {
            ruled_now = self.evaluate(&fv, ev)?;
        }

        // Per-source baseline breach → attributed rule straight away.
        if let Some(ip) = profile_hit {
            ruled_now |= self.emit(
                RuleSubject::Ip(ip),
                "per-source baseline breach".to_string(),
                ev.ts_ms,
            )?;
        }
        // Machine-cadence inter-arrivals → beacon/C2 → attributed rule.
        if let Some(ip) = beacon_hit {
            ruled_now |= self.emit(
                RuleSubject::Ip(ip),
                "beacon cadence (regular inter-arrival)".to_string(),
                ev.ts_ms,
            )?;
        }
        // Predicted kill-chain — recon+enum saw steps 0+1: emit the
        // pre-emptive rule BEFORE the exploit payload ever lands.
        if predicted {
            ruled_now |= self.emit(
                RuleSubject::Ip(ev.src_ip),
                "predicted kill-chain (recon+enum → exploit imminent)".to_string(),
                ev.ts_ms,
            )?;
        }
        // Actor fingerprint match — the same ja3+ua flagged under
        // another IP: rotation detected, pre-empt instantly.
        if actor_flagged {
            ruled_now |= self.emit(
                RuleSubject::Ip(ev.src_ip),
                "actor fingerprint match (ip rotation)".to_string(),
                ev.ts_ms,
            )?;
        }
        // Scout flagged this event — emit + consume (score must
        // re-accumulate through renewed attack behavior).
        if let Some(scout_score) = scout_hit {
            let emitted = self.emit(
                RuleSubject::Ip(ev.src_ip),
                format!("scout suspicion {:.2}", scout_score),
                ev.ts_ms,
            )?;
            if emitted {
                self.scout.consumed_flag(ev.src_ip);
                ruled_now = true;
            }
        }

        // A rule created this call may catch this same event — re-check
        // only in that case (check() consumes rate-limit tokens). Soft
        // sources always Allow — enforced elsewhere means audited here.
        Ok(match verdict {
            Verdict::Allow if ruled_now && !soft => self.rules.check(ev),
            v => v,
        })
    }

    /// Score one finalized window through the SNN and remediate if needed.
    /// Returns `true` when a new rule was inserted.
    fn evaluate(&mut self, fv: &FeatureVector, ev: &ConnEvent) -> io::Result<bool> {
        // Slow-window drift + meta channels cycle with the fast window.
        let slow_hits = self.slow.push(fv);
        let meta = self.meta_win.values();
        self.meta_win.reset();

        self.sample_seq += 1;
        let mut values = fv.values.clone();
        values.extend(meta); // channels 7-15: port entropy … ja3_diversity
        values.push(fv.jitter); // index 15 — appended last, baseline-stable
        let sample = TelemetrySample {
            seq: self.sample_seq,
            ts_ms: fv.start_ms,
            values,
        };
        let det: Detection = self.detector.observe(&sample);

        let src = fv.top_src.map(|(ip, _)| ip);
        self.audit.record(eval_record(
            fv.start_ms,
            ev.tenant.clone(),
            src,
            det.score,
            det.anomaly && det.score >= self.policy.anomaly_threshold,
            det.max_deviation,
        ));

        // Reference-anchor breach: |observed - frozen baseline| escapes
        // adaptive absorption entirely — slow walks stay visible.
        let ref_breach = det.reference_drift > self.policy.ref_drift_threshold;
        // Reputation: a clean window accrues trust to its participants
        // — innocence accumulates over time, and ONLY shields ambiguous
        // window attribution, never signature/scout/chain evidence.
        if !det.anomaly && !ref_breach {
            if let Some((ip, _)) = fv.top_src {
                let e = self.rep.entry(ip).or_insert(0);
                *e = (*e).saturating_add(1).min(5);
            }
        }
        if (det.anomaly && det.score >= self.policy.anomaly_threshold) || ref_breach {
            // Down-driven or stale-echo anomaly: this eval's input was
            // pure down-spike, OR no up-channel activity for 2+ evals
            // (covers refractory gaps in an attack AND silent evals
            // carrying detector echo from the previous window). Logged
            // as informational; never escalated — there's no actor left
            // to block. Up-spikes anywhere ⇒ inbound flood ⇒ remediate.
            let down_driven =
                (det.up_spikes == 0 && det.down_spikes > 0) || det.up_free_streak >= 2;
            if self.policy.exempt_down_spikes && down_driven {
                self.audit.record(downshift_record(
                    fv.start_ms,
                    ev.tenant.clone(),
                    src,
                    det.score,
                    det.max_deviation,
                ));
                return Ok(false);
            }
            return self.remediate(fv, &det, ev);
        }

        // Distributed scan: 4+ distinct srcs sharing one request shape —
        // the fingerprint every per-IP rate channel misses entirely.
        let shared_srcs = self.meta_win.shared_shape_srcs();
        if shared_srcs >= 4 && (ev.meta.method == 0 || ev.meta.path_len == 0 || ev.meta.dst_port > 0) {
            return self.emit(
                RuleSubject::Pattern(ShapePattern {
                    method: ev.meta.method,
                    proto: ev.meta.proto,
                    dst_port: ev.meta.dst_port,
                    max_path_len: ev.meta.path_len,
                }),
                format!("distributed scan — {shared_srcs} srcs, one shape"),
                ev.ts_ms,
            );
        }
        // Slow-drip (slowloris): tiny rate + very long inter-arrivals.
        if fv.mean_gap_ms > 8_000.0 && fv.values.first().copied().unwrap_or(0.0) < 1.0 {
            if let Some((ip, _)) = fv.top_src {
                return self.emit(
                    RuleSubject::Ip(ip),
                    "slow-drip connection hold".to_string(),
                    ev.ts_ms,
                );
            }
        }

        // ── persistence-strikes + joint correlation (TPR frontier) ──
        // A borderline eval — detector anomalous but under the firewall
        // threshold, OR many channels mildly deviant TOGETHER — doesn't
        // rule on its own. Instead it strikes: repeat borderline evals
        // on the same subject graduate to a real mitigation (attacks
        // persist; a borderline eval that happens once doesn't).
        let joint_dev: f32 = fv
            .values
            .iter()
            .zip(det.baselines.iter())
            .map(|(v, b)| (*v - *b).abs() / b.max(1.0))
            .sum();
        let borderline = det.anomaly || joint_dev > 1.5;
        let down_driven2 =
            (det.up_spikes == 0 && det.down_spikes > 0) || det.up_free_streak >= 2;
        // Defer to the kill-chain: an in-flight chain predicts the same
        // threat with a better reason — don't let a strike rule land
        // first and suppress the "predicted kill-chain" emit.
        let chain_in_flight = fv
            .top_src
            .map(|(ip, _)| self.tracker.has_progress(&ip, fv.start_ms))
            .unwrap_or(false);
        // No strikes during cold start — the baseline needs ~10 evals
        // before deviations mean anything; graduating earlier is noise.
        let trusted = fv
            .top_src
            .map(|(ip, _)| self.rep.get(&ip).copied().unwrap_or(0) >= 3)
            .unwrap_or(false);
        if borderline && !down_driven2 && !chain_in_flight && !trusted && self.sample_seq > 10 {
            let key = if let Some((ip, _)) = fv.top_src {
                format!("ip:{ip}")
            } else {
                format!("shape:{}:{}", ev.meta.proto, ev.meta.dst_port)
            };
            let n = {
                let e = self.strikes.entry(key.clone()).or_insert((0, 0));
                if fv.start_ms.saturating_sub(e.1) > 60_000 {
                    *e = (0, fv.start_ms);
                }
                e.0 += 1;
                e.1 = fv.start_ms;
                e.0
            };
            if n >= 2 {
                self.strikes.remove(&key);
                return self.remediate(fv, &det, ev);
            }
        }
        // Low-and-slow: gradual drift the delta encoder misses → scope
        // by shape when the attack is bare; Global only as last resort.
        if !slow_hits.is_empty() {
            let subject = if ev.meta.method == 0 || ev.meta.path_len == 0 {
                RuleSubject::Pattern(ShapePattern {
                    method: ev.meta.method,
                    proto: ev.meta.proto,
                    dst_port: ev.meta.dst_port,
                    max_path_len: ev.meta.path_len,
                })
            } else {
                RuleSubject::Global
            };
            return self.emit(
                subject,
                format!("slow-tick drift on channels {slow_hits:?}"),
                ev.ts_ms,
            );
        }
        // Clean eval — any pending searches proved their last candidate.
        self.close_searches();
        Ok(false)
    }

    /// Rule generation: attribute → pick ladder rung → enforce + push + audit.
    /// Returns `true` when a new rule was inserted.
    fn remediate(&mut self, fv: &FeatureVector, det: &Detection, ev: &ConnEvent) -> io::Result<bool> {
        let now_ms = ev.ts_ms;
        // Attribution: dominant source gets the rule; diffuse gets a
        // shape-scoped Pattern (TNR-preserving) or Global as last resort.
        // req_rate is events/sec — convert back to a count for the share.
        let total_events = (fv.values[0] * self.policy.tick_ms as f32 / 1000.0).max(f32::EPSILON);
        let subject = match fv.top_src {
            Some((ip, count))
                if count as f32 / total_events >= self.policy.attribution_min_share =>
            {
                RuleSubject::Ip(ip)
            }
            _ => {
                // Bare-shaped attack (scans, SYN floods, raw probes —
                // no method and/or no path) can be scoped by transport
                // shape: legitimate HTTP requests never match it.
                if ev.meta.method == 0 || ev.meta.path_len == 0 {
                    RuleSubject::Pattern(ShapePattern {
                        method: ev.meta.method,
                        proto: ev.meta.proto,
                        dst_port: ev.meta.dst_port,
                        max_path_len: ev.meta.path_len,
                    })
                } else if self
                    .active_rules()
                    .iter()
                    .any(|r| matches!(r.subject, RuleSubject::Pattern(_)))
                {
                    // A non-bare event triggered this anomaly — we can't
                    // scope it — but a live Pattern rule already covers
                    // the attack's shape. A new Global adds only
                    // collateral (TNR loss) — skip it.
                    return Ok(false);
                } else if let Some((ip, _)) = fv.top_src {
                    // No shape to scope by — ambiguous attribution.
                    // Reputation shield: a source with accrued clean
                    // history is watched, never ruled on co-presence.
                    // Then watchlist: only a REPEAT top_src graduates.
                    if self.rep.get(&ip).copied().unwrap_or(0) >= 3
                        || !self.watch_graduate(ip, now_ms)
                    {
                        return Ok(false);
                    }
                    RuleSubject::Ip(ip)
                } else {
                    RuleSubject::Global
                }
            }
        };

        // Structural-evidence gate: a pure rate-channel anomaly
        // (req_rate/new_srcs) on well-formed HTTP traffic is almost
        // always a benign burst (page load, image batch) — throttle,
        // never drop. Bare shapes and payload channels keep the ladder.
        if matches!(subject, RuleSubject::Ip(_))
            && ev.meta.method != 0
            && ev.meta.path_len > 0
        {
            let dom = fv
                .values
                .iter()
                .zip(det.baselines.iter())
                .enumerate()
                .max_by(|(_, a), (_, b)| {
                    (a.0 - a.1)
                        .abs()
                        .partial_cmp(&(b.0 - b.1).abs())
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|(i, _)| i)
                .unwrap_or(0);
            if dom <= 1 {
                return self.emit_with(
                    subject.clone(),
                    Some(MitigationKind::RateLimit { max_rps: 10.0 }),
                    format!(
                        "rate-channel anomaly, well-formed traffic (score={})",
                        det.score
                    ),
                    now_ms,
                );
            }
        }

        if self.policy.search.enabled {
            return self.search_or_fix(fv, det, subject, now_ms);
        }
        self.emit(
            subject.clone(),
            format!(
                "snn anomaly: score={} dev={:.1} subject={:?}",
                det.score, det.max_deviation, subject
            ),
            now_ms,
        )
    }

    /// Ambiguous-attribution gate: a top_src must appear dominant in
    /// ≥2 unattributed anomalous windows (within 60s) before graduating
    /// to a real Ip rule. Prunes stale entries; returns true when the
    /// strike threshold is met.
    fn watch_graduate(&mut self, ip: IpAddr, now_ms: u64) -> bool {
        const WINDOW_MS: u64 = 60_000;
        const STRIKES: u8 = 2;
        self.watch.retain(|_, (_, last)| now_ms - *last < WINDOW_MS);
        let e = self.watch.entry(ip).or_insert((0, now_ms));
        e.0 = e.0.saturating_add(1);
        e.1 = now_ms;
        if e.0 >= STRIKES {
            self.watch.remove(&ip);
            true
        } else {
            false
        }
    }

    /// Feedback-driven mitigation search: playbook hit → instant reuse;
    /// else iterate the ordered candidates — each gets `eval_windows`
    /// to clear the anomaly before advancing to a harsher fix.
    fn search_or_fix(
        &mut self,
        fv: &FeatureVector,
        det: &Detection,
        subject: RuleSubject,
        now_ms: u64,
    ) -> io::Result<bool> {
        // Dominant channel = attack shape (req flood vs new-src churn vs
        // payload scan). The shape keys the learned playbook.
        let dom = fv
            .values
            .iter()
            .zip(det.baselines.iter())
            .enumerate()
            .max_by(|(_, a), (_, b)| {
                (a.0 - a.1)
                    .abs()
                    .partial_cmp(&(b.0 - b.1).abs())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(i, _)| i)
            .unwrap_or(0);
        let key = format!("{:?}:{}", subject, dom);
        if let Some(kind) = self.playbook.get(&key).cloned() {
            return self.emit_with(subject, Some(kind), format!("playbook fix: {key}"), now_ms);
        }
        // Federated fix — the herd learned this anomaly channel's fix.
        if let Some(kind) = self.shared.get(&(dom as u8)).cloned() {
            return self.emit_with(subject, Some(kind), format!("herd fix: ch{dom}"), now_ms);
        }
        // First anomaly for this shape → register the search + emit
        // candidate 0.
        if !self.search.contains_key(&key) {
            let kind = self.policy.search.candidates[0].clone();
            let start_val = fv.values.get(dom).copied().unwrap_or(0.0);
            self.search.insert(
                key.clone(),
                SearchStep {
                    idx: 0,
                    kind: kind.clone(),
                    waited: 0,
                    start_val,
                    descending: false,
                },
            );
            return self.emit_with(subject, Some(kind), format!("search {key} cand0"), now_ms);
        }

        // Snapshot the search decision before mutating borrows.
        let (idx, descending, waited) = {
            let st = self.search.get(&key).unwrap();
            (st.idx, st.descending, st.waited)
        };

        let hits = self.rules.hits_for(&subject);
        let improved = fv
            .values
            .get(dom)
            .map(|v| *v <= self.search.get(&key).map(|s| s.start_val).unwrap_or(0.0) * 0.6)
            .unwrap_or(false);
        // Descent confirms only on metric improvement — a weaker rule
        // still accumulates hits while letting traffic through.
        let confirmed = improved || (!descending && hits >= self.policy.search.confirm_hits);

        if waited + 1 < self.policy.search.eval_windows {
            self.search.get_mut(&key).unwrap().waited = waited + 1;
            return Ok(false);
        }

        // Decide the next index.
        let candidates_len = self.policy.search.candidates.len();
        let (next_idx, done_kind) = if confirmed {
            if descending {
                if idx == 0 {
                    (0, Some(self.policy.search.candidates[0].clone()))
                } else {
                    (idx - 1, None) // keep probing weaker
                }
            } else if idx == 0 {
                (0, Some(self.policy.search.candidates[0].clone())) // weakest confirmed
            } else {
                (idx - 1, None) // start descending
            }
        } else if descending {
            // Weaker rung failed to contain → revert to the last
            // confirmed level (idx+1) — that's the minimal fix.
            (
                idx + 1,
                Some(self.policy.search.candidates[idx + 1].clone()),
            )
        } else {
            ((idx + 1).min(candidates_len - 1), None) // escalate
        };

        if let Some(kind) = done_kind {
            self.playbook.insert(key.clone(), kind);
            self.search.remove(&key);
            // Restore the confirmed rule if descent overstepped.
            if descending && !confirmed {
                if let Some(old) = self.rules.remove_subject(&subject) {
                    let _ = self.sink.revoke(old.id);
                }
                let _ = self.emit_with(
                    subject,
                    Some(self.playbook[&key].clone()),
                    format!("search {key} revert"),
                    now_ms,
                );
            }
            return Ok(false);
        }

        {
            let st = self.search.get_mut(&key).unwrap();
            st.idx = next_idx;
            // Confirmation starts the descent probe; escalation keeps
            // climbing (stays ascending until the first confirm).
            st.descending = descending || confirmed;
            st.waited = 0;
            st.kind = self.policy.search.candidates[next_idx].clone();
        }
        if let Some(old) = self.rules.remove_subject(&subject) {
            let _ = self.sink.revoke(old.id);
        }
        let kind = self.policy.search.candidates[next_idx].clone();
        self.emit_with(
            subject,
            Some(kind),
            format!("search {key} cand{next_idx}"),
            now_ms,
        )
    }

    /// A clean eval closes every pending search — the last candidate
    /// per shape is the learned fix → into the playbook.
    fn close_searches(&mut self) {
        for (key, step) in self.search.drain() {
            self.playbook.insert(key, step.kind);
        }
    }

    /// Shared rule-push: dedupe → cooldown → ladder → insert + sink + audit.
    fn emit(&mut self, subject: RuleSubject, reason: String, now_ms: u64) -> io::Result<bool> {
        self.emit_with(subject, None, reason, now_ms)
    }

    /// `emit` with an explicit mitigation kind (search/playbook path);
    /// `None` picks the offense ladder rung as usual.
    fn emit_with(
        &mut self,
        subject: RuleSubject,
        kind_override: Option<MitigationKind>,
        reason: String,
        now_ms: u64,
    ) -> io::Result<bool> {
        // Soft-allowed IP subjects: flag → audit alert, never a rule.
        if let RuleSubject::Ip(ip) = &subject {
            if self.static_policy.allow.contains(ip) {
                self.audit.record(AuditRecord {
                    ts_ms: now_ms,
                    tenant: self.tenant.clone(),
                    src: Some(*ip),
                    kind: AuditKind::Alert { reason },
                });
                return Ok(false);
            }
        }
        // Don't stack a second live rule on the same subject.
        if self.rules.has_subject(&subject) {
            return Ok(false);
        }

        // Cooldown: don't re-rule a subject that's still hot.
        let (offense, last_ms) = self.subjects.get(&subject).copied().unwrap_or((0, 0));
        if now_ms.saturating_sub(last_ms) < self.policy.cooldown_ms {
            return Ok(false);
        }
        let offense = offense + 1;
        self.subjects.insert(subject.clone(), (offense, now_ms));

        let kind = match kind_override {
            Some(k) => k,
            None => {
                let ladder_idx = (offense as usize - 1).min(self.policy.action_ladder.len() - 1);
                self.policy.action_ladder[ladder_idx].clone()
            }
        };
        let ttl =
            (self.policy.ttl_ms as f32 * self.policy.ttl_growth.powi(offense as i32 - 1)) as u64;

        let rule = MitigationRule {
            id: self.next_rule_id,
            subject,
            kind,
            created_ms: now_ms,
            expires_ms: now_ms.saturating_add(ttl),
            offense,
            reason,
        };
        self.next_rule_id += 1;

        // Enforce locally first (never depends on downstream success),
        // then push to the proxy/fetch policy layer.
        self.rules.insert(rule.clone());
        self.sink.apply(&rule)?;
        self.audit
            .record(mitigation_record(now_ms, self.tenant.clone(), rule));
        Ok(true)
    }

    /// Live rules — for the orchestrator's status/policy endpoints.
    pub fn active_rules(&self) -> Vec<&MitigationRule> {
        (1..self.next_rule_id)
            .filter_map(|id| self.rules.get(id))
            .collect()
    }

    pub fn detector(&self) -> &Detector {
        &self.detector
    }

    pub fn sink_mut(&mut self) -> &mut P {
        &mut self.sink
    }

    pub fn audit(&self) -> &A {
        &self.audit
    }

    /// Persistable state: the learned brain (detector checkpoint incl.
    /// baselines + STDP traces), live unexpired rules, offense counters,
    /// and the rule-id counter. The feature window is transient and
    /// deliberately not restored — a restarted engine re-baselines on
    /// fresh traffic, which is the safe direction.
    pub fn snapshot(&self) -> io::Result<FirewallSnapshot> {
        Ok(FirewallSnapshot {
            detector: self.detector.checkpoint()?,
            subjects: self
                .subjects
                .iter()
                .map(|(s, &(offense, _))| (s.clone(), offense))
                .collect(),
            next_rule_id: self.next_rule_id,
            rules: self.active_rules().into_iter().cloned().collect(),
            playbook: self.playbook.clone(),
            tracker: self.tracker.clone(),
            identity: self.identity.clone(),
        })
    }

    /// Rebuild from a snapshot. Live rules are reinserted AND re-applied
    /// to `sink` — downstream may have lost them during the restart, so
    /// the push is deliberately idempotent-on-restore.
    pub fn restore(
        detector_config: DetectorConfig,
        policy: FirewallPolicy,
        snap: FirewallSnapshot,
        sink: P,
        audit: A,
    ) -> io::Result<Self> {
        let FirewallSnapshot {
            detector,
            subjects,
            next_rule_id,
            rules,
            playbook,
            tracker,
            identity,
        } = snap;
        // Baselines are irrelevant post-restore — the checkpointed encoder
        // overwrites them — but `new` requires a correctly-sized slice.
        let zeros = vec![0.0; detector_config.metrics.len()];
        let mut this = Self::new(detector_config.clone(), policy, &zeros, sink, audit);
        this.detector = Detector::from_checkpoint(detector_config, detector)?;
        this.subjects = subjects.into_iter().map(|(s, o)| (s, (o, 0))).collect();
        this.next_rule_id = next_rule_id;
        this.playbook = playbook;
        this.tracker = tracker;
        this.identity = identity;
        for rule in rules {
            this.rules.insert(rule.clone());
            this.sink.apply(&rule)?;
        }
        Ok(this)
    }
}

/// Serializable engine state produced by [`Firewall::snapshot`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FirewallSnapshot {
    pub detector: Checkpoint,
    /// `(subject, offense_count)` — cooldown timestamps restart at 0, so
    /// a reboot can re-rule a still-offending subject immediately.
    pub subjects: Vec<(RuleSubject, u32)>,
    pub next_rule_id: u64,
    pub rules: Vec<MitigationRule>,
    /// Learned fixes from the search path — survives restarts so a
    /// repeat attack hits the known-working mitigation instantly.
    #[serde(default)]
    pub playbook: HashMap<String, MitigationKind>,
    /// Kill-chain prediction state — survives restarts so an attacker
    /// mid-sequence stays predicted across reboots.
    #[serde(default)]
    pub tracker: SequenceTracker,
    /// Actor fingerprints — flagged ja3+ua identities survive restarts.
    #[serde(default)]
    pub identity: IdentityMap,
}
