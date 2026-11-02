# SNN — pure Rust spiking neural network workspace

## Layout

- `crates/snn-core` — hybrid clock-driven sim: `NeuronModel` trait, LIF +
  Izhikevich neurons, CSR synapses (`SparseSynapses`, hand-rolled for in-place
  STDP mutation + aligned per-synapse delays), `DelayQueue` ring buffer for
  axonal delays, rayon-parallel `Network::step`. No RNG in core — deterministic.
- `crates/snn-encode` — `PoissonEncoder` (seeded `StdRng`, not serde) and
  `DeltaModulator` (serde, up/down channels) for telemetry → spikes.
- `crates/snn-learn` — `StdpLearner`: trace-based pairwise STDP, lives outside
  `Network`; apply via `snn_learn::apply_all(&mut learners, &frame, &mut net)`.
- `crates/snn-io` — `Checkpoint` (serde + bincode): weights, membranes,
  refractory counters, STDP traces, in-flight delayed spikes, step count.
  `to_bytes`/`from_bytes` are the Postgres `bytea` seam; `save`/`load` for files.
  `aux` map carries named blobs for layers above (encoder state, detector
  bookkeeping).
- `crates/snn-mesh` — Phase 2 integration: `Detector` (delta-encode → SNN →
  STDP → rolling anomaly score), `CheckpointStore` trait + `FileStore` /
  `MemoryStore` / `PostgresStore` (feature `postgres-store`, off by default),
  `Agent` (detector + store + cadence — what a worker holds), `run_worker`
  (mpsc in, detections out).
- `crates/snn-firewall` — behavioral firewall: `FeatureWindow` buckets
  `ConnEvent`s into 1 s metric vectors, `Firewall` evaluates through a
  `Detector` and on anomaly generates TTL'd `MitigationRule`s (escalation
  ladder, cooldown, IP/Global attribution). Local enforcement via
  `RuleTable` (incl. rate-limit token buckets); downstream push via
  `PolicySink`; tenant-scoped `AuditLog` (`JsonlAudit` → `jobs/{id}/
  network.jsonl`). `FirewallSnapshot`/`restore` for persistence.
- `crates/snn-runtime` — orchestrator: `JobSpec` → `Job` (telemetry `Agent`
  + `Firewall` + per-component stores), `StoreFactory`/`SinkFactory`
  injection, `JsonApi` (JSON strings in/out — the Wasm/IPC surface),
  `sinks`: `FilePolicySink` (atomic policy.json for watched-config
  proxies) + `HttpPolicySink` (`PUT/DELETE /rules/{id}`, feature
  `http-sink` → ureq).
- `crates/snn-wasm` — `WasmShim` (native-testable JSON façade) +
  `#[wasm_bindgen]` `SnnFirewall` under `cfg(target_arch="wasm32")`.
  Verified to compile for `wasm32-unknown-unknown`.
- `crates/swarm` — live nodes: `swarm-worker` bin (TCP listener →
  Orchestrator → Verdict/Detection; rules → FilePolicySink + upstream
  Report) and `swarm-orchestrator` bin (Report frames →
  `jobs/{id}/mesh.jsonl`). Protocol: 4-byte BE len + JSON `Frame`.
  Windows gotcha: accepted sockets inherit listener nonblocking —
  `set_nonblocking(false)` before framed I/O.

## Commands

- `cargo test` — full suite (dynamics math, propagation latency, STDP sign,
  encoder determinism, checkpoint bit-identical resume). All green.
- `cargo run -p snn-io --example telemetry_anomaly` — end-to-end demo.

### Newer layers (post-v5)

- `Scout` (scout.rs) — lenient profiler: suspicion = persistence (5s spans,
  machine-rate gated) + payload shape + sig hits. `observe` returns
  `Some(score)` ONLY when the event contributed AND crossed `flag_at`;
  successful emits consume the score (→ flag_at/2). Never blocks itself.
- `SequenceTracker` (sequence.rs) — kill-chain prediction: stage0=unusual
  dst_port, stage1=errors/long-paths, stage2=sig hit. recon+enum inside
  `window_ms` (60s) → pre-emptive rule BEFORE the exploit lands.
- `IdentityMap` (identity.rs) — actor fingerprint `ja3<<16|ua_id`;
  flagged actor on a NEW ip → "actor fingerprint match" rule on event
  one. Skipped when ja3==0 (no TLS → no stable identity; NAT-safe).
- `PcapSource` (enhance.rs) — pure-Rust libpcap parser (LE magic,
  Ethernet/IPv4/TCP) → `ConnEvent`; `EventSource` impl. Live capture
  verified via scapy+Npcap → real .pcap → replay.
- `SearchPolicy` (engine.rs) — ordered candidates; mid-attack
  confirmation via rule `hits` (ascending) or metric improvement
  (descent only); descend probes for MINIMAL sufficient fix; failures
  revert to last confirmed rung; learned fixes land in `playbook`
  (subject:dom_metric → MitigationKind, serialized in snapshot).
- `http_shield` (swarm/src/bin) — HTTP front: request → ConnEvent →
  verdict → 200 / tarpit (chunked fake page dripped at 400ms/chunk —
  no 403 notice, wastes attacker compute). Parses X-Forwarded-For/
  CF-Connecting-IP/X-Real-IP → src_ip. Thread-per-conn + shared
  Mutex<Firewall> (verdicts serialize; tarpits can't block others).
- Tests: `realworld.rs` (sqlmap/nikto/slowloris profiles),
  `livepcap.rs` (real capture replay, skips if absent),
  `universal_fuzz.rs` (200k events, 80/20 legit-mix collateral metric).

## Invariants (do not break)

- Fixed step order: deliver → integrate (parallel) → propagate → clear inputs.
- STDP order: decay → pre spikes (LTD) → post spikes (LTP).
- CSR layout sorted by `(pre, post)`; delay d delivers at spike_step + 1 + d.
- Weights mutate ONLY via `SparseSynapses::add_weight` (enforces bounds).
- `FORMAT_VERSION` in snn-io gates checkpoint compat — bump on layout change
  (v2 added `aux`; v6 = 15-channel detectors + reference/rebound state).
- `scout.rs` — the lenient first gate (Gemini's "honey-gateway"): profiles
  every event, never denies. `Persistence` (5s-span contact counts —
  catches modeless beacons via VOLUME of check-ins), payload shape
  (entropy + printable ratio), sig hits → per-IP suspicion; `observe`
  returns `Some(score)` ONLY when that event contributed AND score ≥
  `flag_at` (passive residue can't flag — self-heal preserved); a
  successful `emit` calls `consumed_flag` (score → flag_at/2).
- `DetectorState.reference` = frozen anchor baselines;
  `Detection.reference_drift` = max|observed − anchor| —
  `ref_drift_threshold` (default 30) trips a rule where the adaptive
  encoder would absorb a slow walk.
- Detector input layout: metric i → channels 2i (up) / 2i+1 (down).
- `DeltaModulator` ratchets only on |diff| > threshold — baselines converge
  to within one threshold of the signal, not exactly to it.
- Evaluation lags one tick (window finalizes on the NEXT window's first
  event) and detector spikes lag one step — tests need ≥2 anomalous
  windows before rules land.
- Flood RECOVERY is anomalous too (baseline ratcheted high → down-spikes) —
  but `FirewallPolicy::exempt_down_spikes` (default true) logs them as
  `AuditKind::DownShift` instead of ruling. Exemption fires when the eval is
  down-driven (`up==0 && down>0`) OR `up_free_streak >= 2` (refractory gaps
  + silent evals carrying detector echo). Any up-spike ⇒ full escalation.
- `DetectorState.up_free_streak` serializes into checkpoints → bincode can't
  skip fields, so the bump revved `FORMAT_VERSION` to 3.
- Rebound semantics: a down-spike sets `DetectorState.rebound[metric]`; the
  next up-spike on that metric counts as down-direction (post-attack
  normalization is recovery swing, not new evidence).
- `enhance.rs`: `StaticPolicy` (allow/deny, deny→`Denied{rule:0}`),
  `SlowTick` (60-tick drift → Global, σ floored at 1), `SourceProfiles`
  (per-IP z-score → Ip rule, σ floored at 1), `Beacons` (CV + linear-50ms
  gap-histogram; gaps <50ms = burst-internal, skipped; flag needs last
  gap in dominant bucket pair — NO persistence path: ratio heuristics
  false-flag unbounded walks), `MetaWindow` (channels 7–15 ×100; engine
  computes entropy+sig itself when `ConnEvent.payload` attached),
  `Signatures` (normalize: comment-strip/%XX-decode/ws-collapse; bits
  1,2,4,8,16,32,64,128), `EventSource`/`JsonlSource` ingest seam.
- Detector score counts input+detector spikes — a lone channel firing
  can't always drive a detector neuron but repeated firing IS evidence.
- DOCUMENTED blind spots (pinned by adversarial.rs tests): modeless
  random-walk beacons (information-theory boundary), producer meta when
  `payload` isn't attached, sustained sub-threshold signal absorption
  (delta encoder learns new normal — by design), content beyond the
  signature bitmask.
- `Firewall::emit` is the shared rule path (dedupe → cooldown → ladder →
  insert/push/audit) for SNN anomalies, profiles, slow-tick, and beacons.
- Per-metric `DeltaModulator::set_threshold` overrides ride inside the
  encoder aux blob. `FORMAT_VERSION` = 6 (15-channel detectors).
- Rules ALWAYS carry `expires_ms`; `RuleTable::sweep` reaps on every
  event. `has_subject` prevents rule stacking per subject.
- Firewall `remediate` attribution ladder (TNR-preserving):
  top_src_share ≥ `attribution_min_share` → `RuleSubject::Ip`;
  bare-shaped trigger (method==0 || path_len==0) → `RuleSubject::Pattern`
  (`ShapePattern{method,proto,dst_port,max_path_len}` — scans/floods get
  scoped, legit HTTP never matches); a live Pattern rule + non-bare
  trigger → skip (no Global stacking); window has top_src →
  `Ip(top_src)` (narrow misattribution beats Global collateral);
  else `Global` (last resort). Same bare→Pattern gate applies to the
  `slow_hits` drift path. `RuleSubject` is serialized — enum growth
  requires `FORMAT_VERSION` bump only if snapshots cross the wire
  (ProxyRule maps Pattern → `"pattern:mXpYdZxW"`).

## Integration hooks

- Worker holds an `Agent<S: CheckpointStore>`; producers feed
  `TelemetrySample`s through `run_worker` (or call `agent.observe` directly).
- `TelemetrySample`/`Detection`/`ConnEvent`/`Verdict`/`JobSpec`/`AuditRecord`
  are all serde — safe across IPC/Wasm boundaries. `JsonApi` is the
  ready-made JSON string façade.
- Postgres: build with `--features postgres-store`, then
  `PostgresStore::connect(conn_str, "{worker_id}:snn")`. Table
  `snn_checkpoints` is auto-created (name, state bytea, step_count, ts).
- Checkpoint cadence: `agent.checkpoint_every` (default 1000 samples);
  `run_worker`/`Orchestrator::flush` persist on shutdown too.
- `Orchestrator::register` restores BOTH telemetry agent and firewall
  snapshot; a fresh orchestrator on the same stores keeps enforcing live
  rules and re-applies them to the sink.
- Blanket impls exist for `&T`/`Arc<T>`/`Box<dyn>` on `CheckpointStore`,
  and `Box<dyn>` on `PolicySink`/`AuditLog` — jobs are type-erased.
- Live Postgres test: `SNN_TEST_PG="postgres://..." cargo test -p snn-mesh
  --features postgres-store` (skips cleanly when unset).
- Proxy push contract: `ProxyRule {id, subject("ip:"/"tenant:"/"global"),
  action, max_rps?, expires_ms, reason}` — `FilePolicySink` rewrites
  `policy.json` atomically; `HttpPolicySink` PUTs/DELETEs `/rules/{id}`.
- Wasm: `cargo build -p snn-wasm --target wasm32-unknown-unknown` compiles
  (rayon included). getrandom `wasm_js` feature wired under target deps.
