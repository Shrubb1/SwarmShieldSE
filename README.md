# SwarmShieldSE

A pure-Rust behavioral firewall powered by a spiking neural network.
No Python, no external AI services — a deterministic, thread-safe,
dependency-light anomaly engine that learns your traffic's normal and
stops what deviates from it.

## Verified, not claimed

| Test | Result |
|---|---|
| `sqlmap` (industry pen-test tool) | Defeated — sqlmap itself suggested `--tamper` evasion |
| `sqlmap --tamper=space2comment,between,randomcase` | Also defeated — 31×403 + 35×429 |
| `sqlmap` overnight scan (~2h, all techniques + DBs) | **0 injectable** — 4,639 denied; sqlmap quit, suggesting a WAF |
| `sqlmap --level=5 --risk=3` (~7.5h, every technique + every header) | **0 injectable** — 11,580 denied; sqlmap quit recommending a WAF |
| `nuclei` full CVE template scan (6,471 templates) | **0 vulnerabilities found** — marked the target unresponsive 30× (tarpit) |
| Malformed HTTP protocol fuzz (binary garbage, smuggling headers, negative Content-Length) | 300/300 survived AND ruled — zero crashes |
| 200,000-event adversarial fuzz | ~27k events/sec sustained, zero degradation |
| Real libpcap wire capture (scapy+Npcap) | 361 events parsed → rules applied |
| Test suite | **86 passing, 0 warnings** |

## What it catches

Floods (single and distributed), port scans, low-and-slow DoS,
rotating botnets (ja3+UA fingerprint — rotation dies on event one),
C2 beacons (regular and jittered), SQLi/XSS/traversal/command-injection/
JNDI/SSTI (even obfuscated), kill-chains *predicted* before the exploit
lands, threshold-riders, and allowlisted-gone-hostile (alerted, not
blindly passed).

## The deceptive edge

Flagged attackers don't get a `403` — they get a **tarpit**: a fake
`200 OK` page dripped one chunk at a time. Their scan tools stall for
seconds per probe while the Scout layer keeps profiling them. Wasted
compute is time they can't spend attacking anything else.

## Quickstart

```bash
cargo build --release

# consumer runner — plain-English feed, consent gate, tiers
./swarmshield 9101:8081               # protect any TCP service
./swarmshield --token SS-SE-XXXX 9101:8081   # paid tier unlocks

# per-protocol fronts
./http_shield 127.0.0.1:8081          # HTTP + tarpit; XFF/CF-IP aware
./universal_gateway 0.0.0.0:9101 127.0.0.1:3306   # any TCP, L4 tarpit
./sys_proxy 127.0.0.1:9090            # CONNECT proxy — OS-wide coverage
./scan_server 0.0.0.0:9200            # free dropbox scanner (site)
./license_server 127.0.0.1:9100       # licensing + herd-immunity feed
./swarm_svc                           # Windows SCM service (elevated install)
sqlmap -u "http://127.0.0.1:8081/?id=1" --batch   # watch it give up
```

Tiers: **free** = full signature library + core detection;
**paid** (`--token` + `SWARM_LICENSE_URL`) = SNN learning, tarpit,
kill-chain prediction, fingerprints, herd immunity.

Licensing is cryptographically real: the license server signs
`token|expiry|machine-id` with Ed25519 — the client verifies the grant
with the public key baked in. Tokens can't be forged or shared, and
one build serves everyone: the free download IS the product — a
signed token activates Pro.

Replay a Wireshark/tcpdump capture through the engine:

```bash
LIVE_PCAP=/path/capture.pcap cargo test -p snn-firewall --test livepcap -- --nocapture
```

## Architecture

```
events ──► Scout (silent profiling) ──► FeatureWindow ──► Detector (SNN)
                 │                                              │
      SequenceTracker (kill-chain)                    SearchPolicy
      IdentityMap (fingerprint)                       try→confirm→descend
                 │                                      │
                 └────► emit() ── TTL rules ── local enforce + sink push
                              └──► playbook (learned fixes, serialized)
```

- `snn-core` — deterministic spiking net (LIF + Izhikevich, CSR, delays, rayon)
- `snn-encode` / `snn-learn` — delta encoding, STDP
- `snn-mesh` — detector + checkpoint stores
- `snn-firewall` — the engine: windows, detector, rules, scout, tracker,
  fingerprints, signatures (incl. credential-leak + prompt-injection),
  Pattern-scoped attribution, watchlist, search, playbook, snapshots
- `swarm` — fronts: `swarmshield` (consumer runner), `http_shield`,
  `universal_gateway`, `sys_proxy`, `scan_server`, `license_server`,
  `swarm_svc` (SCM); `crash.rs` privacy-preserving panic telemetry;
  worker/orchestrator mesh
- `snn-wasm` — wasm32 JSON façade
- `deploy/` — systemd + launchd service templates · `install.bat` —
  no-admin Startup install · `site/` — landing + signup + scanner pages

## License

Apache-2.0 — see [LICENSE](LICENSE).
