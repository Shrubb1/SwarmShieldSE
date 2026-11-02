# snn-firewall

A pure-Rust behavioral firewall powered by a spiking neural network.
No Python, no external AI services — a deterministic, thread-safe,
dependency-light anomaly engine that learns your traffic's normal and
stops what deviates from it.

## Verified, not claimed

| Test | Result |
|---|---|
| Real `sqlmap` (industry pen-test tool) | Defeated — 403/429 storm; sqlmap itself suggested `--tamper` evasion |
| `sqlmap --tamper=space2comment,between,randomcase` | Also defeated — 31×403 + 35×429 |
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
cargo build --release --bin http_shield
./http_shield 127.0.0.1:8081          # listens; XFF/CF-Connecting-IP aware
curl http://127.0.0.1:8081/           # 200 OK
sqlmap -u "http://127.0.0.1:8081/?id=1" --batch   # watch it give up
```

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
  fingerprints, signatures, search, playbook, snapshots
- `swarm` — `http_shield` (real HTTP front + tarpit), worker/orchestrator mesh
- `snn-wasm` — wasm32 JSON façade

## License

Apache-2.0 — see [LICENSE](LICENSE).
