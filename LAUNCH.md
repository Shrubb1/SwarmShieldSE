# I built a spiking-neural-network firewall in pure Rust — and sqlmap gave up

*Draft launch post — dev.to / Medium / HN-ready.*

Every WAF I've deployed felt like a compromise: heavyweight regex engines
(ModSecurity), cloud-only AI black boxes you can't audit, or rule lists
an attacker walks around in an afternoon. So I built one differently —
a **spiking neural network** that learns what your traffic's *normal*
looks like and rules anything that deviates. Pure Rust, zero external
AI services, deterministic and thread-safe.

## The moment it proved itself

I pointed real `sqlmap` at the HTTP shield — not a test harness, the
actual industry pen-test tool:

```
403 (Forbidden) - 78 times
"all tested parameters do not appear to be injectable"
"If you suspect that there is some kind of protection mechanism
 involved (e.g. WAF) maybe you could try to use option '--tamper'"
```

sqlmap *recommended its own evasion toolkit*. I ran that too —
`--tamper=space2comment,between,randomcase` — and got `31×403 + 35×429`.
The normalization pipeline held.

## Then I stopped slamming the door

A `403` is a courtesy notice — it tells the attacker they hit a WAF and
to try something else. So flagged traffic now gets a **tarpit**: a fake
`200 OK` page dripped one chunk at a time. sqlmap's threads sat waiting
on "negotiating session…" while my Scout layer kept profiling it.

The attacker can't tell it's a tarpit — it just looks like a slow server.
Meanwhile every second they wait is wasted botnet compute and pristine
attack telemetry.

## What's under the hood

- **SNN detector** — delta-encoded metrics through a clock-driven
  LIF/Izhikevich network; anomaly score, not signatures alone.
- **Kill-chain prediction** — recon+enum inside a window → the exploit
  is *predicted* and ruled before the payload ever lands.
- **Fingerprinting** — ja3+UA actor IDs: IP rotation dies on event one.
- **Mitigation search** — try candidate → confirm live → descend to the
  *minimal* sufficient fix → persist to a serialized playbook.
- **Tarpit** — deception layer wasting attacker time.

## Verified, not claimed

| | |
|---|---|
| sqlmap + tamper evasion | defeated |
| 300 malformed-HTTP fuzz | 300/300 survived, all ruled |
| Real libpcap capture | parsed → rules |
| 200k-event adversarial fuzz | ~27k ev/s sustained |
| Test suite | 86 passing, 0 warnings |

Apache-2.0, one binary, `docker run` deployable:
**github.com/Shrubb1/SwarmShieldSE**

The honest limit: traffic *statistically identical* to legitimate users
can't be classified — that's information theory, not engineering.
Everything else leaves a trace; the engine was built to catch all of it.
