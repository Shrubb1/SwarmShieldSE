# SwarmShieldSE — hardening roadmap

An honest escalation ladder: attacks that historically beat good
firewalls, and the engine/test work that counters each tier. Every
tier ships with a regression corpus entry so it can never re-open.

## Tier 0 — shipped

- [x] Signature classes (SQLi, XSS, traversal, shell, scanners, JNDI,
      template, creds, prompt-injection, EICAR)
- [x] Behavioral SNN (8 window channels + jitter, ~95% TPR / ~4% TNR)
- [x] Pattern/watchlist/Global attribution ladder
- [x] Random-per-request obfuscation fuzz (99.0% coverage after
      leet-fold + double-decode + NUL-strip + `+`→space)
- [x] Evasion regression corpus (`tests/corpus.rs` — every bypass ever
      found stays dead)
- [x] sqlmap `--level=5 --risk=3` overnight — 0 injectable / 4,639 denied

## Tier 1 — attacks that beat real WAFs

| attack | why it beats sigs today | counter |
|---|---|---|
| HTTP request smuggling (TE.CL/CL.TE) | two parsers disagree on body length | strict Content-Length/Transfer-Encoding conflict rules + desync harness test |
| Charset/Unicode confusion | UTF-7/overlong encodings bypass decoders | byte-level scanning + overlong-UTF8 rejection |
| JSON/parameter pollution | `{"a":["safe","sqli"]}` smuggles past | structural parse + per-value scan |
| DNS/ICMP exfil | off-TCP channel the gateway can't see | doc'd scope: add a UDP/DNS EventSource |
| Domain fronting / TLS cover | legit CDN hostname hides C2 | ja3 fingerprint + cert-chain meta |
| Slowloris / slow-drip DoS | per-byte rate ~normal | conn-hold duration channel |
| Distributed ultra-low-rate scan | one event/IP/day — below every rate channel | cross-IP shared-shape correlation |

## Tier 2 — the learning roadmap

| mechanism | what it adds |
|---|---|
| corpus growth | every new bypass → permanent regression (shipped) |
| recursive-until-stable normalization | the remaining ~1% deep-encoded evasions |
| baseline-poisoning defense | rate-limited baseline ratchet + reference floor |
| checkpoint cadence in `http_shield` | learned state survives restarts today it doesn't |
| channel-anonymous herd sync | already shipping `ch{idx}=fix` — extend to shape patterns |
| nightly adversarial self-fuzz | cron the evasion fuzz with new transforms → auto-corpus |

## Tier 3 — platform ceiling

The honest limits that aren't code gaps: MITM TLS inspection
(root-cert opt-in), WinDivert/WFP for proxy-ignoring apps, signed
license JWTs, Stripe/Twilio billing. All documented seams.

## Standing rule

Any attack that ever gets through lands in `tests/corpus.rs` under
`CAUGHT` the moment it's fixed, or `KNOWN_GAP` until it is — the
suite enforces it forever.
