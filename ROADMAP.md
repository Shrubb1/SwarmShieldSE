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

- [x] **HTTP request smuggling** — `scan_smuggling`: TE.CL/CL.TE
      conflict, duplicate Content-Length; `http_shield` 400s on sight
- [x] **Charset/Unicode confusion** — UTF-7/UTF-16 markers, overlong
      `%c0%ae`, raw C0/C1 lead bytes
- [x] **JSON key pollution** — duplicate-key objects flagged
- [x] **Slowloris / slow-drip** — `mean_gap_ms` channel; tiny rate +
      long holds → `Ip` rule
- [x] **Distributed low-rate scan** — `by_shape` correlation: 4+ srcs
      sharing one request shape → `Pattern` rule
- [ ] DNS/ICMP exfil — needs a UDP `EventSource` (scope doc'd)
- [ ] Domain fronting — ja3 + cert-chain meta (partial via fingerprints)

## Tier 2 — the learning roadmap

| mechanism | what it adds |
|---|---|
| corpus growth | every new bypass → permanent regression (shipped) |
| recursive-until-stable normalization | the remaining ~1% deep-encoded evasions |
| baseline-poisoning defense | rate-limited baseline ratchet + reference floor |
| checkpoint cadence in `http_shield` | learned state survives restarts today it doesn't |
| channel-anonymous herd sync | already shipping `ch{idx}=fix` — extend to shape patterns |
| nightly adversarial self-fuzz | cron the evasion fuzz with new transforms → auto-corpus |

## Tier 2.5 — the untested industry battery

The real-world test plan — sqlmap covered one class; these cover the
rest. Run order = value-per-effort:

| # | tool | covers | status |
|---|---|---|---|
| 1 | **nuclei** | 10k+ real CVE templates — XSS/RCE/traversal/exposure classes sqlmap doesn't touch | queued |
| 2 | **nikto** | classic web vuln scanner — misconfigs, dangerous files | queued |
| 3 | **hydra** | credential brute-force — rate/lockout behavior | queued |
| 4 | **Metasploit** | real exploit framework — actual exploit code | needs install (heavy) |
| 5 | **real C2** | Sliver/Havoc beacon traffic — the SNN's actual job | needs framework setup |
| 6 | **malware samples** | MalwareBazaar drops through the scanner | needs VM isolation |

Each run's output goes into `tests/corpus.rs` — every real bypass
found becomes a permanent regression.

## Tier 3 — platform ceiling

- [x] **Signed offline grants** — keyed-hash `token|expiry|mid`
      signature; a hand-edited cache can't forge a grant (prod:
      asymmetric ed25519 — same contract)
- [ ] MITM TLS inspection — needs `rustls`/`rcgen` + a user-installed
      root cert (admin + big-dep)
- [ ] WinDivert/WFP capture — needs a signed driver + admin install
- [ ] Stripe/Twilio billing — needs your accounts; the API contract
      is already wired

## Standing rule

Any attack that ever gets through lands in `tests/corpus.rs` under
`CAUGHT` the moment it's fixed, or `KNOWN_GAP` until it is — the
suite enforces it forever.
