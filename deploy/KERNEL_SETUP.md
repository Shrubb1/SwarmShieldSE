# Kernel-layer coverage — what YOU need to do

The engine is already ready — a `WinDivertSource` adapter plugs into
`EventSource` and feeds raw packets through the same SNN pipeline.
What it needs on the deployment machine is admin + the driver, which
this dev box doesn't have. Here's the path:

## What you'll need

- **Administrator access** on the target Windows machine (driver
  installs require elevation — nothing works around that honestly)
- **A code-signing certificate** for the driver (EV cert ~$300-500/yr,
  or use WinDivert's existing signed binary instead of building your own)
- **WinDivert** — the established signed packet-diversion driver
  (windivert.org / basil00/Divert on GitHub — already signed, saves
  you the signing pipeline entirely)

## The steps

1. **Download WinDivert** (signed binary — no signing needed from you)
2. **Build the adapter**: `cargo build --features windivert` in
   `snn-firewall` — compiles the real `poll()` path against the
   `windivert` Rust crate + the WinDivert DLL
3. **Install the driver** (elevated): `WinDivertInstall.exe` or
   `sc create` — standard admin setup
4. **Run**: `swarm_svc` picks up `WinDivertSource` → every packet on
   the machine flows through the SNN — proxy-ignoring apps included

## What it unlocks

```text
proxy-ignoring apps    → kernel capture sees them anyway
ICMP/covert channels   → raw socket layer visible
driver-level covert    → the engine scores what proxies miss
```

## What it still won't do

Inner-TLS content (that needs a user-installed root cert + MITM —
documented separately). Everything else the kernel can see, the
engine can score.
