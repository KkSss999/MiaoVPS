# AGENTS.md

Guidance for coding agents working in this repository. Humans should start with
`README.md` and `docs/`.

## How to work

You are a lazy senior developer. The best code is code never written. Before
solving the problem, check whether it can be solved with less.

**Before you write**: read the task and the code it touches. List every place
the change must reach — callers, tests, fixtures, config, exports. Check what it
could break: data it would destroy or expose, callers that stop working. That is
the scope; features nobody asked for are not.

**The smallest complete change**: take the first option that fully works.

1. Does it need to exist? Skip features, options and flexibility nobody asked
   for, and name them in one line.
2. Already in this repo (helper, module, pattern)? Use it the way the
   surrounding code does.
3. Standard library or platform feature? Use it, unless the project has its own.
4. Already-installed dependency? Use it. Never add a dependency for a few lines.
5. Can it be one line a reader gets at a glance? One line.
6. Otherwise: the minimum code that works.

- Be lazy about the solution, never about the change itself: finish the callers,
  tests and fixtures it breaks.
- No abstraction, wrapper, type conversion, option, config, or "wire it later"
  code nobody asked for. Deletion beats addition. Keep the layers, interfaces
  and conventions this repo already has.
- The shortest working diff wins — once you know everything it must touch. A
  one-liner that needs decoding is not short.
- Comment only the "why" the code cannot show, in one line.
- Bug fix: grep every caller of the function you touch first, then fix the root
  cause once in the shared code.
- Code you move or merge keeps its error handling and validation.
- Between options of equal size, take the one that is correct on edge cases.
- New non-trivial logic (a branch, a loop, a parser, money, security, a new
  script or app) leaves one small test or an assert-based self-check. Trivial
  changes need none.
- A shortcut with a known limit gets one line in the code:
  `shortcut: <the limit>, <when to upgrade>`.

**Never cut**: validation at trust boundaries, error handling that prevents data
loss, security, accessibility, whatever real-hardware calibration needs, anything
the user explicitly asked for.

**When you report back**: end with one or two lines on what you skipped, what you
did not verify, and any risk the user must know.

## What this project is

A local-first desktop WireGuard VPN client: it turns the user's own VPS into a
VPN node, and the client takes over system traffic with a pure-Rust stack
(boringtun). No accounts, no central service, no resident agent on the server.

**Control plane and data plane are independent and share no runtime state** —
this is the key to reading the codebase:

- Control plane: deploy WireGuard over SSH. `miaovps-ssh` (russh) →
  `miaovps-provisioner` (9-step state machine + environment detection +
  rollback).
- Data plane: local TUN interface (utun on macOS, `tunN` on Linux) + boringtun
  encryption, no `wg-quick`.
  `miaovps-connect`, the only part that touches live packets.

## Commands

```bash
cargo build                          # all crates
cargo test                           # all tests
cargo test -p miaovps-connect        # one crate
cargo test -p miaovps-connect backoff  # one test by name
cargo clippy --all-targets           # lint
```

The CLI binary is `miaovps` (not `miaovps-cli`):

```bash
cargo run -p miaovps-cli -- help
./target/debug/miaovps validate <ip:port> <client-priv> <server-pub>
sudo ./target/debug/miaovps connect [--full] [--skip-validate]
sudo ./target/debug/miaovps disconnect
```

Logging defaults to `miaovps=info` only (see `crates/miaovps-cli/src/logging.rs`).
Tunnel internals need `RUST_LOG=miaovps=debug`.

Real-hardware scripts (start the tunnel with sudo first):

```bash
bash scripts/test-reconnect.sh    # reconnect; blocks the port for 130s
bash scripts/test-tunnel-health.sh
bash scripts/bootstrap-server.sh  # manual server-side deploy (run on the VPS)
```

## CI and releases

- `.github/workflows/ci.yml`: `cargo test --workspace` on Ubuntu and macOS, plus
  `cargo clippy --all-targets` on Ubuntu. The macOS job is the only automated
  compile of the macOS code paths. Clippy findings are printed but do not fail
  the build: CI uses a floating `stable`, and new lints landing would otherwise
  turn `main` red without any code change. Pin the toolchain first if you want
  a strict gate.
- `.github/workflows/release.yml`: releasing is automatic. Bump
  `[workspace.package] version` in `Cargo.toml` and push to `main`; the workflow
  creates tag `v<version>` when missing and publishes Linux x86_64 plus macOS
  arm64/x86_64 binaries. Same version again is a no-op; a missing release (failed
  run) is re-published on the next run. The Linux artifact is built on
  `ubuntu-22.04` on purpose — the runner's glibc becomes the artifact's minimum
  (2.34), so 24.04-built binaries would not start on Debian 12.
- The version has exactly one source: `Cargo.toml`. Anything that displays a
  version uses `env!("CARGO_PKG_VERSION")`, never a literal.

## Crate layering

Strictly one-directional; `core` is pure domain models with no internal
dependencies, and no horizontal dependencies within a layer:

```
core ← wireguard-config ← connect
     ← ssh ← provisioner
     ← storage / telemetry / tunnel-api
                              ↑
                             cli （aggregation layer; depends on all but
                                  telemetry/tunnel-api）
```

Also `miaovps-app` (application-service layer shared by the CLI and frontends)
and `miaovps-control` (private control plane: HTTPS JSON API; it does not proxy
VPN traffic and never stores client private keys).

## Data plane: three threads, not mergeable

`connect/src/native.rs` runs three threads. This split is necessary, not a style
choice:

```
[outbound] TUN poll(500ms) → read → encapsulate → UDP send
[inbound]  UDP recv(500ms timeout) → decapsulate → TUN write
[timers]   update_timers every 250ms → handshake retransmit / keepalive / reconnect
```

- **Outbound and inbound must be separate threads**: merged, the `udp.recv()`
  timeout blocks the outbound direction, so TUN is read once per timeout on an
  idle link and throughput collapses.
- **Outbound uses `poll`, not a direct `read`**: `TunReader` holds the TUN fd;
  if the thread blocks in `read()`, `shutdown()`'s `join()` deadlocks against it
  — Ctrl+C hangs on an idle tunnel. `poll(500ms)` then read breaks the cycle.
- All three threads poll the stop flag on a 500ms scale; `shutdown()` returns in
  at most 500ms.
- `Tunn` is shared via `Arc<Mutex<..>>`; the lock is held only during
  encrypt/decrypt, never across I/O.

## TUN: macOS utun vs Linux

**Linux TUN is raw IP** (the tun crate defaults to `IFF_NO_PI`). Do not add the
4-byte address-family header there — the peer drops every packet. macOS utun
always carries the header. The split lives in `frame_packet()` in
`connect/src/tun.rs`; the read path strips the header only when it is present,
so it is safe on both.

Linux also names the interface `tun0`/`tunN` (kernel-assigned) instead of
`utunN`; nothing in the code may hardcode a device name.

### macOS utun: three hard constraints

All were hit in practice. Read before touching `connect/src/tun.rs`:

1. **4-byte address-family header**: every IP packet is prefixed with an AF
   header (`AF_INET`=2 / `AF_INET6`=30); strip on read, prepend on write. A real
   IPv4 packet starts with `0x45`, which as a BE u32 never collides with 2/30, so
   matching by value is safe.
2. **Writes must be a single `write()`**: utun is a character device and each
   write is one packet. Writing the AF header and body separately makes the
   kernel see two malformed packets and drop both.
3. **Pass the address via `Configuration`, do not `set_alias` afterwards**:
   `Device::new` already calls `set_alias` once (default 10.0.0.1). Calling it
   again **appends** a second address, leaving a stale 10.0.0.1 plus a
   10.0.0.255 host route. Also, for POINTOPOINT interfaces the second argument
   of `set_alias` is the **peer address**, not the broadcast address — passing a
   broadcast address makes the gateway unreachable.

## Platform seams

Everything OS-specific is confined to these places. Anything else that branches
on `target_os` is a smell:

| Concern | Where | macOS | Linux |
| --- | --- | --- | --- |
| Routes, gateway, IPv6 block | `cli/src/net.rs` | `route(8)` | `ip(8)` |
| Full Tunnel DNS | `cli/src/dns.rs` (`platform` module) | `networksetup` + service name mapping | `resolvectl` per link, else `/etc/resolv.conf` |
| TUN framing | `connect/src/tun.rs` | 4-byte AF header, single write | raw IP |
| Rebind errnos | `connect/src/native.rs` | 49/50/51/64/65 | 99/100/101/112/113 |
| Privilege prompt | `app/src/tunnel_ctl.rs` | `osascript` | `pkexec` (polkit) |
| Interface address probe | `app/src/tunnel.rs` | `ifconfig` | `ip -4 -o addr show` |
| User home under sudo | `cli/src/main.rs` | `/Users/<user>` | `/home/<user>` |

Notes:

- `ip route add` reports an existing route as `RTNETLINK answers: File exists`;
  both platforms treat that as success (the target state already holds).
- Linux DNS takeover refuses to run when `/etc/resolv.conf` is a symlink and
  systemd-resolved is absent — an unrevertable change is worse than a leak.
- With systemd-resolved, the backup file only stores the interface name; resolved
  drops per-link config when the link disappears, so a crash leaves no residue.
- Never use a tool's stderr text to decide control flow — it is localized
  (`Failed to resolve interface "tun0": 没有那个设备`). Check state instead: the
  Linux DNS revert checks `/sys/class/net/<iface>`, because a destroyed TUN makes
  resolved drop its per-link config on its own.
- `ip -6 route add prohibit 2000::/3` replaces macOS `-reject` (same ICMP
  admin-prohibited semantics). If IPv6 is disabled on the host the add fails
  with "not supported"/"disabled" and the guard reports `Ipv6Block::Unsupported`
  instead of failing the connection.

## Reconnect: do not duplicate boringtun's logic

boringtun already implements the RFC behavior (its `src/noise/timers.rs`):
15s of silence triggers a handshake → retransmit every 5s → give up at 90s
cumulative and return `ConnectionExpired`.

**Do not layer your own silence detection on top** — the two fight and produce
duplicate handshakes. MiaoVPS takes over only at the point where boringtun gives
up:

```
0s ─────15s──────────────────────105s──────────────→
  silent   boringtun retransmits  ConnectionExpired
              every 5s                 ↓  MiaoVPS takes over, revives forever
```

`Tunn` can **revive in place**, no need to rebuild it:
`format_handshake_initiation(force_resend=true)` calls `timers.clear()` in the
expired state, and the inner layer unconditionally rewrites state to `InitSent`.
Policy is unlimited retries with 5s→60s backoff. Outages shorter than 105s heal
inside boringtun.

## Network changes: two things, one order

On a WiFi subnet change or a WiFi↔wired switch, missing either half means no
recovery:

1. **The UDP socket source address is pinned by the kernel.** After `connect()`,
   `local_addr()` goes from `0.0.0.0:0` to a concrete IP; once the subnet
   changes that address no longer exists and `send()` fails forever (macOS
   errno 49). It must be rebound — `Endpoint` wraps `RwLock<Arc<UdpSocket>>`.
   The server identifies peers by public key and supports endpoint roaming, so a
   new source port is accepted (verified on hardware).
2. **The direct-to-VPS route is pinned to the old gateway.** `VpsRouteGuard`
   verifies and rebuilds it every 5s.

**The order must be "fix the route first, then rebind"** — while the route is
broken, binding any local address still sends nothing. The CLI calls
`NativeTunnel::notify_network_changed()` after repairing the route.

### Trap: never rebind on the data path

The first version put the rebind inside `Endpoint::send`; while offline, every
packet queued in TUN triggered one — **measured 700 rebinds and 700 log lines
per second**. Current behavior:

- the data-path `send` never rebinds, it only counts dropped packets (dropping
  outbound packets while offline is correct: recovery depends on handshake
  packets only, and TCP retransmits itself)
- rebinding is rate-limited to 2s, and the handshake path uses
  `send_with_rebind`
- a 1-minute outage produces about 6 visible log lines by default

## Full Tunnel fallback on disconnect (default behavior)

30s into a session outage → withdraw `0/1` + `128/1` and restore DNS, keep
reconnecting → re-take over automatically once recovered. State lives in
`FullTunnelOverlay`.

Without the fallback all traffic and DNS fall into a black hole, macOS decides
"connected but no internet", and the user experiences "WiFi cannot connect". The
fallback explicitly tells the user traffic is not going through the VPN.

Two easy-to-miss spots: **re-taking over must re-capture the DNS backup** (the
network may have changed during fallback, and a stale backup writes the wrong
DNS); **`teardown` must distinguish takeover from fallback state** (DNS is
already restored during fallback, so restoring again writes a stale backup).

### Trap: keepalive returns `Done`, not `WriteToTunnel*`

`validate_decapsulated_packet` returns `TunnResult::Done` directly for
`len == 0`. During fallback the tunnel carries **only keepalives, no data** — if
liveness is judged by `WriteToTunnel*`, recovery is never detected, the tunnel
stays in direct-connect mode forever, and **the user believes they are protected
while traffic is in the clear**.

Judge recovery with `Tunn::stats().0` (`time_since_last_handshake()` returning
`Some` means the session exists), independent of traffic. See
`TunnelStats::session_alive`.

## Invariants that must hold

The product rule is "never lose the network with one click". These cannot break:

- **Change routes only after all validation passes.** Any failure returns
  immediately and touches no route table.
- **Routes are transactional**: `apply_routes` applies one by one and rolls back
  in reverse order on any failure. A half-applied route set is worse than none —
  the user cannot tell which entries to remove to recover.
- **The VPS public IP must go direct via the original gateway**, otherwise
  encrypted packets are routed back into the tunnel and loop.
- **Full Tunnel must take over DNS too.** With only routes switched, interface
  routes for local subnets are more specific than `0/1`, so queries still go to
  the ISP — IP traffic in the VPN, domain names leaked in plaintext. The original
  config is persisted to `dns-backup.json` so `disconnect` can restore it even
  after `kill -9`.
- **Client keys must be stable.** The server only accepts public keys already in
  the peer list; handshakes from a newly generated key are **silently dropped**
  (symptom: "handshake timeout", very hard to diagnose). `connect` verifies at
  startup that the public key derives from the private key and refuses
  otherwise.
- Keys are always truncated with `short_key()` in logs.

## Privileges and key storage

`connect` / `disconnect` need root (create TUN, change routes). The privilege
check runs first in the flow so users do not wait through validation to fail.

**Keys live in a file, not the Keychain**: under sudo the process sees **root's**
Keychain and cannot read keys written in the user session.
`~/.miaovps/profile.json` (0600) is visible to both identities. `data_dir()`
resolves the real user's home through `SUDO_USER` so root does not write to
`/var/root`.

MTU defaults to 1380 and **must match the server's wg0**, otherwise large
packets are silently dropped (symptom: "ping works, file transfer hangs").
`TunInterface::create` verifies the MTU took effect.

### Trap: `kill(pid, 0)` returning EPERM does not mean "process is dead"

The tunnel process runs as root, the App as a normal user — `kill` returns `-1`
with **`EPERM`** (process alive, no permission to signal); only `ESRCH` means it
is gone. Testing only for `== 0` classifies every healthy tunnel as `Stale`, and
the `Stale` branch of `TunnelCtl::connect` runs a disconnect to clean up first —
**the App tears down the tunnel it just created**, trapping the user in
"connect → shows crashed → connect again → actually disconnected".

Treating `EPERM` as alive still cannot detect "pid recycled by another process",
so an `updated_at` heartbeat backstops it (the tunnel refreshes every 5s;
`HEARTBEAT_TIMEOUT` 60s means `Stale`).

### Trap: when Tauri is wired up, a sync command runs on the main thread

(The frontend has not started; this is a known trap for when it does.)

A non-`async` function marked `#[tauri::command]` goes through `body_blocking`
and expands inline on the IPC handler thread — on macOS, the main thread. Tunnel
control synchronously waits on the osascript auth dialog (tens of seconds while
the user types a password) plus up to 4s polling the state file, freezing the
main thread the whole time: no redraw, clicks ignored, and the auth dialog can
end up behind the frozen window. The symptom is **"disconnect does nothing and
the App hangs until killed"**.

Only `async fn` goes through `respond_async_serialized` →
`async_runtime::spawn`. Being async is not enough on its own — a blocking call
occupies a tokio worker until the user finishes typing. The correct form is
`async fn` + `spawn_blocking`. Any command that spawns a subprocess or waits on
user interaction must do this.

## Not wired up (do not mistake for working)

- The `TunnelBackend` trait in `miaovps-tunnel-api` has **no implementation**,
  and `miaovps-connect` does not depend on it. Reserved for future platform
  abstraction.
- The `VpnConnection` state machine in `connect/src/lib.rs` is **unused by the
  CLI**; the CLI calls `NativeTunnel` directly. Reserved for frontend IPC.
- `miaovps-telemetry` is **referenced by nothing**.
- CLI `inspect` / `deploy` / `status` / `export-config` are placeholders that
  only print hints; they need real SSH wiring.
- **IPv6 is not handled**: Full Tunnel only routes IPv4, so v6 traffic bypasses
  the tunnel and leaks the real IP.
- Frontend is 0 lines (planned: Tauri 2 + React).

## Measurement traps

Performance on a high-RTT international link is easy to misjudge. Already hit:

- **A single iperf3 run is not trustworthy**. Nine samples of one config spanned
  5.6x (15.1–85.5 Mbps). Take at least 6 and use the median, and **record
  retransmits at the same time** — low throughput with zero retransmits is a
  completely different fault from low throughput with many.
- **ICMP loss says nothing about link quality**. Cloud providers often rate-limit
  ICMP to public IPs: direct ping once showed 73% loss while in-tunnel ping was
  50/50 with zero loss.
- **Small-file speed tests are meaningless**, dominated by TCP slow start
  (5MB→5.2 Mbps, 20MB→14.3 Mbps on the same link).
- **Testing reconnect requires an outage longer than 105s**; anything shorter
  tests boringtun's own retransmits, not this project's reconnect code.
- **Testing a network change requires actually changing networks** (WiFi off for
  >40s, or a different subnet). `scripts/test-reconnect.sh` only blocks the VPS
  port, so source address and gateway are unchanged and the socket-rebind and
  gateway-guard paths are never exercised.

When running sudo commands on the test VPS over SSH,
`echo pw | sudo -S cmd <<EOF` **writes the password into a file** — `sudo -S`
and the heredoc fight over stdin. Correct approach: write a temp file as the
normal user, then `sudo cp` it.

## Docs and commits

- Code comments and CLI strings are Chinese; public docs (`README.md`, `docs/`)
  are English-first, with `README.zh-CN.md` as the Chinese version; this file is
  English.
- Never commit build output, local MiaoVPS state, credentials, private keys,
  exported WireGuard config, or real infrastructure details (use example IPs
  from `203.0.113.0/24`).
- Describe the problem, the approach, user-visible behavior, and the validation
  performed; networking and routing changes also need platform, OS version,
  failure behavior, and rollback evidence. See `CONTRIBUTING.md`.
