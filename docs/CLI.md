# MiaoVPS CLI

`miaovps` is the command-line entry point for local server records, SSH-based
deployment, device-key management, and AmneziaWG/WireGuard tunnel connections.

## Install

Requires Rust 1.97 or newer.

```bash
cargo install --locked --path crates/miaovps-cli
miaovps --help
```

Re-run `cargo install` to upgrade a locally installed build. Workspace build
artifacts stay under the repository-level `target/` directory.

## Client requirements

`miaovps connect` and `miaovps disconnect` run as root, because they create a
TUN interface and change the routing table.

| Platform | Requirements |
| --- | --- |
| macOS | built-in utun device. Full Tunnel takeover changes the active network service's DNS through `networksetup` and restores it on exit. |
| Linux | `/dev/net/tun` available (`modprobe tun`) and iproute2 (`ip`). Full Tunnel takes DNS over through systemd-resolved (`resolvectl`) when it runs; otherwise it rewrites `/etc/resolv.conf` only when that file is a regular file, and skips DNS takeover when neither applies. |

The desktop app launches the tunnel through `pkexec` on Linux, which needs a
polkit authentication agent in the session.

## Typical workflow

```bash
# 1. Register a VPS. Use either --key or --password authentication.
miaovps add-server "my-vps" 203.0.113.10 22 ubuntu --key ~/.ssh/id_ed25519

# 2. Verify the SSH host key independently and add it to ~/.ssh/known_hosts, then inspect.
miaovps inspect <server-id>

# 3. Allow UDP 52181 in both firewalls, then deploy AWG and create this machine's profile.
miaovps deploy <server-id> --port 52181

# 4. Connect using the saved profile.
sudo miaovps connect --full

# 5. Stop the tunnel and restore MiaoVPS-owned route and DNS changes.
sudo miaovps disconnect
```

`<server-id>` and `<device-id>` accept a full UUID or a unique prefix. Full
tunnel mode routes IPv4 and DNS through the VPS. The current data plane does
not provide an IPv6 tunnel, so MiaoVPS installs an explicit public-IPv6 reject
route to prevent silent bypass. Disconnect and fallback remove only rules owned
by MiaoVPS.

## Choose the protocol

`deploy`, `connect`, `validate`, `status`, `list-devices`, `profile show` and
`export-config` default to AmneziaWG. Use `--wg` explicitly for WireGuard;
peer-management commands `add-device` and `profile init` are WireGuard-only and
require `--wg`. `deploy` saves one local AWG profile at `~/.miaovps/miao-awg-trial.conf` (or under
`MIAOVPS_DATA_DIR`). Use `miaovps validate` to verify it without changing routes.
A missing or invalid profile never causes a fallback to WireGuard.

Use `sudo miaovps connect --wg --full` to use your existing WireGuard profile,
or include the server and device to select a registered WG peer. Stop the current
connection before switching protocols. Omit `--full` to route only the private
VPN subnet. For AWG, normally omit server/device: `deploy` saves one profile and
registers no device entry. Explicit server/device with AWG only works when the
profile was produced by `deploy-awg` for an already registered WG peer.

## Continuous diagnostics

```bash
sudo miaovps connect --full --dev
# Native WireGuard, with explicit device selection and background mode:
sudo miaovps connect <server-id> --device <device-id> --wg --full --daemon --dev
```

`--dev` appends application and protocol engine debug events to
`~/.miaovps/tunnel-dev.log`, or the directory selected by `MIAOVPS_DATA_DIR`.
Restarting the tunnel preserves previous entries. Logs rotate at approximately
16 MiB per file, keeping the active file and three backups (`.1` is newest).
Files use mode `0600` and are owned by the data directory's owner, including
when the tunnel runs under `sudo`. Logs do not include command arguments, private keys,
passwords, or packet payloads. `RUST_LOG` still controls console verbosity;
detailed file logging has its own filter. Background mode also retains the
existing `tunnel.log` console-output file.

Diagnostics include session start time and process ID, handshake retries,
protocol rejection types, socket rebindings, fallback/recovery events, and
five-second snapshots of traffic, confirmed receive times, peer handshake request
counts, and errors.
Keep the entire rotated file set when investigating an incident.

Link health requires recent bidirectional confirmation: decrypted transport
packets (including empty keepalives), or a verified response to our own handshake.
Incoming handshake requests and locally generated responses do not refresh health;
repeated peer requests cannot indefinitely defer recovery. After 30 seconds without
confirmation, a rate-limited socket rebind and non-forced handshake probe check the
path without replacing an in-flight handshake. At 45 seconds of silence the
link is marked unavailable. Full tunnel mode falls back to direct routing
only after roughly another 30 seconds of continuous unavailability; fresh
bidirectional confirmation and a usable session permit recovery. Session/replay
rejections are no longer assumed to be harmless rekey loss.

## Automatic reconnection and port escalation

A connection is fully torn down and rebuilt after about 45 seconds of continuous
**unavailable** link state (on top of the initial freshness window), or when its
raw `WrongIndex` count reaches **2**. Each cold-start validation that exhausts
all authenticated handshake attempts also counts toward recovery. Local UDP
errors, invalid config and route errors do not authorize a remote port change.
The old TUN, routes and DNS are cleaned up before the next attempt.

A retry must receive actual tunnel traffic within 45 seconds; handshake responses
alone are insufficient. An ICMP probe to the VPN gateway generates traffic even
when idle. After at least 30 seconds with traffic and a healthy session the retry
is considered established. A `WrongIndex` relapse before that point counts as a
failed retry. A later incident starts a new retry sequence.

After **two consecutive failures**, recovery verifies the SSH host key, live VPN
public key and peer registration and tries the next UDP port on **the same
protocol**. It changes only the live listen port first; the client must complete
an authenticated handshake on the candidate before the VPS configuration and
local profile are updated. If the candidate fails, MiaoVPS tries to restore the old
port immediately. A server-side timer also restores it after about 60 seconds
if the client disappears before commit. Port 65535 never wraps. Allow the
candidate UDP port in both firewalls in advance. Recovery tries at most one
new port per outage; if that does not restore the tunnel, it stops rather than
cycling through ports.

Profile-only recovery needs an unambiguous local SSH node. Ctrl+C, SIGTERM and
daemon stop requests stop recovery. Listeners are shared: every peer on the same
interface may be interrupted during the test and must use the new port after a
successful change. AWG and WG listeners stay independent. Full tunnel recovery
can temporarily route traffic directly; it is not a kill switch.

## Command reference

| Command | Purpose |
| --- | --- |
| `add-server` / `remove-server` | Add or remove a local VPS record |
| `list-servers` | List known servers |
| `inspect` | Run read-only deployment prerequisite checks |
| `deploy` / `deploy --wg` | Deploy AWG (default) or native WG, or verify a port change |
| `deploy-awg <server-id> <wg-device-id> <udp-port> <new.conf>` | Optionally reuse an existing WG peer key for a [separate AWG deployment](deployment.md#reuse-an-existing-wireguard-peer-optional) |
| `add-device --wg` | Register a native WG peer (AWG `deploy` creates the sole peer) |
| `list-devices [--wg]` | List AWG's saved local peer, or native WG devices |
| `status [--wg]` | Read remote AWG or native WG status |
| `export-config` / `export-config --wg <device-id>` | Export the local AWG profile or a registered WG peer |
| `generate-keypair` | Generate a keypair usable with either protocol |
| `validate` / `validate --wg` | Validate the saved AWG or WG profile without changing routes |
| `profile show [--wg]` / `profile --wg init` | Inspect the selected profile or create a native WG profile manually |
| `connect` / `disconnect` | Start or stop the local tunnel |

Use `miaovps --help` and command-specific help as the source of truth for the
current argument surface.

## Security notes

- Private keys belong in the local credential store. Never commit terminal
  output, exported `.conf` files, passwords, or real infrastructure details.
- `connect` and `disconnect` require elevated privileges because they manage a
  TUN device, routes, and DNS.
- `inspect` is read-only. Before `deploy`, verify that the target is not a
  critical production host and retain provider-console access.
- SSH refuses unknown or changed host keys. Add the independently verified key
  to the credential owner's `~/.ssh/known_hosts` before inspecting or deploying.
- Stop your local tunnel before manually changing a server listen port with
  `deploy [--wg] --port`. Allow it in both firewalls first. If commit acknowledgement
  is lost, verify with `status [--wg]` and repeat `deploy [--wg] --port <live-port>`
  to revalidate and sync the local profile.
