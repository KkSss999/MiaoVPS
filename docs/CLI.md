# MiaoVPS CLI

`miaovps` is the command-line entry point for local server records, SSH-based
deployment, device-key management, and WireGuard tunnel connections.

## Install

```bash
cargo install --path crates/miaovps-cli
miaovps --help
```

Re-run `cargo install` to upgrade a locally installed build. Workspace build
artifacts stay under the repository-level `target/` directory.

## Typical workflow

```bash
# 1. Register a VPS. Use either --key or --password authentication.
miaovps add-server "my-vps" 203.0.113.10 22 ubuntu --key ~/.ssh/id_ed25519

# 2. Inspect operating-system, privilege, network, and WireGuard prerequisites.
miaovps inspect <server-id>

# 3. Deploy WireGuard. Choose another UDP port if 51820 is unsuitable.
miaovps deploy <server-id> --port 443

# 4. Create a distinct peer for each physical device.
miaovps add-device <server-id> "my-mac" mac

# 5. Connect. Omit --full to route only the private VPN network.
sudo miaovps connect <server-id> --device <device-id> --full

# 6. Stop the tunnel and restore MiaoVPS-owned route and DNS changes.
sudo miaovps disconnect
```

`<server-id>` and `<device-id>` accept a full UUID or a unique prefix. Full
tunnel mode routes IPv4 and DNS through the VPS. The current data plane does
not provide an IPv6 tunnel, so MiaoVPS installs an explicit public-IPv6 reject
route to prevent silent bypass. Disconnect and fallback remove only rules owned
by MiaoVPS.

## Continuous diagnostics

```bash
sudo miaovps connect --full --dev
# Compatible with explicit device selection and background mode:
sudo miaovps connect <server-id> --device <device-id> --full --daemon --dev
```

`--dev` appends application and boringtun debug events to
`~/.miaovps/tunnel-dev.log`, or the directory selected by `MIAOVPS_DATA_DIR`.
Restarting the tunnel preserves previous entries. Logs rotate at approximately
16 MiB per file, keeping the active file and three backups (`.1` is newest).
Files use mode `0600`. Logs do not include command arguments, private keys,
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

A connection is fully torn down and rebuilt when its raw `WrongIndex` count
reaches **2**. A 250 ms watchdog observes the count independently of the
rate-limited warning log. TUN threads, routes and DNS are cleaned up before
creating the next TUN, UDP socket and WireGuard session.

A retry must receive actual tunnel traffic within 45 seconds; handshake responses
alone are insufficient. An ICMP probe to the VPN gateway generates traffic even
when idle. After at least 30 seconds with traffic and a healthy session the retry
is considered established. A `WrongIndex` relapse before that point counts as a
failed retry. A later incident starts a new retry sequence.

After **two consecutive failed retries**, the current endpoint port is incremented
by one and the existing SSH deployment flow redeploys the selected node. Existing
server keys and peers are retained. Subnet, DNS and MTU settings are reused.
The node record, profile and subsequent `--port` argument are updated only after
deployment reports success. Failed deployment stops escalation for manual review;
port 65535 never wraps. Cloud-provider firewall rules still need to allow the new
UDP port; deployment can only configure the VPS firewall.

Explicit server/device selection is preserved across retries. Profile-only
connections can redeploy only when the stored server public key identifies one
local node unambiguously. Ctrl+C, SIGTERM and daemon stop requests stop recovery
as well. Automatic redeployment changes the shared server listen port, so other
devices on that node must use the new port too.

## Command reference

| Command | Purpose |
| --- | --- |
| `add-server` / `remove-server` | Add or remove a local VPS record |
| `list-servers` | List known servers |
| `inspect` | Run read-only deployment prerequisite checks |
| `deploy` | Install and configure WireGuard over SSH |
| `add-device` / `list-devices` | Manage devices and WireGuard peers |
| `status` | Read remote WireGuard status |
| `export-config` | Export a device configuration |
| `generate-keypair` | Generate a WireGuard keypair |
| `validate` | Validate UDP and WireGuard without changing routes |
| `profile init` / `profile show` | Create or inspect the default connection profile |
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
- `deploy --port` changes the VPS WireGuard listen port. Update both cloud and
  host firewalls and ensure every device uses the same target port.
