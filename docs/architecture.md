# Core Architecture

MiaoVPS contains the Rust core, CLI, protocols, provisioner, storage, and
tunnel data plane.

## Data flow

```text
miaovps CLI / compatible clients
        │
        ├─ Control plane: SSH
        │  inspection, deployment, peer registration, status
        │
        └─ Data plane: AmneziaWG (default) or WireGuard UDP
                         │
                         ▼
        VPS: miao-awg or wg0 + forwarding + NAT
```

The control and data planes are independent. SSH is used for administration;
VPN traffic is never tunneled through SSH. The VPS receives only peer public keys.
When an administrator enrolls another device, its private key is generated on
the administrator's machine and delivered to that device in its private profile.
SSH host keys are checked against `~/.ssh/known_hosts`; an unknown or changed key aborts the
connection before credentials are sent.

Protocols use separate server listeners and local profiles:

| Protocol | Server interface | Local profile | Peer model |
| --- | --- | --- | --- |
| AmneziaWG (default) | `miao-awg` | `miao-awg-trial.conf` | Multiple peers; one imported profile per local user |
| WireGuard (`--wg`) | `wg0` | `profile.json` | Multiple registered devices |

`deploy` installs the default AWG listener; `deploy --wg` installs native
WireGuard. Neither path silently replaces the other.

## Crate boundaries

| Crate | Responsibility |
| --- | --- |
| `miaovps-core` | Domain models for servers, devices, and tunnels |
| `miaovps-wireguard-config` | Key and WireGuard/AWG configuration parsing and generation |
| `miaovps-ssh` | SSH authentication and remote command execution |
| `miaovps-provisioner` | Environment detection, installation, configuration, startup, and rollback |
| `miaovps-storage` | Local SQLite state and operating-system credential storage |
| `miaovps-connect` | TUN, routes, DNS, handshake validation, framing, and reconnect logic |
| `miaovps-app` | Application-service boundary reusable by the CLI and other clients |
| `miaovps-cli` | User-facing command-line entry point |
| `miaovps-tunnel-api` | Platform-neutral tunnel contracts |
| `miaovps-telemetry` | Local status-observation client |

## Connection safety boundary

Administrative SSH verifies the host key. Tunnel setup (including profile-only
clients with no SSH account) validates UDP reachability and an authenticated
handshake for the selected protocol, then creates the tunnel and applies routes. A critical validation failure does not switch
global routes. Port changes bind the candidate listener first and commit only
after the client completes a handshake; otherwise the old port is restored.

Full tunnel mode uses `0.0.0.0/1` and `128.0.0.0/1` while preserving a direct
route to the VPS, preventing the WireGuard transport from routing into its own
tunnel. Because the current data plane carries IPv4 only, MiaoVPS also installs
a reject route for public IPv6 (`2000::/3`) to prevent bypass. Ownership markers
allow fallback and disconnect to remove only MiaoVPS-managed state.

## Build boundary

```bash
cargo build
cargo test --workspace
cargo clippy --workspace --all-targets --all-features
```

Workspace artifacts are written under the repository-level `target/`
directory.
