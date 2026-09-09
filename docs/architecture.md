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
        └─ Data plane: WireGuard UDP
                         │
                         ▼
                VPS: wg0 + forwarding + NAT
```

The control and data planes are independent. SSH is used for administration;
VPN traffic is never tunneled through SSH. WireGuard client private keys are
generated and stored on the client, while the VPS receives peer public keys.

## Crate boundaries

| Crate | Responsibility |
| --- | --- |
| `miaovps-core` | Domain models for servers, devices, and tunnels |
| `miaovps-wireguard-config` | Key and WireGuard configuration generation |
| `miaovps-ssh` | SSH authentication and remote command execution |
| `miaovps-provisioner` | Environment detection, installation, configuration, startup, and rollback |
| `miaovps-storage` | Local SQLite state and operating-system credential storage |
| `miaovps-connect` | TUN, routes, DNS, handshake validation, and reconnect logic |
| `miaovps-app` | Application-service boundary reusable by the CLI and other clients |
| `miaovps-cli` | User-facing command-line entry point |
| `miaovps-tunnel-api` | Platform-neutral tunnel contracts |
| `miaovps-telemetry` | Local status-observation client |

## Connection safety boundary

Connection setup validates UDP reachability, the WireGuard handshake, tunnel
creation, and route application in sequence. A critical validation failure does
not switch global routes.

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
