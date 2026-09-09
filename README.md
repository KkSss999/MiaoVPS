# MiaoVPS

**Turn a VPS you already own into a private WireGuard network — from one local-first Rust CLI.**

[![License: MIT](https://img.shields.io/badge/license-MIT-0f766e.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2021-000000.svg?logo=rust)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/status-pre--1.0-f59e0b.svg)](#project-status)

[中文说明](README.zh-CN.md) · [CLI guide](docs/CLI.md) · [Deployment](docs/deployment.md) · [Architecture](docs/architecture.md) · [Security](SECURITY.md)

MiaoVPS provisions WireGuard on a remote VPS over SSH, manages servers and
device peers locally, and creates split or full tunnels on the client. It does
not sell public nodes, require an account, or depend on a hosted control plane.

## Why MiaoVPS?

- **Own the infrastructure.** Bring any compatible VPS and keep control of the
  server, peer configuration, and network path.
- **Local-first by design.** Server metadata stays in local SQLite storage;
  credentials and private keys use the operating system credential store.
- **One operational workflow.** Inspect, deploy, add devices, validate, connect,
  observe, and disconnect from one CLI.
- **Fail closed.** MiaoVPS validates reachability and the WireGuard handshake
  before taking over routes. Failed validation does not switch global traffic.
- **Recoverable networking.** Full-tunnel setup preserves the direct route to
  the VPS and restores routes and DNS on disconnect or connection fallback.
- **Explicit IPv6 policy.** The current data plane is IPv4-only. Full-tunnel
  mode blocks public IPv6 instead of silently allowing traffic to bypass the
  tunnel.

## How it works

```text
                         SSH control plane
┌──────────────┐  inspect / deploy / peers / status  ┌──────────────┐
│ MiaoVPS CLI  │ ───────────────────────────────────▶ │ Your VPS     │
│ local state  │                                      │ WireGuard wg0│
│ + key store  │ ◀════════ WireGuard UDP ═══════════▶ │ NAT + routing│
└──────────────┘             data plane               └──────────────┘
```

SSH is used for server administration only; VPN traffic is carried by
WireGuard. Client private keys are generated and retained on the client. The
VPS receives peer public keys.

## Quick start

```bash
# Build and install.
cargo install --path crates/miaovps-cli

# Register and inspect a VPS.
miaovps add-server "my-vps" 203.0.113.10 22 ubuntu --key ~/.ssh/id_ed25519
miaovps inspect <server-id>

# Deploy WireGuard and add a device.
miaovps deploy <server-id> --port 443
miaovps add-device <server-id> "my-mac" mac

# Split tunnel: route only the private VPN network.
sudo miaovps connect <server-id> --device <device-id>

# Full tunnel: route IPv4 through the VPS and block public IPv6 bypass.
sudo miaovps connect <server-id> --device <device-id> --full

# Restore MiaoVPS-owned routes and DNS state.
sudo miaovps disconnect
```

Run `miaovps <command> --help` and read the [CLI guide](docs/CLI.md) before
using MiaoVPS on important infrastructure.

## Core capabilities

| Area | Capabilities |
| --- | --- |
| VPS lifecycle | Local server records, environment inspection, SSH deployment, WireGuard port migration |
| Device lifecycle | Per-device keypairs, peer registration, allocation, listing, configuration export |
| Connection | Preflight validation, split tunnel, IPv4 full tunnel, daemon mode, disconnect cleanup |
| Resilience | Endpoint rebinding, handshake monitoring, reconnect backoff, route and DNS restoration |
| Security | OS credential storage, log masking, client-side private keys, no hosted control plane |

## Workspace

```text
crates/
├── miaovps-core              # Domain models
├── miaovps-wireguard-config # Keys and WireGuard configuration
├── miaovps-ssh              # SSH transport and authentication
├── miaovps-provisioner      # Detection, deployment and rollback
├── miaovps-storage          # SQLite and OS credential storage
├── miaovps-connect          # TUN, routes, DNS, handshake and reconnect
├── miaovps-app              # Reusable application-service boundary
├── miaovps-cli              # Command-line entry point
├── miaovps-tunnel-api       # Platform-neutral tunnel contracts
└── miaovps-telemetry        # Local status-observation client
```

## Development

```bash
cargo build
cargo test --workspace
cargo clippy --workspace --all-targets --all-features
```

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md), and
do not include real infrastructure addresses, credentials, private keys,
exported WireGuard configurations, or local MiaoVPS data in issues or commits.

## Project status

MiaoVPS is **pre-1.0**. The Rust workspace and macOS client tunnel path are the
currently exercised development path. SSH management may be portable, but a
platform must not be considered supported until its TUN, routing, DNS,
privilege, and recovery behavior have been validated end to end.

Use a non-critical VPS first and retain provider-console access. Review the
[security policy](SECURITY.md) and [deployment guide](docs/deployment.md) before
deployment.

## License

MiaoVPS is available under the [MIT License](LICENSE). Copyright © 2026 Wentao Ge.
