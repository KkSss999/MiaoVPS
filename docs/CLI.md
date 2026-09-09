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
