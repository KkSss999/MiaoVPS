# VPS Deployment Guide

MiaoVPS performs a one-time WireGuard deployment over SSH. No persistent
MiaoVPS agent is required on the VPS.

## Prerequisites

The target host should provide:

- a supported Linux distribution such as Ubuntu or Debian;
- SSH access as root or a user that can run the required `sudo` commands;
- a reachable public IPv4 address;
- a cloud firewall rule for the selected WireGuard UDP port; and
- permission to enable IP forwarding, NAT, and a systemd service.

## Deploy

```bash
miaovps add-server "my-vps" 203.0.113.10 22 ubuntu --key ~/.ssh/id_ed25519
miaovps inspect <server-id>
miaovps deploy <server-id> --port 443
miaovps add-device <server-id> "my-mac" mac
sudo miaovps connect <server-id> --device <device-id> --full
```

Password authentication is supported, but do not place a password in a shell
script, command history, issue, or commit. Prefer key-based SSH access.

## Firewall rules

| Protocol | Port | Direction | Purpose |
| --- | ---: | --- | --- |
| UDP | Same as `deploy --port` | Inbound | WireGuard handshake and data |
| TCP | SSH port, commonly 22 | Inbound | Deployment and diagnostics |

ICMP is optional. A blocked `ping` does not by itself prove that the WireGuard
data plane is unavailable.

## Port migration

If UDP 51820 is unsuitable on the current network path:

```bash
miaovps deploy <server-id> --port 443
sudo miaovps connect <server-id> --device <device-id> --full
```

UDP 443 is still WireGuard, not HTTPS, and may remain subject to local or
provider UDP policy. Update both the cloud firewall and the VPS firewall when
migrating a port.

## Multiple devices

One WireGuard interface has one server listen port. All devices on a MiaoVPS
node connect to that same target port and use distinct public keys and VPN
addresses:

```text
Device A: random local UDP port -> VPS:443  (unique key, 10.66.66.2/32)
Device B: random local UDP port -> VPS:443  (unique key, 10.66.66.3/32)
```

Create one peer per physical device:

```bash
miaovps add-device <server-id> "MacBook" mac
miaovps add-device <server-id> "iPhone" iphone
miaovps list-devices <server-id>
miaovps export-config <device-id>
```

Do not reuse a client private key, public key, or VPN address across physical
devices. WireGuard would treat them as one peer and repeatedly move the remote
endpoint between devices.

`connect --port` temporarily overrides the client target port. It does not add
a server listen port. `deploy --port` migrates the node's `wg0` listen port and
therefore affects every device.

## Verification and troubleshooting

```bash
miaovps inspect <server-id>
sudo miaovps connect <server-id> --device <device-id> --full
curl -4 https://ifconfig.me
bash scripts/test-tunnel-health.sh --vps 203.0.113.10
```

For handshake timeouts, verify UDP rather than TCP firewall rules, the selected
listen port, the server peer public key, and the selected local server/device
pair.

## Rollback

```bash
sudo miaovps disconnect
```

The deployer keeps backups of relevant remote network configuration. If remote
deployment fails, preserve the CLI output and `inspect` result, then recover
through SSH or the provider console instead of overwriting production network
state blindly.
