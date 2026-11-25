# VPS Deployment Guide

MiaoVPS deploys AmneziaWG by default, or native WireGuard with `--wg`, over SSH.
No persistent MiaoVPS agent is required on the VPS.

## Prerequisites

The target host should provide:

- Ubuntu 22.04 or 24.04 for AWG, with headers for the running kernel if the
  AmneziaWG module needs installing;
- SSH access as root or a user that can run the required `sudo` commands;
- a reachable public IPv4 address;
- an inbound rule for the selected UDP port in the cloud and host firewalls; and
- permission to enable IP forwarding, NAT, and a systemd service.

Verify the VPS SSH host key through a trusted channel such as the provider
console, then add the verified key to `~/.ssh/known_hosts`. MiaoVPS will not
send credentials to an unknown host or accept a changed key automatically.

## Deploy

```bash
miaovps add-server "my-vps" 203.0.113.10 22 ubuntu --key ~/.ssh/id_ed25519
miaovps inspect <server-id>
miaovps deploy <server-id> --port 52181
miaovps validate
sudo miaovps connect --full
```

`deploy` creates one AWG peer, checks a real handshake from your device and
saves `~/.miaovps/miao-awg-trial.conf`. It does not need `wg0` and does not
modify it. If verification fails, fix firewall access and retry the same
command; the client key is retained for the retry. The default port is 52181.
For native WireGuard, use `miaovps deploy --wg <server-id>`, then
`miaovps add-device --wg <server-id> <name>` and `connect --wg`.

Password authentication is supported, but do not place a password in a shell
script, command history, issue, or commit. Prefer key-based SSH access.

## Reuse an existing WireGuard peer (optional)

`deploy-awg` is only needed to deploy AWG with an **existing registered WG peer**,
for example to keep a device identity that already exists in the local database.
The default `deploy` generates its own client key and needs no WG peer.

For an existing MiaoVPS device on an IPv4-addressed Ubuntu 22.04/24.04 node, choose an unused UDP port and allow it in both the cloud and host firewalls. Run as the device's local user (not `sudo`):

```bash
# After `miaovps add-device --wg <server-id> ...` has registered the peer:
miaovps deploy-awg <server-id> <device-id> 52181 ~/.miaovps/miao-awg-trial.conf
miaovps validate
sudo miaovps connect --full
```

This creates a separate `miao-awg` interface, server key, framing parameters and a non-overlapping private `/30` subnet selected from the VPS routes. It reuses the selected device's key from Keychain; the device private key is never sent to the VPS. The regular `wg0`, device records and WG connection profile stay unchanged. If needed the command installs Amnezia's [Ubuntu PPA and kernel module](https://docs.amnezia.org/ru/documentation/instructions/install-amneziawg-kernel-module-linux/); matching kernel headers and permission to load the module are required. No automatic kernel upgrade or reboot is requested.

Stop the current tunnel before `connect`. No external client is required; you may also import the private `.conf` into an AmneziaWG app, but do not connect both clients using the same peer key at once. `sudo awg show miao-awg` on the VPS shows handshakes and transfer counters. Full tunnel provides IPv4 internet access only.

One device per AWG listener. Retry with the same arguments and a **new output filename** to re-export without rotating keys. To roll back to WG, stop AWG locally and reconnect using `sudo miaovps connect --wg --full`; to remove the AWG listener, run `sudo systemctl disable --now awg-quick@miao-awg` on the VPS. This leaves the protected AWG config, packages and repository installed.

## Firewall rules

| Protocol | Port | Direction | Purpose |
| --- | ---: | --- | --- |
| UDP | Same as `deploy --port` | Inbound | AWG or WireGuard handshake and data |
| TCP | SSH port, commonly 22 | Inbound | Deployment and diagnostics |

ICMP is optional. A blocked `ping` does not by itself prove that the VPN
data plane is unavailable.

## Port migration

Stop your local tunnel, then open the new UDP port in both firewalls:

```bash
miaovps deploy <server-id> --port 52182        # AWG
miaovps deploy --wg <server-id> --port 51821   # Native WG; requires a saved matching WG profile
```

The candidate replaces the current listen port temporarily. A successful
client handshake commits the change. Otherwise the old listener is restored,
with a server-side timer as a fallback if SSH is lost. Other devices on that
interface can be interrupted during the test. Keys, peers and the other
protocol's listener are unchanged. Only run the command for your chosen protocol.

## Multiple devices

AWG deployments currently hold one peer each. Native WireGuard (all commands
below use `--wg`) supports multiple devices per interface. One WireGuard
interface has one server listen port; all its devices use that port with
distinct public keys and VPN addresses:

```text
Device A: random local UDP port -> VPS:443  (unique key, 10.66.66.2/32)
Device B: random local UDP port -> VPS:443  (unique key, 10.66.66.3/32)
```

Create one peer per physical device:

```bash
miaovps add-device --wg <server-id> "MacBook" mac
miaovps add-device --wg <server-id> "iPhone" iphone
miaovps list-devices --wg <server-id>
miaovps export-config --wg <device-id>
```

Do not reuse a client private key, public key, or VPN address across physical
devices. WireGuard would treat them as one peer and repeatedly move the remote
endpoint between devices.

`connect --port` temporarily overrides the client target port. It does not add
a server listen port. `deploy --wg --port` migrates `wg0` and therefore affects
all devices using that interface.

## Verification and troubleshooting

```bash
miaovps inspect <server-id>
miaovps status <server-id>
sudo miaovps connect --full
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
