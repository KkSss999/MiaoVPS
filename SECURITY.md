# Security Policy

## Supported versions

MiaoVPS is currently pre-1.0. Security fixes are applied to the latest commit
on the default branch only.

## Reporting a vulnerability

Please do not open a public issue for suspected vulnerabilities, leaked
credentials, or infrastructure details. Report them privately through GitHub's
private vulnerability reporting feature when it is available for this
repository, or contact the maintainer at `keryege@gmail.com`.

Include the affected component, reproduction steps, impact, and any suggested
mitigation. Please allow a reasonable remediation window before public
disclosure.

## Operator responsibility

MiaoVPS modifies remote AmneziaWG or WireGuard configuration and may modify
local routes and DNS settings. It refuses unknown or changed SSH host keys, so
verify the VPS fingerprint through a trusted channel before the first connection.
Changes to a server listen port interrupt every peer on that interface until they
use the new port. Test on non-critical infrastructure first, keep provider-console
access to the VPS, and review the deployment and rollback guidance before use.

Never commit VPS credentials, VPN private keys, exported `.conf` files,
private `.conf.pending` files, real infrastructure addresses, or local MiaoVPS
data directories. Deliver newly enrolled AWG profiles only to their intended
device over a trusted channel. Once imported, remove any transfer copies you
no longer need.
