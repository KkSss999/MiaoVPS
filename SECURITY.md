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

MiaoVPS modifies remote WireGuard configuration and may modify local routes and
DNS settings. Test on non-critical infrastructure first, keep provider-console
access to the VPS, and review the deployment and rollback guidance before use.

Never commit VPS credentials, WireGuard private keys, exported `.conf` files,
real infrastructure addresses, or local MiaoVPS data directories.
