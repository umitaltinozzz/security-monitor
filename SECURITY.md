# Security policy

## Supported versions

Security Monitor is pre-release, version 0.1.0, and under active development. Security fixes are currently made against the `main` branch. Review the [feature status matrix](docs/feature-status.md) for implemented scope and unsupported features. Do not use this build as the sole production security control.

## Reporting a vulnerability

Please do not report vulnerabilities in a public issue. Use [GitHub's private vulnerability reporting page](https://github.com/umitaltinozzz/security-monitor/security/advisories/new) if the repository offers the private reporting form. If that form is unavailable, do not disclose technical details publicly; use the maintainer's GitHub contact page to request a private reporting channel.

Include the affected commit or version, impact, and a minimal reproduction when safe to do so. Avoid attaching real credentials, source code, customer data, or production inventory. We will acknowledge and coordinate a fix and disclosure timeline with the reporter.

## Security boundaries

The desktop build provides local scans and approved Linux-agent collection over pinned SSH, within the limits listed in the feature status matrix. Debian and Ubuntu OS packages are evaluated only when package collection is complete and local OSV data is fresh; unsupported distributions are marked not evaluated. Missing, stale, or unsupported evidence must not be interpreted as a safe result. Notification delivery and agentless SSH collection are not available.
