---
title: Threat model
description: Security goals, assets, trust boundaries, and residual risks.
---

# Threat model

## Security goals

- Keep source code, lockfiles, package inventory, SSH keys, provider credentials, and webhook/SMTP secrets under user control.
- Prevent untrusted repository, advisory, scanner, agent, and model text from becoming instructions or executable commands.
- Make evidence provenance and freshness visible, and avoid a green/safe state when verification is incomplete.
- Limit remote collection to read-only inventory through a fixed SSH forced command.

## Assets and trust boundaries

| Asset | Boundary / control |
| --- | --- |
| Source files, lockfiles, inventory | Local filesystem; path checks canonicalize symlinks; outbound transfer requires recorded approval |
| Findings and evidence | Local SQLite through typed repository APIs; source, freshness, and verification state retained |
| SSH and provider secrets | Operating system credential store; never SQLite, logs, or error text |
| Linux host | SSH host key pinned after user confirmation; dedicated key restricted to collection command |
| External advisories and scanner results | Untrusted input; parse and validate before storage or display |
| AI provider and model output | Optional remote boundary; approved metadata only, redaction and budget controls; model cannot change user-owned states or priority |

## In-scope threats

Malicious repository files or dependency names; path traversal and symlink escapes; fabricated or stale advisory data; scanner output injection; compromised AI output; accidental data upload; credential leakage; SSH host impersonation; and attempts to gain arbitrary command execution through the agent.

## Out of scope

The product is not an endpoint detection and response tool, exploit framework, production patching/deployment system, cloud service, or remote shell. The current repository is incomplete and must not be used as an operational security control.

## Residual risk

Advisory coverage, package metadata, scanners, and remote host configuration can be incomplete or wrong. A clean result cannot prove absence of vulnerabilities. The application must show stale, missing, or unknown evidence as unverified and direct users to original sources.
