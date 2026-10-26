---
title: Roadmap
description: How Security Monitor grows from 0.1 to 1.0 and beyond, version by version.
---

# Roadmap

Security Monitor 0.1 is the foundation. This page describes how it grows into 1.0, and where it may go after that.

Everything after 0.1 is **planned, not shipped**. Order and scope change with user feedback; open a [feature request](https://github.com/umitaltinozzz/security-monitor/issues/new/choose) or start a [discussion](https://github.com/umitaltinozzz/security-monitor/discussions) if something here matters to you. For what works today, see [Feature status](feature-status.md).

## Principles that do not change

Every version follows the same rules:

- **Local-first.** No account and no cloud dashboard. Source code, lockfiles, and inventory stay on your device unless you approve a specific transfer.
- **Read-only by default.** The server agent has no remote-command feature; its checks come from a compile-time allowlist. Connectors ask for read scopes first; every write is a separate, recorded approval.
- **Never green by default.** Missing, stale, or unverifiable data is shown as "could not verify", never as safe. "No signs found" always lists what was checked and what could not be checked.
- **Only your own assets.** Any active check runs only against assets whose ownership has been verified.
- **AI advises, you decide.** AI can explain and propose, but it never changes priority scores or marks a finding as not reachable, a false positive, or an accepted risk.
- **Secrets stay in the OS credential store.** Never in the database, logs, or error messages.

## At a glance

| Version | Theme | Goal |
| --- | --- | --- |
| **0.1** (now) | Foundation | Find known vulnerabilities in projects and Linux servers, and show whether a fix actually reached production |
| **0.2** | Close the gaps | Answer "what should I do about it?" for every finding, without connecting any new external account |
| **0.3** | Connectors and services | Use the services you already run as evidence sources and fix channels; know when a service you depend on is breached |
| **0.4** | Prevent and attack surface | Stop vulnerable code from entering the codebase and know everything that is visible from outside |
| **0.5** | Detect and respond | If a vulnerability stayed open, help answer "did someone get in?" |
| **0.6** | Platforms | Cover assets beyond Linux servers |
| **0.7** | Teams and compliance | Work as a team and turn collected evidence into audit material |
| **1.0** | Deep analysis | Reachability, supply-chain proof, and posture you can explain |

## 0.1 — Foundation (now)

- Local dependency inventory and matching against vulnerability advisories (OSV, GitHub Advisory Database, NVD, CISA KEV, EPSS), with a deterministic, explained priority.
- Scanner adapters for established open-source tools.
- Read-only Linux agent collected over SSH with a forced command and a pinned host key; no daemon and no open port.
- Repository-to-production drift: a fix in the repository is not shown as finished until the server proves it is running.
- Desktop app (Windows, macOS, Linux), CLI, JSON/SARIF/CycloneDX/OpenVEX reports, Git hooks.
- Coding-agent integrations, a local MCP server, and an approval-gated AI layer.
- Desktop, webhook, Slack, Discord, and email notifications.

## 0.2 — Close the gaps

**Goal:** every finding comes with a clear next step, and nothing in this release needs a new external account.

### End-of-life and runtime freshness

"No known vulnerability" is not the same as "safe": end-of-life software receives no security patches.

- Lifecycle data from endoflife.date, cached locally and refreshed daily.
- Sources on servers: OS release, runtimes (Node.js, Python, PHP, Java, Ruby, Go), and services (nginx, PostgreSQL, MySQL, Redis).
- Sources in projects: `engines`, `.nvmrc`, `.python-version`, `requires-python`, Composer and Go versions, Dockerfile `FROM` lines, CI matrices.
- Finding types: end-of-life reached, end-of-life within 90/30 days, and behind the latest security release of the same major version.
- If a version cannot be read or mapped, the result is "could not verify", not silence.
- A guided upgrade skill proposes the next LTS, checks dependency compatibility, and runs tests in the sandbox.

### Risk ownership: SLAs, owners, exceptions, metrics

- SLA policy with sensible defaults (critical 3, high 14, medium 45, low 90 days) and a stricter target for actively exploited, internet-facing production findings; per-project overrides.
- An owner for every finding, with a per-project default.
- Accepted-risk exceptions require an approver, a reason, and an **expiry date** (365 days at most); expired exceptions reopen automatically.
- Metrics: time to remediate by severity and project, SLA compliance, open-finding trend, deploy lag (fixed in the repository → running in production), the dependencies that cause the most findings, and the oldest open findings. Exportable as CSV/JSON.

### Server configuration audit (CIS-lite)

About 40 initial rules, collected by new read-only agent collectors and shipped as signed rule packs:

- **SSH:** root and password login, legacy key exchange and ciphers, `MaxAuthTries`, X11 forwarding, `AllowUsers`.
- **Network:** listening ports with their processes, databases or caches listening on all interfaces, firewall state.
- **Updates:** automatic security updates enabled, pending security updates.
- **Web servers:** TLS protocols, version disclosure, directory listing, security headers, exposed `.git`/`.env`.
- **Accounts and files:** passwordless sudo, extra UID 0 accounts, world-writable web roots, backups in the web root.
- **Docker:** root containers, privileged mode, host networking, Docker socket mounts, `latest` tags.

The agent never applies fixes. The app shows a proposed change, a lockout warning when a rule can lock you out, and a rollback step. If Lynis is already installed, its report can be read as an additional source.

### CI/CD and repository checks (local files)

- **GitHub Actions:** actions not pinned to a commit SHA, broad default permissions, `pull_request_target` with checkout, untrusted `github.event` expressions inside `run:`, `secrets: inherit`, self-hosted runners on public repositories.
- **GitLab CI:** `latest` images, unprotected variables, security jobs allowed to fail.
- **Dockerfile:** `latest`, running as root, `ADD` from remote URLs, secrets baked in through `ENV`/`ARG`.

### Guided fix skills

The first six fix skills cover the most common weakness classes: SQL injection, cross-site scripting, command injection, path traversal, secrets in code (including a rotation checklist), and weak cryptography. Each skill explains why the pattern is dangerous, shows the safe pattern per language and framework, lists common **wrong** fixes, adds a regression test, and re-runs the scanner to confirm the finding closes. Every change goes through the existing worktree → sandbox test → your approval pipeline.

### More ecosystems and CI integrations

- Java (Maven, Gradle), .NET, and Ruby lockfiles.
- An official GitHub Action and a GitLab CI template that run offline against a cached advisory database and upload SARIF.

### Agentless drift for self-hosted PaaS

Many independent developers already deploy through a self-hosted platform whose API knows which commit and image are running where. Read-only connectors for **Dokploy, Coolify, Openship, CapRover, Dokku, and Kamal** provide deploy evidence without installing an agent:

- Applications, environments, last successful deploy (commit, branch, image digest), running images, domains and TLS state, and environment variable **names** (never values).
- Only allowlisted read endpoints can be called; deploy, restart, and delete endpoints do not exist in the code.
- Platform data is evidence, not a verdict: production is only shown as fixed when the deployed commit contains the fix **and** the running image matches that commit.

## 0.3 — Connectors and services

**Goal:** turn the services you already use into evidence sources and fix channels, and warn you when one of them is breached.

- **Connector framework:** each connector declares its origin, auth method, and separate read and write scopes. Tokens live only in the OS credential store; every run records freshness, and stale evidence stops counting.
- **Compensating controls:** a WAF rule, a closed firewall port, or a disabled feature can lower a finding's priority, with the evidence and its age shown in the explanation. User-declared controls are labelled "not verified". The finding becomes *mitigated*, not closed.
- **GitHub:** Dependabot and secret scanning alerts for cross-checking, branch protection, required reviews, Actions settings; issues and pull requests only with approval.
- **Cloudflare:** unproxied records that expose the origin, dangling records (subdomain takeover risk), weak TLS settings, and whether a managed WAF rule covers a CVE. **Virtual patching:** a proposed custom WAF rule starts in log mode, shows matched requests after 24 hours, and moves to block only with your approval; once the code is fixed and deployed, the app reminds you to remove it.
- **Cloud and hosting firewalls:** Hetzner Cloud, DigitalOcean, AWS security groups, and GCP firewalls, combined with agent data ("listening and exposed", "listening but blocked", "unused rule").
- **More deploy evidence:** Vercel, Netlify, Render, Railway, and Fly; Sentry traces as an extra signal that vulnerable code actually runs.
- **Issue trackers:** GitHub Issues, GitLab, Jira, and Linear. Content is previewed and redacted before sending, code is excluded by default, and closing an issue moves the finding to "awaiting verification".
- **Third-party service inventory and incident tracking:** detects the services each project relies on from SDK packages, environment variable names, deploy configuration, and DNS. Values are never read. When a service publishes a security incident, you learn which projects and which keys are affected, get a rotation checklist, and can track every key until it is rotated. Official announcements are incidents; news reports stay unverified signals until confirmed.
- **Six more fix skills:** SSRF, insecure deserialization, authentication and session issues, broken access control, open redirects, and unsafe file uploads. Dart, Swift, and Elixir lockfiles.
- **Dependency update assistant:** the smallest safe version, breaking changes from release notes, the affected call sites in your code, a step-by-step plan for major upgrades, and a sandboxed test run.

## 0.4 — Prevent and attack surface

**Goal:** vulnerable code should not enter the codebase, and everything visible from outside should be known.

- **Ownership verification:** connected DNS or cloud accounts, agent-confirmed server IPs, or a DNS TXT record. If ownership lapses, active checks stop immediately.
- **Asset discovery:** finds assets you own but have not added, from your cloud and DNS accounts, local SSH, Docker, and Kubernetes contexts, and Certificate Transparency logs for verified domains. An inventory comparison shows what is monitored, found but unmonitored, and gone.
- **External attack surface (your assets only):** passive checks by default (DNS, CT subdomains, dangling records, SPF/DKIM/DMARC, CAA). Light active checks only with explicit approval and verified ownership: TLS expiry and configuration, security headers and version leaks, a short fixed list of sensitive paths with plain GET requests at a low rate, and a small port summary. Services seen from outside but missing from the inventory are reported.
- **Threat-intel enrichment:** signals that a CVE is being mass-exploited right now, plus locally cached public blocklists. Only CVE identifiers are queried; IP lookups that would send your data out are opt-in and off by default. Signals appear in the priority explanation; AI cannot change the score.
- **Pull request security review:** changed lines only, combining static analysis, the dependency diff, and an approval-gated AI review. Blocking decisions come only from deterministic rules.
- **Malicious package detection:** known malicious package records, typosquatting, install scripts with network access or obfuscation, sudden maintainer changes. By default only local signals are used; registry metadata lookups are opt-in.
- **Dependency policy:** banned licences, minimum package age, approval for new packages with install scripts, allowed registries; enforced in Git hooks and CI.
- **Secure defaults:** skills for Next.js, Express, FastAPI, and Laravel (security headers, CSP, rate limiting, cookies) and generated authorization and input-validation tests.

## 0.5 — Detect and respond

**Goal:** when a vulnerability stayed open in production, help answer "did someone get in?". This is not a SIEM or EDR; "not seen" never means "did not happen", and every screen says so.

- **Vulnerability-specific compromise checks** for actively exploited CVEs that are still open in production: published indicators in allowed log paths, suspicious files in web roots created after disclosure, unexpected cron entries, new SSH keys, users, or systemd units. Rules come from community Sigma and YARA sets with compatible licences, shipped in signed packs. Results read "No signs found (these 6 checks ran, these 2 could not run)" or "Review: this file appeared 3 days after disclosure" — never "clean".
- **Lightweight file integrity monitoring** for directories you choose (web root, `/etc/ssh`, cron, sudoers, systemd). Baselines are taken with your approval, and changes that match a known deploy can be accepted as expected. Existing AIDE or Wazuh reports can be read instead.
- **Local event summaries:** the agent turns journald, auth logs, and web server logs into counts and redacted samples; raw logs never leave the server. Covers brute force, first-time successful logins, root activity at unusual hours, requests matching open CVEs (with "attempted" kept separate from "may have succeeded"), and sudden changes such as new ports or services.
- **Canary tokens:** guidance for placing decoy keys in `.env` files, repositories, and servers, an inventory of where they are, and alerts linked to findings. Uses canarytokens.org or your own OpenCanary; Security Monitor does not run a trigger server.
- **Response playbooks:** step-by-step checklists for a web shell, a leaked secret, a compromised dependency, a leaked SSH key, and a third-party breach — with evidence preservation notes, when to call professional help, and data-breach notification reminders (not legal advice). Mapped to MITRE ATT&CK and D3FEND.
- **Secret inventory and rotation tracking:** which kinds of secrets live where (never values), last rotation dates, age policies, and a one-click "rotate these" list when a leak is suspected.

## 0.6 — Platforms

**Goal:** cover assets beyond Linux servers. This release may ship in smaller steps.

- **Windows Server and macOS agents:** installed software, services, IIS sites, .NET runtimes, pending updates, and Defender status on Windows; Homebrew, applications, and pending updates on macOS. Same rules: compile-time allowlist, no general exec, no shell.
- **Push-based agent with a self-hosted relay** for servers behind NAT or without SSH. The relay runs on your own server and is end-to-end encrypted; the desktop can only send a "collect" signal, never a command. It ships with its own threat model and an independent review.
- **Kubernetes and container registries:** running image digests mapped to workloads and repositories (drift for Kubernetes); GHCR, Docker Hub, and GitLab Registry images scanned locally.
- **Hosting panels and CMS:** read-only cPanel and Plesk inventory; WordPress and Joomla plugin and theme inventory.
- **Network devices and appliances:** firewalls and VPN gateways that cannot run an agent, inventoried manually, through read-only vendor APIs (FortiGate, PAN-OS, MikroTik, SonicOS, Cisco RESTCONF), SNMPv3, or discovered from the external surface. Matched against vendor PSIRT feeds, CISA KEV, and NVD; internet-facing management interfaces on actively exploited versions go to the top, with "remove it from the internet" as an interim step. Firmware end-of-life is tracked too.
- **Developer machines (optional, local):** OS and browser versions, IDE extensions (malicious, compromised, typosquatted, over-privileged), global developer tools, firmware, and SSH keys without passphrases or with legacy algorithms (key contents are never read).
- **More Linux distributions:** SUSE, Arch, Amazon Linux, and Wolfi.

## 0.7 — Teams and compliance

**Goal:** work as a team and turn the evidence you already collect into audit material. Individual use stays free and account-free.

- **Self-hosted team panel** (single binary or Docker, PostgreSQL). Desktops sync decisions and metadata only; source code and raw inventory are not synced by default. Viewer, approver, and admin roles, approval chains (for example two approvals for an accepted risk), OIDC single sign-on, and audit log export.
- **Compliance evidence reports:** vulnerability management, SLA compliance, patch history, configuration audits, and approval records mapped to ISO 27001, SOC 2, PCI DSS, and KVKK controls, as PDF/HTML reports and CSV evidence indexes. Labelled as evidence collection help, never as certification.
- **Exports to blue-team tools:** findings and SBOMs to DefectDojo and Dependency-Track, event summaries to Wazuh and Elastic, and approved cases to TheHive.

## 1.0 — Deep analysis

- **Reachability:** call-graph analysis that shows whether the vulnerable function is actually called, starting with JavaScript/TypeScript and Python. Shown as evidence; only you can mark a finding as not reachable.
- **Supply-chain proof:** SLSA provenance and Sigstore signature verification, building the chain "this production image was built from this commit by this pipeline" — the cryptographic form of drift.
- **Explainable posture:** a per-project and per-server summary that shows why it dropped and what would raise it, with a documented formula.
- **Plugin SDK:** third-party scanners, data sources, collectors, and skills as signed plugins running in a WASM sandbox with explicit network and file permissions.
- **DAST against your own test environments:** orchestration of a mature tool such as OWASP ZAP, limited by a scope file of allowed hosts, paths, and rates. Off for production by default and gated by ownership verification. Results are merged with static findings ("confirmed in code and in the running app").
- **Cloud and Kubernetes posture:** read-only checks for public buckets, over-privileged IAM, unencrypted disks, RBAC, pod security, and network policies, with the option to read Prowler or kube-bench output.

## Beyond 1.0: a mini SOC for small teams

A research direction, not a commitment. The idea is to give a small team the core of a security operations center without the cost of running one:

- **Compromise assessment:** a guided "was this server compromised?" flow — who has access, what the server talks to, persistence, management surface, external reputation, and reports from scanners you run yourself. Linux first, Windows event logs later.
- **Identity and access event detection:** brute force, password spraying, a successful login after failures, logins outside working hours, new accounts, firewall or remote-access port changes, logins from IPs on local blocklists. No automatic blocking; suggestions or one-time, reversible blocks with your approval. If auditing is off, the result is "auditing disabled, could not verify".
- **Defense coverage map and maturity check:** which defensive layers exist for each asset (with evidence), and a short self-assessment that ends with "your next three steps", not a score.
- **Coverage and quality KPIs:** stale inventory, unscanned projects, false-positive rates per rule, rules that never fire, and ATT&CK coverage.
- **Control-to-framework mapping:** every rule mapped to NIST CSF, ISO 27001, CIS Controls, SOC 2, PCI DSS, MITRE ATT&CK, and Turkish KVKK guidance.
- **OCSF output** for SIEMs such as Splunk, Microsoft Sentinel, and AWS Security Lake; always previewed and approved.
- **Cloud and SaaS posture** for the most valuable 30–50 checks.
- **Hardening of the machine Security Monitor runs on:** it holds the keys to every server, so the app checks disk encryption, updates, screen lock, and data directory permissions.
- **Detection engineering lifecycle:** positive and negative tests for every rule, local hit and false-positive statistics, and quarterly reviews.
- **Continuous external surface monitoring:** new subdomains, dangling DNS, takeover signatures, certificate changes, and new open ports, with imports from Prowler, Kubescape, and Trivy.
- **Optional network sensor:** a separate Zeek or Suricata sensor whose log summaries are read (raw packets never leave it), with detections such as beaconing, DNS tunnelling, rogue DHCP, and data leaving at night. "The sensor went quiet" is reported as blind, not as safe.
- **Static triage of suspicious files:** hashes, file type, entropy, sections, imports, YARA matches, and local hash lists. No dynamic execution; the file itself is never uploaded.
- **Lab and self-test:** `secmon lab up` starts a local, isolated environment with known problems for a five-minute end-to-end demo, and `secmon selftest` replays attack patterns against the product's own detections to show what works and what is blind.

## Never in scope

| Topic | Why |
| --- | --- |
| Testing, scanning, or exploiting systems you do not own | The product is defensive and only for your own assets |
| Automatic patches, deploys, or root access in production | Every change is approved and isolated |
| A general command channel in the agent | One weakness would open every server |
| Claiming to be a full EDR, XDR, SIEM, or antivirus | Lightweight local summaries, without that claim |
| Guaranteed zero-day discovery | Signals and compromise checks help; they do not guarantee |
| Findings created directly from news or social media | News stays a signal; an official advisory becomes an incident |
| A managed SaaS | A self-hosted team panel instead |
| Telemetry | It contradicts the privacy promise |
