---
title: Scan orchestration and notifications
description: Local scan queues, scheduling, file watching, startup checks, and privacy controls for alerts.
---

# Scan orchestration and notifications

`security-monitor-scan-orchestrator` coordinates local project scans. The desktop app can start quick and full scans; `secmon scan` currently starts the Quick profile using local inventory and cached advisory data.

## Queue and profiles

The bounded queue limits parallel scans to at most two by default, accepts up to 64 pending jobs, and applies a ten-minute maximum scan duration. Limits are configurable. Jobs carry cancellation tokens and a reason so callers can distinguish manual, startup, file-change, and scheduled work.

Quick scans parse local manifests and lockfiles, hash supported dependency inputs, save package inventory metadata in SQLite, and correlate against the local advisory records. They do not invoke external scanners. Full scans add OSV-Scanner, Trivy filesystem and misconfiguration checks, and Semgrep when the caller has configured a local rules file. Missing engines, incomplete inventories, unavailable rules, stale advisory data, and scanner failures produce partial or unverified outcomes rather than a clean result.

The stored checkpoint contains only parsed inventory metadata, an input hash, and timestamps. It does not copy source files or lockfiles. Scanner evidence paths are relative to the project root.

## Startup, watching, and schedules

Startup checks canonicalize each configured project root and compare the supported dependency-input hash with its saved checkpoint. Only changed, incomplete, or previously unverified inputs are queued for a quick scan. Invalid or missing roots are returned as unverified. Advisory refresh can also re-correlate cached inventories without running package scanners again, so new local advisory records can produce findings against existing inventories.

The recursive file watcher rejects paths outside the canonical root and ignores generated dependency/build directories. Dependency manifest and lockfile changes use the quick profile; source and security configuration changes use the full profile. Events are grouped for three seconds after the most recent relevant change, and a full-profile event takes precedence in a mixed batch.

The default scheduler checks project inputs every 15 minutes, refreshes advisory sources every 10 minutes, and schedules full scans weekly. Missed ticks are skipped instead of launching a burst of delayed scans. Provider-specific refresh intervals and privacy settings still control whether external provider requests can occur.

Parent-folder discovery returns canonical project candidates for user review. It never adds the discovered projects to SQLite automatically.

## Notification channels

`security-monitor-notify` supports desktop alerts, HTTPS webhooks, Slack, Discord, and SMTP with implicit TLS or STARTTLS. External delivery is disabled globally by default. Each enabled external channel also requires a timestamped user approval, an approved destination authority, and an opaque credential reference.

Webhook URLs, SMTP passwords, and other channel configuration are stored only in the operating-system credential store through `keyring`. SQLite stores only the opaque keyring reference, approved origin/host and port, and approval time. Logs and error messages omit credential values and full webhook URLs. Webhook, Slack, and Discord requests go through the shared HTTP client. SMTP is the one outbound path that does not, because it is not HTTP: it uses the `lettre` mail transport directly, but applies the same rules — delivery only to the approved host and port, a recorded user approval, TLS required, the destination host logged locally, and errors mapped to generic failures. Notification payloads contain finding identifiers, advisory identifiers, severity, priority, and an optional validated asset alias; they do not include source code, lockfiles, package inventories, or evidence paths.

Delivery state is stored per channel and finding fingerprint. The default deduplication window is 15 minutes; an in-flight lease prevents concurrent duplicate sends. Users can snooze a channel/finding pair for up to 30 days. The transport layer returns generic failures without embedding destination URLs or credential contents.

## Verification fixtures

Deterministic, offline fixtures are under `tests/fixtures/orchestration/`. Unit coverage includes three-second debounce precedence, changed-input hashing, nested Git-less discovery, startup scans for changed projects only, advisory re-correlation without another scan, bounded concurrency and cancellation, and a 50-project quick-scan batch. Notification tests cover persisted deduplication, snoozing, global outbound privacy defaults, credential references, and destination approval.
