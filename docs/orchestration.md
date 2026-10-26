---
title: Scan orchestration
description: Local scan queues, desktop scheduling, file watching, and startup checks.
---

# Scan orchestration

`security-monitor-scan-orchestrator` coordinates local project scans. The desktop app can start quick and full scans; `secmon scan` currently starts the Quick profile using local inventory and cached advisory data.

## Queue and profiles

The bounded queue limits parallel scans to at most two by default, accepts up to 64 pending jobs, and applies a ten-minute maximum scan duration. Limits are configurable. Jobs carry cancellation tokens and a reason so callers can distinguish manual, startup, file-change, and scheduled work.

Quick scans parse local manifests and lockfiles, hash supported dependency inputs, save package inventory metadata in SQLite, and correlate against the local advisory records. They do not invoke external scanners. Full scans add OSV-Scanner, Trivy filesystem and misconfiguration checks, and Semgrep when the caller has configured a local rules file. Missing engines, incomplete inventories, unavailable rules, stale advisory data, and scanner failures produce partial or unverified outcomes rather than a clean result.

The stored checkpoint contains only parsed inventory metadata, an input hash, and timestamps. It does not copy source files or lockfiles. Scanner evidence paths are relative to the project root.

## Desktop startup, watching, and schedules

When the desktop starts, it checks configured projects and starts a recursive watcher for each valid project root. Startup checks compare the supported dependency-input hash with its saved checkpoint. Only changed, incomplete, or previously unverified inputs are queued for a quick scan. Invalid or missing roots stay unverified. The tray process keeps these services running after the window closes; explicitly quitting the app stops them.

The recursive file watcher rejects paths outside the canonical root and ignores generated dependency/build directories. Dependency manifest and lockfile changes queue the quick profile; source and security configuration changes queue the full profile. Events are grouped for three seconds after the most recent relevant change, and a full-profile event takes precedence in a mixed batch. The desktop reconciles watcher roots as projects are added or removed.

The scheduler checks project inputs every 15 minutes, re-correlates cached inventories every 10 minutes, and schedules full scans at the interval selected in Settings (default 24 hours; allowed range 1–168 hours) while the desktop process is running. Missed ticks are skipped instead of launching a burst of delayed scans. External provider requests remain subject to the public-download setting and provider-specific refresh intervals.

Parent-folder discovery returns canonical project candidates for user review. It never adds the discovered projects to SQLite automatically.

## Notifications

The tray background sends a local OS notification for new critical/high findings, drift status changes, and server inventories that have not had a complete collection within 24 hours. OS notifications are enabled by default. The optional daily summary sends at most once per UTC date.

Settings supports HTTPS webhooks, Slack, Discord, ntfy, and SMTP. External delivery is off by default; the user must enable outbound notifications and record approval for each destination. Complete URLs, ntfy tokens, and SMTP passwords are stored only through the OS credential store. The database keeps an opaque credential reference and the approved origin/host. The preview command does not send a request; test delivery is an explicit action. A delivered event fingerprint is suppressed permanently, while a new stale-snapshot period or changed drift state receives a new fingerprint.

## Verification fixtures

Deterministic, offline fixtures are under `tests/fixtures/orchestration/`. Unit coverage includes three-second debounce precedence, changed-input hashing, nested Git-less discovery, startup scans for changed projects only, advisory re-correlation without another scan, bounded concurrency and cancellation, a 50-project quick-scan batch, webhook delivery through wiremock, permanent fingerprint suppression, and keeping channel secrets out of database records.
