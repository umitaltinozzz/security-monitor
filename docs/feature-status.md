---
title: Feature status
description: Product maturity and current scope for Security Monitor 0.1.0.
---

# Feature status

Security Monitor is pre-release, version **0.1.0**. This page is the source of truth for what the product currently supports.

**Ready** means usable within the scope stated in the table. **Experimental** means implemented but still needs broader validation; do not use it as the only production security control. **Planned** means the feature is not available in the desktop product. None of these labels means an environment is safe. Missing, stale, or unsupported data remains unverified or not evaluated.

| Feature | Status | Current scope |
| --- | --- | --- |
| Local quick scans and local inventory storage | Ready | Supported repository manifests and lockfiles are read on-device; matching uses locally stored advisory data. A quick scan does not run full source-code scanners. |
| CLI reports and Git hooks | Experimental | Reports are generated locally. Hooks check supported changed dependency inputs; review the configured warn or block behavior before relying on a hook to gate a release. |
| Optional full-scan adapters | Experimental | OSV-Scanner, Trivy, and Semgrep run only when available and configured. Missing engines or incomplete results do not produce a clean state. |
| Public advisory downloads | Experimental | Downloads are off by default and require the public-download setting. Requests use the local ecosystem selection; package inventories are not uploaded. |
| Linux server pairing and inventory | Experimental | Requires the read-only Linux agent, pinned SSH, and user approval for each collection. Linux distributions and host configurations still need broader real-server validation. |
| Linux OS package advisory evaluation | Experimental | Debian and Ubuntu packages are evaluated against fresh local OSV data when package collection is complete. RPM, APK, and other unsupported distributions are shown as not evaluated. |
| Repository-to-production drift | Experimental | Requires a verified project reference and a recent approved Linux server inventory linked by the user. Missing evidence stays unknown or needs review. |
| Desktop startup checks, scheduler, and file watcher | Experimental | Runs while the desktop tray process is open. Project checks and file changes can queue scans; scheduled full scans use the interval in Settings. |
| Coding-agent integrations and local MCP | Experimental | Claude Code, Codex, and OpenCode integrations operate on local data. Remediation prepares edits in a separate worktree for manual review and application; discarding or seven-day expiry removes its worktree and branch. Agent configuration and hooks remain subject to the boundaries in the integration guide. |
| AI analysis and approved data transfers | Experimental | Transfers require a reviewed approval. Provider, budget, and data-category controls apply; provider retention is outside this product's control. |
| Agentless SSH collection | Planned | Not available in the desktop or CLI product. Server collection requires the Linux agent. |
| OS package evaluation for RPM, APK, and other distributions | Planned | These packages are collected where supported but are not evaluated for OSV findings. |
| Desktop, webhook, Slack, Discord, and email notifications | Planned | Notification delivery is not wired into the desktop product and has no channel-management UI. |
| Signed desktop installers and application updates | Planned | Version 0.1.0 has no published signed installers. |

