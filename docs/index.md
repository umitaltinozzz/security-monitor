---
title: Security Monitor documentation
description: Architecture, privacy, data sources, and contribution guidance for Security Monitor.
template: splash
hero:
  tagline: Local-first security monitoring for projects and deployed environments.
  actions:
    - text: Architecture
      link: /architecture/
      icon: right-arrow
    - text: Privacy model
      link: /privacy/
      variant: minimal
---

> **Development status:** the product is under active development. The desktop app and `secmon` CLI provide local project scans and review, reports, advisory refresh, diagnostics, approved server collection, Git hooks, coding-agent integrations, AI request review, and a read-only MCP server. Missing, stale, partial, or unverified evidence remains `needs_review`; the current build is not a guarantee of complete protection.

These pages describe implemented workflows and clearly mark their limits. Some deeper orchestration and agent-to-agent shared-memory features remain out of scope for the current build.
