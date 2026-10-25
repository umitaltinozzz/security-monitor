---
title: Security Monitor
description: Local-first security monitoring for your projects and your Linux servers.
template: splash
hero:
  tagline: You fixed it in the repo. Is production still vulnerable?
  image:
    light: ../../assets/logo-light.png
    dark: ../../assets/logo-dark.png
    alt: Two raven heads facing outward around an eye
  actions:
    - text: Get started
      link: /security-monitor/getting-started/
      icon: right-arrow
    - text: How drift works
      link: /security-monitor/drift/
      variant: minimal
    - text: GitHub
      link: https://github.com/umitaltinozzz/security-monitor
      icon: external
      variant: minimal
---

Security Monitor matches your dependencies against vulnerability advisories on your own machine, then checks what actually runs on your Linux servers, so a fix that never got deployed does not look finished. There is no account and no cloud dashboard, and missing or stale data is always shown as *could not verify*, never as safe.

> **Pre-release: 0.1.0.** The product is in active development; signed installers are not published. See the [feature status](feature-status.md) for current scope, including unsupported server distributions.

## What it does

- **Finds vulnerable dependencies locally** from supported lockfiles and local advisory data, with optional OSV-Scanner, Trivy and Semgrep adapters. Server OS packages are evaluated only for Debian and Ubuntu when collection is complete and local OSV data is fresh; other distributions are marked not evaluated.
- **Compares the repository with production.** A read-only Linux agent over pinned SSH reports installed packages, running kernels and processes that still use deleted libraries; linked projects show "fixed in repo, still running in production". Agentless collection is not available in the product.
- **Warns before vulnerable code is pushed** with a Git hook that checks only changed lockfiles, offline.
- **Works with coding agents** through a local MCP server and skills for Claude Code, Codex and OpenCode.
- **Prepares fixes you approve** in an isolated Git worktree with network-disabled sandbox tests.

## Where to go next

- New here: [Getting started](getting-started.md)
- Current scope: [Feature status](feature-status.md)
- Trust and data handling: [Privacy](privacy.md) and [Threat model](threat-model.md)
- Servers: [Linux agent](agent-install.md) and [Deploy ID](deploy-id.md)
- Command line and automation: [CLI](cli.md) and [Coding-agent integrations](integrations.md)

A missing finding is not proof that software or an environment is secure. Verify results against the original advisory and your own environment before making security decisions.
