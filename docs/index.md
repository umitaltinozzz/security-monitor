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

> **Development status:** the product is under active development. The current build includes local Rust libraries for dependency inventory, advisory ingestion, scanner adapters, and finding correlation, plus a desktop shell and a CLI with help/version output. The desktop app and CLI do not yet connect these libraries into an end-to-end scan workflow.

These pages describe implemented libraries and clearly mark planned application behavior. A library feature is not yet available as an end-user workflow until the desktop app or CLI connects and verifies it.
