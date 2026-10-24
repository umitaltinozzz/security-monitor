---
title: CLI
description: Current secmon commands and planned CLI surface.
---

# CLI

## Current commands

The current `secmon` binary exposes only Clap's help and version output:

```text
cargo run -p secmon -- --help
cargo run -p secmon -- --version
```

There are no scan, report, database, MCP, or server-management commands in the current build.

## Planned commands

The v1.0 specification plans CLI access to the same local core services as the desktop app. Command syntax, exit codes, and output formats will be documented here when implemented. The CLI must not bypass privacy approvals, typed repositories, or evidence freshness rules.
