---
title: CLI
description: Current secmon commands and planned CLI surface.
---

# CLI

## Current commands

The CLI exposes help and version output and starts a local read-only MCP server:

```text
cargo run -p secmon -- --help
cargo run -p secmon -- --version
cargo run -p secmon -- mcp
cargo run -p secmon -- mcp --database <path-to-existing-database>
```

`secmon mcp` opens the existing SQLite database read-only, loads enabled tool names from the adjacent `ai-settings.json`, and serves MCP JSON-RPC over stdio. It does not migrate or write the database. Source reads additionally require the project's explicit local-MCP source-access setting. See [Local MCP](local-mcp.md).

## Planned commands

Future CLI commands must not bypass privacy approvals, typed repositories, or evidence freshness rules.
