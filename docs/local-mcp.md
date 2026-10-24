---
title: Local MCP server
description: Run secmon mcp with explicit local tool permissions and bounded local memory access.
---

# Local MCP server

`secmon mcp` serves the local Security Monitor database over stdio using MCP JSON-RPC. It reads the current AI tool settings from the same application-data directory as the database and opens an existing SQLite database without creating or migrating it. It does not start scans, change findings, modify project files, or call external networks. The only local writes are bounded, expiring shared notes and their audit records when the user enables those tools.

```text
secmon mcp
secmon mcp --database <path-to-existing-security-monitor.sqlite3>
secmon mcp --agent <stable-client-name>
```

Configure the command in the MCP client as a local stdio server. Keep stdin/stdout reserved for MCP messages; diagnostics go to stderr. The server lists only tool names enabled in **Settings → AI**. Read tools expose local project, finding, advisory, and server-alias data. `remember` and `forget` can write only to shared memory when enabled; agents cannot set finding status, change priority, or write to project files. Use a stable `--agent` name so agent-authored notes have a consistent owner.

## Source-file access

The `read_project_file` and `search_project` tools are available only when both tools are enabled in **Settings → AI** and the target project is selected under **Local MCP source access**. No project is approved by default. Each grant and revocation is recorded in the local Activity history, and a project that is absent from the approved list is denied even when a client calls the tool directly. Returned files and snippets are redacted, size-limited, and confined to the canonical project root.

The local MCP server cannot verify which provider an MCP client may use or whether that client forwards returned text. Grant access only to projects suitable for the configured MCP client. Desktop AI requests use a separate flow that checks the project's provider allowlist and displays a request-specific destination and content approval.

The default AI settings enable no MCP tools. Source file access still requires a separately recorded per-project grant. Memory write controls and note scopes are described in [Shared local memory](shared-memory.md). Unknown deployment identity and missing evidence remain `needs_review`.
