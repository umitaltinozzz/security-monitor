---
title: Local MCP server
description: Run secmon mcp with explicit local tool permissions and read-only database access.
---

# Local MCP server

`secmon mcp` serves the local Security Monitor database over stdio using MCP JSON-RPC. It reads the current AI tool settings from the same application-data directory as the database and opens SQLite read-only. It does not start scans, write findings, or call external networks.

```text
secmon mcp
secmon mcp --database <path-to-existing-security-monitor.sqlite3>
```

Configure the command in the MCP client as a local stdio server. Keep stdin/stdout reserved for MCP messages; diagnostics go to stderr. The server lists only tool names enabled in **Settings → AI**. Read-only project, finding, advisory, and server-alias tools are available; write-capable tools are not exposed.

## Source-file access

The local MCP server does not expose source-file read or search tools. It cannot verify which provider an MCP client might use after receiving a file. Source reads remain available only inside desktop AI requests, where the app checks the project's provider allowlist, displays and records the destination approval, redacts the file, and confines access to the project directory.

The default AI settings enable no tools. The MCP server cannot modify SQLite, source files, finding statuses, or priority scores. Unknown deployment identity and missing evidence remain `needs_review`.
