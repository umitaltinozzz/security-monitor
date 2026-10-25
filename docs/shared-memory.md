---
title: Shared local memory
description: How shared notes work across Security Monitor and supported coding agents.
---

# Shared local memory

Security Monitor stores notes in the local SQLite database. Notes can be scoped globally, to a project, a server, or a finding. The desktop app lets the user create, edit, pin, review, and delete notes, and import or export a versioned JSON archive from AI settings.

Notes are context, not evidence. MCP returns note text in an explicit `untrusted_text` envelope. `recall` without a scope returns only notes from the approved project set; an unscoped local CLI workspace returns global notes only. When enabled, `analyze_impact` adds only matching project, server, or finding notes. Agents cannot pin notes, set finding status, change priority, or create user decisions. An agent may delete only notes it authored.

Agent-written notes are redacted before storage, have bounded size, and expire according to the configured retention period. Archive imports are re-authored as user notes, validated against existing project, server, and finding IDs, redacted, and assigned the current retention period. Exported note text is redacted again.

The `memory_agent_writes_enabled` setting controls whether MCP agents may use `remember` and `forget`. The user may disable agent writes at any time. Enabling `recall` exposes notes to the configured local MCP client; as with other local MCP tools, the client may choose to forward returned context, so review the client and its configuration.

## MCP tools

| Tool | Behavior |
| --- | --- |
| `recall` | Read untrusted notes, optionally filtered by scope and a literal search query. |
| `remember` | Save a redacted, expiring note under the current agent identity. It cannot create a user decision. |
| `forget` | Delete a note created by the same agent identity. |

Use `secmon mcp --agent <stable-name>` to give each client a stable author identity. Notes are shared between separate MCP processes that use the same local database.

## Archive format

The desktop export contains a version, export timestamp, and note records with scope, kind, content, and pin state. Import validates the version and all scope references before writing. Imported IDs, authorship, timestamps, expiry, and user verification are regenerated locally; an archive cannot transfer an old verification claim.
