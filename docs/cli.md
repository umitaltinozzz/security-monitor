---
title: CLI
description: Local scan, report, advisory-cache, diagnostics, server collection, Git-hook, and coding-agent integration commands.
---

# CLI

`secmon` shares the local SQLite database and settings used by the desktop app. Set `--database <path>` on any command to use a specific database; advisory caches, AI settings, and other app data are resolved next to that database. Without the option, the platform application-data directory is used.

## Scan a project

```text
secmon scan <path> [--format table|json|sarif] [--fail-on critical|high|medium|low] [--offline]
```

The CLI scan uses the Quick profile with local inventory parsers and cached advisory data; it does not launch external scanner processes. A missing or stale cache, incomplete inventory, or unknown evidence stays `needs_review`; it is not reported as clean. `--offline` disables public-data requests. JSON and SARIF output is validated against its vendored schema before it is written.

`--fail-on` selects the minimum finding severity that returns exit code `2`. Incomplete or unverified results return `3`; successful verification returns `0`. Invalid input or operational failures return `1`.

## Export a report

```text
secmon report [--format json|sarif|cyclonedx|openvex] [--project <id>]
```

Reports read the existing local database. An OpenVEX document with no statements is rejected by its schema and is not emitted.

## Advisory data and diagnostics

```text
secmon db update [--ecosystems <comma-separated-ecosystems>]
secmon doctor
```

`db update` requires public downloads to be enabled in local settings. With no ecosystem list, it refreshes the configured ecosystems. Downloads are explicit user actions and use the shared HTTP wrapper. `doctor` reports database, latest scan, scanner, and advisory-cache availability; missing or stale checks return `3` and print `needs_review`.

## Collect an approved server inventory

```text
secmon server collect <asset-id> --approve-transfer
```

This sends an explicit one-time approval with the inventory collection request. The SSH target must already be paired, and its host key must have been verified. Collection remains limited to the server agent's allowlisted checks.

## Git hooks

```text
secmon hook install [--pre-push|--pre-commit] [--mode warn|block] [--fail-on critical|high|medium|low]
secmon hook run [--pre-push|--pre-commit] [--mode warn|block] [--fail-on critical|high|medium|low]
secmon hook uninstall [--pre-push|--pre-commit]
```

The default hook is `pre-push`, mode is `warn`, and threshold is `high`. The check reads changed dependency files from the staged Git index for `pre-commit` and from the refs being pushed for `pre-push`; it uses only the local advisory cache. Unsupported or deleted dependency inputs and unavailable/stale advisory data produce `needs_review`. Warn mode reports and continues; block mode stops the commit or push when the threshold is exceeded or verification is incomplete. Existing hooks are preserved and chained. Uninstall restores the prior hook and refuses to overwrite edits made after installation.

## Coding-agent integrations

```text
secmon integrate <claude-code|codex|opencode> [--scope user|project] [--project <path>] [--dry-run] [--yes]
secmon integrate remove <claude-code|codex|opencode> [--scope user|project] [--project <path>]
```

`--dry-run` prints the exact planned MCP, skill, and supported hook changes without writing files. Installation requires an interactive confirmation unless `--yes` is provided. Existing configuration is preserved in the OS credential store so removal can restore it byte for byte. Project scope defaults to the current directory; pass `--project` to select another project. See [Coding-agent integrations](integrations.md) for paths and behavior by agent.

## Local MCP server

```text
secmon mcp [--database <path-to-existing-database>]
```

The MCP server opens SQLite read-only and serves stdio JSON-RPC without making network requests. It uses the adjacent `ai-settings.json` and successful user-authored audit events to decide which tools are enabled. `read_project_file` and `search_project` require a separate project grant as well as their tool grants; absent, stale, or revoked grants deny access. See [Local MCP](local-mcp.md) and [AI providers](ai-providers.md).
