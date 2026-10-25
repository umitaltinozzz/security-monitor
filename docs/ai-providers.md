---
title: AI providers
description: Provider setup, request review, privacy controls, budgets, and AI authority limits.
---

# AI providers

## Supported providers

The desktop app supports user-configured OpenAI-compatible HTTPS endpoints, Anthropic Messages endpoints, and loopback-local OpenAI-compatible endpoints such as a local model server. Model IDs, prices, and regions are entered by the user. The app does not hard-code provider model names or prices. Agent CLI execution is implemented with the isolated worktree and approval workflow in the remediation milestone.

Provider credentials are stored through the operating-system credential store. SQLite stores only the opaque credential reference and provider metadata. Provider failures do not include response bodies or credentials in errors.

## Configure a provider

Open **Settings → AI**, add the provider origin and model ID, enter the input/output prices shown by that provider, and optionally label its data region. Local endpoints must use `localhost`, `127.0.0.1`, or `::1`; remote endpoints require HTTPS. Redirects are disabled for AI calls.

Assign a provider to a task tier and allow it in each project that may use it. The tiers are `triage`, `analysis`, and `patch`. Triage source-code requests are disabled by default. The default daily and monthly budgets are zero, so paid requests stay disabled until the user sets limits. A provider without prices cannot receive a request because the cost cannot be verified.

## Review before sending

For each request the app shows the provider, model, approved origin, user-entered region, data category, enabled tools, redacted prompt, and a conservative maximum cost estimate. The estimate includes the configured output cap and bounded tool-loop limits. Approval is bound to the displayed prompt, destination, provider version, region, tier, tools, project permissions, token estimate, and budget decision. If any of these change between review and send, the request is rejected and must be reviewed again.

Only enabled tools are sent to the API. Source reads are available only for analysis/patch tiers unless the separate triage-code setting is enabled. The app rechecks the project's provider allowlist immediately before sending. File reads reject secret paths, canonicalize and contain paths under the project root, redact common secret patterns and high-entropy values, and cap the amount of tool output and context.

CLI MCP opens an existing database without creating or migrating it and exposes only enabled tools. Source-file reads and search require both tools to be enabled and a successful per-project grant under **Settings → AI → Local MCP source access**. The CLI intersects the configured project list with the latest successful grant/revocation audit event and denies when either source is missing. Grants and revocations are recorded in Activity. A local MCP client may forward returned text, so grant only projects suitable for that client. Desktop AI source reads remain inside the reviewed provider request and require the project provider allowlist. When enabled, MCP agents can write only bounded, redacted shared notes; see [Shared local memory](shared-memory.md).

Every project, asset, finding, and project-memory read is restricted to the executor's approved project set. Desktop AI binds that set to the selected project; CLI MCP uses the projects with a current local grant. Explicit IDs outside the set are denied. Recall without a scope returns only notes for the approved project set (or global notes in the local CLI workspace); it never returns every memory note.

## Data and authority limits

Repository files, advisory text, scanner output, MCP results, and model output are untrusted data. Models cannot change finding priority or set `not_reachable`, `false_positive`, or `accepted_risk`. The AI tool list has no shell, generic process execution, remote-command, finding-status, priority, or write-to-project operation. Missing, stale, or unverified evidence remains uncertain.

The app records provider, model, tier, token usage, cost when known, outcome, approved transfer metadata, and file paths submitted; it never records file contents or provider credentials. Unknown usage cost blocks later budget checks until it can be verified.

## Current boundaries

The AI workspace accepts a user prompt for a selected project and can use enabled read tools. If a primary request is rejected by the budget before any provider call, the app can offer a second review using the configured fallback; it never fails over silently. A provider-call failure with unknown usage cost blocks later budget checks until cost can be verified. Coding-agent integrations use the separate local CLI MCP server; their shared notes remain untrusted and cannot change finding status or priority.
