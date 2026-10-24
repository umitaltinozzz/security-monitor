---
title: Privacy
description: Current data behavior and the product's privacy requirements.
---

# Privacy

## Current behavior

The desktop app can run local scans and explicitly approved advisory updates. AI requests are sent only after the user reviews the redacted prompt, provider origin, data category, tools, region label, and bounded cost estimate. The AI HTTP request uses the shared wrapper, disables redirects, logs the destination host, and sends credentials only in authorization headers. The CLI's `secmon mcp` opens SQLite read-only and makes no network requests. It serves only configured tools; source reads also require the tool to be enabled and a per-project grant recorded in the audit history. An MCP client may forward source text returned by those tools, so grants should be limited to projects suitable for that client. Dependency installation and development tooling may access their configured package registries while being run by a developer.

When the library is explicitly enabled, cve.now requests use its global status, entry cursor, and public advisory IDs; filtered feeds and stack-check uploads are not used. OSV archive URLs include an ecosystem slug selected from local inventory, which discloses that ecosystem to OSV. GHSA requests contain public GHSA IDs discovered from the public advisory feed. CISA KEV and FIRST EPSS are full public catalog downloads. Requests do not contain source code, lockfiles, package names, package versions, or a package list. Provider caches and results are stored locally. The desktop app invokes these requests only after public downloads are enabled and the user starts an update.

When public downloads are enabled, the desktop also polls the configured security-news RSS/Atom feeds every 30 minutes. Feed servers can observe the device's network address and request timing. Feed requests contain no local package names, inventory, lockfiles, or source code; feed items are matched and stored locally. Feed URLs and product synonyms are editable in the app-data directory. A 304 response reuses validators and is not parsed again.

## Product requirements

- Repository source, lockfiles, and inventory remain on the device by default.
- Every outbound request uses the approved HTTP wrapper, identifies the destination host in logs, and honors provider privacy settings.
- Any transfer of source, lockfiles, or inventory requires explicit, recorded approval for that transfer.
- Secret material is stored only in the operating system credential store and never in SQLite, logs, or errors.
- Server-side inventory is returned only over the confirmed SSH connection. Missing or stale server checks stay partial or `needs_review`.
- AI receives only the approved and redacted context needed for the current task. Provider, model, budget, and data-sharing settings are user-controlled.
- Local AI endpoints are clearly identified; the UI must not imply data leaves the device for a local endpoint.
- Missing, stale, or unknown evidence is not described as safe.

## cve.now and package lists

The global incremental feed can be read without sending a project's package list. Filtered feeds that encode local ecosystem or technology names are not used because their query parameters reveal inventory-derived data. cve.now's stack-check feature accepts lockfiles and stores uploads for analytics and feed generation; anyone holding the resulting stack-feed link can see matches. Security Monitor does not use stack-check or lockfile upload. Any future package-list transfer requires a clear, specific user approval and a recorded audit event before the request is sent.

## Data lifecycle

There is no product telemetry. Provider cache files, downloaded public records, and freshness metadata are stored on-device; current provider code does not upload these caches. Settings explain provider destination and data category before an AI request. Provider retention terms depend on the user's selected service and are not asserted by Security Monitor. Users can revoke project provider permissions and local MCP source access, disable AI tools, and remove local run and approval records with the local database. External notification destinations have their own keyring-backed configuration and approval.
