---
title: Privacy
description: Current data behavior and the product's privacy requirements.
---

# Privacy

## Current behavior

The current desktop shell and CLI do not scan projects or invoke advisory providers at runtime. The `agent-transport` library opens SSH only when a caller supplies a user-selected target, confirmed host-key fingerprint, and timestamped inventory-collection approval. It returns that approval with the remote inventory so the desktop caller can persist it in the audit history; the agent does not make third-party network requests. Its agentless mode also requires an explicit approval value and runs a fixed command list. The `advisory-providers` Rust library can download public feeds and databases only when a caller constructs it with `public_downloads_enabled: true`. It has no user settings UI or persisted approval record yet, so the shell and CLI must not enable it until that user-facing consent and audit record exist. Dependency installation and development tooling may access their configured package registries while being run by a developer.

When the library is explicitly enabled, cve.now requests use its global status, entry cursor, and public advisory IDs; filtered feeds and stack-check uploads are not used. OSV archive URLs include an ecosystem slug selected from local inventory, which discloses that ecosystem to OSV. GHSA requests contain public GHSA IDs discovered from the public advisory feed. CISA KEV and FIRST EPSS are full public catalog downloads. Requests do not contain source code, lockfiles, package names, package versions, or a package list. Provider caches and results are stored locally. The desktop and CLI currently do not initiate any of these requests.

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

There is no product telemetry. Provider cache files, downloaded public records, and freshness metadata are stored on-device; current provider code does not upload these caches. Before the desktop or CLI invokes providers, settings must explain the destination, purpose, ecosystem disclosure for OSV archive requests, retention terms where known, and how to disable downloads or delete local cache data. AI and external notification delivery are not implemented; before they ship, their settings must describe data sent, destination, purpose, retention terms where known, and how to revoke approval or delete local records.
