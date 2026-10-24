---
title: Privacy
description: Current data behavior and the product's privacy requirements.
---

# Privacy

## Current behavior

The current desktop shell and CLI do not scan projects, contact advisory providers, send telemetry, or upload repository data at runtime. Dependency installation and development tooling may access their configured package registries while being run by a developer.

## Product requirements

- Repository source, lockfiles, and inventory remain on the device by default.
- Every outbound request uses the approved HTTP wrapper, identifies the destination host in logs, and honors provider privacy settings.
- Any transfer of source, lockfiles, or inventory requires explicit, recorded approval for that transfer.
- Secret material is stored only in the operating system credential store and never in SQLite, logs, or errors.
- AI receives only the approved and redacted context needed for the current task. Provider, model, budget, and data-sharing settings are user-controlled.
- Local AI endpoints are clearly identified; the UI must not imply data leaves the device for a local endpoint.
- Missing, stale, or unknown evidence is not described as safe.

## cve.now and package lists

Public advisory feeds can be read without sending a project's package list. cve.now's stack-check feature accepts lockfiles and stores uploads for analytics and feed generation; anyone holding the resulting stack-feed link can see matches. Security Monitor must keep that path disabled unless the user explicitly approves and the approval is recorded. The target integration may use public feed endpoints without using stack-check.

## Data lifecycle

The current implementation has no product telemetry or provider data lifecycle. Before provider and AI features ship, their settings and documentation must describe the data sent, destination, purpose, retention terms where known, and how to revoke approval or delete local records.
