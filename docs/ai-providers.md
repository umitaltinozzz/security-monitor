---
title: AI providers
description: Availability, provider model, privacy controls, and AI authority limits.
---

# AI providers

## Availability

AI integrations, local model support, MCP tools, and automated triage are not implemented yet. No provider credentials or model requests are used by the current product.

## Planned provider model

The product is planned to support user-selected agent CLIs, OpenAI-compatible APIs, Anthropic APIs, and local OpenAI-compatible endpoints. Provider and model identifiers, budgets, and defaults belong in editable data/configuration, not hard-coded product logic. Credentials belong only in the operating system credential store.

Before a request, the user must be able to review the data category and destination. Project source, lockfiles, and inventory are excluded by default. Remote AI may receive only approved, redacted advisory metadata and explicitly selected context. Local endpoints must be labeled as local.

## AI authority limits

Model output is untrusted. AI may suggest explanations or triage metadata, but it must not change priority scores or set `not_reachable`, `false_positive`, or `accepted_risk`; those states are user decisions. Tool calls must use a narrow allowlist, with no generic shell, filesystem, network, or remote command capability.
