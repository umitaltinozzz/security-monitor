---
title: Architecture
description: Current implementation, target components, and trust boundaries.
---

# Architecture

## Current implementation

The repository is a Rust Cargo workspace and pnpm workspace. `apps/desktop` contains the Tauri 2 + React application, and `apps/cli` contains the `secmon` binary for local scans, reports, advisory refresh, diagnostics, approved server collection, Git hooks, agent integrations, and the local MCP server. Rust libraries provide SQLite repositories and domain types (`core`, `database`), repository inventory (`inventory`), advisory ingestion and offline matching (`advisory-providers`), scanner process adapters (`scanner-adapters`), finding correlation (`correlation`), local scan orchestration with tray scheduling and file watching, and read-only Linux collection over pinned SSH (`agent-protocol`, `agent-transport`, `agents/linux`). Notification delivery is not available in the desktop build. The desktop and CLI share a local SQLite memory store for untrusted notes across supported coding agents.

| Component | Responsibility |
| --- | --- |
| `crates/agent-protocol` | Versioned bounded inventory document and generated JSON Schema. |
| `crates/agent-transport` | Pinned SSH connections, dedicated key pairing, SSH config parsing, fixed-command agentless scans, and local project association suggestions. |
| `agents/linux` | Root-free Linux collection for OS packages, runtimes, processes, services, containers, selected lockfiles, and deployment identity. |

## Target architecture

The target is a local application that stores project and deployment observations in SQLite, with the desktop app and CLI using shared Rust services. Repository inventory and lockfiles are parsed locally. Advisory feeds and scanner adapters populate normalized evidence through narrowly scoped provider crates. A read-only Linux agent may return a fixed inventory protocol over SSH. Optional AI receives only approved, redacted metadata and uses a restricted tool set.

```mermaid
flowchart TD
  Desktop[Tauri desktop] --> Core[Local Rust core]
  CLI[secmon CLI] --> Core
  Core --> Inventory[Local inventory]
  Core --> Orchestrator[Scan orchestrator]
  Core --> Correlation[Finding correlation]
  Inventory --> DB[(SQLite)]
  Orchestrator --> Providers[Advisory providers and scanner adapters]
  Providers --> Correlation
  Correlation --> DB
  Orchestrator -->|SSH pull| Agent[Read-only Linux agent]
  Agent -->|bounded inventory JSON| Orchestrator
  Providers --> DB
  DB --> AI[Optional approved AI workflow]
```

This is the target, not a claim that the desktop pairing flow exists. Network-capable components must use the single HTTP client wrapper, record destination hosts, and honor privacy settings. Core must not depend on Tauri. All database access goes through `crates/database` repository functions.

## Trust boundaries

- Repository contents, lockfiles, scanner output, advisory text, model output, and remote agent output are untrusted data.
- Local project files, SQLite, OS credential storage, external data providers, SSH servers, and optional AI providers are separate trust zones.
- Project source, lockfiles, and inventory stay local unless the user explicitly records approval for a specific transfer.
- A server agent has no generic command execution path; it only exposes the compile-time allowlisted collection command.
- Missing or stale evidence is represented as unverified or `needs_review`, never as a safe result.
