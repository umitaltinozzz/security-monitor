---
title: Getting started
description: Build Security Monitor, scan your first project, and compare it with a production server.
---

# Getting started

This guide takes you from a fresh checkout to a finding that shows both its repository and its production status. Signed installers are not published yet, so the app is built from source.

## 1. Build and open the desktop app

Install Rust, Node.js 22 or newer, pnpm 10.27.0, and the [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/) for your platform. Then, from the repository root:

```text
pnpm install --frozen-lockfile
pnpm -C apps/desktop tauri dev
```

The first launch walks you through privacy, scanners, advisory data, projects, servers and AI. Every step can be skipped and changed later in **Settings**.

## 2. Allow advisory downloads

Matching needs local advisory data. In **Settings**, turn on **Allow public advisory, scanner, and application update downloads**, then choose **Download advisory data**. Requests name only the ecosystem; no project files, lockfiles or inventory are sent. Until data is present, findings stay *could not verify*.

## 3. Scan a project

1. Open **Projects** and enter a project folder path.
2. Keep **Start a quick scan after adding** checked and choose **Add project**.
3. Open **All findings**. Each finding shows its severity, status, repository status, production status and priority. Select one to see why it matters and where it was found.

A quick scan reads only dependency metadata. Run a full scan from the project card to add Trivy and Semgrep results.

The repository status becomes *fixed in repo* only when the project sits on its reference branch tip and the dependency files match the committed versions. Uncommitted lockfile changes never count as a fix.

## 4. Pair a Linux server

1. Install the read-only agent on the server as described in [Linux agent](agent-install.md).
2. In **Servers**, enter the host alias, address and SSH user, then choose **Check host key**.
3. Confirm the fingerprint with the server administrator, tick the confirmation, and choose **Create pairing key**. Install the printed `authorized_keys` line on the server.
4. Choose **Collect inventory**, review what will be transferred, then **Approve and collect**.

The agent never needs root and has no remote-command feature; it runs only a fixed set of read-only collectors.

## 5. Link the server to the project

On the server card, under **Projects running here**, pick the project, confirm that this server runs its deployments, and choose **Link**. Security Monitor then compares the project's findings with the server's latest approved collection.

- A finding fixed on the reference branch but still present on the server shows **Fixed in repo · Still affected in production**.
- Production status needs a deploy ID on the server; see [Deploy ID](deploy-id.md). Without one, or with a collection older than 24 hours, production stays *could not verify*.
- With several linked servers, a finding counts as fixed in production only when every server shows the fix.

See [Repository-to-production drift](drift.md) for the full rules.

## 6. Optional: Git hook and coding agents

Warn before vulnerable dependencies are pushed:

```text
cargo run -p secmon -- hook install --pre-push --mode warn
```

Connect a coding agent to the local MCP server and skills; `--dry-run` shows the exact changes first:

```text
cargo run -p secmon -- integrate claude-code --dry-run
```

See [CLI](cli.md) and [Coding-agent integrations](integrations.md).
