---
title: Contributing
description: Development workflow, verification, pull requests, and privacy expectations.
---

# Contributing

Thanks for helping improve Security Monitor. Read the repository's contributor guidance and security policies before making changes.

## Before you start

- Search existing issues and discussions for related work.
- Use the bug, feature, or false-positive issue form for public product reports.
- For a suspected vulnerability, follow the [security policy](security.md); do not post exploit details in a public issue.
- Keep changes within the published product goals and current milestone.

## Development

Install Rust from `rust-toolchain.toml`, Node.js 22 or newer, pnpm 10.27.0, and the platform prerequisites for Tauri 2. Then:

```text
pnpm install --frozen-lockfile
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
pnpm -C apps/desktop lint
pnpm -C apps/desktop typecheck
pnpm -C apps/desktop test
pnpm -C apps/desktop e2e
```

The repository build workflow also launches the Tauri shell. Tests must be deterministic and offline. Add fixtures under `tests/fixtures/` for parsed external data; do not make real network requests in tests.

## Pull requests

- Keep each change focused and explain user-visible behavior and privacy impact.
- Add tests for behavior and update user documentation when behavior changes.
- Do not commit secrets, local planning files, generated build output, or real user inventory.
- Use a Conventional Commit style subject, such as `feat(inventory): parse pnpm lockfiles`.
- CI must pass on Windows, macOS, and Linux.

By participating, you agree to follow the project's Code of Conduct.
