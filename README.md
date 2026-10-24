# Security Monitor

Security Monitor is a local-first security monitoring product for software projects and deployed environments.

## Development setup

Install the prerequisites for [Tauri 2](https://v2.tauri.app/start/prerequisites/), including Rust, Node.js, and the native desktop dependencies for your operating system. This repository uses pnpm 10.27.0.

```text
pnpm install --frozen-lockfile
pnpm -C apps/desktop tauri dev
```

The CLI can be run from the Cargo workspace:

```text
cargo run -p secmon -- --version
```

## Checks

The GitHub Actions workflow runs the Rust and desktop checks on Windows, macOS, and Linux.
