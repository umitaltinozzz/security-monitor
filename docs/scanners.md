---
title: Scanner adapters
description: Supported local scanners, data handling, offline behavior, and output normalization.
---

# Scanner adapters

`security-monitor-scanner-adapters` is a local Rust library for detecting scanner installations, running supported scan modes, downloading pinned scanner binaries after explicit approval, and normalizing recorded JSON output. The desktop app and CLI do not invoke this library yet.

## Supported engines

| Engine | Supported modes | Installation behavior |
| --- | --- | --- |
| OSV-Scanner | Local dependency scan | Detects a system install or downloads the pinned platform binary after caller approval. Uses offline vulnerability matching and an explicit empty trusted config to prevent repository `osv-scanner.toml` files from changing results. The advisory updater keeps its validated upstream archive in `osv/scanner-db/osv-scanner/<ecosystem>/all.zip`; the scanner cache environment points there. |
| Trivy | Dependency/filesystem vulnerabilities and secrets; misconfiguration; local image archive | Detects a system install or downloads the pinned platform binary after caller approval. Scan commands disable updates, telemetry, and repository ignore/config files. Vulnerability data and check bundles must already be available in the local cache. |
| Semgrep | Code scan with caller-provided local rules | Detects a system install only. Rules must be a file inside the selected project. Network metrics and version checks are disabled; Git ignore rules and inline `nosem` suppressions are bypassed. A repository `.semgrepignore` blocks the scan until an approval flow exists. |

Pinned versions, minimum supported versions, artifact URLs, and SHA-256 checksums are in `crates/scanner-adapters/versions.toml`. The installer streams downloads through the shared privacy-aware HTTP client, verifies the pinned checksum before extraction, extracts only the expected binary, and records an integrity marker beside the installed file. The caller must both approve the download and enable public downloads in the HTTP policy. To share the offline OSV database, construct `AdvisoryService` with the same cache root passed to `ScannerAdapters::new` as its app data directory.

Engine detection reports missing, outdated, unsupported, or unverified engines explicitly. A missing engine produces no scan result. Scanner arguments are fixed arrays passed directly to the process API; no shell is involved. The process environment is cleared and scanner execution has time and output limits.

`NormalizedScan.complete` means the process returned parseable output without detected path or process errors. It is not a safety verdict and does not verify vulnerability database freshness. Consumers must combine it with verified, current scanner data and must never turn an absent or stale data source into a green state. Scanner output paths are canonicalized and kept inside the selected project; secret values and code excerpts are not retained.

Golden normalization fixtures are under `tests/fixtures/scanner-adapters/`. The adapters execute scanners only when called by a future application workflow; they do not scan repositories in the current desktop or CLI.

## Upstream references

- [OSV-Scanner usage](https://google.github.io/osv-scanner/usage/) and [configuration](https://google.github.io/osv-scanner/configuration/)
- [Trivy air-gap scanning](https://trivy.dev/docs/latest/advanced/air-gap/) and [disabling configuration files](https://trivy.dev/docs/latest/guide/configuration/)
- [Semgrep CLI reference](https://docs.semgrep.dev/cli-reference/)
