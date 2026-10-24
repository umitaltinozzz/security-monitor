---
title: Performance budgets
description: Reproduce and interpret local scan and resource measurements.
---

# Performance budgets

The product targets below are from `proje.md` §10.7. Measurements must use release builds and representative hardware before a target can be marked verified.

| Operation | Target | Evidence in this repository |
| --- | --- | --- |
| Typical quick scan | Under 5 seconds | Fixture scan tests verify correctness; the release benchmark below measures a synthetic 50k dependency project. |
| 50-project first quick scan | Under 2 minutes | Deterministic orchestration fixture acceptance test. |
| 50k-dependency monorepo incremental scan | Under 30 seconds | The benchmark measures an unchanged startup scan, including dependency-input hashing and local advisory refresh. |
| Linux agent collection | Under 20 seconds and 100 MB | Agent fixture tests verify output and permissions; measure on a real supported Linux server before release. |
| Desktop idle | CPU under 1%; combined window and webview memory under 250 MB | Must be measured on each release platform with the packaged app idle after startup. |
| Tray idle | Memory under 60 MB | Deferred until the app destroys its webview while in the tray; verify on release platforms. |
| SQLite data | Under 500 MB | The benchmark reports the file-backed database size after a 50k dependency scan. Retention settings must be applied before measuring a long-lived profile. |

## Reproduce the scan measurement

From the repository root, run:

```text
cargo run --release -p security-monitor-scan-orchestrator --example performance -- 50000
```

The example creates a temporary npm v3 lockfile and file-backed SQLite database, disables public downloads, runs a full quick scan, then runs the unchanged startup path. It prints JSON with the dependency count, elapsed times, database size, inventory completeness, and whether network access was enabled. No project or inventory data leaves the process. The temporary files are removed when it exits.

This synthetic fixture measures parsing, persistence, hashing, and local advisory refresh for one 50k-dependency project. It does not measure scanner engines, a real monorepo's filesystem layout, or cold disk behavior. Record CPU, memory, OS, CPU model, Rust version, and command output when comparing machines. Do not treat a result from one workstation as proof for every supported platform.

## Current measurement

Release-mode 50k fixture on Windows 11, Intel Core i7-11800H (8 cores / 16 logical processors), Rust stable, 2026-10-24:

```json
{
  "dependency_count": 50000,
  "full_scan_ms": 66850,
  "incremental_scan_ms": 10212,
  "inventory_complete": true,
  "network_enabled": false,
  "outcome": "partial",
  "sqlite_bytes": 100556800
}
```

The initial scan completed in 66.9 seconds. The unchanged startup path completed in 10.2 seconds, below the 30-second target. SQLite used about 95.9 MiB, below the 500 MiB target. The run intentionally had no advisory database, so its partial result is expected and remains unverified; this is a performance measurement, not a security-clean result. One working-set sample during the scan was about 159.6 MiB; this was not a sampled peak, so a stable peak-memory figure remains unverified.

Desktop idle CPU/memory, tray memory, and real Linux agent measurements still need platform-specific runs. Those targets remain unverified until evidence is recorded.
