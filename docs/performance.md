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
| Desktop idle | CPU under 1%; combined window and webview memory under 500 MB | Must be measured on each release platform with the packaged app idle after startup. |
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

The Windows desktop/tray sample below records one platform. macOS and Linux desktop samples and real Linux agent measurements remain pending.

## Windows desktop and tray sample

Release-mode Windows 11 sample on the same Intel Core i7-11800H workstation, 2026-10-24. After 30 seconds of warmup and 60 seconds idle with the window open, the desktop process plus six WebView2 descendants used 372.8 MiB summed working set, 82.3 MiB private working set, and 166.7 MiB private commit. Normalized CPU was 0.018% of system capacity. The summed working set was above the original 250 MiB target; it is within the revised 500 MiB target (ADR-047). Summed working sets can count shared WebView pages more than once, so all three memory figures are recorded rather than treating the private figure as a substitute.

After closing the window into the tray, the WebView2 descendants exited. A 30-second idle sample contained only `security-monitor-desktop.exe`: 33 MiB working set, 7.8 MiB private commit, and 0% measured normalized CPU. The process remained running with no window. The 33 MiB tray working set is below the 60 MiB target. The tray sample used an isolated app-identifier overlay; the user's default application database was not opened or changed.

The close-to-tray runtime sample used the equivalent exit-policy build before the final switch to Tauri main-thread dispatch. The current dispatch implementation passes workspace tests and a release build, but still needs interactive verification.

These measurements cover one Windows workstation only. macOS and Linux desktop samples, real Linux agent collection time/RSS, and an interactive tray restore/quit check remain pending. The tray restore path is implemented, but the sample verifies close-to-tray process retention and resource use only.

## Repeat Windows windowed sample (2026-10-25)

Diagnostic release-mode repeat on Windows 11 Pro 10.0.26300, Intel Core i7-11800H (8 cores / 16 logical processors), with the same Evergreen WebView2 runtime. Built from commit 756f0ea using `pnpm -C apps/desktop tauri build --no-bundle` and a temporary app-identifier overlay so the run used a fresh isolated profile. The profile contained no project inventory. After a 30-second warmup and 60-second idle interval, the app process plus six WebView2 descendants used 370 MiB summed working set, 162.5 MiB private commit, and 0.024% normalized CPU.

This repeat measured 370 MiB against the original 250 MiB target; it is within the revised 500 MiB target (ADR-047). The release-mode executable was not installed from a signed package, so this diagnostic does not replace the packaged-app measurement required for release acceptance. The product currently creates one WebView2 control; Microsoft documents that each control uses a multi-process browser, renderer, GPU, and utility architecture. Disabling GPU rendering is not an appropriate memory shortcut because Microsoft recommends keeping hardware acceleration enabled for performance: [WebView2 performance best practices](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/performance).
