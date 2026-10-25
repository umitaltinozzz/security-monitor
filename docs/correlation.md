---
title: Finding correlation
description: Alias merging, version matching, fingerprints, deterministic priority, and status changes.
---

# Finding correlation

The `correlation` crate combines advisory records with local component inventory. The desktop scan workflow and CLI quick scan use the local orchestration and reporting services to surface these findings. Scanner coverage and advisory freshness still determine whether a result is verified.

## Advisory aliases

Advisory IDs and aliases are compared case-insensitively. Records sharing an ID form one advisory, including transitive links across providers. Canonical ID selection is deterministic: CVE IDs rank before GHSA, GHSA before OSV, then other IDs, with a case-insensitive lexical tie-break. The selected ID retains its source spelling. Ranges, fixed versions, and source attributions are merged and sorted. Conflicting version sources remain visible to matching and produce `needs_review` where their conclusions differ.

When a persisted advisory changes canonical ID, the database repository layer repoints existing findings and removes the old advisory row in one transaction.

## Matching and finding identity

The correlation matcher uses ecosystem-aware package normalization and the advisory's range semantics. Exact, semantic-version, and supported ecosystem ranges can establish an affected version. Missing versions, unsupported range forms, empty event sequences, or disagreement between sources remain `needs_review`. A malformed PURL or a mismatch between its embedded version and the component version also stays in `needs_review`. Stale, incomplete, or unknown inventory freshness and unverified component-to-project/asset relationships keep a finding in `needs_review` even when the package version matches. The persistence entry point checks that component, instance, and parent scope records still match SQLite before it writes findings.

Affected-version ranges for Packagist (Composer), Maven, NuGet, and RubyGems are not currently evaluated. Their advisories may still be downloaded, but matching findings stay `needs_review`; Settings and the finding evidence show this limitation. Do not interpret a missing finding for one of these ecosystems as evidence that its installed version is unaffected.

A finding fingerprint is SHA-256 over the canonical advisory ID, project/asset/service/deployment IDs, package URL, component version, and a normalized relative evidence path. Absolute paths, traversal paths, scanner references, and free-form evidence labels are excluded. Identical sources at the same scope and evidence location therefore share a fingerprint; a different location has a separate fingerprint.

## Priority calculation

Priority is deterministic and returns a score from 0 to 100 with sorted machine-readable reasons. A valid CVSS score contributes `round(CVSS × 5)` points. Without CVSS, the base is 45 for critical, 38 for high, 28 for medium, 18 for low, or 0 for unknown severity.

| Signal | Points |
| --- | ---: |
| CISA KEV listing | +20 |
| Fresh EPSS ≥ 0.5 / ≥ 0.1 / > 0 | +15 / +10 / +5 |
| Public exploit listing | +10 |
| SSVC exploitation active / proof of concept | +15 / +10 |
| SSVC automatable | +10 |
| SSVC total / partial technical impact | +10 / +5 |
| Production / production and internet-facing | +5 / +10 |
| Internet-facing outside production | +5 |
| User-confirmed reachable vulnerable path | +10 |
| Authentication boundary / customer data / safety-critical impact | +5 / +5 / +10 |
| Fix available | +5 |
| Medium / high test cost | +1 / +3 |

EPSS older than 30 days is stale and contributes no points. Alias merging keeps each EPSS score paired with its own date, so a newer date without a valid score cannot refresh an older score. Missing or stale signals add a reason code instead of lowering risk. Invalid and future-dated scores are rejected. Positive additions cap at 100; no missing signal marks a finding safe. These weights are rule-based triage guidance, not an exploitability proof.

## Finding status changes

Only a user action can assign `not_reachable`, `accepted_risk`, or `false_positive`; users cannot assign states that require verified system evidence. User dispositions store a controlled reason code, scope type and ID, set time, and optional expiry. Accepted risk and false positive require an expiry later than the decision time. Correlation refreshes preserve active user dispositions, clear expired dispositions, and re-evaluate the finding against current evidence. The transition API reopens an expired disposition as `new` only when its expiry matches the stored finding expiry. Incomplete current evidence moves to `needs_review`.

System transitions to `mitigated`, `fix_proposed`, `fixed_in_repo`, or `fixed_in_production` require the corresponding mitigation, proposal, reference-branch, or production evidence. A verified affected version can reopen an older fixed or `not_reachable` state. The database rejects user-only statuses without a complete disposition record.
