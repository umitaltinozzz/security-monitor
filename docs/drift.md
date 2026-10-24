---
title: Repository-to-production drift
description: Compare verified reference-branch and deployment inventories for existing findings.
---

# Repository-to-production drift

The `security-monitor-drift` crate compares an existing finding's package against a verified reference-branch inventory and a current, user-associated Linux deployment inventory. It returns separate repository and production statuses, the observed versions, machine-readable reasons, and a status-transition proposal that the caller must validate and persist through the normal finding workflow.

## Evidence requirements

- A repository result is `fixed_in_repo` only when the caller supplies an inventory from the configured reference branch tip, identifies its branch and full commit SHA, marks that tip verified, and the inventory is complete. The local working-tree state and its package status/versions are evaluated separately; uncommitted changes never establish `fixed_in_repo`.
- Production results require a user-confirmed project association, a known commit SHA or image digest present in the collected inventory, and a current valid observation. An unknown deployment identity, stale or future-dated observation, partial inventory, missing package version, malformed package URL, or unverified advisory range remains `unknown` / `needs_review` for negative conclusions.
- A current, valid observation of an affected version can still report `still_affected` when unrelated collection areas are incomplete. This positive evidence does not turn incomplete evidence into a clean result.
- A package absent from a complete inventory can count as not affected. Absence from incomplete data cannot.

The crate is a pure comparison layer. It does not fetch Git refs, connect to servers, modify findings, or send inventory anywhere. A future caller must gate Git fetches on the user's recorded setting and must pass only the verified reference-branch snapshot. All comparisons use local data.

## Finding transitions

When evidence supports a system status change, the assessment includes a `StatusTransition` proposal. The proposal uses the correlation state machine's evidence types for `fixed_in_repo`, `fixed_in_production`, affected-version verification, and incomplete current data. It is not applied automatically; callers retain the existing database and audit-history controls. User-only statuses such as `accepted_risk`, `false_positive`, and `not_reachable` are never proposed by this crate.

Deterministic fixtures cover a fixed reference branch with affected production, both inventories fixed, an unknown deploy ID, missing Git evidence, incomplete association, and uncommitted working-tree changes. They are under `tests/fixtures/drift/`.
