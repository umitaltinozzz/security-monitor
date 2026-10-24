---
name: prepare-safe-fix
description: Plan a minimal dependency or configuration fix with explicit review of scope, tests, and rollback.
---

# Prepare a safe fix

1. Confirm the affected component, current version, verified fixed version, and supported upgrade path.
2. Propose the smallest change that addresses the advisory while preserving declared compatibility constraints.
3. Keep proposed edits isolated from the user's main worktree. Do not edit files, execute commands, commit, push, or deploy without the relevant feature and explicit approval.
4. List deterministic offline checks first. Identify any test that would require network or privileged access before it is run.
5. Summarize the proposed diff, expected behavior, test results, and rollback option for user review.
