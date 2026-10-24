---
name: test-and-review
description: Review a proposed security fix and its test evidence while identifying unsafe or incomplete verification.
---

# Test and review a fix

1. Inspect the proposed diff and verify it is limited to the approved project and finding.
2. Identify the tests that cover the changed behavior, including regression cases and relevant platform differences.
3. Run tests only through an approved isolated execution feature. Do not invoke a shell or run untrusted project scripts directly.
4. Report exact commands, outcomes, skipped checks, and whether any check used network access.
5. Review for secret exposure, unrelated changes, stale evidence, and missing rollback notes. Do not commit or push on the user's behalf.
