---
name: runtime-drift
description: Compare repository and deployment evidence while preserving freshness, completeness, and identity uncertainty.
---

# Review runtime drift

1. Check the reference revision and deployment identity are verified, associated with the intended project, and current.
2. Compare complete repository and deployment inventories for the same component identity and advisory range.
3. Keep the working tree separate from the configured reference revision.
4. If an identity is unknown, an inventory is partial, or evidence is stale, report `needs_review`; do not infer a fix.
5. Present repository and production results separately with the evidence timestamps and any collection gaps.
