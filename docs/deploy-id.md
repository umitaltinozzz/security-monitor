---
title: Deploy ID
description: Planned deployment correlation and verification semantics.
---

# Deploy ID

## Availability

Deploy ID assignment and production correlation are not implemented yet. The current UI and CLI do not create, read, or verify deploy IDs.

## Planned purpose

The planned product uses a deploy ID to connect a deployment observation to the repository and build evidence that produced it. A deploy ID is an identifier, not proof of integrity by itself. The application must verify its association and provenance before using it for correlation.

Unknown, missing, stale, or mismatched deploy IDs must produce `needs_review` / “could not verify”. They must never produce a green or safe state. The value must not be used to execute commands or fetch arbitrary remote resources.

Implementation documentation will specify the exact format, issuer, signature or verification method, rotation behavior, and UI workflow before this feature ships.
