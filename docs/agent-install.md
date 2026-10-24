---
title: Linux agent installation
description: Availability and planned security model for the read-only Linux agent.
---

# Linux agent installation

## Availability

The `secmon-agent` binary, SSH pairing workflow, and collection protocol are not implemented yet. This page describes the intended boundary; it is not an install guide for a usable agent. No agent download or pairing command is available in the current version.

## Planned security model

- The agent is a static musl Rust binary and runs only when invoked; it is not a daemon.
- The desktop connects over SSH and pins the host key after the user confirms its fingerprint.
- The dedicated public key is installed as a forced command for `secmon-agent collect` with forwarding and PTY disabled.
- Collection is read-only, root-free at runtime, and limited to a compile-time allowlist of host commands.
- The agent emits a versioned JSON protocol to stdout. It has no generic remote command or arbitrary shell feature.
- The desktop must display collection freshness and treat protocol errors or unknown deploy IDs as unverified.

When implementation is available, this page will include verified package checksums, exact pairing steps, distro requirements, and a recovery procedure for rotating or removing the dedicated key.
