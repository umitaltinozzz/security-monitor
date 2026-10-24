---
title: Linux Agent Installation and Pairing
description: Build, install, and pair the read-only Linux inventory agent over SSH.
---

# Linux agent installation and pairing

`secmon-agent` is a pull-based, read-only collector. It is not a daemon. The desktop connects over SSH and requests one versioned JSON inventory. The server does not open an inbound port, and the agent contains no general remote-command interface.

## Build and verify the binary

Build a static x86-64 Linux binary on a Linux build machine:

```sh
rustup target add x86_64-unknown-linux-musl
cargo build -p secmon-agent --target x86_64-unknown-linux-musl --release
sha256sum target/x86_64-unknown-linux-musl/release/secmon-agent
```

For ARM64, build `aarch64-unknown-linux-musl` with an installed musl cross-linker.

Copy `install.sh` and the binary to the Linux server using a channel you trust. Compare the checksum from the build machine with the checksum you pass to the installer:

```sh
sudo ./install.sh --binary ./secmon-agent --sha256 YOUR_64_CHARACTER_SHA256
```

The installer accepts only a local binary; transfer the binary and script over a channel you trust, then provide the checksum you verified on the build machine. It makes no network requests. It creates a locked system account named `secmon` with home `/var/lib/secmon` if needed, installs the binary root-owned at `/usr/local/bin/secmon-agent`, and creates `/etc/secmon/agent.toml`. The account uses `/bin/sh` because OpenSSH invokes a forced command through the account shell; the pairing key itself still forces the one fixed collection command and disables interactive and forwarding features. Do not add unrestricted keys to this account.

The installed agent runs as the SSH account and does not need root. The installer does not add `secmon` to the Docker group. Docker group membership grants root-equivalent access and should remain disabled unless you have explicitly reviewed and accepted that privilege.

## Select local inventory paths

Edit `/etc/secmon/agent.toml` as root. An empty configuration leaves dependency-file inventory unavailable and reports it as partial. To scan selected project directories, use canonical absolute paths:

```toml
allowed_paths = ["/srv/web", "/srv/api"]
docker_cli_approved = false
max_processes = 4096
```

The agent resolves each path before scanning, rejects duplicate or invalid roots, applies file-count/depth/size limits, and returns dependency metadata with relative evidence paths. It does not send source files, `.env` values, lockfiles, or credentials to third parties. Docker collection is disabled by default. Turning on `docker_cli_approved` only works if the account has Docker access; that access can expose host-level control.

## Pair a host

The pairing library creates a dedicated Ed25519 key in the local operating-system credential store. It reports the observed SHA-256 host-key fingerprint for independent confirmation and produces an `authorized_keys` line restricted to:

```text
command="/usr/local/bin/secmon-agent collect",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,restrict ssh-ed25519 PUBLIC_KEY secmon@DEVICE
```

Create `/var/lib/secmon/.ssh` as `secmon` with mode `0700`, then add the generated line to `/var/lib/secmon/.ssh/authorized_keys` owned by `secmon` with mode `0600`. Keep the host-key fingerprint pinned on the desktop. A later mismatch must be rejected and reviewed; do not automatically accept a changed key.

Until the desktop pairing flow is available, this repository includes a direct-host developer harness. It prompts you to verify the fingerprint, writes the generated private key only to the OS credential store, displays the public forced-command line, waits for installation, then asks for explicit approval to send inventory to this device. The returned collection includes the approval timestamp, which the desktop caller must persist in its audit history:

```sh
cargo run -p security-monitor-agent-transport --example pair-agent -- web-prod web.example.test secmon 22
```

The example accepts a direct SSH target. The library also supports a single `ProxyJump` hop when both the bastion and target have independently confirmed fingerprints. SSH config discovery reads host directives only; it never opens configured private-key files. `Include` files and dynamic `Match` blocks are reported as unsupported instead of being executed or followed.

## Check collection results

The protocol document has a schema at `crates/agent-protocol/schema/agent-inventory.schema.json`. It includes one status for each collection area. Missing permissions, missing tools, unavailable optional checks, stale observations, and unknown deployment identities remain partial, unavailable, or `needs_review`; they never imply a safe state. The agent reports a deployment identity as observed metadata only and always leaves `integrity_verified` false.

To test a forced-command SSH flow in a disposable OpenSSH container, run the Linux CI E2E test. It builds the static binary, creates a fresh container host key and a restricted client key, verifies that a changed host key is rejected, then collects inventory as the unprivileged `secmon` account. The test talks only to the container on loopback; the CI setup builds the image before the test starts.
