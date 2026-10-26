---
title: Linux Agent Installation and Pairing
description: Build, install, and pair the read-only Linux inventory agent over SSH.
---

# Linux agent installation and pairing

`secmon-agent` is a pull-based, read-only collector. It is not a daemon. The desktop connects over SSH and requests one versioned JSON inventory. The server does not open an inbound port, and the agent contains no general remote-command interface.

Türkçe kurulum adımları: [agent-install.tr.md](https://github.com/umitaltinozzz/security-monitor/blob/main/docs/agent-install.tr.md).

## Runbook: first install on a real server

This walk-through was written for two Oracle Cloud free-tier hosts and applies to any comparable Linux server:

| Host | Shape | OS | Default login | Agent binary |
| --- | --- | --- | --- | --- |
| A | Ampere A1, 2 OCPU / 12 GB | Oracle Linux 9 (`aarch64`) | `opc` | `secmon-agent-linux-aarch64` |
| B | AMD micro, 1 GB | Ubuntu 24.04 (`x86_64`) | `ubuntu` | `secmon-agent-linux-x86_64` |

There is no systemd unit and nothing to start: the agent runs only when the desktop opens an SSH session with the restricted pairing key, and exits after printing one inventory.

### 1. Prepare network access

- Reach the server over SSH with your own key. Oracle images ship with password login disabled; keep it that way.
- In **Networking → Virtual Cloud Networks → your VCN → Security Lists**, allow ingress only on `22/tcp`, ideally restricted to your own address (`x.x.x.x/32`). If you use Tailscale, you can remove the public `22/tcp` rule after Tailscale SSH works and pair the desktop with the Tailscale address instead.
- Oracle Linux uses `firewalld`, which allows SSH by default. Oracle's Ubuntu images ship their own `iptables` rules in `/etc/iptables/rules.v4`; do not replace them with `ufw` without first making sure SSH stays allowed, or you can lock yourself out.

### 2. Get the agent binary (on your desktop)

Before the first release, use the main-branch CI artifact. It is integrity-checked with its `.sha256` file, but it is **not** minisign-signed; your trust in it comes from your authenticated GitHub download. Released binaries also carry `.minisig` signatures (see [Signed releases](release.md#verify-a-download)).

```sh
gh run list -R umitaltinozzz/security-monitor -w CI -b main -s success -L 1
gh run download <run-id> -R umitaltinozzz/security-monitor -n secmon-agent-linux-aarch64 -D agent-a
gh run download <run-id> -R umitaltinozzz/security-monitor -n secmon-agent-linux-x86_64 -D agent-b
```

Copy the matching binary, its `.sha256` file, and `install.sh` from the repository root to each server:

```sh
scp agent-a/secmon-agent-linux-aarch64 agent-a/secmon-agent-linux-aarch64.sha256 install.sh opc@HOST_A:
scp agent-b/secmon-agent-linux-x86_64 agent-b/secmon-agent-linux-x86_64.sha256 install.sh ubuntu@HOST_B:
```

### 3. Install (on each server)

```sh
uname -m                     # aarch64 on host A, x86_64 on host B
case "$(uname -m)" in
  x86_64) agent=secmon-agent-linux-x86_64 ;;
  aarch64) agent=secmon-agent-linux-aarch64 ;;
  *) echo "unsupported architecture" >&2; exit 1 ;;
esac
sha256sum -c "$agent.sha256"
read -r agent_sha256 _ < "$agent.sha256"
chmod +x install.sh
sudo ./install.sh --binary "./$agent" --sha256 "$agent_sha256"
```

Expected output ends with `secmon-agent installed at /usr/local/bin/secmon-agent.` The installer creates the `secmon` system account (home `/var/lib/secmon`, no usable password), `/etc/secmon/agent.toml`, and `/etc/secmon/deployments.d`.

Check the result without running a collection:

```sh
ls -l /usr/local/bin/secmon-agent          # root-owned, mode 0755
getent passwd secmon                       # home /var/lib/secmon, shell /bin/sh
sudo cat /etc/secmon/agent.toml            # empty until you add paths
```

### 4. Optional: let the agent see an application

Dependency files and deployment identity are only read under paths you allow. For a demo application in `/srv/demo`:

```sh
sudo tee /etc/secmon/agent.toml >/dev/null <<'EOF'
allowed_paths = ["/srv/demo"]
docker_cli_approved = false
max_processes = 4096
EOF
```

Give the application a deployment identity so drift can be compared, either with `/srv/demo/.secmon-deploy.json` or `/etc/secmon/deployments.d/<service>.json` (format in [Deployment identity](deploy-id.md)). Leave `docker_cli_approved = false` unless you have reviewed that Docker access is root-equivalent.

### 5. Pair from the desktop

1. On the server, print the host-key fingerprints so you can compare them with the desktop:

   ```sh
   for key in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$key"; done
   ```

2. In the desktop, open **Servers → Pair a Linux server**. Enter an alias, the hostname or IP (or Tailscale address), SSH username `secmon`, port `22`, and the environment.
3. Compare the observed SHA-256 fingerprint with the matching line from step 1. Tick the confirmation only if they are identical. If they differ, stop.
4. Copy the restricted `authorized_keys` line the desktop shows, then install it on the server:

   ```sh
   sudo install -d -o secmon -g secmon -m 0700 /var/lib/secmon/.ssh
   sudo tee /var/lib/secmon/.ssh/authorized_keys >/dev/null <<'EOF'
   PASTE THE LINE FROM THE DESKTOP HERE
   EOF
   sudo chown secmon:secmon /var/lib/secmon/.ssh/authorized_keys
   sudo chmod 0600 /var/lib/secmon/.ssh/authorized_keys
   ```

5. **Oracle Linux and other SELinux-enforcing systems:** OpenSSH may not read keys under `/var/lib` until they carry the SSH label. Run:

   ```sh
   getenforce
   sudo semanage fcontext -a -t ssh_home_t '/var/lib/secmon/\.ssh(/.*)?'
   sudo restorecon -Rv /var/lib/secmon/.ssh
   ```

   If `semanage` is missing, install `policycoreutils-python-utils`.
6. Back in the desktop, approve one inventory transfer.

### 6. Verification checklist

Record each item as seen in the desktop:

- [ ] The collection finishes as complete or partial, never as a silent success. Partial areas name a reason.
- [ ] **Packages:** the list is populated. On host B (Ubuntu) OS packages are evaluated against fresh local OSV data. On host A (Oracle Linux) the status reads *Unverified — no OSV data source is available for this distribution*, not "no vulnerabilities".
- [ ] **Kernel:** the running kernel is shown; if a newer kernel is installed, a restart notice appears.
- [ ] **Services:** `sshd` and other running units are listed.
- [ ] **Containers:** with `docker_cli_approved = false`, container inventory is reported as unavailable rather than empty.
- [ ] **Deployment identity:** a service without deployment data is unknown or omitted; it is never marked verified.
- [ ] **Drift:** link the server to a project (**Projects running here → Link a project**). Repository and production status then appear for that project; without a link, production status stays unverified.
- [ ] A second collection after changing a package or the deploy ID shows the change.

### 7. If something goes wrong

All commands below only read state.

| Symptom | Where to look |
| --- | --- |
| Desktop cannot connect | `sudo journalctl -u sshd -n 50 --no-pager` (Oracle Linux) or `sudo journalctl -u ssh -n 50 --no-pager` (Ubuntu) |
| Key rejected | `sudo ls -laZ /var/lib/secmon/.ssh` (permissions `0700`/`0600`, owner `secmon`, SELinux type `ssh_home_t`); `sudo ausearch -m avc -ts recent` on SELinux systems |
| Host-key mismatch | Do not accept the new key. Compare `ssh-keygen -lf` output again and find out why the key changed. |
| Wrong architecture | `uname -m` and `file /usr/local/bin/secmon-agent` |
| Collection partial | Read the reason shown for each area in the desktop; permission-denied areas stay partial by design. |
| Port blocked | Security List ingress rules in the Oracle console; `sudo firewall-cmd --list-all` (Oracle Linux) or `sudo iptables -S` (Ubuntu) |

The desktop's own log is in the application data directory under `logs/`; it is redacted and never contains private keys.

### Remove the agent

```sh
sudo rm -f /usr/local/bin/secmon-agent /var/lib/secmon/.ssh/authorized_keys
sudo userdel -r secmon
sudo rm -rf /etc/secmon
```

In the desktop app, open **Servers** and choose **Remove pairing**. The default keeps local inventory history and marks the server as removed; you can instead delete that history and its approval records. The desktop removes its pinned host key and dedicated SSH credential. This does not remove the `authorized_keys` line from the server. To revoke access, run `sudo rm /var/lib/secmon/.ssh/authorized_keys` on the server.

## Build and verify the binary

The agent is available as static musl binaries for `x86_64` and `aarch64` (ARM64). Build the x86-64 binary on a Linux build machine:

```sh
rustup target add x86_64-unknown-linux-musl
RUSTFLAGS="-C relocation-model=static" cargo build -p secmon-agent --target x86_64-unknown-linux-musl --release
cp target/x86_64-unknown-linux-musl/release/secmon-agent secmon-agent-linux-x86_64
sha256sum secmon-agent-linux-x86_64
```

Install Zig 0.16.0, then cross-compile the ARM64 binary from Linux with cargo-zigbuild 0.23.4:

```sh
rustup target add aarch64-unknown-linux-musl
cargo install --locked cargo-zigbuild --version 0.23.4
RUSTFLAGS="-C relocation-model=static" cargo zigbuild -p secmon-agent --target aarch64-unknown-linux-musl --release
cp target/aarch64-unknown-linux-musl/release/secmon-agent secmon-agent-linux-aarch64
sha256sum secmon-agent-linux-aarch64
```

The main-branch CI workflow also builds both architectures and keeps each binary with its `.sha256` sidecar as a downloadable workflow artifact for seven days.

On the server, select the matching release binary from its reported machine architecture. The installer accepts only the matching architecture-labelled filename and rejects unknown architectures:

```sh
case "$(uname -m)" in
  x86_64) agent=secmon-agent-linux-x86_64 ;;
  aarch64) agent=secmon-agent-linux-aarch64 ;;
  *) printf 'Unsupported Linux architecture: %s\n' "$(uname -m)" >&2; exit 1 ;;
esac
read -r agent_sha256 _ < "$agent.sha256"
sha256sum -c "$agent.sha256"
sudo ./install.sh --binary "./$agent" --sha256 "$agent_sha256"
```

Copy `install.sh` and the selected binary to the Linux server using a channel you trust. Compare its checksum with the value from the build machine before installing. The installer accepts only a local binary and makes no network requests. It creates a system account named `secmon` with home `/var/lib/secmon` if needed and sets its password field to the unusable value `NP`, so OpenSSH permits public-key authentication while password authentication cannot succeed. It installs the binary root-owned at `/usr/local/bin/secmon-agent` and creates `/etc/secmon/agent.toml`. The account uses `/bin/sh` because OpenSSH invokes a forced command through the account shell; the pairing key itself forces the one fixed collection command and disables interactive and forwarding features. Do not add unrestricted keys to this account.

The installed agent runs as the SSH account and does not need root. The installer does not add `secmon` to the Docker group. Docker group membership grants root-equivalent access and should remain disabled unless you have explicitly reviewed and accepted that privilege.

## Select local inventory paths

Edit `/etc/secmon/agent.toml` as root. An empty configuration leaves dependency-file inventory unavailable and reports it as partial. To scan selected project directories, use canonical absolute paths:

```toml
allowed_paths = ["/srv/web", "/srv/api"]
docker_cli_approved = false
max_processes = 4096
```

The agent resolves each path before scanning, rejects duplicate or invalid roots, applies file-count/depth/size limits, and returns dependency metadata with relative evidence paths. It does not send source files, `.env` values, lockfiles, or credentials to third parties. Docker collection is disabled by default. Turning on `docker_cli_approved` only works if the account has Docker access; that access can expose host-level control.

## Host restart and manual-install evidence

The collector compares the running kernel release from `/proc/sys/kernel/osrelease` with the newest installed kernel package when both values can be read and parsed. This includes RPM `kernel-core` and Oracle UEK `kernel-uek`/`kernel-uek-core` packages; known architecture suffixes such as `.x86_64` are ignored for the version comparison. A proven difference is restart evidence; it is not proof that a vulnerability is fixed in production. Unknown or unsupported version formats stay partial and unverified.

For processes whose `/proc/<pid>/maps` files are readable, the collector records bounded deleted shared-library basenames. It does not record library contents or restart services. Permission-denied process maps make the process check partial. The collector also checks a closed product allowlist beneath canonical `/opt` and `/usr/local` roots, using fixed per-product `--version` argument vectors. Those records have low confidence and `source_type=manual`; binaries outside the allowlist or roots are ignored. No arbitrary command can be requested remotely.

## Pair a host

The pairing library creates a dedicated Ed25519 key in the local operating-system credential store. It reports the observed SHA-256 host-key fingerprint for independent confirmation and produces an `authorized_keys` line restricted to:

```text
command="/usr/local/bin/secmon-agent collect",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,restrict ssh-ed25519 PUBLIC_KEY secmon@DEVICE
```

Create `/var/lib/secmon/.ssh` as `secmon` with mode `0700`, then add the generated line to `/var/lib/secmon/.ssh/authorized_keys` owned by `secmon` with mode `0600`. Keep the host-key fingerprint pinned on the desktop. A later mismatch must be rejected and reviewed; do not automatically accept a changed key.

For lower-level direct-host development and transport testing, this repository includes a pairing harness. It prompts you to verify the fingerprint, writes the generated private key only to the OS credential store, displays the public forced-command line, waits for installation, then asks for explicit approval to send inventory to this device. The returned collection includes the approval timestamp, which the desktop caller persists in its audit history:

```sh
cargo run -p security-monitor-agent-transport --example pair-agent -- web-prod web.example.test secmon 22
```

The example accepts a direct SSH target. The library also supports a single `ProxyJump` hop when both the bastion and target have independently confirmed fingerprints. SSH config discovery reads host directives only; it never opens configured private-key files. `Include` files and dynamic `Match` blocks are reported as unsupported instead of being executed or followed.

## Check collection results

The protocol document has a schema at `crates/agent-protocol/schema/agent-inventory.schema.json`. It includes one status for each collection area. Missing permissions, missing tools, unavailable optional checks, stale observations, and unknown deployment identities remain partial, unavailable, or `needs_review`; they never imply a safe state. The agent reports a deployment identity as observed metadata only and always leaves `integrity_verified` false.

To test a forced-command SSH flow in a disposable OpenSSH container, run the Linux CI E2E test. It builds the static binary, creates a fresh container host key and a restricted client key, verifies that a changed host key is rejected, then collects inventory as the unprivileged `secmon` account. The test talks only to the container on loopback; the CI setup builds the image before the test starts.
