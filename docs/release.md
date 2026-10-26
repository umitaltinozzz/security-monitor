---
title: Signed releases and updates
description: Build, sign, verify, and install Security Monitor releases.
---

# Signed releases and updates

Security Monitor publishes Windows (`x86_64`), macOS (`x86_64` and `aarch64`), and Linux (`x86_64`) desktop packages. Each platform build also includes the `secmon` CLI; the Linux build includes the static musl `secmon-agent` for `x86_64` and `aarch64`.

## What is always signed, and what can be unsigned

| Signature | Covers | Required |
| --- | --- | --- |
| Tauri updater signature | Every in-app update payload and `latest.json` | Always. The workflow stops without it. |
| Minisign | The `secmon` CLI, both `secmon-agent` binaries, and `SHA256SUMS` | Always. The workflow stops without it. |
| Windows Authenticode | `.msi` and `.exe` installers | Optional. Without a certificate the Windows packages are built unsigned. |
| Apple Developer ID + notarization | macOS `.app` / `.dmg` | Optional. Without a certificate the macOS packages are ad-hoc signed only. |

An unsigned platform is never silent: the build job emits a warning, and the published release notes list every unsigned platform with verification instructions. A *partly* configured certificate (for example a Windows certificate without its password) fails the build instead of falling back to unsigned.

## Configure release signing

Store private material only in GitHub Actions secrets; never commit it or put it in a workflow file. Release jobs run in the `release` environment, which requires a maintainer's approval before any signing secret is used.

| Platform | Required configuration |
| --- | --- |
| All | Variables `SECMON_UPDATE_PUBLIC_KEY` and `MINISIGN_PUBLIC_KEY`; secrets `TAURI_SIGNING_PRIVATE_KEY`, `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`, and `MINISIGN_PRIVATE_KEY` |
| Windows (optional) | Variable `SECMON_WINDOWS_CERTIFICATE_THUMBPRINT`; secrets `WINDOWS_CERTIFICATE` (base64 PFX) and `WINDOWS_CERTIFICATE_PASSWORD` |
| macOS (optional) | Variables `APPLE_SIGNING_IDENTITY`, `APPLE_TEAM_ID`, `APPLE_API_ISSUER`, `APPLE_API_KEY` (key ID); secrets `APPLE_CERTIFICATE` (base64 P12), `APPLE_CERTIFICATE_PASSWORD`, `APPLE_ID`, `APPLE_PASSWORD`, `APPLE_API_KEY_CONTENT` (base64 API key file), and `KEYCHAIN_PASSWORD` |

### Generate the always-required keys

Run these on a trusted machine, outside the repository. Back up the private keys and the Tauri password before adding them to GitHub: if the updater key or its password is lost, installed apps can no longer receive updates and users must reinstall manually.

Windows PowerShell:

```powershell
mkdir "$HOME\secmon-keys"; cd "$HOME\secmon-keys"
pnpm -C <repo>\apps\desktop tauri signer generate -w "$HOME\secmon-keys\tauri.key"
winget install jedisct1.minisign
minisign -G -W -p minisign.pub -s minisign.key

$R = "<owner>/<repo>"
Get-Content -Raw tauri.key     | gh secret set TAURI_SIGNING_PRIVATE_KEY -R $R
gh secret set TAURI_SIGNING_PRIVATE_KEY_PASSWORD -R $R
Get-Content -Raw minisign.key  | gh secret set MINISIGN_PRIVATE_KEY -R $R
Get-Content -Raw tauri.key.pub | gh variable set SECMON_UPDATE_PUBLIC_KEY -R $R
Get-Content -Raw minisign.pub  | gh variable set MINISIGN_PUBLIC_KEY -R $R
```

Linux or macOS:

```sh
mkdir -m 700 ~/secmon-keys && cd ~/secmon-keys
pnpm -C <repo>/apps/desktop tauri signer generate -w ~/secmon-keys/tauri.key
minisign -G -W -p minisign.pub -s minisign.key

R=<owner>/<repo>
gh secret set TAURI_SIGNING_PRIVATE_KEY -R "$R" < tauri.key
gh secret set TAURI_SIGNING_PRIVATE_KEY_PASSWORD -R "$R"
gh secret set MINISIGN_PRIVATE_KEY -R "$R" < minisign.key
gh variable set SECMON_UPDATE_PUBLIC_KEY -R "$R" < tauri.key.pub
gh variable set MINISIGN_PUBLIC_KEY -R "$R" < minisign.pub
```

`minisign -G -W` creates an unencrypted key so CI can sign without a prompt; protect the private key file like any other secret and delete the local copy once it is backed up. `MINISIGN_PUBLIC_KEY` holds the whole `minisign.pub` file, comment line included. The update public key must match the Tauri private key.

## Rehearse a release (dry run)

Before tagging, run **Actions → Signed release → Run workflow** with `dry_run` checked and `release_tag` empty. The workflow builds every platform from the selected branch, signs the updater payloads, CLI, agents, and checksums, verifies the signatures, and uploads the assembled files as the `release-dry-run` workflow artifact. It does not create a tag or a GitHub release. The `release` environment still asks for approval because the signing secrets are used.

## Create a release

Set the version in `apps/desktop/package.json`, `apps/desktop/src-tauri/tauri.conf.json`, and the Cargo workspace together. Commit the version change, create and push a matching `vMAJOR.MINOR.PATCH` tag, approve the `release` environment in **Actions → Signed release**, then check that all four build jobs and the publish job are green before distributing the release.

A tag with a pre-release suffix is published as a GitHub pre-release. GitHub's `releases/latest` endpoint, which the in-app updater uses, skips pre-releases, so testers can download them without the updater offering them to everyone. Windows MSI packages only accept a numeric pre-release identifier, so use tags such as `v0.1.0-1` rather than `v0.1.0-rc.1`.

## Verify a download

Every release includes `SHA256SUMS`, its minisign signature `SHA256SUMS.minisig`, and a `.minisig` file for each CLI and agent binary. The release minisign public key is:

```text
RWSCG0MdSat+y/ed/xVrTGxCQvIHl7ux3jPa73kHaa255vRVMMqS00mb
```

Verify the checksum list with that key, then compare the hash of the file you downloaded:

```sh
minisign -Vm SHA256SUMS -P RWSCG0MdSat+y/ed/xVrTGxCQvIHl7ux3jPa73kHaa255vRVMMqS00mb
sha256sum --ignore-missing -c SHA256SUMS
```

On Windows, use `Get-FileHash <file> -Algorithm SHA256` and compare the value with the matching line in `SHA256SUMS`.

For an unsigned Windows installer, SmartScreen shows **Windows protected your PC**; choose **More info → Run anyway** only after the hash matches. For an unsigned macOS app, Gatekeeper refuses the first launch; after the hash matches, open it once with right-click → **Open**, or run `xattr -dr com.apple.quarantine "/Applications/Security Monitor.app"`.

## Install an update

Open **Settings → Updates** and choose **Check for updates**. Checking and downloading require **Allow public downloads** in network and privacy settings. The app only contacts this repository's HTTPS release endpoint and GitHub's release asset host, checks the Tauri signature, and displays bounded release notes. Choose **Install update** to download and restart into the reviewed version. The app checks the manifest again before installation and refuses if the available version changed.

Updates are manual and user initiated. The app does not send project paths, source, lockfiles, package inventory, or server inventory with an update request. The release hosts receive ordinary network metadata such as IP address and user agent.
