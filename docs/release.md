---
title: Signed releases and updates
description: Build, sign, verify, and install Security Monitor releases.
---

# Signed releases and updates

Security Monitor publishes Windows (`x86_64`), macOS (`x86_64` and `aarch64`), and Linux (`x86_64`) desktop packages. Each platform build also includes the `secmon` CLI; the Linux build includes the static musl `secmon-agent`. The release workflow refuses to build when signing configuration is missing.

## Configure release signing

Add these repository Actions variables and secrets before creating a release tag. Store private material only in GitHub Actions secrets; never commit it or put it in a workflow file.

| Platform | Required configuration |
| --- | --- |
| All | Variable `SECMON_UPDATE_PUBLIC_KEY`; secrets `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` |
| Windows | Variable `SECMON_WINDOWS_CERTIFICATE_THUMBPRINT`; secrets `WINDOWS_CERTIFICATE` (base64 PFX) and `WINDOWS_CERTIFICATE_PASSWORD` |
| macOS | Variables `APPLE_SIGNING_IDENTITY`, `APPLE_TEAM_ID`, `APPLE_API_ISSUER`; secrets `APPLE_CERTIFICATE` (base64 P12), `APPLE_CERTIFICATE_PASSWORD`, `APPLE_ID`, `APPLE_PASSWORD`, `APPLE_API_KEY` (key ID), `APPLE_API_KEY_CONTENT` (base64 API key file), and `KEYCHAIN_PASSWORD` |

The update public key must match the private key used by Tauri. Windows packages use Authenticode signing. macOS packages are signed and notarized. Linux update payloads use Tauri's signed updater metadata; Linux desktop packages themselves are not Authenticode-style signed. `SHA256SUMS` covers published files for independent transfer checks.

## Create a release

Set the version in `apps/desktop/package.json`, `apps/desktop/src-tauri/tauri.conf.json`, and the Cargo workspace together. Commit the version change, create and push a matching `vMAJOR.MINOR.PATCH` tag, then monitor **Actions → Signed release**. The workflow builds on the native platform runners, validates the full updater target matrix, and publishes packages, the signed `latest.json` manifest, and checksums to the GitHub Release. The workflow can also be dispatched with an existing version tag.

The workflow is fail-closed: it does not create an unsigned release when any required platform signing configuration is absent. Check that all four build matrix jobs and the publish job are green before distributing a release.

## Install an update

Open **Settings → Updates** and choose **Check for updates**. Checking and downloading require **Allow public downloads** in network and privacy settings. The app only contacts this repository's HTTPS release endpoint and GitHub's release asset host, checks the Tauri signature, and displays bounded release notes. Choose **Install update** to download and restart into the reviewed version. The app checks the manifest again before installation and refuses if the available version changed.

Updates are manual and user initiated. The app does not send project paths, source, lockfiles, package inventory, or server inventory with an update request. The release hosts receive ordinary network metadata such as IP address and user agent.
