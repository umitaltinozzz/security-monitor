---
title: Deployment Identity
description: Record and interpret observed deployment metadata without treating it as provenance.
---

# Deployment identity

Security Monitor can compare a locally known repository identity with metadata observed from a running service. A match suggests a project association; it does not prove that the running process came from that source or that the build is trustworthy.

## Metadata sources

For a service in a container, the collector checks OCI revision, version, source, and image ID metadata first. For a process with an allowlisted project directory, it then checks these sources in order and keeps the first valid result:

1. `<application-root>/.secmon-deploy.json`
2. `/etc/secmon/deployments.d/<service>.json`
3. Only `SECMON_COMMIT_SHA`, `SOURCE_COMMIT`, and `GIT_COMMIT` in the service environment
4. `.git/HEAD` with a safe loose or packed reference in the application root

Deployment checks apply to services under an allowlisted application root or with an explicit system deployment file or recognized deployment environment variable. A service with no deployment configuration (for example, an ordinary system daemon such as `sshd`) is omitted from the deployment check and does not make that check partial. Configured services with missing or invalid identity data remain unknown. Containers are evaluated when their OCI metadata provides a recognized deployment identity.

The JSON record accepts these fields:

```json
{
  "commit_sha": "0123456789abcdef0123456789abcdef01234567",
  "repo": "https://github.com/acme/web",
  "release_id": "v2.4.1",
  "image_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  "built_at": "2026-10-20T12:00:00Z"
}
```

Values are bounded and validated. Repository URLs must be HTTP(S) without embedded credentials, query strings, or fragments. Commit values must be hexadecimal. Arbitrary environment variables and source files are not collected.

## Build metadata examples

A GitHub Actions workflow can write a deployment record as part of its build:

```yaml
- name: Write deployment identity
  env:
    COMMIT_SHA: ${{ github.sha }}
    REPOSITORY: https://github.com/${{ github.repository }}
    RELEASE_ID: ${{ github.ref_name }}
  run: |
    node -e 'const fs = require("node:fs"); fs.writeFileSync(".secmon-deploy.json", JSON.stringify({commit_sha: process.env.COMMIT_SHA, repo: process.env.REPOSITORY, release_id: process.env.RELEASE_ID}) + "\n")'
```

GitLab CI can use `CI_COMMIT_SHA`, `CI_PROJECT_URL`, and `CI_COMMIT_TAG` to create the same file. Container builds should add `org.opencontainers.image.revision`, `org.opencontainers.image.version`, and `org.opencontainers.image.source` labels. Do not place secrets or build credentials in the file or labels.

## Project association and limits

Repository and commit values are compared locally against known projects. The result is only a suggestion; it does not auto-associate a host or change a finding status. Missing, invalid, stale, or unmatched identifiers produce an unknown or `needs_review` state. `integrity_verified` remains false because observing a commit or image ID does not verify build provenance or the running artifact.
