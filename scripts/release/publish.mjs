import { readdir, readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const tagPattern = /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const platformLabels = {
  'windows-x86_64': 'Windows x86_64',
  'macos-x86_64': 'macOS x86_64',
  'macos-aarch64': 'macOS aarch64',
  'linux-x86_64': 'Linux x86_64',
};

export async function collectRelease(artifactRootArg, tag) {
  if (!artifactRootArg || !tagPattern.test(tag ?? '')) {
    throw new Error('Release tag must be a semantic version beginning with v.');
  }
  const root = resolve(artifactRootArg);
  const assets = [];
  const unsigned = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    for (const name of await readdir(join(root, entry.name))) {
      if (name.endsWith('.signing.json')) {
        const artifact = name.slice(0, -'.signing.json'.length);
        const { codeSigning } = JSON.parse(await readFile(join(root, entry.name, name), 'utf8'));
        if (!['signed', 'unsigned', 'not_applicable'].includes(codeSigning)) {
          throw new Error(`Invalid code-signing status for ${artifact}.`);
        }
        if (codeSigning === 'unsigned') unsigned.push(platformLabels[artifact] ?? artifact);
      } else if (!name.endsWith('.updater.json')) {
        assets.push(join(root, entry.name, name));
      }
    }
  }
  assets.push(join(root, 'latest.json'), join(root, 'SHA256SUMS'));

  const prerelease = tag.includes('-');
  const notes = [];
  if (prerelease) {
    notes.push('**Pre-release.** For testing only; the in-app updater does not offer pre-releases.');
  }
  if (unsigned.length) {
    notes.push(
      `**Unsigned packages:** ${unsigned.sort().join(', ')}. These installers are not code-signed, so Windows SmartScreen or macOS Gatekeeper will warn. ` +
        'Verify `SHA256SUMS` with minisign and compare the package hash before installing; see docs/release.md. ' +
        'Updater payloads and the CLI and agent binaries are still signed.',
    );
  }
  return { assets, prerelease, notes: notes.join('\n\n') };
}

export function releaseArgs(tag, { assets, prerelease, notes }) {
  const args = ['release', 'create', tag, ...assets, '--title', `Security Monitor ${tag}`, '--generate-notes'];
  if (notes) args.push('--notes', notes);
  // GitHub's releases/latest endpoint skips pre-releases, which keeps them out of the updater feed.
  if (prerelease) args.push('--prerelease', '--latest=false');
  return args;
}

const scriptPath = fileURLToPath(import.meta.url);
if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  const [, , artifactRootArg, tag] = process.argv;
  const release = await collectRelease(artifactRootArg, tag);

  const run = (args) => {
    const result = spawnSync('gh', args, { stdio: 'inherit', windowsHide: true });
    if (result.error) throw result.error;
    return result.status;
  };

  const existing = spawnSync('gh', ['release', 'view', tag], { stdio: 'ignore', windowsHide: true });
  if (existing.status === 0) {
    if (run(['release', 'upload', tag, ...release.assets, '--clobber']) !== 0) throw new Error('Release asset upload failed.');
  } else if (run(releaseArgs(tag, release)) !== 0) {
    throw new Error('GitHub release creation failed.');
  }
}
