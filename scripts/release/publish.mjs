import { readdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export async function publishRelease(artifactRoot, tag, run = (args, options = {}) => spawnSync('gh', args, {
  stdio: 'inherit', ...options, windowsHide: true,
})) {
  const nightly = tag === 'nightly';
  if (!/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(tag ?? '') && !nightly) {
    throw new Error('Release tag must be nightly or a semantic version beginning with v.');
  }

  const root = resolve(artifactRoot);
  const assets = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    for (const name of await readdir(join(root, entry.name))) {
      if (!name.endsWith('.updater.json')) assets.push(join(root, entry.name, name));
    }
  }
  if (!nightly) assets.push(join(root, 'latest.json'));
  assets.push(join(root, 'SHA256SUMS'), join(root, 'SHA256SUMS.minisig'));
  if (assets.length === 0) throw new Error('No release assets were staged.');

  const existing = run(['release', 'view', tag], { stdio: 'ignore', windowsHide: true });
  if (existing.error) throw existing.error;
  if (existing.status === 0) {
    const uploaded = run(['release', 'upload', tag, ...assets, '--clobber']);
    if (uploaded.error) throw uploaded.error;
    if (uploaded.status !== 0) throw new Error('Release asset upload failed.');
    if (nightly) {
      const edited = run(['release', 'edit', tag, '--prerelease', '--latest=false']);
      if (edited.error) throw edited.error;
      if (edited.status !== 0) throw new Error('Nightly release metadata update failed.');
    }
  } else {
    const args = ['release', 'create', tag, ...assets, '--title', `Security Monitor ${tag}`, '--generate-notes'];
    if (nightly) args.push('--prerelease', '--latest=false');
    const created = run(args);
    if (created.error) throw created.error;
    if (created.status !== 0) throw new Error('GitHub release creation failed.');
  }
}

const scriptPath = fileURLToPath(import.meta.url);
if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  const [, , artifactRoot, tag] = process.argv;
  if (!artifactRoot || process.argv.length !== 4) throw new Error('A staged release directory and tag are required.');
  await publishRelease(artifactRoot, tag);
}
