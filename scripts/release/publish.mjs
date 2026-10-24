import { readdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const [, , artifactRootArg, tag] = process.argv;
if (!artifactRootArg || !/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(tag ?? '')) {
  throw new Error('Release tag must be a semantic version beginning with v.');
}

const root = resolve(artifactRootArg);
const assets = [];
for (const entry of await readdir(root, { withFileTypes: true })) {
  if (!entry.isDirectory()) continue;
  for (const name of await readdir(join(root, entry.name))) {
    if (!name.endsWith('.updater.json')) assets.push(join(root, entry.name, name));
  }
}
assets.push(join(root, 'latest.json'), join(root, 'SHA256SUMS'));
if (!assets.length) throw new Error('No release assets were staged.');

function run(args) {
  const result = spawnSync('gh', args, { stdio: 'inherit', windowsHide: true });
  if (result.error) throw result.error;
  return result.status;
}

const existing = spawnSync('gh', ['release', 'view', tag], { stdio: 'ignore', windowsHide: true });
if (existing.status === 0) {
  if (run(['release', 'upload', tag, ...assets, '--clobber']) !== 0) throw new Error('Release asset upload failed.');
} else if (run(['release', 'create', tag, ...assets, '--title', `Security Monitor ${tag}`, '--generate-notes']) !== 0) {
  throw new Error('GitHub release creation failed.');
}
