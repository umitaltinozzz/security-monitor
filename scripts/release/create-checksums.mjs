import { createHash } from 'node:crypto';
import { lstat, readdir, readFile, writeFile } from 'node:fs/promises';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

async function filesUnder(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    const info = await lstat(path);
    if (info.isSymbolicLink()) throw new Error('Release artifacts cannot contain symbolic links.');
    if (info.isDirectory()) files.push(...await filesUnder(path));
    else if (info.isFile()) files.push(path);
  }
  return files;
}

export async function createChecksums(artifactRoot) {
  const root = resolve(artifactRoot);
  const files = await filesUnder(root);
  const entries = files
    .filter((path) => !path.endsWith('.updater.json') && !['SHA256SUMS', 'SHA256SUMS.minisig', 'latest.json'].includes(relative(root, path)))
    .map((path) => ({ path, name: relative(root, path).replaceAll('\\', '/') }))
    .sort((left, right) => left.name.localeCompare(right.name, 'en'));
  if (entries.length === 0) throw new Error('No release assets were staged for checksumming.');
  if (entries.some(({ name }) => /[\r\n]/.test(name))) throw new Error('Release asset names cannot contain line breaks.');

  const lines = await Promise.all(entries.map(async ({ path, name }) => {
    const digest = createHash('sha256').update(await readFile(path)).digest('hex');
    return `${digest}  ${name}`;
  }));
  await writeFile(join(root, 'SHA256SUMS'), `${lines.join('\n')}\n`, { flag: 'wx' });
}

const scriptPath = fileURLToPath(import.meta.url);
if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  const artifactRoot = process.argv[2];
  if (!artifactRoot || process.argv.length !== 3) throw new Error('A staged release artifact directory is required.');
  await createChecksums(artifactRoot);
}
