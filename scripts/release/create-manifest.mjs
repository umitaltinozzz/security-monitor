import { createHash } from 'node:crypto';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { basename, join, resolve } from 'node:path';

const [, , artifactRootArg, tag] = process.argv;
if (!artifactRootArg || !/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(tag ?? '')) {
  throw new Error('Release tag must be a semantic version beginning with v.');
}

const root = resolve(artifactRootArg);
const packageInfo = JSON.parse(await readFile('apps/desktop/package.json', 'utf8'));
const version = tag.slice(1);
if (packageInfo.version !== version) throw new Error('Release tag must match the desktop package version.');

async function filesUnder(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isSymbolicLink()) throw new Error('Release artifacts cannot contain symbolic links.');
    if (entry.isDirectory()) files.push(...await filesUnder(path));
    else if (entry.isFile()) files.push(path);
  }
  return files;
}

const files = await filesUnder(root);
const updaterFiles = files.filter((path) => path.endsWith('.updater.json'));
const required = new Set([
  'windows-x86_64-msi', 'windows-x86_64-nsis',
  'darwin-x86_64', 'darwin-aarch64',
  'linux-x86_64-appimage',
]);
const updaterExtensions = {
  'windows-x86_64-msi': '.msi',
  'windows-x86_64-nsis': '.exe',
  'darwin-x86_64': '.app.tar.gz',
  'darwin-aarch64': '.app.tar.gz',
  'linux-x86_64-appimage': '.appimage',
};
const platforms = {};
const assetNames = new Set();
for (const path of updaterFiles) {
  const updates = JSON.parse(await readFile(path, 'utf8'));
  for (const [target, data] of Object.entries(updates)) {
    if (platforms[target]) throw new Error(`Duplicate updater target: ${target}`);
    if (!required.has(target)) throw new Error(`Unexpected updater target: ${target}`);
    if (typeof data.asset !== 'string' || !data.asset || data.asset.includes('/') || data.asset.includes('\\')) {
      throw new Error(`Invalid updater asset for target: ${target}`);
    }
    if (!data.asset.toLowerCase().endsWith(updaterExtensions[target])) {
      throw new Error(`Invalid updater bundle format for target: ${target}`);
    }
    if (assetNames.has(data.asset)) throw new Error(`Duplicate updater asset: ${data.asset}`);
    if (typeof data.signature !== 'string' || !data.signature.trim()) {
      throw new Error(`Missing updater signature for target: ${target}`);
    }
    const artifactPath = join(resolve(path, '..'), data.asset);
    const artifactDirectory = resolve(path, '..');
    if (!artifactPath.startsWith(`${artifactDirectory}${process.platform === 'win32' ? '\\' : '/'}`)) {
      throw new Error(`Updater asset escaped its artifact directory: ${target}`);
    }
    if (!files.includes(artifactPath)) throw new Error(`Updater asset is missing: ${target}`);
    assetNames.add(data.asset);
    platforms[target] = {
      url: `https://github.com/umitaltinozzz/security-monitor/releases/download/${tag}/${data.asset}`,
      signature: data.signature,
    };
  }
}

for (const target of required) {
  if (!platforms[target]?.signature || !platforms[target]?.url) throw new Error(`Missing signed updater target: ${target}`);
}

const manifest = {
  version,
  notes: `Security Monitor ${version}`,
  pub_date: new Date().toISOString(),
  platforms,
};
await writeFile(join(root, 'latest.json'), `${JSON.stringify(manifest, null, 2)}\n`, { flag: 'wx' });

// GitHub release assets are flat, so checksum lines use bare names that `sha256sum -c` can find.
const sums = [];
const checksumNames = new Set();
for (const path of files) {
  if (path.endsWith('.updater.json') || path.endsWith('.signing.json')) continue;
  const name = basename(path);
  if (checksumNames.has(name)) throw new Error(`Duplicate release asset name: ${name}`);
  checksumNames.add(name);
  const digest = createHash('sha256').update(await readFile(path)).digest('hex');
  sums.push(`${digest}  ${name}`);
}
sums.push(`${createHash('sha256').update(await readFile(join(root, 'latest.json'))).digest('hex')}  latest.json`);
await writeFile(join(root, 'SHA256SUMS'), `${sums.sort().join('\n')}\n`, { flag: 'wx' });
