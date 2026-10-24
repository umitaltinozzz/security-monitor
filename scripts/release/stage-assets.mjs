import { copyFile, mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { basename, join, relative, resolve } from 'node:path';

const [, , target, artifact, platform, arch] = process.argv;
const valid = new Set(['windows-x86_64', 'macos-x86_64', 'macos-aarch64', 'linux-x86_64']);
if (!valid.has(artifact) || !target || !['windows', 'darwin', 'linux'].includes(platform) || !['x86_64', 'aarch64'].includes(arch)) {
  throw new Error('Release target metadata is invalid.');
}

const root = resolve('.');
const output = join(root, 'target', 'release-out', artifact);
const bundle = join(root, 'target', target, 'release', 'bundle');
await mkdir(output, { recursive: true });

async function filesUnder(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isSymbolicLink()) throw new Error('A packaged release contains a symbolic link.');
    if (entry.isDirectory()) files.push(...await filesUnder(path));
    else if (entry.isFile()) files.push(path);
  }
  return files;
}

const packageFiles = await filesUnder(bundle);
if (packageFiles.length === 0) throw new Error('Tauri produced no desktop packages.');
if (packageFiles.some((path) => path.toLowerCase().endsWith('.zip'))) {
  throw new Error('ZIP updater bundles are outside the supported release formats.');
}
const stagedNames = new Map();
for (const source of packageFiles) {
  const safeName = basename(source).normalize('NFKC').replace(/[^A-Za-z0-9._-]+/g, '-').replace(/-+/g, '-');
  const name = `security-monitor-${artifact}-${safeName}`;
  const destination = join(output, name);
  await copyFile(source, destination);
  stagedNames.set(source, name);
}

const updaterTargets = {};
for (const signaturePath of packageFiles.filter((path) => path.endsWith('.sig'))) {
  const payloadPath = signaturePath.slice(0, -4);
  if (!packageFiles.includes(payloadPath)) continue;
  const payloadName = stagedNames.get(payloadPath);
  let updaterTarget;
  if (platform === 'windows' && payloadPath.toLowerCase().endsWith('.msi')) updaterTarget = `windows-${arch}-msi`;
  else if (platform === 'windows' && payloadPath.toLowerCase().endsWith('.exe')) updaterTarget = `windows-${arch}-nsis`;
  else if (platform === 'darwin' && payloadPath.endsWith('.app.tar.gz')) updaterTarget = `darwin-${arch}`;
  else if (platform === 'linux' && payloadPath.toLowerCase().endsWith('.appimage')) updaterTarget = `linux-${arch}-appimage`;
  if (!updaterTarget) continue;
  updaterTargets[updaterTarget] = {
    asset: payloadName,
    signature: (await readFile(signaturePath, 'utf8')).trim(),
  };
}
if (Object.keys(updaterTargets).length === 0) throw new Error('No signed updater package was produced for this platform.');

const binaryDirectory = join(root, 'target', target, 'release');
const cliSuffix = platform === 'windows' ? '.exe' : '';
const cliSource = join(binaryDirectory, `secmon${cliSuffix}`);
const cliName = `secmon-${artifact}${cliSuffix}`;
await copyFile(cliSource, join(output, cliName));

if (platform === 'linux') {
  const agentSource = join(root, 'target', 'x86_64-unknown-linux-musl', 'release', 'secmon-agent');
  const agentName = 'secmon-agent-linux-x86_64';
  await copyFile(agentSource, join(output, agentName));
}

await writeFile(join(output, `${artifact}.updater.json`), `${JSON.stringify(updaterTargets, null, 2)}\n`, { flag: 'wx' });
const names = await readdir(output);
const paths = await Promise.all(names.map(async (name) => relative(root, join(output, name))));
if (paths.some((path) => path.startsWith('..'))) throw new Error('Staged release path escaped the repository.');
