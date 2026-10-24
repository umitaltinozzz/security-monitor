import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));
const scripts = join(repositoryRoot, 'scripts', 'release');

function run(script, args, options = {}) {
  const result = spawnSync(process.execPath, [join(scripts, script), ...args], {
    cwd: options.cwd,
    env: { ...process.env, ...options.env },
    encoding: 'utf8',
    windowsHide: true,
  });
  return result;
}

test('Windows release config accepts a certificate thumbprint without writing signing secrets', async () => {
  const root = await mkdtemp(join(tmpdir(), 'secmon-release-config-'));
  const output = join(root, 'target', 'tauri.release.json');
  const result = run('write-tauri-config.mjs', ['windows', output], {
    cwd: root,
    env: { SECMON_WINDOWS_CERTIFICATE_THUMBPRINT: 'ab'.repeat(20) },
  });
  assert.equal(result.status, 0, result.stderr);
  const config = JSON.parse(await readFile(output, 'utf8'));
  assert.equal(config.bundle.windows.digestAlgorithm, 'sha256');
  assert.equal(config.bundle.windows.certificateThumbprint, 'ab'.repeat(20));
  assert.equal(JSON.stringify(config).includes('PASSWORD'), false);
});

test('release manifest requires all signed targets and writes offline checksums', async () => {
  const root = await mkdtemp(join(tmpdir(), 'secmon-release-manifest-'));
  const artifacts = join(root, 'release-assets');
  await mkdir(artifacts);
  await mkdir(join(root, 'apps', 'desktop'), { recursive: true });
  await writeFile(join(root, 'apps', 'desktop', 'package.json'), JSON.stringify({ version: '0.1.0' }));
  const records = {
    'windows-x86_64': {
      'windows-x86_64-msi': 'windows.msi',
      'windows-x86_64-nsis': 'windows.exe',
    },
    'macos-x86_64': { 'darwin-x86_64': 'mac-intel.app.tar.gz' },
    'macos-aarch64': { 'darwin-aarch64': 'mac-arm.app.tar.gz' },
    'linux-x86_64': { 'linux-x86_64-appimage': 'linux.AppImage' },
  };
  for (const [artifact, targets] of Object.entries(records)) {
    const directory = join(artifacts, `release-${artifact}`);
    await mkdir(directory);
    const mapped = {};
    for (const [target, asset] of Object.entries(targets)) {
      await writeFile(join(directory, asset), 'signed artifact bytes');
      mapped[target] = { asset, signature: `signature:${target}` };
    }
    await writeFile(join(directory, `${artifact}.updater.json`), JSON.stringify(mapped));
  }

  const result = run('create-manifest.mjs', [artifacts, 'v0.1.0'], { cwd: root });
  assert.equal(result.status, 0, result.stderr);
  const manifest = JSON.parse(await readFile(join(artifacts, 'latest.json'), 'utf8'));
  assert.equal(manifest.version, '0.1.0');
  assert.equal(Object.keys(manifest.platforms).length, 5);
  assert.ok(manifest.platforms['windows-x86_64-msi'].url.endsWith('/windows.msi'));
  assert.equal(manifest.platforms['linux-x86_64-appimage'].signature, 'signature:linux-x86_64-appimage');
  const sums = await readFile(join(artifacts, 'SHA256SUMS'), 'utf8');
  assert.match(sums, /latest\.json/);
  assert.match(sums, /linux\.AppImage/);
});

test('release manifest rejects an incomplete platform matrix', async () => {
  const root = await mkdtemp(join(tmpdir(), 'secmon-release-incomplete-'));
  const artifacts = join(root, 'release-assets');
  await mkdir(artifacts);
  await mkdir(join(root, 'apps', 'desktop'), { recursive: true });
  await writeFile(join(root, 'apps', 'desktop', 'package.json'), JSON.stringify({ version: '0.1.0' }));
  const result = run('create-manifest.mjs', [artifacts, 'v0.1.0'], { cwd: root });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Missing signed updater target/);
});

test('release manifest rejects path-like updater asset names', async () => {
  const root = await mkdtemp(join(tmpdir(), 'secmon-release-path-'));
  const artifacts = join(root, 'release-assets');
  const platformDirectory = join(artifacts, 'release-windows-x86_64');
  await mkdir(platformDirectory, { recursive: true });
  await mkdir(join(root, 'apps', 'desktop'), { recursive: true });
  await writeFile(join(root, 'apps', 'desktop', 'package.json'), JSON.stringify({ version: '0.1.0' }));
  await writeFile(
    join(platformDirectory, 'windows-x86_64.updater.json'),
    JSON.stringify({ 'windows-x86_64-msi': { asset: '../outside.msi', signature: 'signature' } }),
  );

  const result = run('create-manifest.mjs', [artifacts, 'v0.1.0'], { cwd: root });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Invalid updater asset/);
});

test('release manifest rejects formats outside the signed platform bundle matrix', async () => {
  const root = await mkdtemp(join(tmpdir(), 'secmon-release-format-'));
  const artifacts = join(root, 'release-assets');
  const platformDirectory = join(artifacts, 'release-macos-x86_64');
  await mkdir(platformDirectory, { recursive: true });
  await mkdir(join(root, 'apps', 'desktop'), { recursive: true });
  await writeFile(join(root, 'apps', 'desktop', 'package.json'), JSON.stringify({ version: '0.1.0' }));
  await writeFile(join(platformDirectory, 'security-monitor.zip'), 'payload');
  await writeFile(
    join(platformDirectory, 'macos-x86_64.updater.json'),
    JSON.stringify({ 'darwin-x86_64': { asset: 'security-monitor.zip', signature: 'signature' } }),
  );

  const result = run('create-manifest.mjs', [artifacts, 'v0.1.0'], { cwd: root });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Invalid updater bundle format/);
});

test('asset staging rejects Tauri ZIP updater bundles', async () => {
  const root = await mkdtemp(join(tmpdir(), 'secmon-release-stage-'));
  const target = 'x86_64-pc-windows-msvc';
  const bundle = join(root, 'target', target, 'release', 'bundle', 'nsis');
  await mkdir(bundle, { recursive: true });
  await mkdir(join(root, 'target', target, 'release'), { recursive: true });
  await writeFile(join(bundle, 'security-monitor-setup.exe'), 'installer');
  await writeFile(join(bundle, 'security-monitor-setup.exe.sig'), 'signature');
  await writeFile(join(bundle, 'security-monitor-setup.nsis.zip'), 'archive');
  await writeFile(join(bundle, 'security-monitor-setup.nsis.zip.sig'), 'signature');
  await writeFile(join(root, 'target', target, 'release', 'secmon.exe'), 'cli');

  const result = run('stage-assets.mjs', [target, 'windows-x86_64', 'windows', 'x86_64'], { cwd: root });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /ZIP updater bundles are outside the supported release formats/);
});
