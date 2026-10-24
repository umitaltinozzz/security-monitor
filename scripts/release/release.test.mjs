import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createChecksums } from './create-checksums.mjs';
import { publishRelease } from './publish.mjs';
import { signReleaseBinaries, signReleaseChecksums } from './sign-binaries.mjs';

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

test('universal and nightly release overlays disable updater artifact generation', async () => {
  for (const mode of ['universal', 'nightly']) {
    const root = await mkdtemp(join(tmpdir(), `secmon-release-${mode}-config-`));
    const output = join(root, 'target', 'tauri.json');
    const result = run('write-tauri-config.mjs', [mode, output], { cwd: root });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(await readFile(output, 'utf8')).bundle.createUpdaterArtifacts, false);
  }
});

test('signed releases require minisign keys without echoing secret values', () => {
  const common = {
    RELEASE_TAG: 'v0.1.0',
    SECMON_UPDATE_PUBLIC_KEY: 'updater-public-fixture',
    TAURI_SIGNING_PRIVATE_KEY: 'updater-private-fixture',
    TAURI_SIGNING_PRIVATE_KEY_PASSWORD: 'updater-password-fixture',
  };
  const missing = run('verify-config.mjs', ['linux'], {
    env: { ...common, MINISIGN_PRIVATE_KEY: '', MINISIGN_PUBLIC_KEY: '' },
  });
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /MINISIGN_PRIVATE_KEY, MINISIGN_PUBLIC_KEY/);
  assert.equal(missing.stderr.includes('fixture'), false);

  const configured = run('verify-config.mjs', ['linux'], {
    env: { ...common, MINISIGN_PRIVATE_KEY: 'minisign-private-fixture', MINISIGN_PUBLIC_KEY: 'minisign-public-fixture' },
  });
  assert.equal(configured.status, 0, configured.stderr);
});

test('nightly release configuration only requires Minisign keys', () => {
  const result = run('verify-config.mjs', ['darwin'], {
    env: {
      RELEASE_TAG: 'nightly',
      MINISIGN_PRIVATE_KEY: 'nightly-private-fixture',
      MINISIGN_PUBLIC_KEY: 'nightly-public-fixture',
    },
  });
  assert.equal(result.status, 0, result.stderr);

  const missing = run('verify-config.mjs', ['darwin'], {
    env: { RELEASE_TAG: 'nightly', MINISIGN_PRIVATE_KEY: '', MINISIGN_PUBLIC_KEY: '' },
  });
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /MINISIGN_PRIVATE_KEY, MINISIGN_PUBLIC_KEY/);
  assert.equal(missing.stderr.includes('nightly-private-fixture'), false);
});

test('CLI and agent binaries receive minisign signatures that are verified before staging', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'secmon-minisign-binaries-'));
  const cli = join(directory, 'secmon-windows-x86_64.exe');
  const agent = join(directory, 'secmon-agent-linux-x86_64');
  const packageFile = join(directory, 'security-monitor-windows-x86_64-setup.msi');
  await Promise.all([
    writeFile(cli, 'cli fixture'),
    writeFile(agent, 'agent fixture'),
    writeFile(packageFile, 'package fixture'),
  ]);
  const calls = [];
  const privateKey = 'private fixture key';
  let privateKeyPath;
  const runMinisignFixture = (executable, args) => {
    assert.equal(executable, 'minisign');
    calls.push(args);
    if (args[0] === '-S') {
      assert.ok(args.includes('-W'));
      privateKeyPath = args[args.indexOf('-s') + 1];
      assert.equal(readFileSync(privateKeyPath, 'utf8').trim(), privateKey);
      writeFileSync(args[args.indexOf('-x') + 1], 'fixture signature');
    } else {
      assert.equal(args[0], '-V');
      assert.ok(readFileSync(args[args.indexOf('-x') + 1], 'utf8').length > 0);
      assert.ok(readFileSync(args[args.indexOf('-p') + 1], 'utf8').includes('public fixture key'));
    }
    return { status: 0 };
  };

  await signReleaseBinaries(directory, {
    env: { MINISIGN_PRIVATE_KEY: privateKey, MINISIGN_PUBLIC_KEY: 'public fixture key' },
    run: runMinisignFixture,
  });

  assert.equal(calls.filter((args) => args[0] === '-S').length, 2);
  assert.equal(calls.filter((args) => args[0] === '-V').length, 2);
  assert.ok(calls.every((args) => !args.includes(privateKey)));
  assert.ok((await readFile(`${cli}.minisig`, 'utf8')).length > 0);
  assert.ok((await readFile(`${agent}.minisig`, 'utf8')).length > 0);
  await assert.rejects(readFile(privateKeyPath, 'utf8'));
  await assert.rejects(readFile(`${packageFile}.minisig`, 'utf8'));
});

test('release checksum manifest is minisign signed and verified', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'secmon-minisign-checksums-'));
  const checksumFile = join(directory, 'SHA256SUMS');
  await writeFile(checksumFile, 'abc  secmon-linux-x86_64\n');
  const calls = [];
  await signReleaseChecksums(directory, {
    env: { MINISIGN_PRIVATE_KEY: 'private fixture key', MINISIGN_PUBLIC_KEY: 'public fixture key' },
    run: (_executable, args) => {
      calls.push(args);
      if (args[0] === '-S') writeFileSync(args[args.indexOf('-x') + 1], 'checksum signature');
      return { status: 0 };
    },
  });

  assert.deepEqual(calls.map((args) => args[0]), ['-S', '-V']);
  assert.ok((await readFile(`${checksumFile}.minisig`, 'utf8')).length > 0);
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
    if (artifact === 'linux-x86_64') {
      await writeFile(join(directory, 'secmon-linux-x86_64'), 'CLI binary');
      await writeFile(join(directory, 'secmon-linux-x86_64.minisig'), 'CLI Minisign signature');
      await writeFile(join(directory, 'secmon-agent-linux-x86_64'), 'agent binary');
      await writeFile(join(directory, 'secmon-agent-linux-x86_64.minisig'), 'agent Minisign signature');
    }
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
  assert.match(sums, /secmon-linux-x86_64\.minisig/);
  assert.match(sums, /secmon-agent-linux-x86_64\.minisig/);
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

test('Linux release staging takes CLI and agent from static musl builds', async () => {
  const root = await mkdtemp(join(tmpdir(), 'secmon-release-linux-stage-'));
  const target = 'x86_64-unknown-linux-gnu';
  const bundle = join(root, 'target', target, 'release', 'bundle', 'appimage');
  const musl = join(root, 'target', 'x86_64-unknown-linux-musl', 'release');
  await mkdir(bundle, { recursive: true });
  await mkdir(musl, { recursive: true });
  await writeFile(join(bundle, 'security-monitor.AppImage'), 'installer');
  await writeFile(join(bundle, 'security-monitor.AppImage.sig'), 'updater signature');
  await writeFile(join(musl, 'secmon'), 'static CLI');
  await writeFile(join(musl, 'secmon-agent'), 'static agent');

  const result = run('stage-assets.mjs', [target, 'linux-x86_64', 'linux', 'x86_64'], { cwd: root });
  assert.equal(result.status, 0, result.stderr);
  const output = join(root, 'target', 'release-out', 'linux-x86_64');
  assert.equal(await readFile(join(output, 'secmon-linux-x86_64'), 'utf8'), 'static CLI');
  assert.equal(await readFile(join(output, 'secmon-agent-linux-x86_64'), 'utf8'), 'static agent');
  assert.equal(JSON.parse(await readFile(join(output, 'linux-x86_64.updater.json'), 'utf8'))['linux-x86_64-appimage'].signature, 'updater signature');
});

test('universal macOS staging accepts a DMG without a duplicate CLI or updater metadata', async () => {
  const root = await mkdtemp(join(tmpdir(), 'secmon-release-universal-stage-'));
  const target = 'universal-apple-darwin';
  const bundle = join(root, 'target', target, 'release', 'bundle', 'dmg');
  await mkdir(bundle, { recursive: true });
  await writeFile(join(bundle, 'Security-Monitor.dmg'), 'universal installer');

  const result = run('stage-assets.mjs', [target, 'macos-universal', 'darwin', 'universal'], { cwd: root });
  assert.equal(result.status, 0, result.stderr);
  const output = join(root, 'target', 'release-out', 'macos-universal');
  assert.deepEqual(await readdir(output), ['security-monitor-macos-universal-Security-Monitor.dmg']);
});

test('nightly staging accepts unsigned desktop packages and omits updater metadata', async () => {
  const root = await mkdtemp(join(tmpdir(), 'secmon-release-nightly-stage-'));
  const target = 'x86_64-pc-windows-msvc';
  const bundle = join(root, 'target', target, 'release', 'bundle', 'nsis');
  const release = join(root, 'target', target, 'release');
  await mkdir(bundle, { recursive: true });
  await mkdir(release, { recursive: true });
  await writeFile(join(bundle, 'security-monitor-setup.exe'), 'unsigned installer');
  await writeFile(join(release, 'secmon.exe'), 'CLI');

  const result = run('stage-assets.mjs', [target, 'windows-x86_64', 'windows', 'x86_64', 'nightly'], { cwd: root });
  assert.equal(result.status, 0, result.stderr);
  const output = join(root, 'target', 'release-out', 'windows-x86_64');
  assert.equal(await readFile(join(output, 'security-monitor-windows-x86_64-security-monitor-setup.exe'), 'utf8'), 'unsigned installer');
  await assert.rejects(readFile(join(output, 'windows-x86_64.updater.json'), 'utf8'));
});

test('nightly checksum creation covers release assets and excludes updater metadata', async () => {
  const root = await mkdtemp(join(tmpdir(), 'secmon-release-nightly-checksums-'));
  const directory = join(root, 'release-linux');
  await mkdir(directory);
  await writeFile(join(directory, 'secmon-linux-x86_64'), 'CLI');
  await writeFile(join(directory, 'secmon-linux-x86_64.minisig'), 'signature');
  await writeFile(join(directory, 'linux-x86_64.updater.json'), '{}');

  await createChecksums(root);
  const checksums = await readFile(join(root, 'SHA256SUMS'), 'utf8');
  assert.match(checksums, /  release-linux\/secmon-linux-x86_64\n/);
  assert.match(checksums, /secmon-linux-x86_64\.minisig/);
  assert.doesNotMatch(checksums, /updater\.json/);
});

test('nightly publishing creates a prerelease and keeps it out of latest', async () => {
  const root = await mkdtemp(join(tmpdir(), 'secmon-release-nightly-publish-'));
  const directory = join(root, 'release-windows');
  await mkdir(directory);
  await writeFile(join(directory, 'installer.exe'), 'installer');
  await writeFile(join(directory, 'release.updater.json'), '{}');
  await writeFile(join(root, 'SHA256SUMS'), 'checksum');
  await writeFile(join(root, 'SHA256SUMS.minisig'), 'signature');
  const calls = [];
  await publishRelease(root, 'nightly', (args) => {
    calls.push(args);
    return { status: args[1] === 'view' ? 1 : 0 };
  });
  assert.equal(calls[0][1], 'view');
  assert.equal(calls[1][1], 'create');
  assert.ok(calls[1].includes('--prerelease'));
  assert.ok(calls[1].includes('--latest=false'));
  assert.ok(calls[1].some((asset) => typeof asset === 'string' && asset.endsWith('installer.exe')));
  assert.equal(calls[1].some((asset) => typeof asset === 'string' && asset.endsWith('latest.json')), false);
  assert.equal(calls[1].some((asset) => typeof asset === 'string' && asset.endsWith('.updater.json')), false);
});

test('updating an existing nightly release reapplies prerelease metadata', async () => {
  const root = await mkdtemp(join(tmpdir(), 'secmon-release-nightly-existing-'));
  const directory = join(root, 'release-linux');
  await mkdir(directory);
  await writeFile(join(directory, 'secmon'), 'CLI');
  await writeFile(join(root, 'SHA256SUMS'), 'checksum');
  await writeFile(join(root, 'SHA256SUMS.minisig'), 'signature');
  const calls = [];
  await publishRelease(root, 'nightly', (args) => {
    calls.push(args);
    return { status: args[1] === 'view' ? 0 : 0 };
  });
  assert.deepEqual(calls.map((args) => args[1]), ['view', 'upload', 'edit']);
  assert.ok(calls[2].includes('--prerelease'));
  assert.ok(calls[2].includes('--latest=false'));
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
