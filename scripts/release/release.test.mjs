import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { signReleaseBinaries, signReleaseChecksums } from './sign-binaries.mjs';
import { collectRelease, releaseArgs } from './publish.mjs';

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

test('release config adds updater settings for every platform', async () => {
  const root = await mkdtemp(join(tmpdir(), 'secmon-release-config-'));
  const publicKey = 'updater-public-fixture';
  const endpoint = 'https://github.com/umitaltinozzz/security-monitor/releases/latest/download/latest.json';

  for (const platform of ['windows', 'darwin', 'linux']) {
    const output = join(root, platform, 'tauri.release.json');
    const env = { SECMON_UPDATE_PUBLIC_KEY: publicKey };
    if (platform === 'windows') {
      env.SECMON_CODE_SIGNING = 'signed';
      env.SECMON_WINDOWS_CERTIFICATE_THUMBPRINT = 'ab'.repeat(20);
    }
    const result = run('write-tauri-config.mjs', [platform, output], { cwd: root, env });
    assert.equal(result.status, 0, result.stderr);
    const config = JSON.parse(await readFile(output, 'utf8'));
    assert.equal(config.plugins.updater.pubkey, publicKey);
    assert.deepEqual(config.plugins.updater.endpoints, [endpoint]);
    if (platform === 'windows') {
      assert.equal(config.bundle.windows.digestAlgorithm, 'sha256');
      assert.equal(config.bundle.windows.certificateThumbprint, 'ab'.repeat(20));
    } else {
      assert.equal(config.bundle, undefined);
    }
    assert.equal(JSON.stringify(config).includes('PASSWORD'), false);
  }
});

test('unsigned Windows release config keeps updater settings without a code-signing overlay', async () => {
  const root = await mkdtemp(join(tmpdir(), 'secmon-release-config-'));
  const output = join(root, 'target', 'tauri.release.json');
  const result = run('write-tauri-config.mjs', ['windows', output], {
    cwd: root,
    env: { SECMON_UPDATE_PUBLIC_KEY: 'updater-public-fixture', SECMON_CODE_SIGNING: 'unsigned' },
  });
  assert.equal(result.status, 0, result.stderr);
  const config = JSON.parse(await readFile(output, 'utf8'));
  assert.equal(config.plugins.updater.pubkey, 'updater-public-fixture');
  assert.equal(config.bundle, undefined);
});

test('release config requires the updater public key and valid Windows signing status', async () => {
  const root = await mkdtemp(join(tmpdir(), 'secmon-release-config-'));
  const output = join(root, 'target', 'tauri.release.json');
  const missingKey = run('write-tauri-config.mjs', ['linux', output], { cwd: root, env: { SECMON_UPDATE_PUBLIC_KEY: '' } });
  assert.notEqual(missingKey.status, 0);
  assert.match(missingKey.stderr, /Tauri updater public key is missing/);

  const invalidWindows = run('write-tauri-config.mjs', ['windows', output], {
    cwd: root,
    env: { SECMON_UPDATE_PUBLIC_KEY: 'updater-public-fixture', SECMON_CODE_SIGNING: 'signed' },
  });
  assert.notEqual(invalidWindows.status, 0);
  assert.match(invalidWindows.stderr, /Windows signing certificate thumbprint is invalid/);
});

test('signed releases require minisign keys without echoing secret values', () => {
  const common = {
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

test('CLI and agent binaries receive minisign signatures that are verified before staging', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'secmon-minisign-binaries-'));
  const cli = join(directory, 'secmon-windows-x86_64.exe');
  const agent = join(directory, 'secmon-agent-linux-x86_64');
  const armAgent = join(directory, 'secmon-agent-linux-aarch64');
  const packageFile = join(directory, 'security-monitor-windows-x86_64-setup.msi');
  await Promise.all([
    writeFile(cli, 'cli fixture'),
    writeFile(agent, 'agent fixture'),
    writeFile(armAgent, 'arm agent fixture'),
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

  assert.equal(calls.filter((args) => args[0] === '-S').length, 3);
  assert.equal(calls.filter((args) => args[0] === '-V').length, 3);
  assert.ok(calls.every((args) => !args.includes(privateKey)));
  assert.ok((await readFile(`${cli}.minisig`, 'utf8')).length > 0);
  assert.ok((await readFile(`${agent}.minisig`, 'utf8')).length > 0);
  assert.ok((await readFile(`${armAgent}.minisig`, 'utf8')).length > 0);
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
    await writeFile(join(directory, `${artifact}.signing.json`), JSON.stringify({ codeSigning: 'unsigned' }));
    if (artifact === 'linux-x86_64') {
      await writeFile(join(directory, 'secmon-linux-x86_64'), 'CLI binary');
      await writeFile(join(directory, 'secmon-linux-x86_64.minisig'), 'CLI Minisign signature');
      await writeFile(join(directory, 'secmon-agent-linux-x86_64'), 'agent binary');
      await writeFile(join(directory, 'secmon-agent-linux-x86_64.minisig'), 'agent Minisign signature');
      await writeFile(join(directory, 'secmon-agent-linux-aarch64'), 'ARM agent binary');
      await writeFile(join(directory, 'secmon-agent-linux-aarch64.minisig'), 'ARM agent Minisign signature');
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
  assert.match(sums, /secmon-agent-linux-aarch64\.minisig/);
  assert.doesNotMatch(sums, /\.signing\.json/);
  assert.match(sums, /^[0-9a-f]{64}  secmon-agent-linux-aarch64$/m);
  assert.doesNotMatch(sums, /release-linux-x86_64\//);
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

  const result = run('stage-assets.mjs', [target, 'windows-x86_64', 'windows', 'x86_64'], {
    cwd: root,
    env: { SECMON_CODE_SIGNING: 'unsigned' },
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /ZIP updater bundles are outside the supported release formats/);
});

test('Linux asset staging includes x86_64 and aarch64 agent binaries', async () => {
  const root = await mkdtemp(join(tmpdir(), 'secmon-release-linux-stage-'));
  const target = 'x86_64-unknown-linux-gnu';
  const releaseDirectory = join(root, 'target', target, 'release');
  const bundle = join(releaseDirectory, 'bundle', 'appimage');
  await mkdir(bundle, { recursive: true });
  await mkdir(join(root, 'target', 'x86_64-unknown-linux-musl', 'release'), { recursive: true });
  await mkdir(join(root, 'target', 'aarch64-unknown-linux-musl', 'release'), { recursive: true });
  await writeFile(join(bundle, 'security-monitor.AppImage'), 'desktop package');
  await writeFile(join(bundle, 'security-monitor.AppImage.sig'), 'updater signature');
  await writeFile(join(releaseDirectory, 'secmon'), 'CLI binary');
  await writeFile(join(root, 'target', 'x86_64-unknown-linux-musl', 'release', 'secmon-agent'), 'x86 agent');
  await writeFile(join(root, 'target', 'aarch64-unknown-linux-musl', 'release', 'secmon-agent'), 'ARM agent');

  const result = run('stage-assets.mjs', [target, 'linux-x86_64', 'linux', 'x86_64'], {
    cwd: root,
    env: { SECMON_CODE_SIGNING: 'not_applicable' },
  });
  assert.equal(result.status, 0, result.stderr);
  const output = join(root, 'target', 'release-out', 'linux-x86_64');
  assert.equal(await readFile(join(output, 'secmon-agent-linux-x86_64'), 'utf8'), 'x86 agent');
  assert.equal(await readFile(join(output, 'secmon-agent-linux-aarch64'), 'utf8'), 'ARM agent');
  const signing = JSON.parse(await readFile(join(output, 'linux-x86_64.signing.json'), 'utf8'));
  assert.equal(signing.codeSigning, 'not_applicable');
});

test('asset staging requires a code-signing status that fits the platform', async () => {
  const root = await mkdtemp(join(tmpdir(), 'secmon-release-stage-signing-'));
  const target = 'x86_64-pc-windows-msvc';
  for (const codeSigning of ['', 'not_applicable', 'signed-ish']) {
    const result = run('stage-assets.mjs', [target, 'windows-x86_64', 'windows', 'x86_64'], {
      cwd: root,
      env: { SECMON_CODE_SIGNING: codeSigning },
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /code-signing status is invalid/);
  }
});

const releaseKeys = {
  SECMON_UPDATE_PUBLIC_KEY: 'updater-public-fixture',
  TAURI_SIGNING_PRIVATE_KEY: 'updater-private-fixture',
  TAURI_SIGNING_PRIVATE_KEY_PASSWORD: 'updater-password-fixture',
  MINISIGN_PRIVATE_KEY: 'minisign-private-fixture',
  MINISIGN_PUBLIC_KEY: 'minisign-public-fixture',
};
const windowsCertificate = {
  WINDOWS_CERTIFICATE: 'certificate-fixture',
  WINDOWS_CERTIFICATE_PASSWORD: 'certificate-password-fixture',
  SECMON_WINDOWS_CERTIFICATE_THUMBPRINT: 'ab'.repeat(20),
};

test('a platform without a code-signing certificate builds unsigned and reports it', async () => {
  const output = join(await mkdtemp(join(tmpdir(), 'secmon-release-output-')), 'github-output');
  const env = { ...releaseKeys, GITHUB_OUTPUT: output };
  for (const name of Object.keys(windowsCertificate)) env[name] = '';
  const result = run('verify-config.mjs', ['windows'], { env });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /::warning::/);
  assert.equal(await readFile(output, 'utf8'), 'code_signing=unsigned\n');
});

test('a complete certificate reports a signed platform', async () => {
  const output = join(await mkdtemp(join(tmpdir(), 'secmon-release-output-')), 'github-output');
  const result = run('verify-config.mjs', ['windows'], {
    env: { ...releaseKeys, ...windowsCertificate, GITHUB_OUTPUT: output },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(await readFile(output, 'utf8'), 'code_signing=signed\n');
});

test('a partial code-signing configuration fails instead of building unsigned', () => {
  const result = run('verify-config.mjs', ['windows'], {
    env: { ...releaseKeys, ...windowsCertificate, WINDOWS_CERTIFICATE_PASSWORD: '', GITHUB_OUTPUT: '' },
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Incomplete windows code-signing configuration: WINDOWS_CERTIFICATE_PASSWORD/);
  assert.equal(result.stderr.includes('fixture'), false);
});

test('pre-releases stay out of the updater feed and unsigned packages are disclosed', async () => {
  const root = await mkdtemp(join(tmpdir(), 'secmon-release-publish-'));
  const records = { 'windows-x86_64': 'unsigned', 'macos-aarch64': 'signed', 'linux-x86_64': 'not_applicable' };
  for (const [artifact, codeSigning] of Object.entries(records)) {
    const directory = join(root, `release-${artifact}`);
    await mkdir(directory);
    await writeFile(join(directory, `${artifact}.signing.json`), JSON.stringify({ codeSigning }));
    await writeFile(join(directory, `${artifact}.updater.json`), '{}');
    await writeFile(join(directory, `secmon-${artifact}`), 'binary');
  }

  const release = await collectRelease(root, 'v0.1.0-1');
  assert.equal(release.prerelease, true);
  assert.ok(release.assets.every((asset) => !/\.(signing|updater)\.json$/.test(asset)));
  assert.ok(release.assets.some((asset) => asset.endsWith('latest.json')));
  assert.match(release.notes, /Unsigned packages:\*\* Windows x86_64\./);
  assert.doesNotMatch(release.notes, /macOS aarch64|Linux x86_64/);
  const args = releaseArgs('v0.1.0-1', release);
  assert.ok(args.includes('--prerelease'));
  assert.ok(args.includes('--latest=false'));

  const stable = releaseArgs('v0.1.0', await collectRelease(root, 'v0.1.0'));
  assert.equal(stable.includes('--prerelease'), false);
  await assert.rejects(collectRelease(root, '0.1.0'), /semantic version/);
});
