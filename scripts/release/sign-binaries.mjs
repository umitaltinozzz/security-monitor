import { spawnSync } from 'node:child_process';
import { lstat, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { basename, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const signableBinary = /^secmon(?:-agent)?-(?:windows-x86_64|macos-x86_64|macos-aarch64|linux-x86_64)(?:\.exe)?$/;

function runMinisign(run, args, action) {
  const result = run('minisign', args, { stdio: 'ignore', windowsHide: true });
  if (result.error || result.status !== 0) throw new Error(`Minisign failed to ${action} a release binary.`);
}

async function signFiles(files, comment, { env = process.env, run = spawnSync } = {}) {
  const privateKey = env.MINISIGN_PRIVATE_KEY?.trim();
  const publicKey = env.MINISIGN_PUBLIC_KEY?.trim();
  if (!privateKey || !publicKey) throw new Error('Minisign release key configuration is missing.');
  if (files.length === 0) throw new Error('No release files were selected for minisign signing.');

  const temporaryDirectory = await mkdtemp(join(tmpdir(), 'security-monitor-minisign-'));
  const privateKeyPath = join(temporaryDirectory, 'minisign.key');
  const publicKeyPath = join(temporaryDirectory, 'minisign.pub');
  try {
    await writeFile(privateKeyPath, `${privateKey}\n`, { flag: 'wx', mode: 0o600 });
    await writeFile(publicKeyPath, `${publicKey}\n`, { flag: 'wx', mode: 0o600 });

    for (const file of files) {
      const fileInfo = await lstat(file).catch(() => null);
      if (!fileInfo?.isFile() || fileInfo.isSymbolicLink()) throw new Error('A release signing input is not a regular file.');
      const signature = `${file}.minisig`;
      if (await lstat(signature).then(() => true, () => false)) {
        throw new Error('A release signature already exists.');
      }
      runMinisign(run, [
        '-S', '-W', '-s', privateKeyPath, '-m', file, '-x', signature,
        '-t', `${comment}: ${basename(file)}`,
      ], 'sign');

      const signatureInfo = await lstat(signature).catch(() => null);
      if (!signatureInfo?.isFile() || signatureInfo.size === 0) {
        throw new Error('Minisign did not create a release signature.');
      }
      runMinisign(run, ['-V', '-m', file, '-x', signature, '-p', publicKeyPath, '-q'], 'verify');
    }
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true });
  }
}

export async function signReleaseBinaries(directory, options = {}) {
  const root = resolve(directory);
  const entries = await readdir(root, { withFileTypes: true });
  const binaries = entries
    .filter((entry) => entry.isFile() && signableBinary.test(entry.name))
    .map((entry) => join(root, entry.name));
  if (binaries.length === 0) throw new Error('No CLI or agent binaries were staged for minisign signing.');
  await signFiles(binaries, 'Security Monitor release binary', options);
}

export async function signReleaseChecksums(directory, options = {}) {
  const root = resolve(directory);
  await signFiles([join(root, 'SHA256SUMS')], 'Security Monitor release checksums', options);
}

const scriptPath = fileURLToPath(import.meta.url);
if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  const directory = process.argv[2];
  if (!directory) throw new Error('A staged release artifact directory is required.');
  if (process.argv[3] === '--checksums') await signReleaseChecksums(directory);
  else if (process.argv.length > 3) throw new Error('The release signing mode is invalid.');
  else await signReleaseBinaries(directory);
}
