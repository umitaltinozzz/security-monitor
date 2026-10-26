import { mkdir, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

const [, , platform, outputPath] = process.argv;
if (!['windows', 'darwin', 'linux'].includes(platform ?? '') || !outputPath) {
  throw new Error('Expected a release platform and an output path.');
}

const publicKey = process.env.SECMON_UPDATE_PUBLIC_KEY?.trim();
if (!publicKey) {
  throw new Error('The Tauri updater public key is missing.');
}

const config = {
  plugins: {
    updater: {
      pubkey: publicKey,
      endpoints: ['https://github.com/umitaltinozzz/security-monitor/releases/latest/download/latest.json'],
    },
  },
};

if (platform === 'windows') {
  const codeSigning = process.env.SECMON_CODE_SIGNING;
  if (!['signed', 'unsigned'].includes(codeSigning ?? '')) {
    throw new Error('The Windows code-signing status is invalid.');
  }

  if (codeSigning === 'signed') {
    const certificateThumbprint = process.env.SECMON_WINDOWS_CERTIFICATE_THUMBPRINT?.replaceAll(' ', '');
    if (!certificateThumbprint || !/^[A-Fa-f0-9]{40}$/.test(certificateThumbprint)) {
      throw new Error('The Windows signing certificate thumbprint is invalid.');
    }
    config.bundle = {
      windows: {
        certificateThumbprint,
        digestAlgorithm: 'sha256',
        timestampUrl: 'http://timestamp.digicert.com',
      },
    };
  }
}

await mkdir(dirname(outputPath), { recursive: true });
await writeFile(outputPath, `${JSON.stringify(config, null, 2)}\n`, { flag: 'wx' });
