import { mkdir, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

const [, , platform, outputPath] = process.argv;
if (!['windows', 'universal', 'nightly'].includes(platform) || !outputPath) {
  throw new Error('Expected a supported release mode and an output path.');
}

let config;
if (platform === 'windows') {
  const certificateThumbprint = process.env.SECMON_WINDOWS_CERTIFICATE_THUMBPRINT?.replaceAll(' ', '');
  if (!certificateThumbprint || !/^[A-Fa-f0-9]{40}$/.test(certificateThumbprint)) {
    throw new Error('The Windows signing certificate thumbprint is invalid.');
  }
  config = {
    bundle: {
      windows: {
        certificateThumbprint,
        digestAlgorithm: 'sha256',
        timestampUrl: 'http://timestamp.digicert.com',
      },
    },
  };
} else {
  config = { bundle: { createUpdaterArtifacts: false } };
}

await mkdir(dirname(outputPath), { recursive: true });
await writeFile(outputPath, `${JSON.stringify(config, null, 2)}\n`, { flag: 'wx' });
