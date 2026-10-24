import { mkdir, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

const [, , platform, outputPath] = process.argv;
if (platform !== 'windows' || !outputPath) {
  throw new Error('Expected the Windows platform and an output path.');
}

const certificateThumbprint = process.env.SECMON_WINDOWS_CERTIFICATE_THUMBPRINT?.replaceAll(' ', '');
if (!certificateThumbprint || !/^[A-Fa-f0-9]{40}$/.test(certificateThumbprint)) {
  throw new Error('The Windows signing certificate thumbprint is invalid.');
}

await mkdir(dirname(outputPath), { recursive: true });
await writeFile(outputPath, `${JSON.stringify({
  bundle: {
    windows: {
      certificateThumbprint,
      digestAlgorithm: 'sha256',
      timestampUrl: 'http://timestamp.digicert.com',
    },
  },
}, null, 2)}\n`, { flag: 'wx' });
