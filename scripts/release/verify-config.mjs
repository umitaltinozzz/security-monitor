import { appendFile } from 'node:fs/promises';

const [, , platform] = process.argv;
const required = [
  'SECMON_UPDATE_PUBLIC_KEY',
  'TAURI_SIGNING_PRIVATE_KEY',
  'TAURI_SIGNING_PRIVATE_KEY_PASSWORD',
  'MINISIGN_PRIVATE_KEY',
  'MINISIGN_PUBLIC_KEY',
];
const codeSigning = {
  windows: ['WINDOWS_CERTIFICATE', 'WINDOWS_CERTIFICATE_PASSWORD', 'SECMON_WINDOWS_CERTIFICATE_THUMBPRINT'],
  darwin: [
    'APPLE_CERTIFICATE', 'APPLE_CERTIFICATE_PASSWORD', 'APPLE_SIGNING_IDENTITY', 'APPLE_ID',
    'APPLE_PASSWORD', 'APPLE_TEAM_ID', 'APPLE_API_ISSUER', 'APPLE_API_KEY',
    'APPLE_API_KEY_CONTENT', 'KEYCHAIN_PASSWORD',
  ],
  linux: [],
};
if (!Object.hasOwn(codeSigning, platform ?? '')) throw new Error('Release platform is invalid.');

const isSet = (name) => Boolean(process.env[name]?.trim());

// Updater and minisign signatures protect every download and update, so they are never optional.
const missing = required.filter((name) => !isSet(name));
if (missing.length) throw new Error(`Missing release signing configuration: ${missing.join(', ')}`);

const platformNames = codeSigning[platform];
const present = platformNames.filter(isSet);
// A partly configured certificate is a configuration mistake, not a request for an unsigned build.
if (present.length > 0 && present.length < platformNames.length) {
  const absent = platformNames.filter((name) => !isSet(name));
  throw new Error(`Incomplete ${platform} code-signing configuration: ${absent.join(', ')}`);
}

let status = 'not_applicable';
if (platformNames.length > 0) status = present.length === platformNames.length ? 'signed' : 'unsigned';
if (status === 'unsigned') {
  console.log(`::warning::No ${platform} code-signing certificate is configured; this platform's packages will be unsigned.`);
}
if (process.env.GITHUB_OUTPUT) await appendFile(process.env.GITHUB_OUTPUT, `code_signing=${status}\n`);
console.log(`Code signing for ${platform}: ${status}`);
