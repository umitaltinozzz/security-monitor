const [, , platform] = process.argv;
const releaseTag = process.env.RELEASE_TAG;
const nightly = releaseTag === 'nightly';
if (!['windows', 'darwin', 'linux'].includes(platform)) throw new Error('Release platform is invalid.');
if (!nightly && !/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(releaseTag ?? '')) {
  throw new Error('Release tag must be nightly or a semantic version beginning with v.');
}

const required = ['MINISIGN_PRIVATE_KEY', 'MINISIGN_PUBLIC_KEY'];
if (!nightly) required.push(
  'SECMON_UPDATE_PUBLIC_KEY',
  'TAURI_SIGNING_PRIVATE_KEY',
  'TAURI_SIGNING_PRIVATE_KEY_PASSWORD',
);

const missing = required.filter((name) => !process.env[name]?.trim());
if (!nightly && platform === 'windows') {
  for (const name of ['WINDOWS_CERTIFICATE', 'WINDOWS_CERTIFICATE_PASSWORD', 'SECMON_WINDOWS_CERTIFICATE_THUMBPRINT']) {
    if (!process.env[name]?.trim()) missing.push(name);
  }
}
if (!nightly && platform === 'darwin') {
  for (const name of [
    'APPLE_CERTIFICATE', 'APPLE_CERTIFICATE_PASSWORD', 'APPLE_SIGNING_IDENTITY', 'APPLE_ID',
    'APPLE_PASSWORD', 'APPLE_TEAM_ID', 'APPLE_API_ISSUER', 'APPLE_API_KEY',
    'APPLE_API_KEY_CONTENT', 'KEYCHAIN_PASSWORD',
  ]) {
    if (!process.env[name]?.trim()) missing.push(name);
  }
}
if (missing.length) throw new Error(`Missing release signing configuration: ${missing.join(', ')}`);
