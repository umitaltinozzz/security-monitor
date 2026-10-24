import { copyFile, mkdir, readdir, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const sourceDirectory = resolve(scriptDirectory, '../..');
const contentDirectory = resolve(scriptDirectory, '../src/content/docs');
const publicPages = [
  'index.md',
  'architecture.md',
  'threat-model.md',
  'privacy.md',
  'data-sources.md',
  'scanners.md',
  'correlation.md',
  'drift.md',
  'orchestration.md',
  'agent-install.md',
  'deploy-id.md',
  'ai-providers.md',
  'local-mcp.md',
  'cli.md',
  'integrations.md',
  'contributing.md',
  'security.md',
];

await mkdir(contentDirectory, { recursive: true });
for (const entry of await readdir(contentDirectory)) {
  if (entry.endsWith('.md')) {
    await rm(resolve(contentDirectory, entry));
  }
}
for (const page of publicPages) {
  await copyFile(resolve(sourceDirectory, page), resolve(contentDirectory, page));
}
