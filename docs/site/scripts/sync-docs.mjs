import { mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const sourceDirectory = resolve(scriptDirectory, '../..');
const contentDirectory = resolve(scriptDirectory, '../src/content/docs');
const publicPages = [
  'index.md',
  'feature-status.md',
  'roadmap.md',
  'getting-started.md',
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
  'shared-memory.md',
  'release.md',
  'performance.md',
  'contributing.md',
  'security.md',
];

await mkdir(contentDirectory, { recursive: true });
for (const entry of await readdir(contentDirectory)) {
  if (entry.endsWith('.md')) {
    await rm(resolve(contentDirectory, entry));
  }
}
// Source pages link to each other as `page.md` so they work on GitHub. The site serves each page
// at `/<page>/`, so those links are rewritten; links to files outside the site stay untouched.
const sitePages = new Set(publicPages.map((page) => page.replace(/\.md$/, '')));
function rewriteLinks(markdown, page) {
  const prefix = page === 'index.md' ? './' : '../';
  return markdown.replace(/\]\(([a-z0-9-]+)\.md(#[^)]*)?\)/g, (match, name, anchor = '') =>
    sitePages.has(name) ? `](${name === 'index' ? prefix : `${prefix}${name}/`}${anchor})` : match,
  );
}

for (const page of publicPages) {
  const markdown = await readFile(resolve(sourceDirectory, page), 'utf8');
  await writeFile(resolve(contentDirectory, page), rewriteLinks(markdown, page));
}
