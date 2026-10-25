import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://umitaltinozzz.github.io',
  base: '/security-monitor',
  integrations: [
    starlight({
      title: 'Security Monitor',
      description: 'Local-first security monitoring for software projects and deployed environments.',
      logo: {
        light: './src/assets/logo-light.png',
        dark: './src/assets/logo-dark.png',
        alt: 'Security Monitor logo',
      },
      favicon: '/favicon.png',
      customCss: ['./src/styles/custom.css'],
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/umitaltinozzz/security-monitor' },
      ],
      head: [
        {
          tag: 'meta',
          attrs: { property: 'og:image', content: 'https://umitaltinozzz.github.io/security-monitor/social-preview.png' },
        },
        { tag: 'meta', attrs: { name: 'twitter:card', content: 'summary_large_image' } },
      ],
      defaultLocale: 'root',
      locales: {
        root: { label: 'English', lang: 'en' },
      },
      sidebar: [
        { label: 'Overview', link: '/' },
        { label: 'Getting started', link: '/getting-started/' },
        {
          label: 'Product',
          items: [
            { label: 'Architecture', link: '/architecture/' },
            { label: 'Threat model', link: '/threat-model/' },
            { label: 'Privacy', link: '/privacy/' },
            { label: 'Data sources', link: '/data-sources/' },
            { label: 'Scanner adapters', link: '/scanners/' },
            { label: 'Finding correlation', link: '/correlation/' },
            { label: 'Repository-to-production drift', link: '/drift/' },
            { label: 'Scan orchestration', link: '/orchestration/' },
          ],
        },
        {
          label: 'Guides',
          items: [
            { label: 'Linux agent', link: '/agent-install/' },
            { label: 'Deploy ID', link: '/deploy-id/' },
            { label: 'AI providers', link: '/ai-providers/' },
            { label: 'Local MCP', link: '/local-mcp/' },
            { label: 'CLI', link: '/cli/' },
            { label: 'Coding-agent integrations', link: '/integrations/' },
            { label: 'Shared local memory', link: '/shared-memory/' },
            { label: 'Signed releases and updates', link: '/release/' },
            { label: 'Performance budgets', link: '/performance/' },
          ],
        },
        {
          label: 'Project',
          items: [
            { label: 'Contributing', link: '/contributing/' },
            { label: 'Security policy', link: '/security/' },
          ],
        },
      ],
    }),
  ],
});
