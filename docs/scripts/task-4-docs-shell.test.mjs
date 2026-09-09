import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import test from 'node:test';
import { rankDocsSearch } from '../src/lib/docs-search.mjs';

const readPage = (path) => readFile(new URL(`../dist/${path}`, import.meta.url), 'utf8');

async function readCombinedStyles() {
  const html = await readPage('docs/installation/index.html');
  const assetsDir = new URL('../dist/_astro/', import.meta.url);
  const assetNames = await readdir(assetsDir);
  const cssChunks = await Promise.all(
    assetNames
      .filter((name) => name.endsWith('.css'))
      .map((name) => readFile(new URL(name, assetsDir), 'utf8')),
  );
  return [html, ...cssChunks].join('\n');
}

const NAV_GROUPS = ['Start', 'Core Operations', 'Automation', 'Security', 'Reference', 'Project'];

test('desktop and mobile docs navigation render all six groups with current-page markers', async () => {
  const html = await readPage('docs/installation/index.html');

  for (const group of NAV_GROUPS) {
    assert.match(html, new RegExp(group));
  }

  assert.match(html, /<details[^>]*class="[^"]*mobile-docs-nav[^"]*"/);
  assert.match(html, /<summary[^>]*>\s*Browse documentation\s*<\/summary>/);
  assert.match(
    html,
    /href="[^"]*docs\/installation\/?"[^>]*aria-current="page"/,
  );
  assert.doesNotMatch(html, /api\.github\.com/);
  assert.match(html, />\s*0\.3\.0\s*</);
});

test('docs search exposes dialog markup, serialized pages, and no-JS docs fallback', async () => {
  const html = await readPage('docs/index.html');

  assert.match(html, /<label[^>]*for="docs-search-input"[^>]*>\s*Search documentation\s*<\/label>/);
  assert.match(html, /<input[^>]*id="docs-search-input"[^>]*type="search"/);
  assert.match(html, /<p[^>]*id="docs-search-status"[^>]*role="status"[^>]*aria-live="polite"/);
  assert.match(html, /<ul[^>]*id="docs-search-results"/);
  assert.match(html, /id="docs-search-data"|data-docs-pages=/);
  assert.match(html, /"title"\s*:\s*"Installation"/);
  assert.match(html, /Watch and Schedule/);
  assert.match(html, /data-docs-search-trigger/);
  assert.match(html, /href="[^"]*docs\/"[^>]*data-docs-search-trigger|data-docs-search-trigger[^>]*href="[^"]*docs\//);
});

test('article chrome renders breadcrumbs, TOC, and previous/next links', async () => {
  const installation = await readPage('docs/installation/index.html');
  const basic = await readPage('docs/usage/basic/index.html');

  assert.match(installation, />\s*Home\s*</);
  assert.match(installation, />\s*Documentation\s*</);
  assert.match(installation, /aria-label="On this page"/);
  assert.match(installation, /href="#homebrew"/i);
  assert.match(installation, />\s*Previous\s*</);
  assert.match(installation, />\s*Next\s*</);
  assert.match(installation, /href="[^"]*docs\/"/);
  assert.match(installation, /href="[^"]*docs\/usage\/basic"/);

  assert.match(basic, /href="[^"]*docs\/installation"/);
  assert.match(basic, /href="[^"]*docs\/commands"/);
});

test('docs layout uses a three-region grid with sidebar and TOC collapse breakpoints', async () => {
  const styles = await readCombinedStyles();

  assert.match(styles, /docs-shell|article-shell/);
  assert.match(styles, /@media\s*\(\s*min-width:\s*1024px\s*\)/);
  assert.match(styles, /@media\s*\(\s*min-width:\s*1200px\s*\)/);
  assert.match(styles, /max-width:\s*(?:72ch|var\(--content-prose\))/);
});

test('WebSite structured data restores SearchAction to docs/?q= and keeps overview reachable', async () => {
  const landing = await readPage('index.html');
  const docs = await readPage('docs/index.html');

  assert.doesNotMatch(landing, /aggregateRating/);
  assert.match(landing, /"@type"\s*:\s*"SearchAction"/);
  assert.match(landing, /docs\/\?q=\{search_term_string\}/);
  assert.match(docs, /docs\/\?q=\{search_term_string\}/);
});

test('rankDocsSearch ranks exact title, title prefix, heading, then description matches', () => {
  const pages = [
    {
      group: 'Core Operations',
      title: 'Commands',
      href: '/docs/commands',
      description: 'Complete command and option reference.',
      headings: ['encrypt', 'Machine-readable output'],
    },
    {
      group: 'Start',
      title: 'Installation',
      href: '/docs/installation',
      description: 'Install a verified NokVault binary or build from source.',
      headings: ['Homebrew', 'Scoop'],
    },
    {
      group: 'Start',
      title: 'Basic Usage',
      href: '/docs/usage/basic',
      description: 'Encrypt, verify, and decrypt your first files and directories.',
      headings: ['Encrypt a file'],
    },
    {
      group: 'Reference',
      title: 'FAQ',
      href: '/docs/faq',
      description: 'Answers about encryption workflows.',
      headings: [],
    },
  ];

  const exact = rankDocsSearch(pages, 'installation');
  assert.equal(exact[0]?.title, 'Installation');

  const prefix = rankDocsSearch(pages, 'comm');
  assert.equal(prefix[0]?.title, 'Commands');

  const heading = rankDocsSearch(pages, 'homebrew');
  assert.equal(heading[0]?.title, 'Installation');

  const description = rankDocsSearch(pages, 'encryption workflows');
  assert.equal(description[0]?.title, 'FAQ');

  assert.deepEqual(rankDocsSearch(pages, ''), []);
  assert.deepEqual(rankDocsSearch(pages, '   '), []);
});
