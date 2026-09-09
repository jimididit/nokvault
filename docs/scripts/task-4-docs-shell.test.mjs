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
  assert.match(html, /Browse documentation/);
  assert.match(html, /data-mobile-docs-close/);
  assert.match(html, /aria-label="Close documentation menu"/);
  assert.match(
    html,
    /href="[^"]*docs\/installation\/?"[^>]*aria-current="page"/,
  );
  assert.doesNotMatch(html, /api\.github\.com/);
  assert.match(html, />\s*0\.4\.0\s*</);
});

test('enhanced mobile docs nav dismisses via a dedicated backdrop target, not ::before inside details', async () => {
  const source = await readFile(new URL('../src/components/Sidebar.astro', import.meta.url), 'utf8');
  const html = await readPage('docs/installation/index.html');
  const styles = await readCombinedStyles();

  // No-JS foundation stays details/summary.
  assert.match(html, /<details[^>]*data-mobile-docs-nav/);
  assert.match(html, /Browse documentation/);
  assert.match(html, /data-mobile-docs-close/);
  assert.match(source, /data-mobile-docs-close/);
  assert.match(source, /mobile-docs-nav__close/);
  assert.match(source, /closeButton\.addEventListener\(\s*['"]click['"]/);

  // Dimmer must be a real backdrop target (element or enhancement-created), not details::before.
  assert.doesNotMatch(source, /mobile-docs-nav\[[^\]]*\]\[open\]::before/);
  assert.doesNotMatch(styles, /mobile-docs-nav[^{]*\[open\]::before|mobile-docs-nav\[open\]::before/);
  assert.match(source, /data-mobile-docs-backdrop|mobile-docs-nav__backdrop/);

  // Runtime-created backdrop must use :global styles; Astro scoping would otherwise miss it.
  assert.match(source, /:global\(\.mobile-docs-nav__backdrop\)/);
  assert.match(source, /:global\(\.mobile-docs-nav__backdrop\.is-visible\)|:global\(\.mobile-docs-nav__backdrop\.is-visible\)/);
  assert.match(source, /document\.body\.appendChild\(\s*backdrop\s*\)/);
  assert.match(styles, /\.mobile-docs-nav__backdrop[^{]*\{[^}]*display:\s*none/s);
  assert.match(styles, /\.mobile-docs-nav__backdrop[^{]*\{[^}]*position:\s*fixed/s);
  assert.doesNotMatch(source, /mobile-docs-nav\[data-enhanced='true'\]\[open\] \.mobile-docs-nav__backdrop/);

  // Backdrop click must close; relying only on !root.contains cannot dismiss a ::before painted on root.
  assert.match(source, /data-mobile-docs-backdrop/);
  assert.match(source, /backdrop\.addEventListener\(\s*['"]click['"][\s\S]{0,80}close\s*\(/);
  assert.match(source, /Escape/);
  assert.match(source, /restoreFocus/);
  assert.match(source, /overflow/);
  assert.match(source, /overflow-y:\s*scroll/);
  assert.match(source, /position:\s*fixed/);
  assert.match(source, /bottom:\s*max\(12px/);
  assert.match(source, /layoutOpenPanel/);
  assert.match(source, /panel\.style\.maxHeight/);
  assert.match(source, /document\.body\.appendChild\(\s*backdrop\s*\)/);
});

test('docs search exposes dialog markup, serialized pages, and no-JS docs fallback', async () => {
  const html = await readPage('docs/index.html');

  assert.match(html, /<label[^>]*for="docs-search-input"[^>]*>\s*Search documentation\s*<\/label>/);
  assert.match(html, /<input[^>]*id="docs-search-input"[^>]*type="search"/);
  assert.match(html, /role="combobox"/);
  assert.match(html, /aria-controls="docs-search-results"/);
  assert.match(html, /<p[^>]*id="docs-search-status"[^>]*role="status"[^>]*aria-live="polite"/);
  assert.match(html, /<ul[^>]*id="docs-search-results"[^>]*role="listbox"/);
  assert.match(html, /id="docs-search-data"|data-docs-pages=/);
  assert.match(html, /"title"\s*:\s*"Installation"/);
  assert.match(html, /Watch and Schedule/);
  assert.match(html, /data-docs-search-trigger/);
  assert.match(html, /href="[^"]*docs\/"[^>]*data-docs-search-trigger|data-docs-search-trigger[^>]*href="[^"]*docs\//);
  assert.match(html, /docs-search__icon/);
  assert.match(html, /docs-search__field/);
  assert.match(html, /circle[^>]*cx="11"[^>]*cy="11"[^>]*r="7"/);
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
