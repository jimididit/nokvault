import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import test from 'node:test';

const readPage = (path) => readFile(new URL(`../dist/${path}`, import.meta.url), 'utf8');
const readSrc = (path) => readFile(new URL(`../${path}`, import.meta.url), 'utf8');

async function readCombinedStyles() {
  const html = await readPage('docs/commands/index.html');
  const assetsDir = new URL('../dist/_astro/', import.meta.url);
  const assetNames = await readdir(assetsDir);
  const cssChunks = await Promise.all(
    assetNames
      .filter((name) => name.endsWith('.css'))
      .map((name) => readFile(new URL(name, assetsDir), 'utf8')),
  );
  return [html, ...cssChunks].join('\n');
}

test('landing security posture avoids unsupported constant-time verification claims', async () => {
  const html = await readPage('index.html');
  const source = await readSrc('src/components/SecurityPosture.astro');

  assert.doesNotMatch(html, /constant-time verification/i);
  assert.doesNotMatch(source, /constant-time verification/i);
  assert.match(html, /AES-GCM tag verification|authenticity via AES-GCM/i);
});

test('code block language labels are not forced to uppercase', async () => {
  const source = await readSrc('src/components/CodeBlock.astro');
  const styles = await readCombinedStyles();

  assert.match(source, /\.code-block__lang\s*\{[^}]*text-transform:\s*none/s);
  assert.match(styles, /\.code-block__lang[^{]*\{[^}]*text-transform:\s*none/s);
});

test('inline code chips do not wrap mid-token on narrow viewports', async () => {
  const source = await readSrc('src/styles/global.css');
  const styles = await readCombinedStyles();

  assert.match(source, /:not\(pre\)\s*>\s*code[\s\S]*?white-space:\s*nowrap/s);
  assert.match(styles, /:not\(pre\)\s*>\s*code[^{]*\{[^}]*white-space:\s*nowrap/s);
});

test('best practices avoid implying password recovery material exists', async () => {
  const html = await readPage('docs/security/best-practices/index.html');

  assert.doesNotMatch(html, /password recovery material/i);
  assert.match(html, /credential backups separately from ciphertext/i);
  assert.match(html, /there is no password recovery/i);
});

test('docs search uses listbox option semantics for aria-selected', async () => {
  const html = await readPage('docs/index.html');
  const source = await readSrc('src/components/DocsSearch.astro');

  assert.match(html, /role="combobox"/);
  assert.match(html, /aria-controls="docs-search-results"/);
  assert.match(html, /<ul[^>]*id="docs-search-results"[^>]*role="listbox"/);
  assert.match(source, /setAttribute\(\s*['"]role['"]\s*,\s*['"]option['"]\s*\)/);
  assert.match(source, /aria-activedescendant/);
  assert.match(source, /aria-selected/);
  assert.match(source, /docs-search__icon/);
  assert.match(source, /justify-content:\s*space-between/);
  assert.match(html, /docs-search__field-icon|docs-search__icon/);
});

test('mobile docs backdrop styles are global so runtime nodes receive them', async () => {
  const source = await readSrc('src/components/Sidebar.astro');
  const styles = await readCombinedStyles();

  assert.match(source, /:global\(\.mobile-docs-nav__backdrop\)/);
  assert.match(styles, /\.mobile-docs-nav__backdrop[^{]*\{[^}]*position:\s*fixed/s);
  assert.match(styles, /\.mobile-docs-nav__backdrop[^{]*\{[^}]*display:\s*none/s);
  assert.match(source, /overflow-y:\s*scroll/);
  assert.match(source, /layoutOpenPanel|panel\.style\.maxHeight/);
  assert.match(source, /data-more-below|syncMoreBelow/);
  assert.match(source, /scrollbar-width:\s*thin/);
  assert.match(source, /data-mobile-docs-close/);
  assert.match(source, /mobile-docs-nav__close/);
  assert.match(styles, /mobile-docs-nav[^\n{]*\[open\][^{]*\{[^}]*position:\s*fixed/s);
  assert.match(styles, /mobile-docs-nav__panel[^\n{]*\{[^}]*overflow-y:\s*scroll/s);
});

test('article previous/next stay on one row at mobile widths', async () => {
  const source = await readSrc('src/components/ArticleNavigation.astro');
  const styles = await readCombinedStyles();

  assert.match(source, /grid-template-columns:\s*1fr 1fr/);
  assert.doesNotMatch(source, /grid-template-columns:\s*1fr\s*;/);
  assert.match(styles, /article-nav[^{]*\{[^}]*grid-template-columns:\s*1fr 1fr/s);
});

test('theme control is an icon toggle with sun and moon marks', async () => {
  const html = await readPage('index.html');
  const source = await readSrc('src/components/ThemeControl.astro');

  assert.match(html, /<button[^>]*data-theme-control/);
  assert.match(html, /theme-control__icon--sun/);
  assert.match(html, /theme-control__icon--moon/);
  assert.doesNotMatch(html, /name="color-theme"/);
  assert.match(source, /Switch to light theme|Switch to dark theme/);
  assert.match(source, /transition:/);
});
