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
});

test('mobile docs backdrop styles are global so runtime nodes receive them', async () => {
  const source = await readSrc('src/components/Sidebar.astro');
  const styles = await readCombinedStyles();

  assert.match(source, /:global\(\.mobile-docs-nav__backdrop\)/);
  assert.match(styles, /\.mobile-docs-nav__backdrop[^{]*\{[^}]*position:\s*fixed/s);
  assert.match(styles, /\.mobile-docs-nav__backdrop[^{]*\{[^}]*display:\s*none/s);
});
