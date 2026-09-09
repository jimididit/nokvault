import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const readPage = (path) => readFile(new URL(`../dist/${path}`, import.meta.url), 'utf8');

test('every layout renders the shared accessible shell and theme initializer', async () => {
  for (const path of ['index.html', 'docs/index.html']) {
    const html = await readPage(path);

    assert.match(html, /href="#main-content"[^>]*>Skip to content</);
    assert.match(html, /<header[^>]*class="site-header"/);
    assert.match(html, /<main[^>]*id="main-content"[^>]*tabindex="-1"/);
    assert.match(html, /<footer[^>]*class="site-footer"/);
    assert.match(html, /data-theme-control/);
    assert.match(html, /nokvault-theme/);
    assert.match(html, /dataset\.themePreference/);
  }
});

test('rendered shell removes GitHub Buttons and unsupported metadata', async () => {
  const html = await readPage('index.html');

  assert.doesNotMatch(html, /buttons\.github\.io/);
  assert.doesNotMatch(html, /aggregateRating|SearchAction/);
  assert.match(html, /property="og:site_name" content="NokVault"/);
  assert.match(html, /name="theme-color"[^>]*media="\(prefers-color-scheme: light\)"/);
  assert.match(html, /name="theme-color"[^>]*media="\(prefers-color-scheme: dark\)"/);
});
