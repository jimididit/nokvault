import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

async function readDocsPagesMeta() {
  const source = await readFile(new URL('../src/data/site.ts', import.meta.url), 'utf8');
  const block = source.match(/export const DOCS_PAGES = \[([\s\S]*?)\] as const;/);
  assert.ok(block, 'DOCS_PAGES export must exist');

  const pages = [];
  for (const match of block[1].matchAll(
    /\{\s*group:\s*'([^']+)'\s*,\s*title:\s*'([^']+)'\s*,\s*href:\s*'([^']+)'\s*,\s*description:\s*'([^']*)'\s*,\s*headings:\s*\[([^\]]*)\]\s*\}/g,
  )) {
    const headings = [...match[5].matchAll(/'([^']+)'/g)].map((m) => m[1]);
    pages.push({
      group: match[1],
      title: match[2],
      href: match[3],
      description: match[4],
      headings,
    });
  }
  return pages;
}

function headingId(heading) {
  return heading
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, '')
    .replace(/[\s_]+/g, '-')
    .replace(/-+/g, '-');
}

const readPage = (path) => readFile(new URL(`../dist/${path}`, import.meta.url), 'utf8');
const readSrc = (path) => readFile(new URL(`../${path}`, import.meta.url), 'utf8');

const BANNED_CLASS_FRAGMENTS = [
  'prose-invert',
  'text-dark-',
  'bg-dark-',
  'border-dark-',
  'text-blue-',
  'grid md:',
  'space-y-',
  'mb-',
  'mt-',
  'px-',
  'py-',
  'rounded-',
];

const TASK_ROUTES = [
  'docs/security/index.html',
  'docs/security/best-practices/index.html',
  'docs/faq/index.html',
  'docs/changelog/index.html',
  'docs/contributing/index.html',
  'docs/license/index.html',
];

const MIT_LICENSE = `MIT License

Copyright (c) 2024 Nokvault Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`;

test('security overview uses DOCS_PAGES anchors and rewritten behavior claims', async () => {
  const pages = await readDocsPagesMeta();
  const security = pages.find((page) => page.href === '/docs/security');
  assert.ok(security);
  const html = await readPage('docs/security/index.html');

  for (const heading of security.headings) {
    assert.match(html, new RegExp(`id=["']${headingId(heading)}["']`), `security missing #${headingId(heading)}`);
  }

  assert.match(html, /AES-256-GCM provides confidentiality and integrity/i);
  assert.match(html, /does not establish author identity/i);
  assert.match(html, /format-?v2|format v2/i);
  assert.match(html, /Argon2id/i);
  assert.match(html, /best-effort/i);
  assert.match(html, /swap|crash dumps|runtime behavior/i);
  assert.match(html, /salts? and nonces?/i);
  assert.match(html, /not descriptor-relative race protection|descriptor-relative/i);
  assert.match(html, /SSD|snapshots|copy-on-write/i);
  assert.doesNotMatch(html, /Ensures data came from the original source/i);
  assert.doesNotMatch(html, /constant-time operations for:\s*<\/p>\s*<ul[^>]*>[\s\S]*Password comparison/i);
  assert.doesNotMatch(html, /Nokvault(?![^<]*Contributors)/);
});

test('best practices keep credential guidance and DOCS_PAGES anchors', async () => {
  const pages = await readDocsPagesMeta();
  const best = pages.find((page) => page.href === '/docs/security/best-practices');
  assert.ok(best);
  const html = await readPage('docs/security/best-practices/index.html');

  for (const heading of best.headings) {
    assert.match(html, new RegExp(`id=["']${headingId(heading)}["']`), `best-practices missing #${headingId(heading)}`);
  }

  assert.match(html, /0600|chmod 600/);
  assert.match(html, /--password/);
  assert.match(html, /NOKVAULT_PASSWORD/);
  assert.match(html, /rotate-key|Rotate/i);
  assert.match(html, /secure-delete/i);
  assert.match(html, /SSD|copy-on-write|snapshots/i);
  assert.match(html, /SYMLINK_DISALLOWED|PATH_ESCAPE/);
  assert.match(html, /backup/i);
  assert.doesNotMatch(html, /Nokvault/);
});

test('FAQ, changelog, contributing, and license use NokVault and factual release copy', async () => {
  const faq = await readPage('docs/faq/index.html');
  const changelog = await readPage('docs/changelog/index.html');
  const contributing = await readPage('docs/contributing/index.html');
  const license = await readPage('docs/license/index.html');

  for (const [name, html] of [
    ['faq', faq],
    ['changelog', changelog],
    ['contributing', contributing],
    ['license', license],
  ]) {
    assert.match(html, /NokVault/, `${name} must use NokVault casing`);
    assert.doesNotMatch(html, /Nokvault(?![^<]*Contributors)/, `${name} must not use Nokvault product casing`);
  }

  assert.match(faq, /does not store passwords|cannot be recovered/i);
  assert.match(faq, /SYMLINK_DISALLOWED|PATH_ESCAPE/);
  assert.doesNotMatch(faq, /Constant-time operations to prevent timing attacks/i);

  assert.match(changelog, /v0\.4\.0/);
  assert.match(changelog, /nokvault --version/);
  assert.doesNotMatch(changelog, /v2\.0\.0|v3\.0\.0|v1\.1\.0|v1\.0\.1/);
  assert.doesNotMatch(changelog, /Major Releases \(v2/);

  assert.match(contributing, /go test \.\/\.\.\./);
  assert.match(contributing, /go fmt|go vet/);

  const licenseBlock = license.match(/<pre[^>]*class=["'][^"']*license-text[^"']*["'][^>]*>[\s\S]*?<code[^>]*>([\s\S]*?)<\/code>/i);
  assert.ok(licenseBlock, 'license page must render MIT text in .license-text');
  const renderedLicense = licenseBlock[1]
    .replace(/&quot;/g, '"')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/\r\n/g, '\n')
    .replace(/^[ \t]+/gm, '')
    .trim();
  assert.equal(renderedLicense, MIT_LICENSE.trim());
});

test('Task 6 pages drop banned Tailwind-era class fragments', async () => {
  for (const route of TASK_ROUTES) {
    const html = await readPage(route);
    const classAttrs = [...html.matchAll(/\bclass=["']([^"']*)["']/gi)].map((match) => match[1]);
    const joined = classAttrs.join(' ');

    for (const fragment of BANNED_CLASS_FRAGMENTS) {
      assert.doesNotMatch(
        joined,
        new RegExp(fragment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
        `${route} still contains ${fragment}`,
      );
    }
    assert.doesNotMatch(joined, /\bprose\b/);
  }
});

test('React and Tailwind packages and integrations are removed', async () => {
  const pkg = JSON.parse(await readSrc('package.json'));
  const deps = { ...pkg.dependencies, ...pkg.devDependencies };

  for (const name of [
    '@astrojs/react',
    '@astrojs/tailwind',
    '@heroicons/react',
    '@tailwindcss/typography',
    'react',
    'react-dom',
    'tailwindcss',
    '@types/react',
    '@types/react-dom',
  ]) {
    assert.equal(deps[name], undefined, `${name} must be uninstalled`);
  }

  const config = await readSrc('astro.config.mjs');
  assert.doesNotMatch(config, /@astrojs\/react|@astrojs\/tailwind/);
  assert.doesNotMatch(config, /\breact\s*\(/);
  assert.doesNotMatch(config, /\btailwind\s*\(/);

  let missingTailwindConfig = false;
  try {
    await readSrc('tailwind.config.mjs');
  } catch {
    missingTailwindConfig = true;
  }
  assert.equal(missingTailwindConfig, true, 'tailwind.config.mjs must be deleted');
});
