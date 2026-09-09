import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

// Load DOCS_PAGES headings via the TypeScript source text (no TS loader in node:test).
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
  assert.ok(pages.length >= 12, 'expected full DOCS_PAGES catalog');
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

const MIGRATED_ROUTES = [
  'docs/index.html',
  'docs/installation/index.html',
  'docs/usage/basic/index.html',
  'docs/commands/index.html',
  'docs/usage/advanced/index.html',
  'docs/configuration/index.html',
];

test('CodeBlock exposes scoped copy UI with live region and header metadata', async () => {
  const source = await readFile(new URL('../src/components/CodeBlock.astro', import.meta.url), 'utf8');
  const html = await readPage('docs/installation/index.html');

  assert.match(source, /copy\?:\s*boolean/);
  assert.match(source, /data-code-block/);
  assert.match(source, /data-code-copy|Copy/);
  assert.match(source, /aria-live=["']polite["']/);
  assert.match(source, /Copied/);
  assert.match(source, /Select and copy manually/);
  assert.match(source, /2000|2\s*\*\s*1000|2_000/);
  assert.match(source, /closest\(\s*['"]\[data-code-block\]['"]\s*\)|querySelectorAll\(\s*['"]\[data-code-block\]['"]/);

  assert.match(html, /data-code-block/);
  assert.match(html, />\s*Copy\s*</);
  assert.match(html, /role=["']status["'][^>]*aria-live=["']polite["']|aria-live=["']polite["'][^>]*role=["']status["']/);
});

test('docs overview uses guided entry paths and links every DOCS_PAGES route', async () => {
  const html = await readPage('docs/index.html');
  const pages = await readDocsPagesMeta();

  assert.match(html, /Start Here/);
  assert.match(html, /Common Workflows/);
  assert.match(html, /Understand the Security Model/);
  assert.doesNotMatch(html, /grid md:grid-cols-2/);

  for (const page of pages) {
    const href = page.href.replace(/\/+$/, '') || '/docs';
    assert.match(
      html,
      new RegExp(`href="[^"]*${href.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\/?"`),
      `overview must link ${page.title} (${page.href})`,
    );
  }
});

test('installation and basic usage preserve start subjects and recovery guidance', async () => {
  const installation = await readPage('docs/installation/index.html');
  const basic = await readPage('docs/usage/basic/index.html');

  for (const heading of ['Homebrew', 'Scoop', 'Release binaries', 'Build from source']) {
    const id = headingId(heading);
    assert.match(installation, new RegExp(`id=["']${id}["']`), `installation missing #${id}`);
    assert.match(installation, new RegExp(heading));
  }

  assert.match(installation, /gh attestation verify/);
  assert.match(installation, /checksums\.txt|SHA-256/i);
  assert.match(installation, /brew (tap|install)/);
  assert.match(installation, /scoop install/);
  assert.match(installation, /go build/);

  for (const heading of ['Encrypt a file', 'Decrypt a file', 'Use a keyfile']) {
    const id = headingId(heading);
    assert.match(basic, new RegExp(`id=["']${id}["']`), `basic missing #${id}`);
  }

  assert.match(basic, /verify recovery before deleting plaintext|Verify recovery before deleting/i);
  assert.match(basic, /0600/);
  assert.match(basic, /NOKVAULT_PASSWORD/);
  assert.match(basic, /--delete-original|--keyfile/);
});

test('commands, advanced, and configuration keep DOCS_PAGES anchors and critical claims', async () => {
  const pages = await readDocsPagesMeta();
  const byHref = Object.fromEntries(pages.map((page) => [page.href.replace(/\/+$/, ''), page]));

  const commands = await readPage('docs/commands/index.html');
  const advanced = await readPage('docs/usage/advanced/index.html');
  const configuration = await readPage('docs/configuration/index.html');

  for (const heading of byHref['/docs/commands'].headings) {
    assert.match(commands, new RegExp(`id=["']${headingId(heading)}["']`), `commands missing #${headingId(heading)}`);
  }
  for (const heading of byHref['/docs/usage/advanced'].headings) {
    assert.match(advanced, new RegExp(`id=["']${headingId(heading)}["']`), `advanced missing #${headingId(heading)}`);
  }
  for (const heading of byHref['/docs/configuration'].headings) {
    assert.match(
      configuration,
      new RegExp(`id=["']${headingId(heading)}["']`),
      `configuration missing #${headingId(heading)}`,
    );
  }

  assert.match(commands, /SYMLINK_DISALLOWED/);
  assert.match(commands, /PATH_ESCAPE/);
  assert.match(commands, /schema-version-1|schema version 1/i);
  assert.match(commands, /newline-delimited JSON|NDJSON/i);
  assert.match(commands, /hard-link|FAT\/exFAT/i);
  assert.match(commands, /--strict/);
  assert.match(commands, /SSD wear leveling|copy-on-write/i);

  assert.match(advanced, /--delay/);
  assert.match(advanced, /schedule encrypt/);
  assert.match(advanced, /rotate-key/);
  assert.match(advanced, /secure-delete/);

  assert.match(configuration, /memory_cost|time_cost|parallelism/);
  assert.match(configuration, /format v2|format-v2/i);
  assert.match(configuration, /\.nokvault\.toml|~\/\.config\/nokvault\/config\.toml/);
  assert.match(configuration, /config --set|no.*config --set/i);
});

test('migrated Start and Core pages drop banned Tailwind-era class fragments', async () => {
  for (const route of MIGRATED_ROUTES) {
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
