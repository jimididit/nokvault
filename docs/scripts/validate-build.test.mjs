import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { validateBuild } from './validate-build.mjs';

const validatorPath = fileURLToPath(new URL('./validate-build.mjs', import.meta.url));

async function fixture(t, files) {
  const root = await mkdtemp(join(tmpdir(), 'nokvault-docs-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const [name, content] of Object.entries(files)) {
    const path = join(root, name);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, content);
  }
  return root;
}

test('reports broken internal routes and anchors', async (t) => {
  const root = await fixture(t, {
    'index.html': '<a href="/docs/missing">Missing</a><a href="/docs/#absent">Anchor</a>',
    'docs/index.html': '<main id="present"></main>',
  });
  const issues = await validateBuild(root);
  assert.deepEqual(issues, [
    'index.html: missing anchor #absent in /docs/',
    'index.html: missing internal target /docs/missing',
  ]);
});

test('reports forbidden runtime scripts and stale utility classes', async (t) => {
  const root = await fixture(t, {
    'index.html': '<script src="https://buttons.github.io/buttons.js"></script><div class="bg-dark-surface prose-invert"></div>',
  });
  const issues = await validateBuild(root);
  assert.deepEqual(issues, [
    'index.html: forbidden third-party script https://buttons.github.io/buttons.js',
    'index.html: stale Tailwind-era class bg-dark-surface',
    'index.html: stale Tailwind-era class prose-invert',
  ]);
});

test('accepts the semantic sr-only class while rejecting stale utilities', async (t) => {
  const root = await fixture(t, {
    'index.html': '<span class="sr-only">Label</span><div class="bg-dark-surface"></div>',
  });
  const issues = await validateBuild(root);
  assert.deepEqual(issues, [
    'index.html: stale Tailwind-era class bg-dark-surface',
  ]);
});

test('recursively validates valid route variants, anchors, and same-site links', async (t) => {
  const root = await fixture(t, {
    'index.html': [
      '<a href="/docs">Docs without slash</a>',
      '<a href="docs/guide">Relative route</a>',
      '<a href="https://nokvault.xyz/docs/guide/#details">Same-origin route</a>',
      '<a href="https://example.com/missing">External route</a>',
      '<a href="mailto:hello@example.com">Email</a>',
      '<a href="tel:+15555550100">Phone</a>',
    ].join(''),
    'docs/index.html': '<main id="intro"><a href="./guide/">Guide with slash</a></main>',
    'docs/guide/index.html': '<main id="details"><a href="../#intro">Relative anchor</a></main>',
    'about.html': '<a href="/docs/#intro">Docs anchor</a>',
  });

  const first = await validateBuild(root);
  const second = await validateBuild(root);
  assert.deepEqual(first, []);
  assert.deepEqual(second, first);
});

test('direct CLI exits zero for a valid build', async (t) => {
  const root = await fixture(t, {
    'dist/index.html': '<main id="ready"></main>',
  });
  const result = spawnSync(process.execPath, [validatorPath], {
    cwd: root,
    encoding: 'utf8',
  });

  assert.equal(result.status, 0);
  assert.equal(result.stderr, '');
});

test('direct CLI prints sorted issues and exits one for an invalid build', async (t) => {
  const root = await fixture(t, {
    'dist/index.html': '<a href="/z-missing">Z</a><a href="/a-missing">A</a>',
  });
  const result = spawnSync(process.execPath, [validatorPath], {
    cwd: root,
    encoding: 'utf8',
  });

  assert.equal(result.status, 1);
  assert.equal(
    result.stderr.replaceAll('\r\n', '\n'),
    'index.html: missing internal target /a-missing\nindex.html: missing internal target /z-missing\n',
  );
});
