import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { validateBuild } from './validate-build.mjs';

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
