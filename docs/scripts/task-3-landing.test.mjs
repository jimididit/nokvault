import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const readPage = (path) => readFile(new URL(`../dist/${path}`, import.meta.url), 'utf8');

const INSTALL_IDS = ['homebrew', 'scoop', 'release', 'source'];
const INSTALL_COMMANDS = [
  'brew install jimididit/nokvault/nokvault',
  'scoop install https://raw.githubusercontent.com/jimididit/nokvault/main/scoop/nokvault.json',
  'gh release download v0.3.0 --repo jimididit/nokvault',
  'go install github.com/jimididit/nokvault/cmd/nokvault@v0.3.0',
];

test('landing hero uses approved Cipher Editorial copy and actions', async () => {
  const html = await readPage('index.html');

  assert.match(html, /Local encryption \/ deliberately private/);
  assert.match(html, /Your files\.\s*<br[^>]*>\s*<span[^>]*>Your keys\.<\/span>\s*<br[^>]*>\s*Your control\./s);
  assert.match(
    html,
    /Strong local encryption without surrendering your data, workflow, or judgment to a cloud service\./,
  );
  assert.match(html, /href="[^"]*docs\/installation"[^>]*>\s*Install NokVault\s*</);
  assert.match(html, /href="[^"]*docs\/"[^>]*>\s*Read the docs\s*</);
  assert.match(html, /PS&gt; nokvault encrypt \.\\archive/);
  assert.match(html, /✓ Encryption completed successfully|&#10003; Encryption completed successfully/);
  assert.match(html, /PS&gt; nokvault decrypt \.\\archive\.nokvault/);
  assert.match(html, /✓ Decryption completed successfully|&#10003; Decryption completed successfully/);
  assert.doesNotMatch(html, /files encrypted|file counts|N files/i);
});

test('landing includes trust rail, beginner path, workflow, and security posture', async () => {
  const html = await readPage('index.html');

  for (const label of ['AES-256-GCM', 'ARGON2ID', 'LOCAL-FIRST', 'OPEN SOURCE']) {
    assert.match(html, new RegExp(label));
  }

  assert.match(html, />\s*Install\s*</);
  assert.match(html, />\s*Encrypt\s*</);
  assert.match(html, />\s*Verify recovery\s*</);
  assert.match(html, /href="[^"]*docs\/installation"/);
  assert.match(html, /href="[^"]*docs\/usage\/basic"/);
  assert.match(html, /href="[^"]*docs\/security\/best-practices"/);

  for (const heading of [
    'Files and directory trees',
    'Trusted local automation',
    'Operator safeguards',
    'JSON and NDJSON integration',
  ]) {
    assert.match(html, new RegExp(heading));
  }

  assert.match(html, />\s*Mechanisms\s*</);
  assert.match(html, />\s*Safeguards\s*</);
  assert.match(html, />\s*Boundaries\s*</);
  assert.match(html, /best-effort secure delete/i);
  assert.match(html, /SSD|COW|snapshot/i);
  assert.match(html, /best-effort memory zeroization/i);
  assert.match(html, /path-validation race|path validation race/i);
});

test('install selector keeps every option in document flow', async () => {
  const html = await readPage('index.html');

  for (const id of INSTALL_IDS) {
    assert.match(html, new RegExp(`id="${id}"`));
  }
  for (const command of INSTALL_COMMANDS) {
    assert.match(html, new RegExp(command.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }

  assert.match(html, /role="tablist"|data-install-selector/);
  assert.match(html, /aria-selected/);
  assert.match(html, /location\.hash|hashchange|history\.replaceState/);
});

test('landing removes legacy dark utility classes and GitHub widgets', async () => {
  const html = await readPage('index.html');

  assert.doesNotMatch(html, /buttons\.github\.io/);
  assert.doesNotMatch(html, /\b(?:bg-dark-|text-dark-|border-dark-|bg-blue-|text-blue-|max-w-4xl|md:grid-cols)\b/);
  assert.doesNotMatch(html, /GitHubButtons|github-btn/);
});

test('landing hero motion is CSS-only and reduced-motion safe', async () => {
  const html = await readPage('index.html');
  const { readdir } = await import('node:fs/promises');
  const assetsDir = new URL('../dist/_astro/', import.meta.url);
  const assetNames = await readdir(assetsDir);
  const cssChunks = await Promise.all(
    assetNames
      .filter((name) => name.endsWith('.css'))
      .map((name) => readFile(new URL(name, assetsDir), 'utf8')),
  );
  const styles = [html, ...cssChunks].join('\n');

  assert.match(styles, /@keyframes/);
  assert.match(styles, /prefers-reduced-motion/);
  assert.match(styles, /(?:600ms|0\.6s|\.6s)/);
  assert.doesNotMatch(html, /gsap|ScrollTrigger/i);
});