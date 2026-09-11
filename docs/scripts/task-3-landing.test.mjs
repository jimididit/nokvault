import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import test from 'node:test';

const readPage = (path) => readFile(new URL(`../dist/${path}`, import.meta.url), 'utf8');

async function readInstallOptionsFromSource() {
  const source = await readFile(new URL('../src/data/site.ts', import.meta.url), 'utf8');
  const block = source.match(/export const INSTALL_OPTIONS = \[([\s\S]*?)\] as const;/);
  assert.ok(block, 'INSTALL_OPTIONS export must exist in site.ts');

  const options = [...block[1].matchAll(/\{\s*id:\s*'([^']+)'\s*,\s*label:\s*'([^']+)'\s*,\s*command:\s*'([^']+)'\s*\}/g)].map(
    (match) => ({ id: match[1], label: match[2], command: match[3] }),
  );

  assert.ok(options.length >= 4, 'INSTALL_OPTIONS must expose the verified install methods');
  return options;
}

async function readLandingStyles() {
  const html = await readPage('index.html');
  const assetsDir = new URL('../dist/_astro/', import.meta.url);
  const assetNames = await readdir(assetsDir);
  const cssChunks = await Promise.all(
    assetNames
      .filter((name) => name.endsWith('.css'))
      .map((name) => readFile(new URL(name, assetsDir), 'utf8')),
  );
  return { html, styles: [html, ...cssChunks].join('\n') };
}

function parseCssTimeToMs(value) {
  const trimmed = value.trim();
  if (trimmed.endsWith('ms')) return Number.parseFloat(trimmed);
  if (trimmed.endsWith('s')) return Number.parseFloat(trimmed) * 1000;
  return Number.NaN;
}

function extractCssTimeToken(declaration) {
  const match = declaration.match(/(?:^|[\s:])(\d*\.?\d+m?s)\b/i);
  return match?.[1] ?? null;
}

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
  assert.match(html, /PS&gt; nokvault decrypt \.\\\\archive.nokv/);
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

test('install selector keeps every option in document flow with button-group semantics', async () => {
  const html = await readPage('index.html');
  const options = await readInstallOptionsFromSource();

  for (const option of options) {
    assert.match(html, new RegExp(`id="${option.id}"`));
    assert.match(html, new RegExp(option.command.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }

  assert.match(html, /data-install-selector/);
  assert.match(html, /aria-pressed="/);
  assert.doesNotMatch(html, /role="tablist"|role="tab"|role="tabpanel"|aria-selected=/);
  assert.match(html, /location\.hash|hashchange|history\.replaceState/);

  const installControls = [...html.matchAll(/<button\b([^>]*data-install-control[^>]*)>/gi)];
  assert.equal(installControls.length, options.length, 'each install option needs a focusable control');
  for (const [, attrs] of installControls) {
    assert.doesNotMatch(attrs, /tabindex\s*=\s*["']-1["']/i);
    assert.match(attrs, /aria-pressed="/);
  }

  for (const option of options) {
    const panel = html.match(new RegExp(`<section\\b[^>]*id="${option.id}"[^>]*>[\\s\\S]*?<\\/section>`, 'i'));
    assert.ok(panel, `panel ${option.id} must remain in the document`);
    assert.doesNotMatch(panel[0], /hidden(?:="[^"]*")?|aria-hidden="true"|style="[^"]*display\s*:\s*none/i);
  }

  assert.doesNotMatch(html, /\.install-selector__panel(?![^{]*\{)[^{]*\{[^}]*display\s*:\s*none/i);
});

test('landing removes legacy dark utility classes and GitHub widgets', async () => {
  const html = await readPage('index.html');

  assert.doesNotMatch(html, /buttons\.github\.io/);
  assert.doesNotMatch(html, /\b(?:bg-dark-|text-dark-|border-dark-|bg-blue-|text-blue-|max-w-4xl|md:grid-cols)\b/);
  assert.doesNotMatch(html, /GitHubButtons|github-btn/);
});

test('landing hero motion stays within 600ms and keeps the primary CTA visible', async () => {
  const { html, styles } = await readLandingStyles();

  assert.match(styles, /@keyframes\s+landing-hero-in/);
  assert.match(styles, /prefers-reduced-motion:\s*reduce/);
  assert.doesNotMatch(html, /gsap|ScrollTrigger/i);

  const durationDeclaration = styles.match(/\.landing-hero__reveal(?:\[[^\]]*\])?\{[^}]*animation:[^;}]+/i);
  assert.ok(durationDeclaration, 'hero reveal duration must be declared');
  const durationToken = extractCssTimeToken(durationDeclaration[0].split('animation:')[1] ?? '');
  assert.ok(durationToken, 'hero reveal duration token must be parseable');
  const durationMs = parseCssTimeToMs(durationToken);
  assert.ok(Number.isFinite(durationMs) && durationMs > 0 && durationMs <= 600, `duration must be ≤600ms, got ${durationToken}`);

  const delayValues = [...styles.matchAll(/\.landing-hero__reveal--delay-\d+(?:\[[^\]]*\])?\{[^}]*animation-delay:\s*([^;}]+)/gi)]
    .map((match) => extractCssTimeToken(match[1]))
    .filter(Boolean)
    .map((token) => parseCssTimeToMs(token));
  const maxDelayMs = delayValues.length ? Math.max(...delayValues) : 0;
  assert.ok(maxDelayMs + durationMs <= 600, `delay+duration must finish within 600ms (delay=${maxDelayMs}ms, duration=${durationMs}ms)`);

  const actionsBlock = html.match(/<div[^>]*class="[^"]*landing-hero__actions[^"]*"[^>]*>[\s\S]*?<\/div>/i);
  assert.ok(actionsBlock, 'hero actions container must exist');
  assert.doesNotMatch(actionsBlock[0], /landing-hero__reveal(?:--delay-\d+)?/);
  assert.match(actionsBlock[0], /Install NokVault/);

  assert.match(
    styles,
    /@media\s*\(\s*prefers-reduced-motion:\s*reduce\s*\)[\s\S]*?\.landing-hero__reveal[\s\S]*?animation\s*:\s*none/,
  );
});
