/**
 * Task 7 browser evidence harness (Chrome headless via puppeteer-core + chrome-launcher).
 * Run while `astro preview` is serving the production build.
 */
import { writeFile, mkdir } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

const require = createRequire(import.meta.url);
const BASE = process.env.PREVIEW_BASE || 'http://localhost:4322';
const OUT = new URL('../../.superpowers/sdd/task-7-evidence/browser-evidence.json', import.meta.url);

async function loadChromeStack() {
  // Prefer packages pulled by `npx lighthouse` / local node_modules resolution.
  const candidates = [
    process.cwd(),
    new URL('.', import.meta.url).pathname,
  ];
  let puppeteer;
  let chromeLauncher;
  for (const base of candidates) {
    try {
      puppeteer = require(require.resolve('puppeteer-core', { paths: [base] }));
      chromeLauncher = require(require.resolve('chrome-launcher', { paths: [base] }));
      return { puppeteer, chromeLauncher };
    } catch {}
  }
  // Fall back to npx cache resolution from lighthouse install.
  puppeteer = require('puppeteer-core');
  chromeLauncher = require('chrome-launcher');
  return { puppeteer, chromeLauncher };
}

const PAGES = ['/', '/docs/', '/docs/installation', '/docs/commands', '/docs/usage/advanced', '/docs/security', '/docs/changelog'];
const WIDTHS = [375, 768, 1024, 1440];

async function measureOverflow(page) {
  return page.evaluate(() => {
    const doc = document.documentElement;
    const offenders = [...document.querySelectorAll('body *')]
      .filter((el) => {
        const rect = el.getBoundingClientRect();
        return rect.width > 0 && rect.right > window.innerWidth + 1;
      })
      .slice(0, 8)
      .map((el) => ({
        tag: el.tagName.toLowerCase(),
        className: String(el.className).slice(0, 80),
        right: Math.round(el.getBoundingClientRect().right),
      }));
    return {
      viewport: { w: window.innerWidth, h: window.innerHeight },
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      overflows: doc.scrollWidth > doc.clientWidth + 1,
      offenders,
    };
  });
}

async function main() {
  const { puppeteer, chromeLauncher } = await loadChromeStack();
  const chrome = await chromeLauncher.launch({
    chromeFlags: ['--headless=new', '--no-sandbox', '--disable-gpu'],
  });
  const browser = await puppeteer.connect({
    browserURL: `http://127.0.0.1:${chrome.port}`,
    defaultViewport: null,
  });

  const evidence = {
    base: BASE,
    generatedAt: new Date().toISOString(),
    overflowMatrix: [],
    theme: {},
    install: {},
    reducedMotion: {},
    mobileNav: {},
    search: {},
    clipboard: {},
    noJs: {},
    contentIntegrity: {},
  };

  const page = await browser.newPage();

  // Overflow matrix
  for (const width of WIDTHS) {
    await page.setViewport({ width, height: 900, deviceScaleFactor: 1 });
    for (const path of PAGES) {
      await page.goto(`${BASE}${path}`, { waitUntil: 'networkidle0', timeout: 60000 });
      const measure = await measureOverflow(page);
      evidence.overflowMatrix.push({ path, width, ...measure });
    }
  }

  // Theme persistence + no flash check via init script
  await page.setViewport({ width: 1440, height: 900 });
  await page.goto(`${BASE}/`, { waitUntil: 'networkidle0' });
  await page.click('input[name="color-theme"][value="dark"]');
  evidence.theme.afterSelectDark = await page.evaluate(() => ({
    preference: document.documentElement.dataset.themePreference,
    theme: document.documentElement.dataset.theme,
    storage: localStorage.getItem('nokvault-theme'),
  }));

  let flashObserved = false;
  await page.evaluateOnNewDocument(() => {
    window.__themeFlash = null;
    const early = document.documentElement.dataset.theme;
    requestAnimationFrame(() => {
      const later = document.documentElement.dataset.theme;
      window.__themeFlash = { early, later, mismatched: early && later && early !== later };
    });
  });
  await page.reload({ waitUntil: 'networkidle0' });
  evidence.theme.afterReload = await page.evaluate(() => ({
    preference: document.documentElement.dataset.themePreference,
    theme: document.documentElement.dataset.theme,
    storage: localStorage.getItem('nokvault-theme'),
    flash: window.__themeFlash,
  }));
  flashObserved = Boolean(evidence.theme.afterReload.flash?.mismatched);
  evidence.theme.noFlashOnReload = !flashObserved;

  // System preference media change
  await page.click('input[name="color-theme"][value="system"]');
  await page.emulateMediaFeatures([{ name: 'prefers-color-scheme', value: 'light' }]);
  await page.evaluate(() => {
    // ThemeControl listens to matchMedia change; force a re-read.
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    media.dispatchEvent(new Event('change'));
  });
  // Remount by reloading with system preference already stored
  await page.reload({ waitUntil: 'networkidle0' });
  evidence.theme.systemLight = await page.evaluate(() => ({
    preference: document.documentElement.dataset.themePreference,
    theme: document.documentElement.dataset.theme,
  }));
  await page.emulateMediaFeatures([{ name: 'prefers-color-scheme', value: 'dark' }]);
  await page.reload({ waitUntil: 'networkidle0' });
  evidence.theme.systemDark = await page.evaluate(() => ({
    preference: document.documentElement.dataset.themePreference,
    theme: document.documentElement.dataset.theme,
  }));

  // Reduced motion
  await page.emulateMediaFeatures([{ name: 'prefers-reduced-motion', value: 'reduce' }]);
  await page.reload({ waitUntil: 'networkidle0' });
  evidence.reducedMotion = await page.evaluate(() => {
    const el = document.querySelector('.landing-hero__reveal');
    if (!el) return { found: false };
    const styles = getComputedStyle(el);
    const anim = styles.animation;
    const durationMs = Number.parseFloat(styles.animationDuration) * (styles.animationDuration.includes('ms') ? 1 : 1000);
    // Global reduced-motion rule uses ~0.01ms; page rule uses animation: none.
    const reduced = /none/i.test(anim) || (!Number.isNaN(durationMs) && durationMs <= 1);
    return { found: true, animation: anim, animationDuration: styles.animationDuration, reduced };
  });
  await page.emulateMediaFeatures([{ name: 'prefers-reduced-motion', value: 'no-preference' }]);

  // Install interactive
  await page.goto(`${BASE}/`, { waitUntil: 'networkidle0' });
  await page.click('[data-install-control="scoop"]');
  evidence.install.clickScoop = await page.evaluate(() => ({
    hash: location.hash,
    pressed: document.querySelector('[data-install-control="scoop"]')?.getAttribute('aria-pressed'),
    panels: [...document.querySelectorAll('[data-install-panel]')].map((p) => ({
      id: p.getAttribute('data-install-panel'),
      display: getComputedStyle(p).display,
      active: p.getAttribute('data-active'),
    })),
  }));
  await page.evaluate(() => {
    history.replaceState(null, '', '#release');
    window.dispatchEvent(new HashChangeEvent('hashchange'));
  });
  evidence.install.hashRelease = await page.evaluate(() => ({
    hash: location.hash,
    pressed: document.querySelector('[data-install-control="release"]')?.getAttribute('aria-pressed'),
  }));

  // Mobile nav at 375
  await page.setViewport({ width: 375, height: 900 });
  await page.goto(`${BASE}/docs/installation`, { waitUntil: 'networkidle0' });
  evidence.mobileNav.exists = await page.evaluate(() => ({
    details: !!document.querySelector('[data-mobile-docs-nav]'),
    enhanced: document.querySelector('[data-mobile-docs-nav]')?.dataset.enhanced === 'true',
    backdrop: !!document.querySelector('[data-mobile-docs-backdrop]'),
  }));
  await page.click('details[data-mobile-docs-nav] > summary');
  await page.waitForFunction(() => {
    const root = document.querySelector('[data-mobile-docs-nav]');
    return root instanceof HTMLDetailsElement && root.open && document.body.style.overflow === 'hidden';
  });
  evidence.mobileNav.afterOpen = await page.evaluate(() => ({
    open: document.querySelector('[data-mobile-docs-nav]')?.open,
    bodyOverflow: document.body.style.overflow,
    backdropDisplay: getComputedStyle(document.querySelector('[data-mobile-docs-backdrop]')).display,
  }));
  await page.keyboard.press('Escape');
  evidence.mobileNav.afterEscape = await page.evaluate(() => ({
    open: document.querySelector('[data-mobile-docs-nav]')?.open,
    bodyOverflow: document.body.style.overflow,
    activeTag: document.activeElement?.tagName,
    activeText: document.activeElement?.textContent?.trim()?.slice(0, 40),
  }));
  await page.click('details[data-mobile-docs-nav] > summary');
  await page.click('[data-mobile-docs-backdrop]');
  evidence.mobileNav.afterBackdrop = await page.evaluate(() => ({
    open: document.querySelector('[data-mobile-docs-nav]')?.open,
  }));

  // Search keyboard / announcements / aria-selected
  await page.setViewport({ width: 1024, height: 900 });
  await page.goto(`${BASE}/docs/?q=encrypt`, { waitUntil: 'networkidle0' });
  evidence.search.fromQueryParam = await page.evaluate(() => ({
    dialogOpen: document.querySelector('[data-docs-search-dialog]')?.open,
    status: document.querySelector('[data-docs-search-status]')?.textContent,
    options: [...document.querySelectorAll('#docs-search-results [role=option]')].map((o) => ({
      text: o.querySelector('strong')?.textContent,
      selected: o.getAttribute('aria-selected'),
      id: o.id,
    })),
    activedescendant: document.querySelector('#docs-search-input')?.getAttribute('aria-activedescendant'),
    expanded: document.querySelector('#docs-search-input')?.getAttribute('aria-expanded'),
  }));
  await page.focus('#docs-search-input');
  await page.keyboard.press('ArrowDown');
  evidence.search.afterArrowDown = await page.evaluate(() => ({
    selected: [...document.querySelectorAll('#docs-search-results [role=option]')].map((o) => o.getAttribute('aria-selected')),
    activedescendant: document.querySelector('#docs-search-input')?.getAttribute('aria-activedescendant'),
  }));

  // Clipboard success
  await page.goto(`${BASE}/docs/commands`, { waitUntil: 'networkidle0' });
  await page.evaluate(async () => {
    // Grant-like stub for success path
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: async () => undefined,
      },
    });
  });
  await page.click('[data-code-copy]');
  evidence.clipboard.success = await page.evaluate(() => ({
    button: document.querySelector('[data-code-copy]')?.textContent,
    status: document.querySelector('[data-code-status]')?.textContent,
  }));
  await new Promise((resolve) => setTimeout(resolve, 2100));
  evidence.clipboard.successReset = await page.evaluate(() => ({
    button: document.querySelector('[data-code-copy]')?.textContent,
    status: document.querySelector('[data-code-status]')?.textContent,
  }));

  // Clipboard failure
  await page.evaluate(() => {
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: async () => {
          throw new Error('denied');
        },
      },
    });
  });
  await page.click('[data-code-copy]');
  evidence.clipboard.failure = await page.evaluate(() => ({
    button: document.querySelector('[data-code-copy]')?.textContent,
    status: document.querySelector('[data-code-status]')?.textContent,
  }));

  // Content / version integrity
  evidence.contentIntegrity = await page.evaluate(() => {
    const text = document.body.innerText;
    return {
      title: document.title,
      versionVisible: /0\.3\.0/.test(text),
      productName: /NokVault/.test(text),
      hasGithubApi: [...document.scripts].some((s) => /api\.github\.com/.test(s.src || s.textContent || '')),
      externalFonts: [...document.querySelectorAll('link')].some((l) => /fonts\.google|typekit|cdn\.font/i.test(l.href)),
    };
  });

  // No-JS install panels remain in flow: fetch HTML without executing scripts by disabling JS
  const noJsPage = await browser.newPage();
  await noJsPage.setJavaScriptEnabled(false);
  await noJsPage.setViewport({ width: 1440, height: 900 });
  await noJsPage.goto(`${BASE}/`, { waitUntil: 'domcontentloaded' });
  evidence.noJs.landing = await noJsPage.evaluate(() => ({
    installPanels: [...document.querySelectorAll('[data-install-panel]')].map((p) => ({
      id: p.id,
      hidden: p.hasAttribute('hidden'),
      text: p.querySelector('pre')?.textContent?.slice(0, 40),
    })),
    themeControlPresent: !!document.querySelector('[data-theme-control]'),
    themeScriptInlinePresent: [...document.scripts].some((s) => /nokvault-theme/.test(s.textContent || '')),
  }));
  await noJsPage.goto(`${BASE}/docs/`, { waitUntil: 'domcontentloaded' });
  evidence.noJs.docs = await noJsPage.evaluate(() => ({
    searchTriggerHref: document.querySelector('[data-docs-search-trigger]')?.getAttribute('href'),
    mobileNavIsDetails: document.querySelector('[data-mobile-docs-nav]')?.tagName === 'DETAILS',
    dialogClosed: !document.querySelector('[data-docs-search-dialog]')?.hasAttribute('open'),
  }));
  await noJsPage.close();

  await browser.disconnect();
  await chrome.kill();

  await mkdir(new URL('.', OUT), { recursive: true });
  await writeFile(OUT, JSON.stringify(evidence, null, 2));
  console.log('Wrote', pathToFileURL(OUT.pathname).href || OUT.href);

  const overflowFails = evidence.overflowMatrix.filter((row) => row.overflows);
  if (overflowFails.length) {
    console.error('OVERFLOW FAILURES', overflowFails);
    process.exitCode = 1;
  } else {
    console.log('Overflow matrix clean:', evidence.overflowMatrix.length, 'checks');
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
