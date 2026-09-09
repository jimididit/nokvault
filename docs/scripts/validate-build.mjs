import { readdir, readFile } from 'node:fs/promises';
import { relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const SITE_ORIGIN = 'https://nokvault.xyz';
const EXTERNAL_PROTOCOLS = new Set(['http:', 'https:', 'mailto:', 'tel:']);
const TAILWIND_UTILITY =
  /^(?:(?:sm|md|lg|xl|2xl|hover|focus|active|dark):)*(?:bg|text|border|ring|shadow|rounded|p[trblxy]?|m[trblxy]?|space-[xy]|gap|w|h|min-[wh]|max-[wh]|flex|grid|block|inline|hidden|items|justify|content|self|font|leading|tracking|transition|duration|ease|overflow|object|relative|absolute|fixed|sticky|inset|top|right|bottom|left|z|opacity|cursor|select|whitespace|break)-/;

async function readHTMLTree(distDir) {
  const root = resolve(distDir);
  const files = [];

  async function visit(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      const path = resolve(directory, entry.name);
      if (entry.isDirectory()) {
        await visit(path);
      } else if (entry.isFile() && entry.name.endsWith('.html')) {
        files.push(path);
      }
    }
  }

  await visit(root);
  return Promise.all(
    files.map(async (path) => {
      const file = relative(root, path).split(sep).join('/');
      return {
        file,
        route: routeForFile(file),
        html: await readFile(path, 'utf8'),
      };
    }),
  );
}

function routeForFile(file) {
  if (file === 'index.html') return '/';
  if (file.endsWith('/index.html')) return `/${file.slice(0, -'index.html'.length)}`;
  return `/${file.slice(0, -'.html'.length)}`;
}

function inspectScripts(page, issues) {
  for (const match of page.html.matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["'][^>]*>/gi)) {
    const source = match[1];
    let url;
    try {
      url = new URL(source, SITE_ORIGIN);
    } catch {
      continue;
    }
    if ((url.protocol === 'http:' || url.protocol === 'https:') && url.origin !== SITE_ORIGIN) {
      issues.push(`${page.file}: forbidden third-party script ${source}`);
    }
  }
}

function inspectLegacyClasses(page, issues) {
  const staleClasses = new Set();
  for (const match of page.html.matchAll(/\bclass=["']([^"']*)["']/gi)) {
    for (const className of match[1].split(/\s+/).filter(Boolean)) {
      if (className === 'prose' || className === 'prose-invert' || TAILWIND_UTILITY.test(className)) {
        staleClasses.add(className);
      }
    }
  }
  for (const className of [...staleClasses].sort()) {
    issues.push(`${page.file}: stale Tailwind-era class ${className}`);
  }
}

function inspectLinks(page, idsByRoute, issues) {
  for (const match of page.html.matchAll(/<a\b[^>]*\bhref=["']([^"']*)["'][^>]*>/gi)) {
    const href = match[1];
    if (!href) continue;

    let url;
    try {
      url = new URL(href, new URL(page.route, SITE_ORIGIN));
    } catch {
      continue;
    }

    if (EXTERNAL_PROTOCOLS.has(url.protocol) && url.origin !== SITE_ORIGIN) continue;
    if (url.origin !== SITE_ORIGIN) continue;

    const route = resolveKnownRoute(decodeURIComponent(url.pathname), idsByRoute);
    if (!route) {
      issues.push(`${page.file}: missing internal target ${url.pathname}`);
      continue;
    }

    if (url.hash) {
      const anchor = decodeURIComponent(url.hash.slice(1));
      if (!idsByRoute.get(route).has(anchor)) {
        issues.push(`${page.file}: missing anchor #${anchor} in ${route}`);
      }
    }
  }
}

function resolveKnownRoute(pathname, idsByRoute) {
  if (idsByRoute.has(pathname)) return pathname;
  if (!pathname.endsWith('/') && idsByRoute.has(`${pathname}/`)) return `${pathname}/`;
  if (pathname.endsWith('/') && pathname !== '/' && idsByRoute.has(pathname.slice(0, -1))) {
    return pathname.slice(0, -1);
  }
  return undefined;
}

export async function validateBuild(distDir) {
  const pages = await readHTMLTree(distDir);
  const issues = [];
  const idsByRoute = new Map();

  for (const page of pages) {
    idsByRoute.set(
      page.route,
      new Set([...page.html.matchAll(/\sid=["']([^"']+)["']/g)].map((match) => match[1])),
    );
  }

  for (const page of pages) {
    inspectScripts(page, issues);
    inspectLegacyClasses(page, issues);
    inspectLinks(page, idsByRoute, issues);
  }
  return issues.sort();
}

const isDirectExecution =
  process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);

if (isDirectExecution) {
  const issues = await validateBuild(resolve('dist'));
  for (const issue of issues) console.error(issue);
  if (issues.length > 0) process.exitCode = 1;
}
