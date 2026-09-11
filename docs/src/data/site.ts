export const SITE = {
  name: 'NokVault',
  version: '0.5.0',
  description: 'Local-first encryption for files, folders, and repeatable workflows.',
  url: 'https://nokvault.xyz',
  repository: 'https://github.com/jimididit/nokvault',
  releases: 'https://github.com/jimididit/nokvault/releases',
} as const;

export const DOCS_PAGES = [
  { group: 'Start', title: 'Overview', href: '/docs/', description: 'Choose the shortest path from installation to a verified recovery.', headings: [] },
  { group: 'Start', title: 'Installation', href: '/docs/installation', description: 'Install a verified NokVault binary or build from source.', headings: ['Homebrew', 'Scoop', 'Release binaries', 'Build from source'] },
  { group: 'Start', title: 'Basic Usage', href: '/docs/usage/basic', description: 'Encrypt, verify, and decrypt your first files and directories.', headings: ['Encrypt a file', 'Decrypt a file', 'Use a keyfile'] },
  { group: 'Core Operations', title: 'Commands', href: '/docs/commands', description: 'Complete command and option reference.', headings: ['Path and symlink policy', 'Machine-readable output', 'encrypt', 'decrypt', 'watch', 'schedule encrypt', 'rotate-key', 'secure-delete', 'config'] },
  { group: 'Core Operations', title: 'Advanced Usage', href: '/docs/usage/advanced', description: 'Compression, automation, rotation, deletion, and batch workflows.', headings: ['Compression', 'Auto-Encryption with File Watching', 'Scheduled Encryption', 'Key Rotation', 'Secure Deletion', 'Batch Operations'] },
  { group: 'Core Operations', title: 'Configuration', href: '/docs/configuration', description: 'Configure Argon2id parameters for new encryptions.', headings: ['Configuration files', 'Key derivation'] },
  { group: 'Security', title: 'Security Overview', href: '/docs/security', description: 'Mechanisms, safeguards, and explicit security boundaries.', headings: ['Authenticated encryption', 'Key derivation', 'Path containment and symlinks', 'Limitations'] },
  { group: 'Security', title: 'Best Practices', href: '/docs/security/best-practices', description: 'Credential, storage, backup, and operational guidance.', headings: ['Passwords', 'Keyfiles', 'Backups', 'Secure deletion'] },
  { group: 'Reference', title: 'FAQ', href: '/docs/faq', description: 'Answers to common product and workflow questions.', headings: [] },
  { group: 'Reference', title: 'Changelog', href: '/docs/changelog', description: 'Release history and upgrade guidance.', headings: [] },
  { group: 'Project', title: 'Contributing', href: '/docs/contributing', description: 'Build, test, and contribute to NokVault.', headings: [] },
  { group: 'Project', title: 'License', href: '/docs/license', description: 'MIT license terms.', headings: [] },
] as const;

export function headingId(heading: string) {
  return heading
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, '')
    .replace(/[\s_]+/g, '-')
    .replace(/-+/g, '-');
}

export const DOCS_NAV = ['Start', 'Core Operations', 'Automation', 'Security', 'Reference', 'Project'].map((group) => ({
  group,
  items: group === 'Automation'
    ? [
        { title: 'Watch and Schedule', href: `/docs/usage/advanced#${headingId('Auto-Encryption with File Watching')}` },
        { title: 'JSON Output', href: `/docs/commands#${headingId('Machine-readable output')}` },
      ]
    : DOCS_PAGES.filter((page) => page.group === group),
}));

export const INSTALL_OPTIONS = [
  { id: 'homebrew', label: 'Homebrew', command: 'brew install jimididit/nokvault/nokvault' },
  { id: 'scoop', label: 'Scoop', command: 'scoop install https://raw.githubusercontent.com/jimididit/nokvault/main/scoop/nokvault.json' },
  { id: 'release', label: 'Release binary', command: 'gh release download v0.5.0 --repo jimididit/nokvault' },
  { id: 'source', label: 'Source', command: 'go install github.com/jimididit/nokvault/cmd/nokvault@v0.5.0' },
] as const;

export function normalizePath(pathname: string) {
  const path = pathname.split(/[?#]/, 1)[0] || '/';
  const withLeadingSlash = path.startsWith('/') ? path : `/${path}`;
  if (withLeadingSlash === '/') return withLeadingSlash;
  return withLeadingSlash.replace(/\/+$/, '');
}

export function getDocPage(pathname: string) {
  const normalizedPath = normalizePath(pathname);
  return DOCS_PAGES.find((page) => normalizePath(page.href) === normalizedPath);
}

export function getAdjacentDocs(pathname: string) {
  const page = getDocPage(pathname);
  const index = page ? DOCS_PAGES.indexOf(page) : -1;

  return {
    previous: index > 0 ? DOCS_PAGES[index - 1] : undefined,
    next: index >= 0 && index < DOCS_PAGES.length - 1 ? DOCS_PAGES[index + 1] : undefined,
  };
}

export function withBase(href: string, base: string) {
  if (/^https?:\/\//i.test(href)) return href;
  const normalizedBase = base.endsWith('/') ? base : `${base}/`;
  const path = href.startsWith('/') ? href.slice(1) : href;
  return `${normalizedBase}${path}`;
}
