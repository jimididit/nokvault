/**
 * Local documentation search ranking for NokVault docs.
 * Match lowercase query tokens across title, description, group, headings, and href.
 * Rank: exact title > title prefix > heading > description (then remaining field hits).
 */

/**
 * @typedef {{ group: string, title: string, href: string, description: string, headings: readonly string[] }} DocsSearchPage
 */

/**
 * @param {string} query
 * @returns {string[]}
 */
export function tokenizeQuery(query) {
  return String(query || '')
    .toLowerCase()
    .trim()
    .split(/\s+/)
    .filter(Boolean);
}

/**
 * @param {DocsSearchPage} page
 * @param {string[]} tokens
 */
function pageMatches(page, tokens) {
  const haystacks = [
    page.title,
    page.description,
    page.group,
    page.href,
    ...(page.headings || []),
  ].map((value) => String(value).toLowerCase());

  return tokens.every((token) => haystacks.some((haystack) => haystack.includes(token)));
}

/**
 * @param {DocsSearchPage} page
 * @param {string[]} tokens
 * @param {string} joined
 */
function scorePage(page, tokens, joined) {
  const title = page.title.toLowerCase();
  const description = page.description.toLowerCase();
  const headings = (page.headings || []).map((heading) => heading.toLowerCase());

  if (title === joined) return 400;
  if (tokens.length === 1 && title.startsWith(tokens[0])) return 300;
  if (title.startsWith(joined)) return 300;
  if (headings.some((heading) => tokens.every((token) => heading.includes(token)))) return 200;
  if (tokens.every((token) => description.includes(token))) return 100;
  return 50;
}

/**
 * @param {readonly DocsSearchPage[]} pages
 * @param {string} query
 * @returns {DocsSearchPage[]}
 */
export function rankDocsSearch(pages, query) {
  const tokens = tokenizeQuery(query);
  if (tokens.length === 0) return [];

  const joined = tokens.join(' ');

  return pages
    .filter((page) => pageMatches(page, tokens))
    .map((page, index) => ({ page, index, score: scorePage(page, tokens, joined) }))
    .sort((a, b) => b.score - a.score || a.index - b.index)
    .map((entry) => entry.page);
}
