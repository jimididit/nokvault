# Documentation Site Setup

This documentation site is built with [Astro](https://astro.build/) and deployed to GitHub Pages.

## Local Development

```bash
cd docs
npm install
npm run dev
```

Visit `http://localhost:4321` to see the site.

## Building

```bash
cd docs
npm run build
```

The built site will be in `docs/dist/`.

## GitHub Pages Setup

### Initial Setup

1. **Enable GitHub Pages:**
   - Go to your repository Settings → Pages
   - Source: Deploy from a branch
   - Branch: `gh-pages` (or use GitHub Actions)

2. **Configure Base Path:**
   - If your repo is `jimididit/nokvault`, the base path should be `/nokvault`
   - If your repo is `jimididit/nokvault` and you want it at the root, change `base` in `astro.config.mjs` to `/`
   - Update all internal links accordingly

3. **Deploy:**
   - The GitHub Actions workflow (`.github/workflows/docs-deploy.yml`) will automatically deploy when you push to `main`
   - Or manually: `npm run build` then push `dist/` to `gh-pages` branch

### Manual Deployment

If you prefer manual deployment:

```bash
cd docs
npm run build
# Copy dist/ contents to gh-pages branch
```

## Customization

- **Colors**: Edit `tailwind.config.mjs` for theme colors
- **Layout**: Modify `src/layouts/Layout.astro`
- **Pages**: Add new `.astro` files in `src/pages/`
- **Styling**: Uses Tailwind CSS - modify classes or add custom CSS

## Notes

- The site uses a dark theme by default
- All paths are relative to the `base` configured in `astro.config.mjs`
- GitHub Pages URL will be: `https://jimididit.github.io/nokvault/`
