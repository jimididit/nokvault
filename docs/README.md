# Nokvault Documentation Site

A modern, dark-themed documentation website built with Astro for the Nokvault CLI tool.

## Features

- 🌙 Dark theme optimized for readability
- 📱 Responsive design
- ⚡ Fast static site generation
- 🎨 Clean, minimal design
- 📚 Comprehensive documentation

## Quick Start

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build
```

## Project Structure

```penguin
docs/
├── src/
│   ├── layouts/
│   │   └── Layout.astro      # Main layout component
│   └── pages/
│       ├── index.astro        # Home page
│       └── docs/
│           └── index.astro    # Documentation page
├── public/
│   └── favicon.svg            # Site favicon
├── astro.config.mjs           # Astro configuration
├── tailwind.config.mjs        # Tailwind CSS configuration
└── package.json               # Dependencies
```

## Configuration

### Base Path

The `base` path in `astro.config.mjs` determines the URL structure:

- **If repo is `username/nokvault`**: Use `base: '/nokvault'`
- **If you want docs at root**: Use `base: '/'` and update all internal links

### GitHub Pages URL

After deployment, your site will be available at:

- `https://username.github.io/nokvault/` (if base is `/nokvault`)
- `https://username.github.io/` (if base is `/`)

## Deployment

The site is automatically deployed via GitHub Actions when changes are pushed to `main`. See `.github/workflows/docs-deploy.yml` for the workflow configuration.

## Customization

- **Colors**: Edit `tailwind.config.mjs`
- **Content**: Edit files in `src/pages/`
- **Layout**: Modify `src/layouts/Layout.astro`
- **Styling**: Uses Tailwind CSS - modify classes or add custom CSS in layout
