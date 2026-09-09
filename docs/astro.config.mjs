import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';

// https://astro.build/config
export default defineConfig({
  integrations: [
    sitemap({
      changefreq: 'weekly',
      priority: 0.7,
      lastmod: new Date(),
      entryLimit: 50000, // Force single sitemap file (default is 45000)
    }),
  ],
  site: 'https://nokvault.xyz',
  base: '/',
  output: 'static',
});
