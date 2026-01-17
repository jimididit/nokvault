/** @type {import('tailwindcss').Config} */
import typography from '@tailwindcss/typography';

export default {
  content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        dark: {
          bg: '#0a0a0a',
          surface: '#121212',
          border: '#1f1f1f',
          text: '#e5e5e5',
          'text-muted': '#a3a3a3',
        }
      },
      typography: {
        invert: {
          css: {
            '--tw-prose-body': '#e5e5e5',
            '--tw-prose-headings': '#ffffff',
            '--tw-prose-lead': '#a3a3a3',
            '--tw-prose-links': '#60a5fa',
            '--tw-prose-bold': '#ffffff',
            '--tw-prose-counters': '#a3a3a3',
            '--tw-prose-bullets': '#a3a3a3',
            '--tw-prose-hr': '#1f1f1f',
            '--tw-prose-quotes': '#e5e5e5',
            '--tw-prose-quote-borders': '#1f1f1f',
            '--tw-prose-captions': '#a3a3a3',
            '--tw-prose-code': '#ffffff',
            '--tw-prose-pre-code': '#e5e5e5',
            '--tw-prose-pre-bg': '#1f1f1f',
            '--tw-prose-th-borders': '#1f1f1f',
            '--tw-prose-td-borders': '#1f1f1f',
          },
        },
      },
    },
  },
  plugins: [typography],
}
