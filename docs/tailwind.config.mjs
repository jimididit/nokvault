/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
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
      }
    },
  },
  plugins: [],
}
