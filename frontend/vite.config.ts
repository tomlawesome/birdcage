import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

// https://vite.dev/config/
export default defineConfig({
  plugins: [svelte()],
  server: {
    proxy: {
      // The Go server serves both the API and this build (web/embed.go);
      // in dev, Vite proxies /api/* to it so a plain `npm run dev` talks
      // to a real backend on :8080 without CORS juggling.
      '/api': {
        target: 'http://localhost:8080',
      },
    },
  },
})
