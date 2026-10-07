import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath, URL } from 'node:url'

const apiURL = 'http://localhost:9000'

// Keep in sync with contentSecurityPolicy in server/dashboard/dashboard.go. The nonce exists only because
// the React Refresh preamble is an inline script in dev; production has no inline scripts.
const devNonce = 'vite-dev'
const devContentSecurityPolicy =
  `default-src 'self'; script-src 'self' 'nonce-${devNonce}'; style-src 'self' 'unsafe-inline'; ` +
  "img-src 'self' data: https: http:; font-src 'self' data:; connect-src 'self'; object-src 'none'; " +
  "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"

// https://vitejs.dev/config/
export default defineConfig(({ command }) => ({
  base: '/dashboard/',
  plugins: [react()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  html: command === 'serve' ? { cspNonce: devNonce } : undefined,
  build: {
    // Embedded into the API binary by server/dashboard
    outDir: '../server/dashboard/ui/dist',
    emptyOutDir: true,
  },
  server: {
    port: 3000,
    headers: {
      'Content-Security-Policy': devContentSecurityPolicy,
    },
    // The dev server mirrors production: the dashboard and the API share one origin
    proxy: {
      '^/(?!dashboard/)': apiURL,
      '/dashboard/config.json': apiURL,
    },
  },
}))
