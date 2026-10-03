import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath, URL } from 'node:url'

const apiURL = 'http://localhost:9000'

// https://vitejs.dev/config/
export default defineConfig({
  base: '/dashboard/',
  plugins: [react()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  build: {
    // Embedded into the API binary by server/dashboard
    outDir: '../server/dashboard/ui/dist',
    emptyOutDir: true,
  },
  server: {
    port: 3000,
    // The dev server mirrors production: the dashboard and the API share one origin
    proxy: {
      '^/(?!dashboard/)': apiURL,
      '/dashboard/config.json': apiURL,
    },
  },
})
