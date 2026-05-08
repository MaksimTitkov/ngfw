import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/sync': { target: 'http://localhost:8000', changeOrigin: true },
      '/commit': { target: 'http://localhost:8000', changeOrigin: true },
      '/login': { target: 'http://localhost:8000', changeOrigin: true },
      '/logout': { target: 'http://localhost:8000', changeOrigin: true },
    },
  },
  build: {
    outDir: '../app/static/dist',
    emptyOutDir: true,
  },
})
