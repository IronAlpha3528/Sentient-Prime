import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: process.env.VITE_API_TARGET || (process.env.DOCKER_ENV ? 'http://api:8000' : 'http://localhost:8000'),
        changeOrigin: true,
      },
    },
  },
})
