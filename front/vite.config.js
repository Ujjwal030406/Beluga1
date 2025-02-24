import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    tailwindcss(),
    react()],
    server: {
      proxy: {
        "/api": {
          target: "http://localhost:8000",  // Change this to match your FastAPI backend URL
          changeOrigin: true,
          secure: false,  // Use false if the backend does not use HTTPS
          rewrite: (path) => path.replace(/^\/api/, ""),
        },
      },
    },
})
