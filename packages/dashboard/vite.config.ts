import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3400,
    proxy: {
      '/v1': {
        target: 'http://localhost:3200',
        changeOrigin: true,
      },
      '/api': {
        target: 'http://localhost:3401',
        changeOrigin: true,
      },
    },
  },
});
