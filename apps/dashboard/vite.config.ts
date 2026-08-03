import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: { host: '127.0.0.1', port: 4173, proxy: { '/v1': 'http://127.0.0.1:4141', '/health': 'http://127.0.0.1:4141' } },
  build: { sourcemap: true }
});
