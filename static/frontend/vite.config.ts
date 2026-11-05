import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: './', // Essential for Forge Custom UI relative asset resolution
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
});
