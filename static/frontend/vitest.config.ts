import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

process.env.NODE_ENV = 'test';

export default defineConfig({
  plugins: [react()],
  mode: 'test',
  define: {
    'process.env.NODE_ENV': JSON.stringify('test'),
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    globals: true,
  },
});
