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
    coverage: {
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/__tests__/**', 'src/test/**', 'src/types.ts'],
      provider: 'v8',
      reporter: ['text'],
      thresholds: {
        lines: 72,
        branches: 65,
        functions: 71,
        statements: 70,
      },
    },
  },
});
