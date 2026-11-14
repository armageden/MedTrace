import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: './', // Essential for Forge Custom UI relative asset resolution
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules/@xyflow/') || id.includes('node_modules/d3-')) {
            return 'vendor-xyflow';
          }
          if (
            id.includes('node_modules/react-dom/') ||
            id.includes('node_modules/react/') ||
            id.includes('node_modules/scheduler/')
          ) {
            return 'vendor-react';
          }
          if (id.includes('node_modules/@forge/') || id.includes('node_modules/@atlaskit/')) {
            return 'vendor-forge';
          }
          return undefined;
        },
      },
    },
  },
});
