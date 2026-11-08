import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { mkdir, copyFile } from 'node:fs/promises';

const cleanDirectoryRoutes = {
  name: 'clean-directory-routes',
  async closeBundle() {
    for (const page of ['portal', 'privacy', 'terms']) {
      await mkdir(`dist/${page}`, { recursive: true });
      await copyFile(`dist/${page}.html`, `dist/${page}/index.html`);
    }
  }
};

export default defineConfig({
  plugins: [react(), cleanDirectoryRoutes],
  build: {
    rollupOptions: {
      input: {
        main: 'index.html',
        portal: 'portal.html',
        privacy: 'privacy.html',
        terms: 'terms.html'
      }
    }
  }
});
