import { defineConfig } from '../../web/node_modules/vitest/dist/config.js';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
export default defineConfig({
  root,
  esbuild: { jsx: 'automatic' },
  resolve: { alias: { react: path.join(root, 'web/node_modules/react'), 'react-dom': path.join(root, 'web/node_modules/react-dom') } },
  test: { include: ['tests/e2e-review/source.test.tsx'], environment: 'jsdom', setupFiles: ['./web/src/test-setup.ts'], maxWorkers: 1, fileParallelism: false }
});
