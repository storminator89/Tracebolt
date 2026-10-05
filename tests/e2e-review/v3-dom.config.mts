import { defineConfig } from '../../web/node_modules/vitest/dist/config.js';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
export default defineConfig({
    root,
    esbuild: { jsx: 'automatic' },
    resolve: { alias: { vitest: path.join(root, 'web/node_modules/vitest/dist/index.js'), react: path.join(root, 'web/node_modules/react'), 'react-dom': path.join(root, 'web/node_modules/react-dom') } },
    test: { env: { TRACEBOLT_V3_DOM_ROOT: root }, include: ['tests/e2e-review/v3-read-coordination.test.tsx'], environment: 'jsdom', environmentOptions: { jsdom: { url: 'http://127.0.0.1/' } }, setupFiles: ['./web/src/test-setup.ts'], maxWorkers: 1, fileParallelism: false, testTimeout: 15000 }
});
