import { configDefaults, defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import environments from './test-environments.json';

// Only individually verified DOM-free contracts move to Node. Every other
// default-discovered test stays in jsdom, including newly added interaction files.
const nodeFiles = environments.nodeFiles;
export default defineConfig({
    plugins: [react()],
    test: {
        environment: 'jsdom',
        environmentOptions: { jsdom: { url: 'https://localhost/' } },
        setupFiles: './src/test-setup.ts',
        css: false,
        projects: [
            { extends: true, test: { name: 'node-contracts', environment: 'node', include: nodeFiles } },
            { extends: true, test: { name: 'browser-interactions', environment: 'jsdom', exclude: [...configDefaults.exclude, ...nodeFiles] } },
        ],
    },
});
