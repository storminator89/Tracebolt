import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
export default defineConfig({ plugins: [react()], test: { environment: 'jsdom', environmentOptions: { jsdom: { url: 'https://localhost/' } }, setupFiles: './src/test-setup.ts', css: false } });
