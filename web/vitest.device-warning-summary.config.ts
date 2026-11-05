import { defineConfig } from 'vitest/config';

// Bounded server-render checks only: no browser, DOM or interaction setup.
export default defineConfig({ test: { environment: 'node', include: ['src/device-warning-summary.test.ts'] } });
