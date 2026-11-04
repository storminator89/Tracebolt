import { defineConfig } from 'vitest/config';

// Bounded server-render contracts only. No DOM or browser setup is loaded.
export default defineConfig({ test: { environment: 'node', include: ['src/device-monitoring-navigation.test.ts'] } });
