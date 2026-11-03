import { defineConfig } from 'vitest/config';

// A bounded Node-only check, without browser, DOM, setup or screenshot jobs.
export default defineConfig({ test: { environment: 'node', include: ['src/incident-work-queue.test.ts'] } });
