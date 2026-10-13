/** Ordinary approved hosted CI only. Does not run on local executors. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { capture, captureMatrix, disclosure, scenes } from './capture-macos-inventory.mjs';
import { validateEvidence } from './check-macos-inventory-evidence.mjs';
const root = fileURLToPath(new URL('../../', import.meta.url)), require = createRequire(new URL('../package.json', import.meta.url));
assert(process.env.GITHUB_ACTIONS === 'true' && process.env.RUNNER_ENVIRONMENT === 'github-hosted', 'Hosted CI only; use --check locally.');
const sourceSha = process.env.TRACEBOLT_SOURCE_SHA; assert(/^[a-f0-9]{40}$/.test(sourceSha)); assert.equal(execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(), sourceSha);
const { chromium, expect } = require('@playwright/test'), output = path.join(root, 'artifacts/review'); await mkdir(output, { recursive: true });
let browser, timer, passed = false;
try {
 await Promise.race([(async () => { browser = await chromium.launch({ headless: true }); const manifest = await capture({ browser, expect, output }); await writeFile(path.join(output, 'macos-inventory-manifest.json'), JSON.stringify({ ...manifest, sourceSha }, null, 2) + '\n'); })(), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('deadline')), 180000); })]); passed = true;
} catch { /* Raw diagnostics can contain captured private material; never print them. */ }
finally {
 clearTimeout(timer); try { await browser?.close(); } catch { passed = false; }
 const report = { sourceSha, status: passed ? 'PASS' : 'FAIL', browserAcceptance: passed, scenes: passed ? scenes.length : 0, screenshots: passed ? captureMatrix.length : 0, requestsToRealAPI: 0, actualMutationRequests: 0, nativeAcceptance: false, disclosure };
 const file = path.join(output, 'macos-inventory-results.json'); await writeFile(file, JSON.stringify(report, null, 2) + '\n');
 if (passed) { try { await validateEvidence(output, sourceSha); } catch { passed = false; Object.assign(report, { status: 'FAIL', browserAcceptance: false, scenes: 0, screenshots: 0 }); await writeFile(file, JSON.stringify(report, null, 2) + '\n'); } }
 console.log(passed ? `PASS: ${captureMatrix.length} synthetic exact-source Mac inventory captures; no real actions or native acceptance.` : 'FAIL: synthetic Mac inventory capture; raw diagnostics withheld.'); process.exitCode = passed ? 0 : 1;
}
