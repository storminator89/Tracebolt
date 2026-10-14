/** Ordinary hosted CI only. Never a local-browser fallback. No live APIs. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { capture } from './capture-windows-enrollment.mjs';
import { diagnostic, disclosure, requireHosted } from './windows-enrollment-contract.mjs';
import { successfulReport, validateEvidence } from './check-windows-enrollment-evidence.mjs';
requireHosted();
const root = fileURLToPath(new URL('../../', import.meta.url)), require = createRequire(new URL('../package.json', import.meta.url));
const sourceSha = process.env.TRACEBOLT_SOURCE_SHA;
assert(/^[a-f0-9]{40}$/.test(sourceSha)); assert.equal(execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(), sourceSha);
const { chromium, expect } = require('@playwright/test'), output = path.join(root, 'artifacts/review'); await mkdir(output, { recursive: true });
let browser, timer, passed = false, tag = diagnostic('launch'), failure = null;
try {
 await Promise.race([(async () => {
  browser = await chromium.launch({ headless: true });
  const manifest = await capture({ browser, expect, output, onStage: value => { tag = value; } });
  tag = diagnostic('manifest'); await writeFile(path.join(output, 'windows-enrollment-manifest.json'), JSON.stringify({ ...manifest, sourceSha }, null, 2) + '\n');
 })(), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('capture deadline')), 120000); })]);
 passed = true;
} catch { failure = tag; }
finally {
 clearTimeout(timer); try { await browser?.close(); } catch { passed = false; failure ??= diagnostic('close-browser'); }
 const report = passed ? successfulReport(sourceSha) : { sourceSha, status: 'FAIL', browserAcceptance: false, scenes: 0, screenshots: 0, contexts: 0, captureContexts: 0, controlContexts: 0, controlCases: 0, syntheticCreates: 0, requestsToRealAPI: 0, actualMutationRequests: 0, nativeAcceptance: false, disclosure, failure: failure ?? tag };
 const reportFile = path.join(output, 'windows-enrollment-results.json'); await writeFile(reportFile, JSON.stringify(report, null, 2) + '\n');
 if (passed) try { await validateEvidence(output, sourceSha); } catch {
  passed = false; Object.assign(report, { status: 'FAIL', browserAcceptance: false, scenes: 0, screenshots: 0, contexts: 0, captureContexts: 0, controlContexts: 0, controlCases: 0, syntheticCreates: 0, failure: diagnostic('evidence') });
  await writeFile(reportFile, JSON.stringify(report, null, 2) + '\n');
 }
 process.exitCode = passed ? 0 : 1;
 console.log(passed ? 'PASS: eight exact-source synthetic Windows Setup instruction captures; no real actions or native acceptance.' : `FAIL: synthetic Windows enrollment gate ${JSON.stringify(report.failure)}; raw diagnostics withheld.`);
}
