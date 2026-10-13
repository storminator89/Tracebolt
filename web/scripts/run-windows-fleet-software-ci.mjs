/** Ordinary hosted-CI-only execution; never run this driver in a denied local browser environment. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { capture } from './capture-windows-fleet-software.mjs';
import { root, sha256, sceneManifestSHA256, contract, captureMatrix, disclosure, validateEvidence } from './windows-fleet-software-contract.mjs';
assert(process.env.GITHUB_ACTIONS === 'true' && process.env.RUNNER_ENVIRONMENT === 'github-hosted', 'Hosted CI only; use the inert --check locally.');
const sourceSha = process.env.TRACEBOLT_SOURCE_SHA ?? '';
assert(/^[a-f0-9]{40}$/.test(sourceSha)); assert.equal(execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(), sourceSha);
const require = createRequire(new URL('../package.json', import.meta.url)), { chromium, expect } = require('@playwright/test');
const output = path.join(root, 'artifacts/review'), temporary = await mkdtemp(path.join(os.tmpdir(), 'tracebolt-fleet-software-'));
await mkdir(output, { recursive: true }); let browser, timer, passed = false, failure = { stage: 'launch', captureIndex: null };
const onStage = (stage, captureIndex = null) => { failure = { stage, captureIndex }; };
try {
    await Promise.race([(async () => {
        browser = await chromium.launch({ headless: true, args: ['--no-sandbox'], env: { ...process.env, HOME: temporary, XDG_CONFIG_HOME: temporary, XDG_CACHE_HOME: temporary } });
        const manifest = await capture({ browser, expect, output, onStage });
        onStage('manifest');
        for (const row of manifest.captures) { row.sha256 = sha256(await readFile(path.join(output, row.file))); row.sourceSha = sourceSha; row.publicSafe = true; row.fullPage = false; }
        Object.assign(manifest, { sourceSha, sceneManifestSHA256 });
        await writeFile(path.join(output, 'windows-fleet-software-manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
    })(), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Capture timed out')), 120000); })]);
    passed = true;
} catch { console.log('FAIL: Windows fleet software browser gate; raw diagnostics withheld.'); }
finally {
    clearTimeout(timer); try { if (browser) await browser.close(); } catch { if (passed) onStage('close'); passed = false; }
    const report = { sourceSha, status: passed ? 'PASS' : 'FAIL', browserAcceptance: passed, sceneManifestSHA256, scenes: passed ? contract.scenes.length : 0, screenshots: passed ? captureMatrix.length : 0, requestsToRealAPI: 0, actualMutationRequests: 0, nativeAcceptance: false, disclosure, ...(!passed ? { failure } : {}) };
    const reportFile = path.join(output, 'windows-fleet-software-results.json');
    await writeFile(reportFile, JSON.stringify(report, null, 2) + '\n');
    if (passed) { try { onStage('evidence'); await validateEvidence(output, sourceSha); } catch { passed = false; Object.assign(report, { status: 'FAIL', browserAcceptance: false, scenes: 0, screenshots: 0, failure }); await writeFile(reportFile, JSON.stringify(report, null, 2) + '\n'); } }
    await rm(temporary, { recursive: true, force: true }); process.exitCode = passed ? 0 : 1;
    if (passed) console.log('PASS: eight exact-source Windows fleet software captures; no real request or software mutation.');
}
