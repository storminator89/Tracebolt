/** Ordinary hosted-CI-only driver. Never use as a local browser fallback. */
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { createRequire } from 'node:module';
import { captureFirstReportFixtures, firstReportMatrix } from './capture-first-report-fixtures.mjs';
import { root, firstReportFailure, firstReportResult, validateFirstReportManifest, validateFirstReportEvidence, verifyFirstReportSource } from './first-report-contract.mjs';
// Refuse before loading Playwright, creating directories or invoking any browser.
if (process.env.GITHUB_ACTIONS !== 'true' || process.env.RUNNER_ENVIRONMENT !== 'github-hosted') {
    console.log('FAIL: hosted CI is required; use the inert recipe --check locally.'); process.exitCode = 1;
} else {
    try { await run(); }
    catch { console.log('FAIL: first-report browser gate; raw diagnostics withheld.'); process.exitCode = 1; }
}
async function run() {
    const sourceSha = process.env.TRACEBOLT_SOURCE_SHA ?? '', sourceTree = verifyFirstReportSource(sourceSha);
    const { chromium, expect } = createRequire(path.join(root, 'web/package.json'))('@playwright/test');
    const output = path.join(root, 'artifacts/review'), temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'tracebolt-first-report-'));
    let browser, timer, work, stopped = false, passed = false, failure = firstReportFailure('launch'), recordedFailure;
    try {
        await fs.mkdir(output, { recursive: true });
        // Do not let same-head output from an earlier invocation describe this run.
        for (const file of ['first-report-results.json', 'first-report-manifest.json', ...firstReportMatrix.map(row => row.file)]) await fs.rm(path.join(output, file), { force: true });
        work = (async () => {
            browser = await chromium.launch({ headless: true, args: ['--no-sandbox'], env: { ...process.env, HOME: temporary, XDG_CONFIG_HOME: temporary, XDG_CACHE_HOME: temporary } });
            if (stopped) { await browser.close(); throw new Error('Stopped capture'); }
            failure = firstReportFailure('capture');
            const manifest = await captureFirstReportFixtures({ browser, expect, output, onCase: coordinate => { assert(!stopped); failure = firstReportFailure('capture', coordinate); } });
            assert(!stopped); failure = firstReportFailure('validate');
            // Bind source provenance, but never replace producer trust flags or hashes.
            for (const row of manifest.captures) row.sourceSha = sourceSha;
            Object.assign(manifest, { sourceSha, sourceTree });
            await validateFirstReportManifest(output, manifest, sourceSha, sourceTree);
            assert.equal(verifyFirstReportSource(sourceSha, manifest.sourceInputs), sourceTree);
            assert(!stopped);
            await fs.writeFile(path.join(output, 'first-report-manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
        })();
        await Promise.race([work, new Promise((_, reject) => { timer = setTimeout(() => { stopped = true; reject(new Error('Hosted first-report gate timed out')); }, 180000); })]);
        passed = true;
    } catch { recordedFailure = { ...failure }; console.log('FAIL: first-report browser gate; raw diagnostics withheld.'); }
    finally {
        clearTimeout(timer); stopped = true;
        try { if (browser) await browser.close(); } catch { if (passed) recordedFailure = firstReportFailure('close'); passed = false; }
        // Drain canceled work before deleting partial evidence; a late continuation
        // must never recreate a manifest after failure cleanup.
        if (work) await work.catch(() => {});
        const resultFile = path.join(output, 'first-report-results.json');
        const writeResult = () => fs.writeFile(resultFile, JSON.stringify(firstReportResult(sourceSha, sourceTree, passed, recordedFailure ?? failure), null, 2) + '\n');
        try {
            await writeResult();
            if (passed) {
                try { await validateFirstReportEvidence(output, sourceSha, sourceTree); }
                catch { passed = false; recordedFailure = firstReportFailure('validate'); await writeResult(); }
            }
            if (!passed) {
                // Partial/invalid images and manifests never become uploadable evidence.
                for (const file of ['first-report-manifest.json', ...firstReportMatrix.map(row => row.file)]) await fs.rm(path.join(output, file), { force: true });
            }
        } finally { await fs.rm(temporary, { recursive: true, force: true }); }
        process.exitCode = passed ? 0 : 1;
        if (passed) console.log(`PASS: ${firstReportMatrix.length} exact-source synthetic first-report EN/DE desktop/mobile captures; no native acceptance.`);
    }
}
