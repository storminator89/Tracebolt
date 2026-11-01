/** Inert source/artifact contracts. Generated test PNGs are not browser evidence. */
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { deflateSync } from 'node:zlib';
import { capture, check, compile } from './capture-windows-complete-service-health.mjs';
import { root, captureMatrix, contract, disclosure, sceneManifestSHA256, sha256, evidenceSummary, validateEvidence, assertHostedSource } from './windows-complete-service-health-contract.mjs';
import { captureMatrix as reviewCaptureMatrix } from './windows-complete-service-review-contract.mjs';
function png(width, height) {
    const chunk = (name, bytes) => { const body = Buffer.concat([Buffer.from(name), bytes]); let crc = -1; for (const byte of body) { crc ^= byte; for (let n = 0; n < 8; n++) crc = crc >>> 1 ^ (crc & 1 ? 0xedb88320 : 0); } const result = Buffer.alloc(body.length + 8); result.writeUInt32BE(bytes.length); body.copy(result, 4); result.writeUInt32BE((crc ^ -1) >>> 0, body.length + 4); return result; };
    const header = Buffer.alloc(13); header.writeUInt32BE(width); header.writeUInt32BE(height, 4); header[8] = 8; header[9] = 2;
    return Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]), chunk('IHDR', header), chunk('IDAT', deflateSync(Buffer.alloc((width * 3 + 1) * height))), chunk('IEND', Buffer.alloc(0))]);
}
test('one canonical matrix preserves the eight original component scene filenames/order', () => {
    assert.equal(contract.scenes.length, 2); assert.equal(captureMatrix.length, 8);
    assert.deepEqual(captureMatrix.map(row => row.file), ['en', 'de'].flatMap(locale => [1440, 390].flatMap(width => ['single-beyond-preview', 'group-exact-review'].map(scene => `complete-service-${scene}-${locale}-${width}.png`))));
    assert.match(disclosure, /Real UI components and hooks/); assert.match(disclosure, /not the whole App/);
});
test('canonical evidence coexists with exact review captures and rejects missing, stale, duplicate, foreign or unsafe artifacts', async () => {
    const output = await mkdtemp(path.join(os.tmpdir(), 'complete-service-contract-')), sourceSha = 'a'.repeat(40), compiled = await compile();
    const report = { sourceSha, status: 'PASS', browserAcceptance: true, runtimeErrorCount: 0, requestsToRealAPI: 0, nativeAcceptance: false, secretsExported: false, realTelemetryExported: false, completeServiceHealth: evidenceSummary() };
    const captures = [];
    try {
        for (const row of captureMatrix) { const bytes = png(row.width, row.height); await writeFile(path.join(output, row.file), bytes); captures.push({ ...row, sha256: sha256(bytes), sourceSha, sourceDigest: compiled.sourceDigest, synthetic: true, publicSafe: true, fullPage: false }); }
        const manifest = { sourceSha, sourceDigest: compiled.sourceDigest, sourceInputs: compiled.sourceInputs, sceneManifestSHA256, captures, browserExecuted: true, appMounted: false, actualMutationRequests: 0, nativeAcceptance: false, disclosure };
        const write = async (summary = report, value = manifest) => { await writeFile(path.join(output, 'windows-service-actions-results.json'), JSON.stringify(summary)); await writeFile(path.join(output, 'windows-complete-service-health-manifest.json'), JSON.stringify(value)); };
        await write(); await validateEvidence(output, sourceSha);
        // Health validates before review capture, then again after the shared runner.
        // Only exact sibling filenames may coexist, including a partial capture on failure.
        assert.equal(new Set([...captureMatrix, ...reviewCaptureMatrix].map(row => row.file)).size, captureMatrix.length + reviewCaptureMatrix.length);
        for (const row of reviewCaptureMatrix) { await writeFile(path.join(output, row.file), png(row.width, row.height)); await validateEvidence(output, sourceSha); }
        for (const name of ['complete-service-foreign.png', 'complete-service-review-foreign.png', 'complete-service-review-matched-read-fr-390.png', reviewCaptureMatrix[0].file.replace('.png', '-extra.png')]) {
            const foreign = path.join(output, name);
            await writeFile(foreign, png(390, 844)); await assert.rejects(validateEvidence(output, sourceSha));
            await rm(foreign); await validateEvidence(output, sourceSha);
        }
        for (const [key, value] of [['sourceSha', 'b'.repeat(40)], ['status', 'FAIL'], ['browserAcceptance', false], ['runtimeErrorCount', 1], ['requestsToRealAPI', 1], ['nativeAcceptance', true], ['secretsExported', true], ['realTelemetryExported', true], ['completeServiceHealth', null]]) { await write({ ...report, [key]: value }); await assert.rejects(validateEvidence(output, sourceSha)); }
        for (const [key, value] of [['screenshots', 7], ['screenshots', true], ['scenes', 1], ['sceneManifestSHA256', '0'.repeat(64)], ['appMounted', true], ['browserExecuted', false], ['actualMutationRequests', 1]]) { await write({ ...report, completeServiceHealth: { ...report.completeServiceHealth, [key]: value } }); await assert.rejects(validateEvidence(output, sourceSha)); }
        for (const value of [
            { ...manifest, sourceSha: 'b'.repeat(40) }, { ...manifest, sceneManifestSHA256: '0'.repeat(64) },
            { ...manifest, captures: captures.slice(1) }, { ...manifest, captures: [captures[0], captures[0], ...captures.slice(2)] },
            { ...manifest, captures: [...captures].reverse() }, { ...manifest, browserExecuted: false }, { ...manifest, appMounted: true },
            { ...manifest, actualMutationRequests: 1 }, { ...manifest, sourceInputs: [] }, { ...manifest, sourceDigest: '0'.repeat(64) },
            { ...manifest, sourceInputs: compiled.sourceInputs.slice(1), sourceDigest: sha256(JSON.stringify(compiled.sourceInputs.slice(1))) },
            ...[['file', '../foreign.png'], ['file', 'foreign.png'], ['sha256', '0'.repeat(64)], ['sourceSha', 'b'.repeat(40)], ['sourceDigest', '0'.repeat(64)], ['width', 390], ['height', 1000], ['locale', 'fr'], ['publicSafe', false], ['synthetic', false], ['fullPage', true]].map(([key, value]) => ({ ...manifest, captures: [{ ...captures[0], [key]: value }, ...captures.slice(1)] }))
        ]) { await write(report, value); await assert.rejects(validateEvidence(output, sourceSha)); }
        await write(); const first = captures[0], file = path.join(output, first.file), bytes = await readFile(file);
        await rm(file); await assert.rejects(validateEvidence(output, sourceSha));
        const target = path.join(output, 'inert-foreign-target.png'); await writeFile(target, bytes); await symlink(target, file); await assert.rejects(validateEvidence(output, sourceSha)); await rm(file); await rm(target);
        await writeFile(file, png(390, 844)); await assert.rejects(validateEvidence(output, sourceSha));
        for (const index of [0, 12, bytes.length - 1]) { const altered = Buffer.from(bytes); altered[index] ^= 1; await writeFile(file, altered); await assert.rejects(validateEvidence(output, sourceSha)); }
        await writeFile(file, bytes); await validateEvidence(output, sourceSha);
    } finally { await rm(output, { recursive: true, force: true }); }
});
test('inert DTO/router check denies policy writes and external requests without browser execution', async () => {
    const result = await check(); assert.equal(result.browserExecuted, false); assert.equal(result.nativeAcceptance, false);
});
test('hosted-only admission rejects before any browser or source subprocess is touched', async () => {
    const previous = process.env.GITHUB_ACTIONS; process.env.GITHUB_ACTIONS = 'false';
    try {
        await assert.rejects(capture({ browser: { newContext() { assert.fail('Browser must remain unused'); } }, expect: null, output: os.tmpdir() }), /Hosted CI only/);
        await assert.rejects(assertHostedSource('a'.repeat(40)), /Hosted CI only/);
    } finally { if (previous === undefined) delete process.env.GITHUB_ACTIONS; else process.env.GITHUB_ACTIONS = previous; }
});
test('existing hosted runner invokes additive capture inside its unchanged timeout and failure boundary', async () => {
    const read = file => readFile(path.join(root, file), 'utf8'), runner = await read('tests/e2e-review/windows-service-actions-runner.mjs'), source = await read('web/scripts/capture-windows-complete-service-health.mjs');
    assert(runner.indexOf('await assertHostedSource(sourceSha)') < runner.indexOf('server=createServer'));
    assert.match(runner, /captureCompleteServiceHealth\(\{browser,expect,output:out\}\)/);
    assert.match(runner, /await validateCompleteServiceManifest\(out,sourceSha,completeServiceHealthManifest\)/);
    assert.match(runner, /completeServiceHealth:passed\?completeServiceEvidenceSummary\(\):null/);
    assert.equal((runner.match(/120000/g) ?? []).length, 1);
    for (const name of ['ServiceActions', 'ServiceActionHistory', 'UpdateJobs', 'UpdateDownload', 'UpdateRetirement', 'UpdateSchedule', 'BackgroundUpdateSchedule', 'FleetUpdateSchedule', 'SoftwareJobs']) assert(runner.includes(`requireWindows${name}Evidence(`));
    assert.match(runner, /catch\{await writeFailure\(\);/); assert.match(runner, /process.exitCode=passed\?0:1/);
    assert.match(source, /for \(const \{ locale, width, height, scene, file \} of captureMatrix\)/);
    assert.match(source, /assert.deepEqual\(errors, \[\]\); assert.equal\(state.external \+ state.writes \+ state.unexpected, 0\); assert.equal\(state.queries, 2\)/);
    assert.match(source, /finally \{ await context.close\(\); \}/);
    assert.doesNotMatch(source, /route\.continue|route\.fetch|ignoreHTTPSErrors|grantPermissions|createServer/);
    // Uploaders run even on failure: only canonical filenames may ever leave CI.
    for (const name of ['pr-checks.yml', 'validate.yml']) {
        const workflow = await read(`.github/workflows/${name}`);
        const images = workflow.split('\n').map(line => line.trim()).filter(line => line.startsWith('artifacts/review/complete-service-') && line.endsWith('.png'));
        // The integrated review scenes share this prefix; admit only both exact canonical matrices.
        assert.deepEqual(images, [...reviewCaptureMatrix, ...captureMatrix].map(row => `artifacts/review/${row.file}`));
        assert(!workflow.includes('artifacts/review/complete-service-*.png'));
    }
});
