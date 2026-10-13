/** Inert source/artifact contracts. Generated test PNGs are not browser evidence. */
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { deflateSync } from 'node:zlib';
import { capture, check, compile, fixture } from './capture-windows-complete-incident-inbox.mjs';
import { root, captureMatrix, contract, disclosure, sceneManifestSHA256, sha256, evidenceSummary, validateEvidence, assertHostedSource } from './windows-complete-incident-inbox-contract.mjs';
function png(width, height) {
    const chunk = (name, bytes) => { const body = Buffer.concat([Buffer.from(name), bytes]); let crc = -1; for (const byte of body) { crc ^= byte; for (let n = 0; n < 8; n++) crc = crc >>> 1 ^ (crc & 1 ? 0xedb88320 : 0); } const result = Buffer.alloc(body.length + 8); result.writeUInt32BE(bytes.length); body.copy(result, 4); result.writeUInt32BE((crc ^ -1) >>> 0, body.length + 4); return result; };
    const header = Buffer.alloc(13); header.writeUInt32BE(width); header.writeUInt32BE(height, 4); header[8] = 8; header[9] = 2;
    return Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]), chunk('IHDR', header), chunk('IDAT', deflateSync(Buffer.alloc((width * 3 + 1) * height))), chunk('IEND', Buffer.alloc(0))]);
}
test('one canonical matrix preserves the eight changed incident scene filenames/order', () => {
    assert.equal(contract.scenes.length, 2); assert.equal(captureMatrix.length, 8);
    assert.deepEqual(captureMatrix.map(row => row.file), ['en', 'de'].flatMap(locale => [1440, 390].flatMap(width => ['active', 'unknown'].map(scene => `complete-incident-inbox-${scene}-${locale}-${width}.png`))));
    assert.match(disclosure, /actual inbox component and protected request adapter/); assert.match(disclosure, /not the whole App/);
});
test('canonical evidence fails closed on missing, stale, duplicate, foreign or unsafe artifacts', async () => {
    const output = await mkdtemp(path.join(os.tmpdir(), 'complete-incident-inbox-contract-')), sourceSha = 'a'.repeat(40), sourceTree = 'c'.repeat(40), compiled = await compile();
    const report = { sourceSha, status: 'PASS', browserAcceptance: true, runtimeErrorCount: 0, requestsToRealAPI: 0, nativeAcceptance: false, secretsExported: false, realTelemetryExported: false, completeIncidentInbox: evidenceSummary() };
    const captures = [];
    try {
        for (const row of captureMatrix) { const bytes = png(row.width, row.height); await writeFile(path.join(output, row.file), bytes); captures.push({ ...row, sha256: sha256(bytes), sourceSha, sourceTree, sourceDigest: compiled.sourceDigest, synthetic: true, publicSafe: true, fullPage: false }); }
        const manifest = { sourceSha, sourceTree, sourceDigest: compiled.sourceDigest, sourceInputs: compiled.sourceInputs, sceneManifestSHA256, captures, browserExecuted: true, appMounted: false, actualMutationRequests: 0, nativeAcceptance: false, disclosure };
        const write = async (summary = report, value = manifest) => { await writeFile(path.join(output, 'windows-service-actions-results.json'), JSON.stringify(summary)); await writeFile(path.join(output, 'windows-complete-incident-inbox-manifest.json'), JSON.stringify(value)); };
        await write(); await validateEvidence(output, sourceSha, sourceTree);
        const foreign = path.join(output, 'complete-incident-inbox-foreign.png');
        await writeFile(foreign, png(390, 844)); await assert.rejects(validateEvidence(output, sourceSha, sourceTree));
        await rm(foreign); await validateEvidence(output, sourceSha, sourceTree);
        for (const [key, value] of [['sourceSha', 'b'.repeat(40)], ['status', 'FAIL'], ['browserAcceptance', false], ['runtimeErrorCount', 1], ['requestsToRealAPI', 1], ['nativeAcceptance', true], ['secretsExported', true], ['realTelemetryExported', true], ['completeIncidentInbox', null]]) { await write({ ...report, [key]: value }); await assert.rejects(validateEvidence(output, sourceSha, sourceTree)); }
        for (const [key, value] of [['screenshots', 7], ['screenshots', true], ['scenes', 1], ['sceneManifestSHA256', '0'.repeat(64)], ['appMounted', true], ['browserExecuted', false], ['actualMutationRequests', 1]]) { await write({ ...report, completeIncidentInbox: { ...report.completeIncidentInbox, [key]: value } }); await assert.rejects(validateEvidence(output, sourceSha, sourceTree)); }
        for (const value of [
            { ...manifest, sourceSha: 'b'.repeat(40) }, { ...manifest, sourceTree: 'b'.repeat(40) }, { ...manifest, sceneManifestSHA256: '0'.repeat(64) },
            { ...manifest, captures: captures.slice(1) }, { ...manifest, captures: [captures[0], captures[0], ...captures.slice(2)] },
            { ...manifest, captures: [...captures].reverse() }, { ...manifest, browserExecuted: false }, { ...manifest, appMounted: true },
            { ...manifest, actualMutationRequests: 1 }, { ...manifest, sourceInputs: [] }, { ...manifest, sourceDigest: '0'.repeat(64) },
            { ...manifest, sourceInputs: compiled.sourceInputs.slice(1), sourceDigest: sha256(JSON.stringify(compiled.sourceInputs.slice(1))) },
            ...[['file', '../foreign.png'], ['file', 'foreign.png'], ['sha256', '0'.repeat(64)], ['sourceSha', 'b'.repeat(40)], ['sourceTree', 'b'.repeat(40)], ['sourceDigest', '0'.repeat(64)], ['width', 390], ['height', 1000], ['locale', 'fr'], ['publicSafe', false], ['synthetic', false], ['fullPage', true]].map(([key, value]) => ({ ...manifest, captures: [{ ...captures[0], [key]: value }, ...captures.slice(1)] }))
        ]) { await write(report, value); await assert.rejects(validateEvidence(output, sourceSha, sourceTree)); }
        await write(); const first = captures[0], file = path.join(output, first.file), bytes = await readFile(file);
        await rm(file); await assert.rejects(validateEvidence(output, sourceSha, sourceTree));
        await writeFile(file, png(390, 844)); await assert.rejects(validateEvidence(output, sourceSha, sourceTree));
        await writeFile(file, bytes); await validateEvidence(output, sourceSha, sourceTree);
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
    const read = file => readFile(path.join(root, file), 'utf8'), runner = await read('tests/e2e-review/windows-service-actions-runner.mjs'), source = await read('web/scripts/capture-windows-complete-incident-inbox.mjs');
    assert(runner.indexOf('await assertHostedSource(sourceSha)') < runner.indexOf('server=createServer'));
    assert.match(runner, /captureCompleteIncidentInbox\(\{browser,expect,output:out,sourceSha\}\)/);
    assert.match(source, /await validateManifest\(output, sourceSha, sourceTree, manifest\)/);
    assert.match(runner, /completeIncidentInbox:passed\?completeIncidentEvidenceSummary\(\):null/);
    assert.equal((runner.match(/120000/g) ?? []).length, 1);
    for (const name of ['ServiceActions', 'ServiceActionHistory', 'UpdateJobs', 'UpdateDownload', 'UpdateRetirement', 'UpdateSchedule', 'BackgroundUpdateSchedule', 'FleetUpdateSchedule', 'SoftwareJobs']) assert(runner.includes(`requireWindows${name}Evidence(`));
    assert.match(runner, /catch\{await writeFailure\(\);/); assert.match(runner, /process.exitCode=passed\?0:1/);
    assert.match(source, /for \(const \{ locale, width, height, scene, file \} of captureMatrix\)/);
    assert.match(source, /assert.deepEqual\(errors, \[\]\); assert.equal\(state.external \+ state.writes \+ state.unexpected, 0\); assert.equal\(state.reads, 1\)/);
    assert.match(source, /finally \{ await context.close\(\); \}/);
    assert.doesNotMatch(source, /route\.continue|route\.fetch|ignoreHTTPSErrors|grantPermissions|createServer|fullPage: true/);
    assert.match(source, /rect\.bottom <= innerHeight \+ 1/);
    assert.match(source, /parseFloat\(style\.fontSize\) >= 11/);
    assert.match(source, /item\.scrollWidth <= item\.clientWidth \+ 1/);
    assert.match(source, /scrollIntoView\(\{ block: 'center'/);
    assert.match(source, /toHaveCount\(0\)/);
    // Uploaders run even on failure: only canonical filenames may ever leave CI.
    for (const name of ['pr-checks.yml', 'validate.yml']) {
        const workflow = await read(`.github/workflows/${name}`);
        const images = workflow.split('\n').map(line => line.trim()).filter(line => line.startsWith('artifacts/review/complete-incident-inbox-') && line.endsWith('.png'));
        assert.deepEqual(images, captureMatrix.map(row => `artifacts/review/${row.file}`));
        assert(!workflow.includes('artifacts/review/complete-incident-inbox-*.png'));
    }
});

test('scene names bind active/unseen and unknown/seen complete-source Go rows', async () => {
    const active = (await fixture('active', '2026-10-13T12:00:00Z')).view;
    const unknown = (await fixture('unknown', '2026-10-13T12:00:00Z')).view;
    for (const view of [active, unknown]) {
        assert.equal(view.schemaVersion, 'tracebolt.windows-incident-inbox.v2');
        assert.equal(view.items.length, 1); const item = view.items[0];
        assert.equal(item.sourceKind, 'windows_full_services'); assert.equal(item.domain, 'service-complete');
        assert.equal(item.resolvedAt, null); assert(item.serviceName.length > 64);
    }
    assert.equal(active.items[0].status, 'attention'); assert.equal(active.items[0].acknowledgedAt, null);
    assert.equal(unknown.items[0].status, 'unknown'); assert(unknown.items[0].acknowledgedAt); assert.equal(unknown.items[0].currentSource, null);
});
