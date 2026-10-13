/** Inert source/artifact contracts. Generated test PNGs are not browser evidence. */
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { deflateSync } from 'node:zlib';
import { capture, check, compile, fixture, origin, routeFixture, routeState } from './capture-windows-complete-notifications.mjs';
import { root, captureMatrix, contract, disclosure, sceneManifestSHA256, sha256, evidenceSummary, validateEvidence, assertHostedSource } from './windows-complete-notifications-contract.mjs';
function png(width, height) {
    const chunk = (name, bytes) => { const body = Buffer.concat([Buffer.from(name), bytes]); let crc = -1; for (const byte of body) { crc ^= byte; for (let n = 0; n < 8; n++) crc = crc >>> 1 ^ (crc & 1 ? 0xedb88320 : 0); } const result = Buffer.alloc(body.length + 8); result.writeUInt32BE(bytes.length); body.copy(result, 4); result.writeUInt32BE((crc ^ -1) >>> 0, body.length + 4); return result; };
    const header = Buffer.alloc(13); header.writeUInt32BE(width); header.writeUInt32BE(height, 4); header[8] = 8; header[9] = 2;
    return Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]), chunk('IHDR', header), chunk('IDAT', deflateSync(Buffer.alloc((width * 3 + 1) * height))), chunk('IEND', Buffer.alloc(0))]);
}
test('one canonical matrix preserves sixteen complete notification scenes and filenames', () => {
    assert.equal(contract.scenes.length, 4); assert.equal(captureMatrix.length, 16);
    assert.deepEqual(captureMatrix.map(row => row.file), ['en', 'de'].flatMap(locale => [1440, 390].flatMap(width => ['review', 'unknown', 'named', 'uncertain'].map(scene => `complete-notifications-${scene}-${locale}-${width}.png`))));
    assert.match(disclosure, /Real collapsed notification panel/); assert.match(disclosure, /not the whole App/);
});
test('canonical evidence fails closed on missing, stale, duplicate, foreign or unsafe artifacts', async () => {
    const output = await mkdtemp(path.join(os.tmpdir(), 'complete-service-contract-')), sourceSha = 'a'.repeat(40), sourceTree = 'c'.repeat(40), compiled = await compile();
    const report = { sourceSha, status: 'PASS', browserAcceptance: true, runtimeErrorCount: 0, requestsToRealAPI: 0, nativeAcceptance: false, secretsExported: false, realTelemetryExported: false, completeNotifications: evidenceSummary() };
    const captures = [];
    try {
        for (const row of captureMatrix) { const bytes = png(row.width, row.height); await writeFile(path.join(output, row.file), bytes); captures.push({ ...row, sha256: sha256(bytes), sourceSha, sourceTree, sourceDigest: compiled.sourceDigest, synthetic: true, publicSafe: true, fullPage: false }); }
        const manifest = { sourceSha, sourceTree, sourceDigest: compiled.sourceDigest, sourceInputs: compiled.sourceInputs, sceneManifestSHA256, captures, browserExecuted: true, appMounted: false, actualMutationRequests: 0, nativeAcceptance: false, disclosure };
        const write = async (summary = report, value = manifest) => { await writeFile(path.join(output, 'windows-service-actions-results.json'), JSON.stringify(summary)); await writeFile(path.join(output, 'windows-complete-notifications-manifest.json'), JSON.stringify(value)); };
        await write(); await validateEvidence(output, sourceSha, sourceTree);
        const foreign = path.join(output, 'complete-notifications-foreign.png');
        await writeFile(foreign, png(390, 844)); await assert.rejects(validateEvidence(output, sourceSha, sourceTree));
        await rm(foreign); await validateEvidence(output, sourceSha, sourceTree);
        for (const [key, value] of [['sourceSha', 'b'.repeat(40)], ['status', 'FAIL'], ['browserAcceptance', false], ['runtimeErrorCount', 1], ['requestsToRealAPI', 1], ['nativeAcceptance', true], ['secretsExported', true], ['realTelemetryExported', true], ['completeNotifications', null]]) { await write({ ...report, [key]: value }); await assert.rejects(validateEvidence(output, sourceSha, sourceTree)); }
        for (const [key, value] of [['screenshots', 7], ['screenshots', true], ['scenes', 1], ['sceneManifestSHA256', '0'.repeat(64)], ['appMounted', true], ['browserExecuted', false], ['actualMutationRequests', 1]]) { await write({ ...report, completeNotifications: { ...report.completeNotifications, [key]: value } }); await assert.rejects(validateEvidence(output, sourceSha, sourceTree)); }
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
        const target = path.join(output, 'inert-foreign-target.png'); await writeFile(target, bytes);
        await symlink(target, file); await assert.rejects(validateEvidence(output, sourceSha, sourceTree));
        await rm(file); await rm(target);
        await writeFile(file, png(390, 844)); await assert.rejects(validateEvidence(output, sourceSha, sourceTree));
        await writeFile(file, bytes); await validateEvidence(output, sourceSha, sourceTree);
    } finally { await rm(output, { recursive: true, force: true }); }
});
test('inert DTO/router check limits invented uncertain POST and denies real writes and external requests without browser execution', async () => {
    const result = await check(); assert.equal(result.browserExecuted, false); assert.equal(result.nativeAcceptance, false);
});
test('hosted-only admission rejects before any browser or source subprocess is touched', async () => {
    const previous = process.env.GITHUB_ACTIONS; process.env.GITHUB_ACTIONS = 'false';
    try {
        await assert.rejects(capture({ browser: { newContext() { assert.fail('Browser must remain unused'); } }, expect: null, output: os.tmpdir() }), /Hosted CI only/);
        await assert.rejects(assertHostedSource('a'.repeat(40)), /Hosted CI only/);
    } finally { if (previous === undefined) delete process.env.GITHUB_ACTIONS; else process.env.GITHUB_ACTIONS = previous; }
});
test('producer mounts the real collapsed panel and cannot route through to a real endpoint', async () => {
    const source = await readFile(path.join(root, 'web/scripts/capture-windows-complete-notifications.mjs'), 'utf8');
    assert.match(source, /import \{ WindowsNotifications \} from '\.\/windows-notifications'/);
    assert.match(source, /<WindowsNotifications devices=/);
    assert.match(source, /for \(const \{ locale, width, height, scene, file \} of captureMatrix\)/);
    assert.match(source, /assert\.equal\(state\.interceptedPosts, scene === 'uncertain' \? 1 : 0\)/);
    assert.match(source, /finally \{ await context.close\(\); \}/);
    assert.doesNotMatch(source, /route\.continue|route\.fetch|ignoreHTTPSErrors|grantPermissions|createServer/);
});


test('one shared hosted capture keeps original failure gates, exact-source checker and canonical uploads', async () => {
    const read = file => readFile(path.join(root, file), 'utf8');
    const runner = await read('tests/e2e-review/windows-service-actions-runner.mjs');
    const producer = await read('web/scripts/capture-windows-complete-notifications.mjs');
    const checker = await read('web/scripts/check-windows-complete-notifications-evidence.mjs');
    const diagnostics = JSON.parse(await read('tests/e2e-review/windows-service-actions-diagnostics.json'));
    assert(runner.indexOf('await assertHostedSource(sourceSha)') < runner.indexOf('server=createServer'));
    assert.equal((runner.match(/captureCompleteNotifications\(\{browser,expect,output:out,sourceSha\}\)/g) ?? []).length, 1);
    assert.match(runner, /completeNotifications:passed\?completeNotificationEvidenceSummary\(\):null/);
    assert.match(runner, /diagnostic.begin\('runner',null,null,'complete-notifications'\)/);
    assert(diagnostics.cases.runner.includes('complete-notifications'));
    assert.equal((runner.match(/120000/g) ?? []).length, 1);
    for (const name of ['ServiceActions', 'ServiceActionHistory', 'UpdateJobs', 'UpdateDownload', 'UpdateRetirement', 'UpdateSchedule', 'BackgroundUpdateSchedule', 'FleetUpdateSchedule', 'SoftwareJobs']) assert(runner.includes(`requireWindows${name}Evidence(`));
    assert.match(runner, /catch\{await writeFailure\(\);/); assert.match(runner, /process.exitCode=passed\?0:1/);
    assert.match(producer, /await validateManifest\(output, sourceSha, sourceTree, manifest\)/);
    assert.match(producer, /assert.equal\(await assertHostedSource\(sourceSha, compiled.sourceInputs\), sourceTree\)/);
    assert.match(checker, /const sourceTree = await assertHostedSource\(process.argv\[2\]\)/);
    assert.match(checker, /validateEvidence\(path.join\(root, 'artifacts\/review'\), process.argv\[2\], sourceTree\)/);
    assert.match(checker, /assert.equal\(await assertHostedSource\(process.argv\[2\], manifest.sourceInputs\), sourceTree\)/);
    assert.match(producer, /expect\(approval\).not.toBeChecked\(\)/);
    assert.match(producer, /expect\(confirm\).toBeDisabled\(\)/);
    assert.match(producer, /if \(scene === 'review'\)[\s\S]*?toBeInViewport\(\{ ratio: 1 \}\)/);
    assert.match(producer, /state.reads, scene === 'uncertain' \? 3 : 1/);
    assert.doesNotMatch(producer, /fullPage: true|route\.continue|route\.fetch|ignoreHTTPSErrors|grantPermissions|createServer/);
    for (const name of ['pr-checks.yml', 'validate.yml']) {
        const workflow = await read(`.github/workflows/${name}`);
        const images = workflow.split('\n').map(line => line.trim()).filter(line => line.startsWith('artifacts/review/complete-notifications-') && line.endsWith('.png'));
        assert.deepEqual(images, captureMatrix.map(row => `artifacts/review/${row.file}`));
        assert.equal((workflow.match(/artifacts\/review\/windows-complete-notifications-manifest.json/g) ?? []).length, 1);
        assert(!workflow.includes('artifacts/review/complete-notifications-*.png'));
        assert(!workflow.includes('capture-windows-complete-notifications.mjs --capture'));
    }
});

test('all unapproved scenes deny complete policy writes and only uncertainty admits one exact failed synthetic POST', async () => {
    const compiled = await compile();
    assert.match(disclosure, /one intercepted failed policy request and GET-only reconciliation/);
    for (const scene of contract.scenes) {
        const data = await fixture(scene, '2026-10-13T12:00:00Z'), state = routeState(), route = routeFixture(data, compiled, state);
        const target = data.view.targets[0], body = { key: target.key, revision: target.revision, enabled: true, destinationBinding: data.view.destinationBinding, payloadAcknowledged: true };
        const aborted = [];
        const post = (url = origin + '/api/fleet/windows-notifications/complete/policy', value = body) => ({
            request: () => ({ url: () => url, method: () => 'POST', postData: () => JSON.stringify(value), headers: () => ({ 'x-csrf-token': data.session.csrfToken, 'content-type': 'application/json' }) }),
            fulfill: () => assert.fail('No policy write may reach a successful response'), abort: reason => aborted.push(reason),
        });
        await route(post('https://untrusted.invalid/api/fleet/windows-notifications/complete/policy'));
        assert.equal(state.external, 1); assert.equal(state.interceptedPosts, 0);
        if (scene === 'uncertain') {
            await assert.rejects(route(post(undefined, { ...body, payloadAcknowledged: false })));
            assert.equal(state.interceptedPosts, 0);
            await route(post()); assert.equal(state.interceptedPosts, 1); assert.equal(state.writes, 0);
            await assert.rejects(route(post())); assert.equal(state.interceptedPosts, 1);
            assert.deepEqual(aborted, ['blockedbyclient', 'failed']);
        } else {
            await route(post()); assert.equal(state.interceptedPosts, 0); assert.equal(state.writes, 1);
            assert.deepEqual(aborted, ['blockedbyclient', 'blockedbyclient']);
        }
        assert.equal(data.bootstrap.admin, scene !== 'named');
        assert.equal(target.enabled, scene === 'unknown'); assert.equal(target.effective, false);
        assert.equal(target.actionable, scene !== 'unknown');
    }
});

test('container typecheck receives only the exact new synthetic notification fixture', async () => {
    const fixture = 'tests/fixtures/windows-complete-notifications-view.json';
    const docker = await readFile(path.join(root, 'Dockerfile'), 'utf8');
    const ignore = await readFile(path.join(root, '.dockerignore'), 'utf8');
    assert.equal(docker.split('\n').filter(line => line === `COPY ${fixture} /src/${fixture}`).length, 1);
    assert.equal(ignore.split('\n').filter(line => line === `!${fixture}`).length, 1);
    assert(ignore.includes('\ntests/fixtures/**\n'));
    assert(!ignore.includes('!tests/fixtures/**'));
    assert(docker.indexOf(`COPY ${fixture} /src/${fixture}`) < docker.indexOf('RUN npm run build'));
});
