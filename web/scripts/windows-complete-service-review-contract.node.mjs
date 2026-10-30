/** Inert contracts only. Generated blank PNGs test artifacts, not browser pixels. */
import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { deflateSync } from 'node:zlib';
import { capture, check, compile } from './capture-windows-complete-service-review.mjs';
import { root, captureMatrix, assertionMatrix, assertionEvidence, contract, disclosure, sceneManifestSHA256, sha256, evidenceSummary, validateEvidence, assertHostedSource, dependencyPackagePath, validateDependencyBindings, validateTrackedInput } from './windows-complete-service-review-contract.mjs';
let compilation;
const compiledSource = () => compilation ??= compile();
function png(width, height) {
    const chunk = (name, bytes) => { const body = Buffer.concat([Buffer.from(name), bytes]); let crc = -1; for (const byte of body) { crc ^= byte; for (let n = 0; n < 8; n++) crc = crc >>> 1 ^ (crc & 1 ? 0xedb88320 : 0); } const result = Buffer.alloc(body.length + 8); result.writeUInt32BE(bytes.length); body.copy(result, 4); result.writeUInt32BE((crc ^ -1) >>> 0, body.length + 4); return result; };
    const header = Buffer.alloc(13); header.writeUInt32BE(width); header.writeUInt32BE(height, 4); header[8] = 8; header[9] = 2;
    return Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]), chunk('IHDR', header), chunk('IDAT', deflateSync(Buffer.alloc((width * 3 + 1) * height))), chunk('IEND', Buffer.alloc(0))]);
}
test('one canonical matrix asserts all five states in both locales/viewports and captures eight critical representatives', () => {
    assert.equal(contract.states.length, 5); assert.equal(assertionMatrix.length, 20); assert.equal(captureMatrix.length, 8);
    assert.deepEqual(assertionMatrix.map(row => row.phase), Array(4).fill(contract.states).flat());
    assert.deepEqual(captureMatrix.map(row => row.file), [
        'complete-service-review-matched-preview-unchecked-en-1440.png',
        'complete-service-review-matched-read-en-390.png',
        'complete-service-review-matched-selected-blank-en-390.png',
        'complete-service-review-unsupported-en-390.png',
        'complete-service-review-matched-selected-blank-de-1440.png',
        'complete-service-review-unknown-de-1440.png',
        'complete-service-review-matched-preview-unchecked-de-390.png',
        'complete-service-review-unknown-de-390.png',
    ]);
    assert.match(disclosure, /not the whole App/); assert.match(disclosure, /eight representative fixed-viewport/); assert.match(disclosure, /approval is never sent/);
});
test('inert source/router rejects absent/wrong review, CSRF, operation, target, replay, approval and external requests', async () => {
    const result = await check(); assert.equal(result.browserExecuted, false); assert.equal(result.nativeAcceptance, false);
    assert.equal(result.assertedViews, 20); assert.equal(result.screenshots, 8); assert(result.sourceInputCount > 1000); assert(result.dependencyPackageCount >= 4);
});
test('tracked input bytes must match exact commit blob, mode and hash without treating dependencies as Git source', () => {
    const bytes = Buffer.from('synthetic source\n'), input = { file: 'web/src/example.ts', sha256: sha256(bytes) };
    const blob = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
    validateTrackedInput(input, bytes, `100644 blob ${blob}`);
    for (const metadata of [undefined, `100755 blob ${blob}`, `120000 blob ${blob}`, '100644 blob ' + '0'.repeat(40)]) assert.throws(() => validateTrackedInput(input, bytes, metadata));
    assert.throws(() => validateTrackedInput({ ...input, sha256: '0'.repeat(64) }, bytes, `100644 blob ${blob}`));
    assert.throws(() => validateTrackedInput(input, Buffer.from('changed source'), `100644 blob ${blob}`));
    assert.throws(() => validateTrackedInput({ ...input, file: 'web/node_modules/react/index.js' }, bytes, `100644 blob ${blob}`));
});
test('compiled dependency closure is bound to tracked/installed npm locks and package metadata, including negative mismatches', async () => {
    const compiled = await compiledSource(), inputs = compiled.sourceInputs;
    const lock = JSON.parse(await readFile(path.join(root, 'web/package-lock.json'))), installed = JSON.parse(await readFile(path.join(root, 'web/node_modules/.package-lock.json'))), metadata = new Map();
    for (const binding of compiled.dependencyBindings) metadata.set(binding.packagePath, JSON.parse(await readFile(path.join(root, binding.packagePath, 'package.json'))));
    const validate = (source = inputs, bindings = compiled.dependencyBindings, trackedLock = lock, installedLock = installed, packageMetadata = metadata) => validateDependencyBindings(source, bindings, trackedLock, installedLock, packageMetadata);
    validate();
    assert.equal(dependencyPackagePath('web/src/auth.tsx'), null);
    assert.equal(dependencyPackagePath('web/node_modules/@scope/a/node_modules/b/file.js'), 'web/node_modules/@scope/a/node_modules/b');
    const first = compiled.dependencyBindings[0], key = first.packagePath.slice('web/'.length);
    for (const [field, value] of [['version', '0.0.0'], ['integrity', 'sha512-not-locked'], ['resolved', 'https://untrusted.invalid/']]) {
        const bad = structuredClone(installed); bad.packages[key][field] = value; assert.throws(() => validate(inputs, compiled.dependencyBindings, lock, bad));
    }
    const missing = structuredClone(installed); delete missing.packages[key]; assert.throws(() => validate(inputs, compiled.dependencyBindings, lock, missing));
    const linked = structuredClone(lock); linked.packages[key].link = true; assert.throws(() => validate(inputs, compiled.dependencyBindings, linked));
    for (const [field, value] of [['name', 'unrelated-package'], ['version', '0.0.0']]) {
        const bad = new Map(metadata); bad.set(first.packagePath, { ...bad.get(first.packagePath), [field]: value }); assert.throws(() => validate(inputs, compiled.dependencyBindings, lock, installed, bad));
    }
    for (const bindings of [[], compiled.dependencyBindings.slice(1), [...compiled.dependencyBindings].reverse(), [{ ...first, packageJSONSha256: '0'.repeat(64) }, ...compiled.dependencyBindings.slice(1)]]) assert.throws(() => validate(inputs, bindings));
    for (const source of [inputs.filter(input => input.file !== 'web/package-lock.json'), inputs.filter(input => input.file !== first.packagePath + '/package.json'), [...inputs, inputs[0]], [...inputs].reverse(), [{ ...inputs[0], file: '../external.js' }, ...inputs.slice(1)]]) assert.throws(() => validate(source));
});
test('evidence fails closed on source drift, incomplete behavior, duplicate/foreign artifacts, bad provenance and approval claims', async () => {
    const output = await mkdtemp(path.join(os.tmpdir(), 'complete-review-contract-')), sourceSha = 'a'.repeat(40), sourceTree = 'c'.repeat(40), compiled = await compiledSource();
    const report = { sourceSha, status: 'PASS', browserAcceptance: true, runtimeErrorCount: 0, requestsToRealAPI: 0, nativeAcceptance: false, secretsExported: false, realTelemetryExported: false, completeServiceReview: evidenceSummary() }, captures = [];
    try {
        for (const row of captureMatrix) { const bytes = png(row.width, row.height); await writeFile(path.join(output, row.file), bytes); captures.push({ ...row, sha256: sha256(bytes), sourceSha, sourceTree, sourceDigest: compiled.sourceDigest, synthetic: true, publicSafe: true, fullPage: false }); }
        const manifest = { sourceSha, sourceTree, sourceDigest: compiled.sourceDigest, sourceInputs: compiled.sourceInputs, dependencyBindings: compiled.dependencyBindings, sceneManifestSHA256, captures, assertions: assertionMatrix.map(assertionEvidence), browserExecuted: true, appMounted: false, interceptedPreviewRequests: 4, approvalRequests: 0, outgoingNetworkRequests: 0, nativeAcceptance: false, disclosure };
        const write = async (summary = report, value = manifest) => { await writeFile(path.join(output, 'windows-service-actions-results.json'), JSON.stringify(summary)); await writeFile(path.join(output, 'windows-complete-service-review-manifest.json'), JSON.stringify(value)); };
        await write(); await validateEvidence(output, sourceSha, sourceTree);
        for (const [key, value] of [['sourceSha', 'b'.repeat(40)], ['status', 'FAIL'], ['browserAcceptance', false], ['runtimeErrorCount', 1], ['requestsToRealAPI', 1], ['nativeAcceptance', true], ['secretsExported', true], ['realTelemetryExported', true], ['completeServiceReview', null]]) { await write({ ...report, [key]: value }); await assert.rejects(validateEvidence(output, sourceSha, sourceTree)); }
        for (const [key, value] of [['screenshots', 20], ['assertedViews', 8], ['states', 3], ['sceneManifestSHA256', '0'.repeat(64)], ['appMounted', true], ['browserExecuted', false], ['approvalRequests', 1], ['outgoingNetworkRequests', 1], ['interceptedPreviewRequests', 0]]) { await write({ ...report, completeServiceReview: { ...report.completeServiceReview, [key]: value } }); await assert.rejects(validateEvidence(output, sourceSha, sourceTree)); }
        for (const [key, value] of [['sourceSha', 'b'.repeat(40)], ['sourceTree', 'b'.repeat(40)], ['sceneManifestSHA256', '0'.repeat(64)], ['browserExecuted', false], ['appMounted', true], ['nativeAcceptance', true], ['approvalRequests', 1], ['outgoingNetworkRequests', 1], ['interceptedPreviewRequests', 0], ['sourceDigest', '0'.repeat(64)], ['disclosure', 'real acceptance']]) { await write(report, { ...manifest, [key]: value }); await assert.rejects(validateEvidence(output, sourceSha, sourceTree)); }
        const dependencyIndex = manifest.sourceInputs.findIndex(input => dependencyPackagePath(input.file));
        const droppedDependency = manifest.sourceInputs.filter((_, index) => index !== dependencyIndex);
        for (const value of [
            { ...manifest, sourceInputs: [], sourceDigest: sha256('[]') },
            { ...manifest, sourceInputs: droppedDependency, sourceDigest: sha256(JSON.stringify(droppedDependency)) },
            { ...manifest, sourceInputs: manifest.sourceInputs.map((input, index) => index === dependencyIndex ? { ...input, sha256: '0'.repeat(64) } : input) },
            { ...manifest, sourceInputs: [...manifest.sourceInputs, manifest.sourceInputs[0]] },
            { ...manifest, dependencyBindings: [] },
            { ...manifest, assertions: manifest.assertions.slice(1) },
            { ...manifest, assertions: [manifest.assertions[0], manifest.assertions[0], ...manifest.assertions.slice(2)] },
            { ...manifest, assertions: manifest.assertions.map((row, index) => index === 2 ? { ...row, interceptedPreviewRequests: 0 } : row) },
            { ...manifest, assertions: manifest.assertions.map((row, index) => index === 0 ? { ...row, controlsUnclipped: false } : row) },
            { ...manifest, captures: captures.slice(1) }, { ...manifest, captures: [captures[0], captures[0], ...captures.slice(2)] }, { ...manifest, captures: [...captures].reverse() },
            ...[['file', '../foreign.png'], ['file', 'foreign.png'], ['sha256', '0'.repeat(64)], ['sourceSha', 'b'.repeat(40)], ['sourceTree', 'b'.repeat(40)], ['sourceDigest', '0'.repeat(64)], ['width', 390], ['height', 1000], ['locale', 'fr'], ['phase', 'matched-read'], ['publicSafe', false], ['synthetic', false], ['fullPage', true]].map(([key, value]) => ({ ...manifest, captures: [{ ...captures[0], [key]: value }, ...captures.slice(1)] }))
        ]) { await write(report, value); await assert.rejects(validateEvidence(output, sourceSha, sourceTree)); }
        await write(); const first = captures[0], file = path.join(output, first.file), bytes = await readFile(file), foreign = path.join(output, 'complete-service-review-foreign.png');
        await writeFile(foreign, png(390, 844)); await assert.rejects(validateEvidence(output, sourceSha, sourceTree)); await rm(foreign);
        await rm(file); await assert.rejects(validateEvidence(output, sourceSha, sourceTree));
        const target = path.join(output, 'inert-foreign-target.png'); await writeFile(target, bytes); await symlink(target, file); await assert.rejects(validateEvidence(output, sourceSha, sourceTree)); await rm(file); await rm(target);
        await writeFile(file, png(390, 844)); await assert.rejects(validateEvidence(output, sourceSha, sourceTree));
        await writeFile(file, bytes); await validateEvidence(output, sourceSha, sourceTree);
    } finally { await rm(output, { recursive: true, force: true }); }
});
test('hosted-only admission rejects before any browser or Git subprocess is touched', async () => {
    const previous = process.env.GITHUB_ACTIONS; process.env.GITHUB_ACTIONS = 'false';
    try {
        await assert.rejects(capture({ browser: { newContext() { assert.fail('Browser must remain unused'); } }, expect: null, output: os.tmpdir() }), /Hosted CI only/);
        await assert.rejects(assertHostedSource('a'.repeat(40)), /Hosted CI only/);
    } finally { if (previous === undefined) delete process.env.GITHUB_ACTIONS; else process.env.GITHUB_ACTIONS = previous; }
});
test('producer retains real components, font/control bounds, fixed viewport and strict manual-only preview routing', async () => {
    const source = await readFile(path.join(root, 'web/scripts/capture-windows-complete-service-review.mjs'), 'utf8');
    assert.match(source, /import \{ AuthBoundary \} from '\.\/auth'/); assert.match(source, /import \{ WindowsCompleteServiceIncidentReview \}/);
    assert.match(source, /for \(const \{ locale, width, height \} of contract.viewports\) for \(const scene of scenes\)/);
    assert.match(source, /assertLayout\(page, review, focus, expect\)/); assert.match(source, /document.fonts.ready/);
    assert.match(source, /getComputedStyle\(document.documentElement\).fontSize/); assert.match(source, /control.scrollWidth > control.clientWidth/);
    assert.match(source, /state.manualPreview = 'stop'; await preview.click\(\)/); assert.match(source, /expect\(approval\).not.toBeChecked\(\)/); assert.match(source, /expect\(confirm\).toBeDisabled\(\)/);
    assert.match(source, /finally \{ await context.close\(\); \}/); assert.match(source, /assert.deepEqual\(assertions, assertionMatrix.map\(assertionEvidence\)\)/);
    assert.match(source, /await validateManifest\(output, sourceSha, sourceTree, manifest\)/);
    assert.equal((source.match(/assertHostedSource\(sourceSha, compiled.sourceInputs, compiled.dependencyBindings\)/g) ?? []).length, 2);
    assert(source.lastIndexOf('assertHostedSource(sourceSha, compiled.sourceInputs, compiled.dependencyBindings)') > source.indexOf('await validateManifest(output, sourceSha, sourceTree, manifest)'));
    assert.doesNotMatch(source, /fullPage: true|route\.continue|route\.fetch|ignoreHTTPSErrors|grantPermissions|createServer|approval\.check\(|confirm\.click\(/);
});
test('one shared hosted browser retains original failures, exact-source checker, focused/full checks and exact uploads', async () => {
    const read = file => readFile(path.join(root, file), 'utf8'), runner = await read('tests/e2e-review/windows-service-actions-runner.mjs'), checker = await read('web/scripts/check-windows-complete-service-review-evidence.mjs');
    const diagnostics = JSON.parse(await read('tests/e2e-review/windows-service-actions-diagnostics.json'));
    assert(runner.indexOf('await assertHostedSource(sourceSha)') < runner.indexOf('server=createServer'));
    assert.equal((runner.match(/captureCompleteServiceReview\(\{browser,expect,output:out,sourceSha\}\)/g) ?? []).length, 1);
    assert.match(runner, /completeServiceReview:passed\?completeServiceReviewEvidenceSummary\(\):null/);
    assert.match(runner, /diagnostic.begin\('runner',null,null,'complete-service-review'\)/); assert(diagnostics.cases.runner.includes('complete-service-review'));
    assert.equal((runner.match(/120000/g) ?? []).length, 1); assert.equal((runner.match(/chromium.launch\(/g) ?? []).length, 1);
    for (const name of ['ServiceActions', 'ServiceActionHistory', 'UpdateJobs', 'UpdateDownload', 'UpdateRetirement', 'UpdateSchedule', 'BackgroundUpdateSchedule', 'FleetUpdateSchedule', 'SoftwareJobs']) assert(runner.includes(`requireWindows${name}Evidence(`));
    assert.match(runner, /catch\{await writeFailure\(\);/); assert.match(runner, /process.exitCode=passed\?0:1/);
    assert.match(checker, /const sourceTree = await assertHostedSource\(process.argv\[2\]\)/);
    assert.match(checker, /validateEvidence\(path.join\(root, 'artifacts\/review'\), process.argv\[2\], sourceTree\)/);
    assert.match(checker, /assertHostedSource\(process.argv\[2\], manifest.sourceInputs, manifest.dependencyBindings\)/);
    for (const name of ['pr-checks.yml', 'validate.yml']) {
        const workflow = await read(`.github/workflows/${name}`), images = workflow.split('\n').map(line => line.trim()).filter(line => line.startsWith('artifacts/review/complete-service-review-') && line.endsWith('.png'));
        assert.deepEqual(images, captureMatrix.map(row => `artifacts/review/${row.file}`));
        assert.equal((workflow.match(/artifacts\/review\/windows-complete-service-review-manifest.json/g) ?? []).length, 1);
        assert(!workflow.includes('artifacts/review/complete-service-review-*.png')); assert(!workflow.includes('capture-windows-complete-service-review.mjs --capture'));
    }
    const focused = await read('tests/security/pr_checks.py'), full = await read('.github/workflows/validate.yml');
    for (const name of ['capture-windows-complete-service-review.mjs', 'windows-complete-service-review-contract.node.mjs', 'check-windows-complete-service-review-evidence.mjs']) assert(focused.includes(name) && full.includes(name));
    assert(full.includes('npm ci')); assert((await read('.github/workflows/pr-checks.yml')).includes('npm ci'));
});
