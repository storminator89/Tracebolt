/** One inert scene/artifact contract for the component capture and both CI tiers. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFile, lstat, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
export const root = fileURLToPath(new URL('../../', import.meta.url));
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export const disclosure = "Synthetic Go-exported complete-service incident history, rendered by the actual inbox component and protected request adapter, not the whole App. Every request intercepted. No native Windows observation, real endpoint, acknowledgement or policy write, external delivery or deployment.";
async function regular(file, maximum) {
    const info = await lstat(file); assert(info.isFile() && !info.isSymbolicLink() && info.size > 0 && info.size <= maximum);
    return readFile(file);
}
const raw = await regular(new URL('./windows-complete-incident-inbox-scenes.json', import.meta.url), 8192);
export const contract = JSON.parse(raw.toString('utf8'));
assert.equal(raw.toString('utf8'), JSON.stringify(contract, null, 2) + '\n');
assert.deepEqual(Object.keys(contract).sort(), ['scenes', 'schemaVersion', 'viewports']);
assert.equal(contract.schemaVersion, 1); assert.deepEqual(contract.scenes, ['active', 'unknown']);
assert.deepEqual(contract.viewports, ['en', 'de'].flatMap(locale => [1440, 390].map(width => ({ locale, width, height: width === 390 ? 844 : 1100 }))));
export const sceneManifestSHA256 = sha256(raw);
// Preserve the original capture's locale, viewport, then scene order and filenames.
export const captureMatrix = contract.viewports.flatMap(view => contract.scenes.map(scene => ({ scene, ...view, file: `complete-incident-inbox-${scene}-${view.locale}-${view.width}.png` })));
export const evidenceSummary = () => ({ sceneManifestSHA256, scenes: contract.scenes.length, screenshots: captureMatrix.length, browserExecuted: true, appMounted: false, nativeAcceptance: false, actualMutationRequests: 0, disclosure });
// Called only by the hosted runner/checker, never by the inert fixture tests.
export async function assertHostedSource(sourceSha, inputs = []) {
    assert(process.env.GITHUB_ACTIONS === 'true' && process.env.RUNNER_ENVIRONMENT === 'github-hosted', 'Hosted CI only.');
    assert(/^[a-f0-9]{40}$/.test(sourceSha));
    const git = args => execFileSync('git', args, { cwd: root, encoding: 'utf8', maxBuffer: 8 << 20 });
    assert.equal(git(['rev-parse', 'HEAD']).trim(), sourceSha);
    const tracked = new Map(git(['ls-tree', '-r', '-z', sourceSha]).split('\0').filter(Boolean).map(row => { const [metadata, file] = row.split('\t'); return [file, metadata]; }));
    const sourceTree = git(['rev-parse', sourceSha + '^{tree}']).trim();
    assert(/^[a-f0-9]{40}$/.test(sourceTree));
    for (const input of inputs) {
        const bytes = await regular(path.join(root, input.file), 4 << 20);
        assert.equal(input.sha256, sha256(bytes));
        const blob = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
        assert.equal(tracked.get(input.file), `100644 blob ${blob}`, 'Compiled source must match the exact hosted commit');
    }
    return sourceTree;
}
let canonicalInputs;
export async function validateManifest(output, sourceSha, sourceTree, manifest) {
    assert(/^[a-f0-9]{40}$/.test(sourceSha) && /^[a-f0-9]{40}$/.test(sourceTree));
    assert.deepEqual(Object.keys(manifest).sort(), ['actualMutationRequests', 'appMounted', 'browserExecuted', 'captures', 'disclosure', 'nativeAcceptance', 'sceneManifestSHA256', 'sourceDigest', 'sourceInputs', 'sourceSha', 'sourceTree']);
    assert.equal(manifest.sourceSha, sourceSha); assert.equal(manifest.sourceTree, sourceTree); assert.equal(manifest.sceneManifestSHA256, sceneManifestSHA256);
    assert.equal(manifest.browserExecuted, true); assert.equal(manifest.appMounted, false); assert.equal(manifest.nativeAcceptance, false); assert.equal(manifest.actualMutationRequests, 0); assert.equal(manifest.disclosure, disclosure);
    assert(Array.isArray(manifest.sourceInputs) && manifest.sourceInputs.length > 0 && manifest.sourceInputs.length < 1000);
    const files = new Set();
    for (const input of manifest.sourceInputs) {
        assert.deepEqual(Object.keys(input).sort(), ['file', 'sha256']); assert(/^web\/(src|scripts)\/[a-zA-Z0-9_./-]+$/.test(input.file) && !input.file.split('/').includes('..'));
        assert(!files.has(input.file)); files.add(input.file); assert.equal(input.sha256, sha256(await regular(path.join(root, input.file), 4 << 20)));
    }
    for (const file of ['web/src/windows-incident-inbox.tsx', 'web/src/windows-incident-inbox-resource.ts', 'web/src/windows-complete-incident-inbox-types.ts', 'web/src/windows-complete-incident-go-fixture.json', 'web/scripts/windows-complete-incident-inbox-scenes.json', 'web/scripts/windows-complete-incident-inbox-contract.mjs', 'web/scripts/capture-windows-complete-incident-inbox.mjs']) assert(files.has(file));
    canonicalInputs ??= import('./capture-windows-complete-incident-inbox.mjs').then(module => module.compile()).then(value => value.sourceInputs);
    assert.deepEqual(manifest.sourceInputs, await canonicalInputs, 'Capture must bind the complete canonical compiled-source inventory');
    assert.equal(manifest.sourceDigest, sha256(JSON.stringify(manifest.sourceInputs)));
    assert(Array.isArray(manifest.captures)); assert.equal(manifest.captures.length, captureMatrix.length);
    // Uploaders include this namespace; every matching image must be canonical.
    const uploadedImages = (await readdir(output)).filter(file => file.startsWith('complete-incident-inbox-') && file.endsWith('.png')).sort();
    assert.deepEqual(uploadedImages, captureMatrix.map(row => row.file).sort());
    for (let index = 0; index < captureMatrix.length; index++) {
        const expected = captureMatrix[index], row = manifest.captures[index];
        assert.deepEqual(Object.keys(row).sort(), ['file', 'fullPage', 'height', 'locale', 'publicSafe', 'scene', 'sha256', 'sourceDigest', 'sourceSha', 'sourceTree', 'synthetic', 'width']);
        for (const [key, value] of Object.entries(expected)) assert.equal(row[key], value);
        assert.equal(row.sourceSha, sourceSha); assert.equal(row.sourceTree, sourceTree); assert.equal(row.sourceDigest, manifest.sourceDigest); assert.equal(row.synthetic, true); assert.equal(row.publicSafe, true); assert.equal(row.fullPage, false);
        const png = await regular(path.join(output, row.file), 8 << 20); assert(png.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10]))); assert.equal(png.toString('ascii', 12, 16), 'IHDR'); assert.equal(png.readUInt32BE(16), row.width); assert.equal(png.readUInt32BE(20), row.height); assert.equal(row.sha256, sha256(png));
    }
}
export async function validateEvidence(output, sourceSha, sourceTree) {
    const report = JSON.parse(await regular(path.join(output, 'windows-service-actions-results.json'), 131072));
    assert.equal(report.sourceSha, sourceSha); assert.equal(report.status, 'PASS'); assert.equal(report.browserAcceptance, true);
    assert.equal(report.runtimeErrorCount, 0); assert.equal(report.requestsToRealAPI, 0); assert.equal(report.nativeAcceptance, false);
    assert.equal(report.secretsExported, false); assert.equal(report.realTelemetryExported, false);
    assert.deepEqual(report.completeIncidentInbox, evidenceSummary());
    const manifest = JSON.parse(await regular(path.join(output, 'windows-complete-incident-inbox-manifest.json'), 2 << 20));
    await validateManifest(output, sourceSha, sourceTree, manifest); return manifest;
}
