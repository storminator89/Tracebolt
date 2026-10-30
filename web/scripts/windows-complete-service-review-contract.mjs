/** Canonical inert source/artifact contract. Browser execution belongs to the shared hosted runner. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFile, lstat, readdir, realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
export const root = fileURLToPath(new URL('../../', import.meta.url));
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export const disclosure = 'Synthetic source evidence: Go-exported complete-service review bytes rendered by the actual review, AuthBoundary and selected-service components, not the whole App. Uniform display-clock translation preserves evidence ages. Action status and deliberately selected preview responses are inert synthetic fixtures. All five states are asserted in EN/DE desktop/mobile; eight representative fixed-viewport images are captured. Every browser request is intercepted; approval is never sent. No real endpoint, native SCM/WUA/MSI, grant, installation, external delivery or deployment.';
async function regular(file, maximum) {
    const info = await lstat(file); assert(info.isFile() && !info.isSymbolicLink() && info.size > 0 && info.size <= maximum, `Expected bounded regular file: ${file}`);
    return readFile(file);
}
const raw = await regular(new URL('./windows-complete-service-review-scenes.json', import.meta.url), 8192);
export const contract = JSON.parse(raw.toString('utf8'));
assert.equal(raw.toString('utf8'), JSON.stringify(contract, null, 2) + '\n');
assert.deepEqual(Object.keys(contract).sort(), ['captures', 'schemaVersion', 'states', 'viewports']);
assert.equal(contract.schemaVersion, 1);
assert.deepEqual(contract.states, ['matched-read', 'matched-selected-blank', 'matched-preview-unchecked', 'unknown', 'unsupported']);
assert.deepEqual(contract.viewports, ['en', 'de'].flatMap(locale => [1440, 390].map(width => ({ locale, width, height: width === 390 ? 844 : 1100 }))));
assert.deepEqual(contract.captures, [
    { phase: 'matched-preview-unchecked', locale: 'en', width: 1440 },
    { phase: 'matched-read', locale: 'en', width: 390 },
    { phase: 'matched-selected-blank', locale: 'en', width: 390 },
    { phase: 'unsupported', locale: 'en', width: 390 },
    { phase: 'matched-selected-blank', locale: 'de', width: 1440 },
    { phase: 'unknown', locale: 'de', width: 1440 },
    { phase: 'matched-preview-unchecked', locale: 'de', width: 390 },
    { phase: 'unknown', locale: 'de', width: 390 },
]);
export const sceneManifestSHA256 = sha256(raw);
export const assertionMatrix = contract.viewports.flatMap(view => contract.states.map(phase => ({ phase, scene: phase.startsWith('matched-') ? 'matched' : phase, ...view })));
export const captureMatrix = contract.captures.map(selection => {
    const row = assertionMatrix.find(row => row.phase === selection.phase && row.locale === selection.locale && row.width === selection.width); assert(row);
    return { ...row, file: `complete-service-review-${row.phase}-${row.locale}-${row.width}.png` };
});
export const assertionEvidence = row => ({ ...row, reviewReads: 1, actionReads: row.scene === 'unsupported' ? 0 : 1, interceptedPreviewRequests: row.phase === 'matched-preview-unchecked' ? 1 : 0, approvalRequests: 0, outgoingNetworkRequests: 0, normalTypography: true, controlsUnclipped: true });
export const evidenceSummary = () => ({ sceneManifestSHA256, states: contract.states.length, assertedViews: assertionMatrix.length, screenshots: captureMatrix.length, browserExecuted: true, appMounted: false, nativeAcceptance: false, interceptedPreviewRequests: 4, approvalRequests: 0, outgoingNetworkRequests: 0, disclosure });
export function dependencyPackagePath(file) {
    if (!file.startsWith('web/node_modules/')) return null;
    const matches = [...file.matchAll(/(?:^|\/)node_modules\/(?:@[^/]+\/)?[^/]+/g)];
    const last = matches.at(-1); assert(last); return file.slice(0, last.index + last[0].length);
}
function validateInputShape(inputs) {
    assert(Array.isArray(inputs) && inputs.length > 0 && inputs.length < 10000);
    const names = new Set();
    for (const input of inputs) {
        assert.deepEqual(Object.keys(input).sort(), ['file', 'sha256']);
        assert(/^web\/(?:src\/|scripts\/|node_modules\/|package(?:-lock)?\.json$)[A-Za-z0-9_@./+-]*$/.test(input.file));
        assert(!input.file.split('/').some(part => part === '..' || part === '.' || part === ''));
        assert(/^[a-f0-9]{64}$/.test(input.sha256)); assert(!names.has(input.file)); names.add(input.file);
    }
    assert.deepEqual(inputs.map(input => input.file), [...names].sort((a, b) => a.localeCompare(b)));
    for (const file of ['web/package.json', 'web/package-lock.json', 'web/src/windows-complete-service-review-go-fixture.json', 'web/src/windows-complete-service-review-fixture.ts', 'web/src/windows-complete-service-incident-review.tsx', 'web/src/windows-complete-service-incident-review-types.ts', 'web/src/windows-service-actions.tsx', 'web/src/windows-service-incident-review-types.ts', 'web/src/api.ts', 'web/src/auth.tsx', 'web/src/styles.css', 'web/src/windows-incident-inbox.css', 'web/scripts/windows-complete-service-review-scenes.json', 'web/scripts/windows-complete-service-review-contract.mjs', 'web/scripts/capture-windows-complete-service-review.mjs']) assert(names.has(file), `Missing canonical source: ${file}`);
    assert(inputs.some(input => input.file.startsWith('web/node_modules/react/')));
    return names;
}
/** Lock binding is separate from tracked source: npm-ci files are not Git blobs.
 * Source bytes are hashed; package identity, version and tarball integrity must
 * match the tracked lock and the installed npm lock. No install/network occurs. */
export function validateDependencyBindings(inputs, bindings, lock, installed, metadata) {
    const names = validateInputShape(inputs);
    assert.equal(lock.lockfileVersion, 3); assert.equal(installed.lockfileVersion, 3);
    const packages = [...new Set(inputs.map(input => dependencyPackagePath(input.file)).filter(Boolean))].sort();
    assert(packages.length > 0); assert.equal(bindings.length, packages.length);
    for (let index = 0; index < packages.length; index++) {
        const packagePath = packages[index], key = packagePath.slice('web/'.length), entry = lock.packages[key], local = installed.packages[key], pkg = metadata.get(packagePath);
        assert(entry && local && pkg && !entry.link && !local.link);
        assert.equal(typeof entry.version, 'string'); assert(entry.version.length > 0);
        assert(/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(entry.integrity));
        assert.equal(typeof entry.resolved, 'string'); assert(entry.resolved.startsWith('https://registry.npmjs.org/'));
        for (const field of ['version', 'integrity', 'resolved']) assert.equal(local[field], entry[field], `Installed dependency differs from locked ${key}`);
        const expectedName = key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length);
        assert.equal(pkg.name, expectedName); assert.equal(pkg.version, entry.version);
        const manifestPath = packagePath + '/package.json'; assert(names.has(manifestPath));
        assert.deepEqual(bindings[index], { packagePath, name: pkg.name, version: entry.version, resolved: entry.resolved, integrity: entry.integrity, packageJSONSha256: inputs.find(input => input.file === manifestPath).sha256 });
    }
}
export async function dependencyBindings(inputs) {
    validateInputShape(inputs);
    const lock = JSON.parse(await regular(path.join(root, 'web/package-lock.json'), 4 << 20));
    const installed = JSON.parse(await regular(path.join(root, 'web/node_modules/.package-lock.json'), 4 << 20));
    const packages = [...new Set(inputs.map(input => dependencyPackagePath(input.file)).filter(Boolean))].sort(), metadata = new Map(), bindings = [];
    for (const packagePath of packages) {
        const bytes = await regular(path.join(root, packagePath, 'package.json'), 4 << 20), pkg = JSON.parse(bytes), entry = lock.packages[packagePath.slice('web/'.length)]; assert(entry);
        assert.equal(inputs.find(input => input.file === packagePath + '/package.json')?.sha256, sha256(bytes)); metadata.set(packagePath, pkg);
        bindings.push({ packagePath, name: pkg.name, version: entry.version, resolved: entry.resolved, integrity: entry.integrity, packageJSONSha256: sha256(bytes) });
    }
    validateDependencyBindings(inputs, bindings, lock, installed, metadata); return bindings;
}
async function validateInputBytes(inputs) {
    validateInputShape(inputs); const moduleRoot = await realpath(path.join(root, 'web/node_modules'));
    for (const input of inputs) {
        const file = path.join(root, input.file), resolved = await realpath(file);
        if (dependencyPackagePath(input.file)) {
            const relative = path.relative(moduleRoot, resolved);
            assert(relative && !relative.startsWith('..') && !path.isAbsolute(relative), 'Dependency input escaped installed root');
        } else assert.equal(resolved, file, 'Tracked inputs cannot redirect through symlinks');
        assert.equal(input.sha256, sha256(await regular(file, 4 << 20)));
    }
}
export function validateTrackedInput(input, bytes, metadata) {
    assert(!dependencyPackagePath(input.file), 'Installed dependencies are lock-bound, not tracked source');
    assert.equal(input.sha256, sha256(bytes));
    const blob = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
    assert.equal(metadata, `100644 blob ${blob}`, 'Tracked compiled source must match exact hosted commit');
}
// Called only in hosted capture/checker. Inert tests validate the pure binding contract.
export async function assertHostedSource(sourceSha, inputs = [], bindings = []) {
    assert(process.env.GITHUB_ACTIONS === 'true' && process.env.RUNNER_ENVIRONMENT === 'github-hosted', 'Hosted CI only.');
    assert(/^[a-f0-9]{40}$/.test(sourceSha));
    const git = args => execFileSync('git', args, { cwd: root, encoding: 'utf8', maxBuffer: 8 << 20 });
    assert.equal(git(['rev-parse', 'HEAD']).trim(), sourceSha);
    const sourceTree = git(['rev-parse', sourceSha + '^{tree}']).trim(); assert(/^[a-f0-9]{40}$/.test(sourceTree));
    if (inputs.length) {
        await validateInputBytes(inputs);
        const tracked = new Map(git(['ls-tree', '-r', '-z', sourceSha]).split('\0').filter(Boolean).map(row => { const [metadata, file] = row.split('\t'); return [file, metadata]; }));
        for (const input of inputs.filter(input => !dependencyPackagePath(input.file))) {
            const bytes = await regular(path.join(root, input.file), 4 << 20);
            validateTrackedInput(input, bytes, tracked.get(input.file));
        }
        assert.deepEqual(bindings, await dependencyBindings(inputs));
    } else assert.equal(bindings.length, 0);
    return sourceTree;
}
let canonicalCompilation;
export async function validateManifest(output, sourceSha, sourceTree, manifest) {
    assert(/^[a-f0-9]{40}$/.test(sourceSha) && /^[a-f0-9]{40}$/.test(sourceTree));
    assert.deepEqual(Object.keys(manifest).sort(), ['appMounted', 'approvalRequests', 'assertions', 'browserExecuted', 'captures', 'dependencyBindings', 'disclosure', 'interceptedPreviewRequests', 'nativeAcceptance', 'outgoingNetworkRequests', 'sceneManifestSHA256', 'sourceDigest', 'sourceInputs', 'sourceSha', 'sourceTree']);
    assert.equal(manifest.sourceSha, sourceSha); assert.equal(manifest.sourceTree, sourceTree); assert.equal(manifest.sceneManifestSHA256, sceneManifestSHA256);
    for (const [key, value] of Object.entries(evidenceSummary())) if (!['states', 'assertedViews', 'screenshots'].includes(key)) assert.equal(manifest[key], value);
    await validateInputBytes(manifest.sourceInputs);
    canonicalCompilation ??= import('./capture-windows-complete-service-review.mjs').then(module => module.compile());
    const canonical = await canonicalCompilation;
    assert.deepEqual(manifest.sourceInputs, canonical.sourceInputs, 'Capture must bind the complete canonical compiled-source inventory');
    assert.deepEqual(manifest.dependencyBindings, canonical.dependencyBindings);
    assert.deepEqual(manifest.dependencyBindings, await dependencyBindings(manifest.sourceInputs));
    assert.equal(manifest.sourceDigest, sha256(JSON.stringify(manifest.sourceInputs)));
    assert.deepEqual(manifest.assertions, assertionMatrix.map(assertionEvidence));
    assert(Array.isArray(manifest.captures)); assert.equal(manifest.captures.length, captureMatrix.length);
    const images = (await readdir(output)).filter(file => file.startsWith('complete-service-review-') && file.endsWith('.png')).sort();
    assert.deepEqual(images, captureMatrix.map(row => row.file).sort());
    for (let index = 0; index < captureMatrix.length; index++) {
        const row = manifest.captures[index], expected = captureMatrix[index];
        assert.deepEqual(Object.keys(row).sort(), ['file', 'fullPage', 'height', 'locale', 'phase', 'publicSafe', 'scene', 'sha256', 'sourceDigest', 'sourceSha', 'sourceTree', 'synthetic', 'width']);
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
    assert.deepEqual(report.completeServiceReview, evidenceSummary());
    const manifest = JSON.parse(await regular(path.join(output, 'windows-complete-service-review-manifest.json'), 4 << 20));
    await validateManifest(output, sourceSha, sourceTree, manifest); return manifest;
}
