/** Closed evidence contract for the seven synthetic first-report scenes only. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { crc32, inflateSync } from 'node:zlib';
import { lstat, readFile, readdir, realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { compileFirstReportAssets, firstReportMatrix, firstReportDisclosure } from './capture-first-report-fixtures.mjs';
export const root = fileURLToPath(new URL('../../', import.meta.url));
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export function verifyFirstReportSource(sourceSha, inputs = []) {
    assert(/^[a-f0-9]{40}$/.test(sourceSha));
    const git = args => execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
    assert.equal(git(['rev-parse', 'HEAD']), sourceSha);
    git(['diff-index', '--quiet', 'HEAD', '--']);
    // Every compiled input must be tracked, including files ignored by Git.
    if (inputs.length) git(['ls-files', '--error-unmatch', '--', ...inputs.map(row => row.file)]);
    const tree = git(['rev-parse', 'HEAD^{tree}']); assert(/^[a-f0-9]{40}$/.test(tree)); return tree;
}
export function firstReportFailure(phase, coordinate = null) {
    assert(['launch', 'capture', 'validate', 'close'].includes(phase));
    if (coordinate !== null) {
        assert.equal(phase, 'capture');
        assert(firstReportMatrix.some(row => row.scene === coordinate.scene && row.locale === coordinate.locale && row.width === coordinate.width));
    }
    return { phase, scene: coordinate?.scene ?? null, locale: coordinate?.locale ?? null, width: coordinate?.width ?? null };
}
export function firstReportResult(sourceSha, sourceTree, passed, failure) {
    assert(/^[a-f0-9]{40}$/.test(sourceSha) && /^[a-f0-9]{40}$/.test(sourceTree));
    assert.equal(typeof passed, 'boolean');
    return { sourceSha, sourceTree, status: passed ? 'PASS' : 'FAIL', browserAcceptance: passed,
        screenshots: passed ? firstReportMatrix.length : 0, requestsToRealAPI: 0, actualMutationRequests: 0,
        nativeAcceptance: false, disclosure: firstReportDisclosure,
        ...(!passed ? { failure: firstReportFailure(failure.phase, failure.scene === null ? null : failure) } : {}) };
}
export const firstReportAssertions = scene => ({ exactState: true, originalTimestamp: scene === 'macos-recorded',
    absentMetricsDoNotImplyAbsentReport: scene === 'macos-recorded', focusRestored: true,
    renewedDisplayConsistent: scene === 'renewed-waiting', manualRefreshUnchangedRevision: scene === 'waiting',
    failureClearsWaiting: scene === 'waiting', actualMutationRequests: 0 });
async function regular(file, maximum) {
    const info = await lstat(file);
    assert(info.isFile() && !info.isSymbolicLink() && info.size > 0 && info.size <= maximum);
    assert.equal(await realpath(file), path.resolve(file));
    return readFile(file);
}
async function document(file, maximum) {
    const raw = await regular(file, maximum), value = JSON.parse(raw);
    assert.equal(raw.toString('utf8'), JSON.stringify(value, null, 2) + '\n'); return value;
}
let pngDecoder;
export function validateFirstReportPNG(png, width, height) {
    // Chromium screenshots only: 8-bit non-interlaced RGB/RGBA. Reject other PNG
    // features instead of expanding this domain evidence gate into a file parser.
    assert(firstReportMatrix.some(row => row.width === width && row.height === height));
    assert(Buffer.isBuffer(png) && png.length > 45 && png.length <= (8 << 20));
    assert(png.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])));
    const compressed = []; let offset = 8, chunks = 0, channels;
    while (offset < png.length) {
        assert(++chunks <= 4096 && offset + 12 <= png.length);
        const length = png.readUInt32BE(offset), type = png.toString('latin1', offset + 4, offset + 8);
        assert(length <= png.length - offset - 12);
        const end = offset + length + 12, data = png.subarray(offset + 8, end - 4);
        assert.equal(crc32(png.subarray(offset + 4, end - 4)), png.readUInt32BE(end - 4));
        if (offset === 8) {
            assert.equal(type, 'IHDR'); assert.equal(length, 13);
            assert.equal(data.readUInt32BE(0), width); assert.equal(data.readUInt32BE(4), height);
            assert.equal(data[8], 8); assert([2, 6].includes(data[9]));
            assert.deepEqual([...data.subarray(10)], [0, 0, 0]); channels = data[9] === 2 ? 3 : 4;
        } else if (type === 'IDAT') {
            assert(length > 0); compressed.push(data);
        } else {
            assert.equal(type, 'IEND'); assert.equal(length, 0);
            assert(compressed.length > 0); assert.equal(end, png.length);
        }
        offset = end;
    }
    assert(png.subarray(-12).equals(Buffer.from([0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130])));
    const bytes = Buffer.concat(compressed), stride = width * channels + 1, expected = stride * height;
    assert(bytes.length > 0 && bytes.length <= (8 << 20) && expected <= (6 << 20));
    const inflated = inflateSync(bytes, { maxOutputLength: expected, info: true });
    assert.equal(inflated.engine.bytesWritten, bytes.length); assert.equal(inflated.buffer.length, expected);
    for (let row = 0; row < height; row++) assert(inflated.buffer[row * stride] <= 4);
    // Reuse the PNG decoder bundled with the project's existing locked browser
    // dependency. Resolve lazily so non-hosted refusal never loads Playwright.
    if (!pngDecoder) {
        const require = createRequire(new URL('../package.json', import.meta.url));
        assert.equal(require('playwright-core/package.json').version, require('./package.json').devDependencies['@playwright/test']);
        pngDecoder = require(path.join(path.dirname(require.resolve('playwright-core/package.json')), 'lib/utilsBundle.js')).PNG;
    }
    const decoded = pngDecoder.sync.read(png, { checkCRC: true });
    assert.equal(decoded.width, width); assert.equal(decoded.height, height);
    assert.equal(decoded.data.length, width * height * 4);
}
let canonicalInputs;
export async function validateFirstReportManifest(output, manifest, sourceSha, sourceTree) {
    assert(/^[a-f0-9]{40}$/.test(sourceSha) && /^[a-f0-9]{40}$/.test(sourceTree));
    assert.deepEqual(Object.keys(manifest).sort(), ['browserExecuted', 'captures', 'disclosure', 'nativeAcceptance', 'sourceDigest', 'sourceInputs', 'sourceSha', 'sourceTree']);
    assert.equal(manifest.sourceSha, sourceSha); assert.equal(manifest.sourceTree, sourceTree);
    assert.equal(manifest.browserExecuted, true); assert.equal(manifest.nativeAcceptance, false); assert.equal(manifest.disclosure, firstReportDisclosure);
    assert(Array.isArray(manifest.sourceInputs) && manifest.sourceInputs.length > 0 && manifest.sourceInputs.length < 1000);
    canonicalInputs ??= compileFirstReportAssets().then(value => value.sourceInputs);
    assert.deepEqual(manifest.sourceInputs, await canonicalInputs);
    for (const input of manifest.sourceInputs) {
        assert.deepEqual(Object.keys(input).sort(), ['file', 'sha256']);
        assert.equal(input.sha256, sha256(await regular(path.join(root, input.file), 4 << 20)));
    }
    assert.equal(manifest.sourceDigest, sha256(JSON.stringify(manifest.sourceInputs)));
    assert(Array.isArray(manifest.captures)); assert.equal(manifest.captures.length, firstReportMatrix.length);
    assert.deepEqual((await readdir(output)).filter(file => file.startsWith('synthetic-first-report-')).sort(), firstReportMatrix.map(row => row.file).sort());
    for (let index = 0; index < firstReportMatrix.length; index++) {
        const expected = firstReportMatrix[index], row = manifest.captures[index];
        assert.deepEqual(Object.keys(row).sort(), ['assertions', 'disclosure', 'file', 'fullPage', 'height', 'locale', 'publicSafe', 'scene', 'sha256', 'sourceDigest', 'sourceSha', 'synthetic', 'width']);
        for (const [key, value] of Object.entries(expected)) assert.equal(row[key], value);
        assert.equal(row.sourceSha, sourceSha); assert.equal(row.sourceDigest, manifest.sourceDigest);
        assert.equal(row.synthetic, true); assert.equal(row.publicSafe, true); assert.equal(row.fullPage, false); assert.equal(row.disclosure, firstReportDisclosure);
        assert.deepEqual(row.assertions, firstReportAssertions(row.scene));
        const png = await regular(path.join(output, row.file), 8 << 20);
        validateFirstReportPNG(png, row.width, row.height);
        assert.equal(row.sha256, sha256(png));
    }
}
export async function validateFirstReportEvidence(output, sourceSha, sourceTree) {
    const report = await document(path.join(output, 'first-report-results.json'), 8192);
    assert.deepEqual(report, firstReportResult(sourceSha, sourceTree, true));
    const manifest = await document(path.join(output, 'first-report-manifest.json'), 2 << 20);
    await validateFirstReportManifest(output, manifest, sourceSha, sourceTree);
    return manifest.sourceInputs;
}
