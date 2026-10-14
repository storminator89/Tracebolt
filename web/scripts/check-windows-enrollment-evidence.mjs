/** Verify exact source, the complete eight-image matrix and public-safe metadata. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from './capture-windows-enrollment.mjs';
import { boundedRegular, captureMatrix, disclosure, scenes, validateDialogPNG } from './windows-enrollment-contract.mjs';
const root = fileURLToPath(new URL('../../', import.meta.url)), hash = bytes => createHash('sha256').update(bytes).digest('hex');
async function document(file, maximum) {
 const bytes = await boundedRegular(file, maximum), value = JSON.parse(bytes);
 assert.equal(bytes.toString('utf8'), JSON.stringify(value, null, 2) + '\n'); return value;
}
export const successfulReport = sourceSha => ({ sourceSha, status: 'PASS', browserAcceptance: true, scenes: scenes.length, screenshots: captureMatrix.length, contexts: 5, captureContexts: 4, controlContexts: 1, controlCases: 6, syntheticCreates: 4, requestsToRealAPI: 0, actualMutationRequests: 0, nativeAcceptance: false, disclosure });
export function validateCaptureRow(row, index, bytes, sourceDigest) {
 const expected = captureMatrix[index]; assert(expected);
 let dimensions; try { dimensions = validateDialogPNG(bytes, expected.width, expected.height); } catch { throw new Error('Invalid PNG evidence'); }
 const { width: imageWidth, height: imageHeight } = dimensions;
 assert.deepEqual(row, { ...expected, synthetic: true, publicSafe: true, fullPage: false, captureScope: 'production-dialog', imageWidth, imageHeight, sha256: hash(bytes), sourceDigest, syntheticCreates: 1, csrfReads: 1, productionFontsLoaded: true });
}
export function validateMetadata(report, manifest, sourceSha, compiled) {
 assert(/^[a-f0-9]{40}$/.test(sourceSha)); assert.deepEqual(report, successfulReport(sourceSha));
 assert.deepEqual(Object.keys(manifest).sort(), ['actualMutationRequests', 'appMounted', 'browserExecuted', 'captures', 'dependencyInputs', 'disclosure', 'nativeAcceptance', 'requestsToRealAPI', 'sourceDigest', 'sourceInputs', 'sourceSha', 'visibilityControls']);
 assert(['positive', 'empty'].includes(manifest.visibilityControls?.closedBodyRange));
 assert.deepEqual(manifest.visibilityControls, { contexts: 1, cases: 6, passed: true, closedBodyRange: manifest.visibilityControls.closedBodyRange, screenshots: 0, syntheticDocumentRequests: 1, requestsToRealAPI: 0, actualMutationRequests: 0 });
 assert.equal(manifest.sourceSha, sourceSha); assert.equal(manifest.browserExecuted, true); assert.equal(manifest.appMounted, false); assert.equal(manifest.nativeAcceptance, false);
 assert.equal(manifest.actualMutationRequests, 0); assert.equal(manifest.requestsToRealAPI, 0); assert.equal(manifest.disclosure, disclosure);
 assert.deepEqual(manifest.sourceInputs, compiled.sourceInputs); assert.deepEqual(manifest.dependencyInputs, compiled.dependencyInputs); assert.equal(manifest.sourceDigest, compiled.sourceDigest); assert.equal(manifest.captures.length, captureMatrix.length);
}
export async function validateEvidence(output, sourceSha) {
 const report = await document(path.join(output, 'windows-enrollment-results.json'), 16384);
 const manifest = await document(path.join(output, 'windows-enrollment-manifest.json'), 1 << 20);
 const compiled = await compile(); validateMetadata(report, manifest, sourceSha, compiled);
 for (const [index, expected] of captureMatrix.entries()) validateCaptureRow(manifest.captures[index], index, await boundedRegular(path.join(output, expected.file), 8 << 20), compiled.sourceDigest);
 assert.equal(execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim(), sourceSha);
 const tree = new Map(execFileSync('git', ['ls-tree', '-r', '-z', sourceSha], { cwd: root, encoding: 'utf8', maxBuffer: 8 << 20 }).split('\0').filter(Boolean).map(row => { const [meta, file] = row.split('\t'); return [file, meta]; }));
 for (const input of manifest.sourceInputs) {
  assert((/^web\/(src|scripts)\/[a-zA-Z0-9_./-]+$/.test(input.file) || ['web/package.json', 'web/package-lock.json', 'web/tsconfig.json', '.github/workflows/pr-checks.yml'].includes(input.file)) && !input.file.split('/').includes('..'));
  const bytes = await boundedRegular(path.join(root, input.file), 4 << 20); assert.equal(hash(bytes), input.sha256);
  assert.equal(tree.get(input.file), `100644 blob ${createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex')}`);
 }
 const fontRoot = path.join(await realpath(path.join(root, 'web/node_modules')), '@fontsource/inter');
 for (const input of manifest.dependencyInputs) {
  const prefix = 'web/node_modules/@fontsource/inter/'; assert(input.file.startsWith(prefix) && !input.file.split('/').includes('..'));
  assert.equal(hash(await boundedRegular(path.join(fontRoot, input.file.slice(prefix.length)), 4 << 20)), input.sha256);
 }
 return { sourceSha, screenshots: captureMatrix.length, browserAcceptance: true, nativeAcceptance: false };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
 try { console.log(JSON.stringify(await validateEvidence(path.join(root, 'artifacts/review'), process.argv[2]))); }
 catch { console.log('FAIL: Windows enrollment evidence; raw diagnostics withheld.'); process.exitCode = 1; }
}
