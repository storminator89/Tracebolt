/** Reject missing, substituted, stale-source or wrong-size hosted UI evidence. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { lstat, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile, captureMatrix, disclosure, scenes } from './capture-macos-inventory.mjs';
const root = fileURLToPath(new URL('../../', import.meta.url)), hash = bytes => createHash('sha256').update(bytes).digest('hex');
async function regular(file, maximum) { const stat = await lstat(file); assert(stat.isFile() && !stat.isSymbolicLink() && stat.size > 0 && stat.size <= maximum); return readFile(file); }
export async function validateEvidence(output, sourceSha) {
 assert(/^[a-f0-9]{40}$/.test(sourceSha));
 const report = JSON.parse(await regular(path.join(output, 'macos-inventory-results.json'), 16384)), manifest = JSON.parse(await regular(path.join(output, 'macos-inventory-manifest.json'), 1 << 20));
 assert.deepEqual(report, { sourceSha, status: 'PASS', browserAcceptance: true, scenes: scenes.length, screenshots: captureMatrix.length, requestsToRealAPI: 0, actualMutationRequests: 0, nativeAcceptance: false, disclosure });
 assert.equal(manifest.sourceSha, sourceSha); assert.equal(manifest.browserExecuted, true); assert.equal(manifest.appMounted, false); assert.equal(manifest.nativeAcceptance, false); assert.equal(manifest.actualMutationRequests, 0); assert.equal(manifest.requestsToRealAPI, 0); assert.equal(manifest.disclosure, disclosure);
 const compiled = await compile(); assert.deepEqual(manifest.sourceInputs, compiled.sourceInputs); assert.equal(manifest.sourceDigest, compiled.sourceDigest);
 const tree = new Map(execFileSync('git', ['ls-tree', '-r', '-z', sourceSha], { cwd: root, encoding: 'utf8', maxBuffer: 8 << 20 }).split('\0').filter(Boolean).map(row => { const [meta, file] = row.split('\t'); return [file, meta]; }));
 for (const input of manifest.sourceInputs) { assert(/^web\/(src|scripts)\/[a-zA-Z0-9_./-]+$/.test(input.file) && !input.file.split('/').includes('..')); const bytes = await regular(path.join(root, input.file), 4 << 20); assert.equal(hash(bytes), input.sha256); assert.equal(tree.get(input.file), `100644 blob ${createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex')}`); }
 assert.equal(manifest.captures.length, captureMatrix.length);
 for (const [index, expected] of captureMatrix.entries()) { const row = manifest.captures[index], bytes = await regular(path.join(output, expected.file), 8 << 20); assert.deepEqual(row, { ...expected, sha256: hash(bytes), sourceDigest: compiled.sourceDigest, publicSafe: true, synthetic: true, fullPage: false }); assert(bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))); assert.equal(bytes.readUInt32BE(16), expected.width); assert.equal(bytes.readUInt32BE(20), expected.height); }
 return { sourceSha, scenes: scenes.length, screenshots: captureMatrix.length, nativeAcceptance: false };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) console.log(JSON.stringify(await validateEvidence(path.join(root, 'artifacts/review'), process.argv[2])));
