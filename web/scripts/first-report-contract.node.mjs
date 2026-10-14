/** Inert contract fixtures. Generated PNG bytes are never browser evidence. */
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { deflateSync } from 'node:zlib';
import { compileFirstReportAssets, firstReportMatrix, firstReportScenes, firstReportDisclosure } from './capture-first-report-fixtures.mjs';
import { root, sha256, firstReportFailure, firstReportResult, firstReportAssertions, validateFirstReportEvidence, validateFirstReportPNG } from './first-report-contract.mjs';
const sourceSha = 'a'.repeat(40), sourceTree = 'b'.repeat(40);
const chunk = (name, bytes) => { const body = Buffer.concat([Buffer.from(name), bytes]); let crc = -1; for (const byte of body) { crc ^= byte; for (let n = 0; n < 8; n++) crc = crc >>> 1 ^ (crc & 1 ? 0xedb88320 : 0); } const result = Buffer.alloc(body.length + 8); result.writeUInt32BE(bytes.length); body.copy(result, 4); result.writeUInt32BE((crc ^ -1) >>> 0, body.length + 4); return result; };
function png(width, height, channels = 3) {
    const header = Buffer.alloc(13); header.writeUInt32BE(width); header.writeUInt32BE(height, 4); header[8] = 8; header[9] = channels === 4 ? 6 : 2;
    return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', header), chunk('IDAT', deflateSync(Buffer.alloc((width * channels + 1) * height))), chunk('IEND', Buffer.alloc(0))]);
}
test('PNG validation decodes bounded RGB/RGBA scanlines and rejects corrupt structure and IDAT streams', () => {
    const width = 390, height = 844, valid = png(width, height), header = valid.subarray(16, 29);
    const compressed = valid.subarray(41, 41 + valid.readUInt32BE(33));
    const signature = valid.subarray(0, 8), end = chunk('IEND', Buffer.alloc(0));
    const pack = (data, currentHeader = header) => Buffer.concat([signature, chunk('IHDR', currentHeader), ...data, end]);
    const raw = Buffer.alloc((width * 3 + 1) * height);
    const withData = data => pack([chunk('IDAT', data)]);
    validateFirstReportPNG(valid, width, height); validateFirstReportPNG(png(width, height, 4), width, height);
    validateFirstReportPNG(pack([chunk('IDAT', compressed.subarray(0, 5)), chunk('IDAT', compressed.subarray(5))]), width, height);
    const filtered = Buffer.from(raw); for (let row = 0; row < height; row++) filtered[row * (width * 3 + 1)] = row % 5;
    validateFirstReportPNG(withData(deflateSync(filtered)), width, height);
    const corruptHeaderCRC = Buffer.from(valid); corruptHeaderCRC[29] ^= 1;
    const corruptDataCRC = Buffer.from(valid); corruptDataCRC[41 + compressed.length] ^= 1;
    const corruptEndCRC = Buffer.from(valid); corruptEndCRC[corruptEndCRC.length - 1] ^= 1;
    const wrongLength = Buffer.from(valid); wrongLength.writeUInt32BE(0xffffffff, 33);
    const corruptStream = Buffer.from(compressed); corruptStream[corruptStream.length - 1] ^= 1;
    const invalidFilter = Buffer.from(raw); invalidFilter[0] = 5;
    const cases = [
        ['missing IDAT', pack([])], ['empty IDAT', withData(Buffer.alloc(0))],
        ['truncated IDAT stream', withData(compressed.subarray(0, -1))],
        ['corrupt IDAT stream with valid chunk CRC', withData(corruptStream)],
        ['invalid deflate bytes with valid chunk CRC', withData(Buffer.from('not compressed image data'))],
        ['trailing compressed bytes', withData(Buffer.concat([compressed, Buffer.from([0])]))],
        ['concatenated compressed streams', withData(Buffer.concat([compressed, compressed]))],
        ['short inflated scanlines', withData(deflateSync(raw.subarray(1)))],
        ['oversized inflated scanlines', withData(deflateSync(Buffer.alloc(raw.length + 1)))],
        ['inflation bomb', withData(deflateSync(Buffer.alloc(7 << 20)))],
        ['invalid scanline filter', withData(deflateSync(invalidFilter))],
        ['bad IHDR CRC', corruptHeaderCRC], ['bad IDAT CRC', corruptDataCRC], ['bad IEND CRC', corruptEndCRC],
        ['out-of-bounds chunk length', wrongLength], ['truncated chunk', valid.subarray(0, -1)],
        ['missing IEND', valid.subarray(0, -12)], ['trailing file bytes', Buffer.concat([valid, Buffer.from([0])])],
        ['duplicate IHDR', pack([chunk('IHDR', header), chunk('IDAT', compressed)])],
        ['unsupported ancillary chunk', pack([chunk('tEXt', Buffer.from('private')), chunk('IDAT', compressed)])],
        ['oversized compressed file', Buffer.alloc((8 << 20) + 1)],
    ];
    for (const [field, index, value] of [['bit depth', 8, 16], ['color type', 9, 3], ['compression', 10, 1], ['filter method', 11, 1], ['interlace', 12, 1]]) {
        const changed = Buffer.from(header); changed[index] = value;
        cases.push([field + ' with valid CRC', pack([chunk('IDAT', compressed)], changed)]);
    }
    for (const [name, bytes] of cases) assert.throws(() => validateFirstReportPNG(bytes, width, height), name);
});
test('fixed first-report matrix remains seven scenes, EN/DE and viewport-only desktop/mobile', () => {
    assert.deepEqual(firstReportScenes, ['activation-pending', 'waiting', 'renewed-waiting', 'denied', 'expired', 'invalid-time', 'macos-recorded']);
    assert.equal(firstReportMatrix.length, 28); assert.equal(new Set(firstReportMatrix.map(row => row.file)).size, 28);
    assert.deepEqual(firstReportMatrix, firstReportScenes.flatMap(scene => ['en', 'de'].flatMap(locale => [1440, 390].map(width => ({ scene, locale, width, height: width === 390 ? 844 : 1000, file: `synthetic-first-report-${scene}-${width}-${locale}.png` })))));
});
test('closed evidence rechecks complete source inventory, PNG bytes, bounds and trust flags', async () => {
    const output = await mkdtemp(path.join(os.tmpdir(), 'first-report-contract-')), compiled = await compileFirstReportAssets();
    const report = firstReportResult(sourceSha, sourceTree, true), captures = [];
    try {
        for (const expected of firstReportMatrix) { const bytes = png(expected.width, expected.height); await writeFile(path.join(output, expected.file), bytes); captures.push({ ...expected, sha256: sha256(bytes), sourceSha, sourceDigest: compiled.sourceDigest, synthetic: true, publicSafe: true, fullPage: false, disclosure: firstReportDisclosure, assertions: firstReportAssertions(expected.scene) }); }
        const manifest = { sourceSha, sourceTree, sourceDigest: compiled.sourceDigest, sourceInputs: compiled.sourceInputs, captures, browserExecuted: true, nativeAcceptance: false, disclosure: firstReportDisclosure };
        const write = async (summary = report, value = manifest) => { await writeFile(path.join(output, 'first-report-results.json'), JSON.stringify(summary, null, 2) + '\n'); await writeFile(path.join(output, 'first-report-manifest.json'), JSON.stringify(value, null, 2) + '\n'); };
        await write(); await validateFirstReportEvidence(output, sourceSha, sourceTree);
        for (const file of ['web/src/App.tsx', 'web/src/enrollment-report.tsx', 'web/src/report-time.tsx', 'web/package-lock.json', '.github/workflows/pr-checks.yml', 'tests/security/pr_checks.py', 'web/scripts/first-report-contract.mjs']) assert(compiled.sourceInputs.some(row => row.file === file));
        for (const [key, value] of [['sourceSha', 'c'.repeat(40)], ['sourceTree', 'c'.repeat(40)], ['status', 'FAIL'], ['screenshots', 27], ['screenshots', true], ['browserAcceptance', false], ['nativeAcceptance', true], ['requestsToRealAPI', 1], ['actualMutationRequests', 1], ['disclosure', ''], ['raw', 'PRIVATE_DTO']]) { await write({ ...report, [key]: value }); await assert.rejects(validateFirstReportEvidence(output, sourceSha, sourceTree)); }
        const missingInput = compiled.sourceInputs.filter(row => row.file !== 'web/src/report-time.tsx');
        for (const value of [
            { ...manifest, sourceSha: 'c'.repeat(40) }, { ...manifest, sourceTree: 'c'.repeat(40) },
            { ...manifest, raw: 'PRIVATE_DTO' }, { ...manifest, browserExecuted: false }, { ...manifest, nativeAcceptance: true },
            { ...manifest, captures: captures.slice(1) }, { ...manifest, captures: [...captures, captures[0]] },
            { ...manifest, captures: [captures[0], captures[0], ...captures.slice(2)] },
            { ...manifest, sourceInputs: [] }, { ...manifest, sourceInputs: missingInput, sourceDigest: sha256(JSON.stringify(missingInput)) },
            { ...manifest, sourceInputs: [{ file: '../private', sha256: 'c'.repeat(64) }] },
            { ...manifest, sourceInputs: compiled.sourceInputs.map((row, index) => index ? row : { ...row, sha256: '0'.repeat(64) }) },
            { ...manifest, sourceDigest: '0'.repeat(64) },
        ]) { await write(report, value); await assert.rejects(validateFirstReportEvidence(output, sourceSha, sourceTree)); }
        for (const [key, value] of [['file', '../private.png'], ['scene', 'unknown'], ['locale', 'fr'], ['width', 390], ['height', 1001], ['sha256', '0'.repeat(64)], ['sourceSha', 'c'.repeat(40)], ['sourceDigest', '0'.repeat(64)], ['synthetic', false], ['publicSafe', false], ['fullPage', true], ['disclosure', ''], ['raw', 'PRIVATE_DTO'], ['assertions', { ...captures[0].assertions, actualMutationRequests: 1 }]]) {
            await write(report, { ...manifest, captures: [{ ...captures[0], [key]: value }, ...captures.slice(1)] }); await assert.rejects(validateFirstReportEvidence(output, sourceSha, sourceTree));
        }
        for (const key of Object.keys(captures[0].assertions)) {
            const assertions = { ...captures[0].assertions }; delete assertions[key];
            await write(report, { ...manifest, captures: [{ ...captures[0], assertions }, ...captures.slice(1)] }); await assert.rejects(validateFirstReportEvidence(output, sourceSha, sourceTree));
        }
        const file = path.join(output, captures[0].file), original = await readFile(file);
        for (const bytes of [Buffer.alloc(24), png(390, 844), Buffer.concat([original, Buffer.from('PRIVATE_DTO')]), Buffer.alloc((8 << 20) + 1)]) {
            await write(report, { ...manifest, captures: [{ ...captures[0], sha256: sha256(bytes) }, ...captures.slice(1)] }); await writeFile(file, bytes); await assert.rejects(validateFirstReportEvidence(output, sourceSha, sourceTree));
        }
        await writeFile(file, original); await write();
        const backing = path.join(output, 'backing.png'); await writeFile(backing, original); await rm(file); await symlink(backing, file);
        await assert.rejects(validateFirstReportEvidence(output, sourceSha, sourceTree)); await rm(file); await writeFile(file, original);
        await writeFile(path.join(output, 'first-report-results.json'), JSON.stringify(report, null, 2).replace('"status": "PASS"', '"status": "FAIL", "status": "PASS"') + '\n');
        await assert.rejects(validateFirstReportEvidence(output, sourceSha, sourceTree));
        await write(); await validateFirstReportEvidence(output, sourceSha, sourceTree);
        const extra = path.join(output, 'synthetic-first-report-unapproved.png'); await writeFile(extra, original);
        await assert.rejects(validateFirstReportEvidence(output, sourceSha, sourceTree)); await rm(extra);
        // Reproduce the reviewed bypass end to end: all 28 matching hashes and
        // dimensions around 46-byte non-images must still fail the evidence gate.
        const forgedCaptures = [];
        for (const row of captures) {
            const forged = Buffer.alloc(46); Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]).copy(forged);
            forged.writeUInt32BE(13, 8); forged.write('IHDR', 12); forged.writeUInt32BE(row.width, 16); forged.writeUInt32BE(row.height, 20);
            chunk('IEND', Buffer.alloc(0)).copy(forged, 34);
            await writeFile(path.join(output, row.file), forged); forgedCaptures.push({ ...row, sha256: sha256(forged) });
        }
        await write(report, { ...manifest, captures: forgedCaptures });
        await assert.rejects(validateFirstReportEvidence(output, sourceSha, sourceTree));
    } finally { await rm(output, { recursive: true, force: true }); }
});
test('failure projection only retains finite coordinates and discards raw diagnostic fields', () => {
    const marker = 'PRIVATE_RAW_EXCEPTION_URL_DTO_MUST_STAY_WITHHELD';
    for (const row of firstReportMatrix) {
        const failure = firstReportFailure('capture', { ...row, raw: marker });
        const result = firstReportResult(sourceSha, sourceTree, false, { ...failure, raw: marker });
        assert.deepEqual(result.failure, { phase: 'capture', scene: row.scene, locale: row.locale, width: row.width });
        assert.equal(result.status, 'FAIL'); assert.equal(result.screenshots, 0); assert(!JSON.stringify(result).includes(marker));
    }
    for (const phase of ['launch', 'capture', 'validate', 'close']) assert.deepEqual(firstReportFailure(phase), { phase, scene: null, locale: null, width: null });
    for (const [key, value] of [['scene', marker], ['locale', marker], ['width', marker], ['width', true]]) assert.throws(() => firstReportFailure('capture', { ...firstReportMatrix[0], [key]: value }));
    assert.throws(() => firstReportFailure(marker)); assert.throws(() => firstReportFailure('validate', firstReportMatrix[0]));
});
test('non-hosted driver refuses before browser loading, Git, directories or temporary profiles', async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'first-report-refusal-'));
    try {
        const guard = path.join(directory, 'inert-guard.mjs');
        await writeFile(guard, `import Module, { syncBuiltinESMExports } from 'node:module';
import fs from 'node:fs/promises'; import cp from 'node:child_process';
const refuse = () => { throw new Error('INERT_BOUNDARY_CROSSED'); };
fs.mkdir = refuse; fs.mkdtemp = refuse; fs.writeFile = refuse; fs.rm = refuse; cp.execFileSync = refuse;
const original = Module._load; Module._load = function(id, ...rest) { if (/playwright/.test(id)) return refuse(); return original.call(this, id, ...rest); }; syncBuiltinESMExports();\n`);
        for (const [actions, environment] of [['false', 'github-hosted'], ['true', 'self-hosted'], ['', '']]) {
            const result = spawnSync(process.execPath, ['--import', guard, path.join(root, 'web/scripts/run-first-report-ci.mjs')], { env: { ...process.env, GITHUB_ACTIONS: actions, RUNNER_ENVIRONMENT: environment, TRACEBOLT_SOURCE_SHA: sourceSha }, encoding: 'utf8', timeout: 10000 });
            assert.equal(result.status, 1); assert.equal(result.stderr, ''); assert.equal(result.stdout, 'FAIL: hosted CI is required; use the inert recipe --check locally.\n');
        }
    } finally { await rm(directory, { recursive: true, force: true }); }
});
test('source pin checks HEAD, clean tracked bytes, compiled input tracking and exact tree', async () => {
    // Exercise the actual helper body with an inert Git recorder, never a checkout mutation.
    const source = await readFile(path.join(root, 'web/scripts/first-report-contract.mjs'), 'utf8');
    const body = source.slice(source.indexOf('export function verifyFirstReportSource('), source.indexOf('export function firstReportFailure(')).replace('export function', 'function');
    const calls = [], inputs = [{ file: 'web/src/App.tsx' }]; let dirty = false, untracked = false, head = sourceSha;
    const git = (_command, args) => { calls.push(args); if (args[0] === 'diff-index' && dirty || args[0] === 'ls-files' && untracked) throw new Error('fixture refusal'); return args.join(' ') === 'rev-parse HEAD' ? head : args.join(' ') === 'rev-parse HEAD^{tree}' ? sourceTree : ''; };
    const verify = new Function('assert', 'execFileSync', 'root', `${body}; return verifyFirstReportSource;`)(assert, git, root);
    assert.equal(verify(sourceSha, inputs), sourceTree);
    assert.deepEqual(calls, [['rev-parse', 'HEAD'], ['diff-index', '--quiet', 'HEAD', '--'], ['ls-files', '--error-unmatch', '--', 'web/src/App.tsx'], ['rev-parse', 'HEAD^{tree}']]);
    dirty = true; assert.throws(() => verify(sourceSha, inputs)); dirty = false; untracked = true; assert.throws(() => verify(sourceSha, inputs)); untracked = false; head = 'c'.repeat(40); assert.throws(() => verify(sourceSha, inputs)); assert.throws(() => verify('invalid', inputs));
});
test('actual driver control flow fails closed, redacts failures and removes partial evidence with inert dependencies', async () => {
    const source = await readFile(path.join(root, 'web/scripts/run-first-report-ci.mjs'), 'utf8');
    const body = source.slice(source.indexOf('async function run() {'));
    const marker = 'PRIVATE_RAW_EXCEPTION_URL_DTO_MUST_STAY_WITHHELD';
    for (const mode of ['pass', 'launch', 'capture', 'validate', 'persisted-evidence', 'close', 'timeout', 'late-launch']) {
        const writes = new Map(), removed = [], logs = [], calls = [];
        const fakeProcess = { env: { TRACEBOLT_SOURCE_SHA: sourceSha }, exitCode: null };
        const fixture = { captures: [{ publicSafe: true, fullPage: false, sha256: 'c'.repeat(64) }], sourceInputs: [{ file: 'web/src/App.tsx' }] };
        const fail = () => { throw new Error(marker); };
        const fakeFS = { mkdir: async () => {}, mkdtemp: async () => '/inert/profile', rm: async file => { removed.push(file); writes.delete(file); }, writeFile: async (file, bytes) => { writes.set(file, bytes); } };
        const browser = { close: async () => { calls.push('close'); if (mode === 'close') fail(); } };
        const make = new Function('assert', 'fs', 'path', 'os', 'createRequire', 'captureFirstReportFixtures', 'firstReportMatrix', 'root', 'firstReportFailure', 'firstReportResult', 'validateFirstReportManifest', 'validateFirstReportEvidence', 'verifyFirstReportSource', 'process', 'console', 'setTimeout', 'clearTimeout', `${body}; return run;`);
        const run = make(assert, fakeFS, path, { tmpdir: () => '/inert' }, () => () => ({ chromium: { launch: async () => { calls.push('launch'); if (mode === 'launch') fail(); if (mode === 'late-launch') await new Promise(setImmediate); return browser; } }, expect: {} }),
            async ({ onCase }) => { calls.push('capture'); onCase(firstReportMatrix[0]); if (mode === 'capture') fail(); if (mode === 'timeout') { await new Promise(setImmediate); await fakeFS.writeFile('/inert/root/artifacts/review/first-report-manifest.json', marker); } return fixture; }, firstReportMatrix, '/inert/root', firstReportFailure, firstReportResult,
            async (_output, manifest) => { calls.push('validate'); assert.equal(manifest.captures[0].sha256, 'c'.repeat(64)); assert.equal(manifest.captures[0].publicSafe, true); assert.equal(manifest.captures[0].fullPage, false); if (mode === 'validate') fail(); },
            async () => { calls.push('persisted-evidence'); if (mode === 'persisted-evidence') fail(); }, () => sourceTree,
            fakeProcess, { log: value => logs.push(value) }, callback => { if (['timeout', 'late-launch'].includes(mode)) queueMicrotask(callback); return 1; }, () => {});
        await run();
        const result = JSON.parse(writes.get('/inert/root/artifacts/review/first-report-results.json'));
        assert.equal(fakeProcess.exitCode, mode === 'pass' ? 0 : 1); assert.equal(result.status, mode === 'pass' ? 'PASS' : 'FAIL');
        assert.equal(result.browserAcceptance, mode === 'pass'); assert.equal(result.screenshots, mode === 'pass' ? 28 : 0);
        assert(!JSON.stringify([...writes.values(), ...logs]).includes(marker)); assert(removed.includes('/inert/profile'));
        if (mode !== 'pass') {
            assert.equal(writes.has('/inert/root/artifacts/review/first-report-manifest.json'), false);
            assert.deepEqual(result.failure, firstReportFailure(mode === 'persisted-evidence' ? 'validate' : mode === 'late-launch' ? 'launch' : mode === 'timeout' ? 'capture' : mode, ['capture', 'timeout'].includes(mode) ? firstReportMatrix[0] : null));
            for (const row of firstReportMatrix) assert(removed.includes('/inert/root/artifacts/review/' + row.file));
        } else assert(writes.has('/inert/root/artifacts/review/first-report-manifest.json'));
        if (['capture', 'validate'].includes(mode)) assert.equal(calls.includes('persisted-evidence'), false);
    }
});
