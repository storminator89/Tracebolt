/** Inert contracts only: no browser, host action, listener or external request. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { crc32, deflateSync } from 'node:zlib';
import { test } from 'node:test';
import { capture, captureMatrix, compile, compilerConfiguration, disclosure, fontWeights, origin, routeFixture, routeState, viewports } from './capture-windows-enrollment.mjs';
import { boundedRegular, diagnostic, stages, requireHosted, validateDialogPNG } from './windows-enrollment-contract.mjs';
import { approvedBody, creation, csrf, invitation, secret } from './windows-enrollment-fixtures.mjs';
import { successfulReport, validateCaptureRow, validateEvidence, validateMetadata } from './check-windows-enrollment-evidence.mjs';
const compiled = await compile(), sourceSha = 'a'.repeat(40);
const requestId = `request_${'5'.repeat(32)}`, rawBody = approvedBody(requestId);
const headers = { 'x-csrf-token': csrf, 'content-type': 'application/json', origin };
function harness() {
 const state = routeState(), handler = routeFixture(compiled, state);
 const request = async (method, target, raw = null, requestHeaders = {}) => {
  let response, aborted = false;
  await handler({ request: () => ({ method: () => method, url: () => target.startsWith('https:') ? target : origin + target, postData: () => raw, headers: () => requestHeaders }), fulfill: value => { response = value; }, abort: () => { aborted = true; } });
  return { response, aborted };
 };
 return { state, request, session: () => request('GET', '/api/session'), create: (body = rawBody, h = headers) => request('POST', '/api/windows/enrollment/invitations', body, h) };
}
const chunk = (type, data) => { const bytes = Buffer.alloc(data.length + 12); bytes.writeUInt32BE(data.length); bytes.write(type, 4, 'latin1'); data.copy(bytes, 8); bytes.writeUInt32BE(crc32(bytes.subarray(4, -4)), bytes.length - 4); return bytes; };
function fixturePNG(row, channels = 3) {
 const width = Math.min(620, row.width - 40), height = row.height - 40, header = Buffer.alloc(13);
 header.writeUInt32BE(width); header.writeUInt32BE(height, 4); header[8] = 8; header[9] = channels === 4 ? 6 : 2;
 return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', header), chunk('IDAT', deflateSync(Buffer.alloc((width * channels + 1) * height))), chunk('IEND', Buffer.alloc(0))]);
}
const captureRow = (index, bytes = fixturePNG(captureMatrix[index])) => ({ ...captureMatrix[index], synthetic: true, publicSafe: true, fullPage: false, captureScope: 'production-dialog', imageWidth: bytes.readUInt32BE(16), imageHeight: bytes.readUInt32BE(20), sha256: createHash('sha256').update(bytes).digest('hex'), sourceDigest: compiled.sourceDigest, syntheticCreates: 1, csrfReads: 1, productionFontsLoaded: true });
const manifest = () => ({ sourceSha, sourceInputs: compiled.sourceInputs, dependencyInputs: compiled.dependencyInputs, sourceDigest: compiled.sourceDigest, captures: captureMatrix.map((_, index) => captureRow(index)), disclosure, browserExecuted: true, appMounted: false, nativeAcceptance: false, actualMutationRequests: 0, requestsToRealAPI: 0 });

test('eight unique instruction/release images in exactly four EN/DE desktop/mobile contexts', () => {
 assert.deepEqual(viewports, ['en', 'de'].flatMap(locale => [1440, 390].map(width => ({ locale, width, height: width === 390 ? 844 : 1100 }))));
 assert.equal(captureMatrix.length, 8); assert.equal(new Set(captureMatrix.map(row => row.file)).size, 8);
 assert.deepEqual(captureMatrix.map(row => row.scene), ['instructions', 'release', 'instructions', 'release', 'instructions', 'release', 'instructions', 'release']);
 assert.equal(new URL(origin).hostname, 'windows-enrollment.invalid');
});
test('invented Windows DTOs validate under the production bounded-inventory contract', () => {
 const created = creation(origin); assert(compiled.data.validSnapshot(created.snapshot));
 assert.equal(created.snapshot.binding.collectionProfile, 'windows-inventory-v1'); assert.equal(created.bootstrap.profile, 'tls'); assert.equal(secret.length, 43);
 assert.deepEqual(compiled.data.publicBootstrap(created.bootstrap, created.snapshot, secret), created.bootstrap);
 assert.equal(compiled.data.publicBootstrap({ ...created.bootstrap, invitationSecret: secret }, created.snapshot, secret), null);
});
test('initial Linux and selected Windows status remain isolated and read-only', async () => {
 const h = harness();
 for (const [route, platform] of [['/api/enrollment', 'linux'], ['/api/windows/enrollment', 'windows']]) {
  const { response, aborted } = await h.request('GET', route); assert.equal(aborted, false);
  const value = JSON.parse(response.body); assert.deepEqual(value.platforms, [platform]); assert.equal(value.items.length, 0); assert(compiled.data.validEnrollmentList(value, platform));
 }
 assert.equal(h.state.syntheticCreates, 0);
});
test('exact production POST bytes and one prior CSRF read create only one inert invitation', async () => {
 const h = harness(); await h.session(); const first = await h.create();
 assert.equal(first.aborted, false); const expected = creation(origin); expected.snapshot.createRequestID = requestId; assert.deepEqual(JSON.parse(first.response.body), expected);
 const list = JSON.parse((await h.request('GET', '/api/windows/enrollment')).response.body);
 assert.equal(list.items.length, 1); assert.equal(list.items[0].invitationID, invitation);
 assert.equal((await h.create()).aborted, true); assert.equal(h.state.syntheticCreates, 1); assert.equal(h.state.csrfReads, 1);
});
test('missing, duplicated or wrong CSRF preflight cannot create an invitation', async () => {
 for (const count of [0, 2]) { const h = harness(); for (let n = 0; n < count; n++) await h.session(); assert.equal((await h.create()).aborted, true); assert.equal(h.state.syntheticCreates, 0); }
 for (const bad of [{ ...headers, 'x-csrf-token': '' }, { ...headers, 'x-csrf-token': 'wrong' }, { ...headers, origin: 'https://other.invalid' }, { ...headers, 'content-type': 'text/plain' }, { ...headers, cookie: 'invented' }, { ...headers, authorization: 'invented' }]) {
  const h = harness(); await h.session(); assert.equal((await h.create(rawBody, bad)).aborted, true); assert.equal(h.state.syntheticCreates, 0);
 }
});
test('different consent, profile, platform, shape or raw byte ordering is rejected', async () => {
 const original = JSON.parse(rawBody);
 const invalid = [null, [], {}, { ...original, platform: 'linux' }, { ...original, collectionAcknowledged: false }, { ...original, insecureHTTPAcknowledged: true }, { ...original, collectionProfile: 'windows-read-admin' }, { ...original, requestId: 'wrong' }, { ...original, invitationSecret: secret }];
 const raws = [...invalid.map(value => JSON.stringify(value)), rawBody + ' ', rawBody.replace('"platform":"windows"', '"platform":"linux","platform":"windows"'), JSON.stringify({ platform: 'windows', requestId, collectionAcknowledged: true, insecureHTTPAcknowledged: false }), '{'];
 for (const raw of raws) { const h = harness(); await h.session(); assert.equal((await h.create(raw)).aborted, true); assert.equal(h.state.syntheticCreates, 0); }
});
test('approval, termination, foreign origins, query-bearing and unknown routes are blocked', async () => {
 for (const [method, target, raw] of [['POST', `/api/windows/enrollment/${invitation}/approve`, '{}'], ['POST', `/api/windows/enrollment/${invitation}/terminate`, '{}'], ['POST', '/api/enrollment/invitations', rawBody], ['GET', 'https://outside.invalid/', null], ['GET', '/api/windows/enrollment?token=unsafe', null], ['GET', '/api/macos/enrollment', null], ['PUT', '/api/windows/enrollment/invitations', rawBody], ['GET', '/api/windows/enrollment', '{}']]) {
  const h = harness(); assert.equal((await h.request(method, target, raw, headers)).aborted, true); assert.equal(h.state.syntheticCreates, 0);
 }
});
test('only bundled in-memory assets are served and no request is forwarded', async () => {
 const h = harness(); for (const asset of ['/', '/app.js', '/app.css']) assert.equal((await h.request('GET', asset)).aborted, false);
 assert.equal((await h.request('GET', '/missing.js')).aborted, true);
 const source = await readFile(new URL('./capture-windows-enrollment.mjs', import.meta.url), 'utf8');
 assert.doesNotMatch(source, /route\.(?:continue|fetch)\(|\bfetch\(|\bspawn\(|ignoreHTTPSErrors|CHROMIUM_PATH|executablePath/);
});
test('browser entry refuses execution outside hosted CI before touching a browser', async () => {
 const oldActions = process.env.GITHUB_ACTIONS, oldRunner = process.env.RUNNER_ENVIRONMENT;
 try { delete process.env.GITHUB_ACTIONS; delete process.env.RUNNER_ENVIRONMENT; assert.throws(() => requireHosted(), /Hosted CI only/); await assert.rejects(() => capture({ browser: null, expect: null, output: '/unused' }), /Hosted CI only/); }
 finally { if (oldActions === undefined) delete process.env.GITHUB_ACTIONS; else process.env.GITHUB_ACTIONS = oldActions; if (oldRunner === undefined) delete process.env.RUNNER_ENVIRONMENT; else process.env.RUNNER_ENVIRONMENT = oldRunner; }
});
test('diagnostics admit only closed stage and matrix metadata, never raw values', () => {
 for (const [index, row] of captureMatrix.entries()) for (const stage of stages) assert.deepEqual(diagnostic(stage, index), { stage, scene: row.scene, locale: row.locale, width: row.width });
 for (const value of ['secret', invitation, origin, {}, null]) assert.throws(() => diagnostic(value));
 for (const value of [-1, 8, 0.5, '1', Infinity]) assert.throws(() => diagnostic('screenshot', value));
});
test('success metadata requires the complete exact-source public-safe matrix', () => {
 validateMetadata(successfulReport(sourceSha), manifest(), sourceSha, compiled);
 for (const change of [{ screenshots: 4 }, { syntheticCreates: 8 }, { contexts: 8 }, { requestsToRealAPI: 1 }, { actualMutationRequests: 1 }, { nativeAcceptance: true }, { status: 'FAIL' }, { secret }]) assert.throws(() => validateMetadata({ ...successfulReport(sourceSha), ...change }, manifest(), sourceSha, compiled));
 for (const change of [{ captures: [] }, { sourceDigest: 'b'.repeat(64) }, { sourceInputs: [] }, { dependencyInputs: [] }, { appMounted: true }, { browserExecuted: false }, { rawInvitation: invitation }]) assert.throws(() => validateMetadata(successfulReport(sourceSha), { ...manifest(), ...change }, sourceSha, compiled));
});
test('every image row binds scene, viewport, cropped dimensions, hash and one synthetic POST', () => {
 for (const [index, row] of captureMatrix.entries()) {
  const bytes = fixturePNG(row), good = captureRow(index, bytes); validateCaptureRow(good, index, bytes, compiled.sourceDigest);
  for (const change of [{ file: '../unsafe.png' }, { width: row.width + 1 }, { imageWidth: good.imageWidth + 1 }, { fullPage: true }, { publicSafe: false }, { captureScope: 'full-page' }, { syntheticCreates: 0 }, { csrfReads: 2 }, { productionFontsLoaded: false }, { sha256: '0'.repeat(64) }, { invitation }]) assert.throws(() => validateCaptureRow({ ...good, ...change }, index, bytes, compiled.sourceDigest));
  const bad = Buffer.from(bytes); bad.writeUInt32BE(row.width + 1, 16); assert.throws(() => validateCaptureRow(captureRow(index, bad), index, bad, compiled.sourceDigest));
 }
});
test('capture uses the unchanged real dialog, scoped scroll and lifecycle secret clearing', async () => {
 const source = await readFile(new URL('./capture-windows-enrollment.mjs', import.meta.url), 'utf8');
 for (const pattern of ["dialog.locator('.enrollment-windows-install')", "window.dispatchEvent(new Event('pagehide'))", "window.dispatchEvent(new Event('pageshow'))", "await expect(input).toHaveCount(0)", "element.closest('[role=\"dialog\"]')", 'dialog.scrollTo', 'await assertPublicSafe(page, dialog, expect)', 'await dialog.screenshot(', 'await expect(target).toBeInViewport({ ratio: 1 })']) assert(source.includes(pattern), pattern);
 assert.doesNotMatch(source, /page\.setContent|innerHTML\s*=|outerHTML\s*=|page\.addStyleTag|mask:|maskColor:|visibility: hidden|\.fill\(|\.type\(|\.pressSequentially\(/);
});
test('existing hosted browser job runs the strict capture gate and uploads its eight exact images', async () => {
 const workflow = await readFile(new URL('../../.github/workflows/pr-checks.yml', import.meta.url), 'utf8');
 assert.match(workflow, /runs-on: ubuntu-24\.04/); assert.match(workflow, /contents: read/); assert.match(workflow, /persist-credentials: false/);
 for (const row of captureMatrix) assert(workflow.includes(`artifacts/review/${row.file}`));
 assert.match(workflow, /if: success\(\)/); assert.match(workflow, /node web\/scripts\/run-windows-enrollment-ci\.mjs/);
 assert.doesNotMatch(workflow, /workflow_dispatch|pull_request_target|secrets\.|ignoreHTTPSErrors|windows-inventory-browser|macos-enrollment/);
 const browserJob = workflow.split('\n  browser:\n')[1]?.split('\n  focused:\n')[0]; assert(browserJob);
 const expectedStep = '      - name: Verify synthetic Windows created-stage instructions\n        run: |\n          node web/scripts/capture-windows-enrollment.mjs --check\n          node --test web/scripts/windows-enrollment-capture.node.mjs\n          node web/scripts/run-windows-enrollment-ci.mjs\n';
 assert(browserJob.includes(expectedStep)); assert(browserJob.indexOf('python3 -I -B tests/security/pr_checks.py browser') < browserJob.indexOf(expectedStep));
 assert(browserJob.indexOf(expectedStep) < browserJob.indexOf('if: success()')); assert.doesNotMatch(browserJob, /continue-on-error/);
 assert.match(workflow, /needs: \[select, backend, frontend, browser\]/); assert.match(workflow, /item\.get\('result'\) != 'success'/);
 const runner = await readFile(new URL('./run-windows-enrollment-ci.mjs', import.meta.url), 'utf8');
 assert(runner.indexOf('requireHosted();') < runner.indexOf('chromium.launch')); assert.match(runner, /validateEvidence\(output, sourceSha\)/);
});

test('PNG evidence requires valid bounded RGB/RGBA pixels, chunks, CRCs and exact zlib completion', () => {
 const row = captureMatrix[1], valid = fixturePNG(row), header = valid.subarray(16, 29), width = header.readUInt32BE(0), height = header.readUInt32BE(4);
 const compressed = valid.subarray(41, 41 + valid.readUInt32BE(33)), signature = valid.subarray(0, 8), end = chunk('IEND', Buffer.alloc(0));
 const pack = (data, ihdr = header) => Buffer.concat([signature, chunk('IHDR', ihdr), ...data, end]);
 const withData = data => pack([chunk('IDAT', data)]), raw = Buffer.alloc((width * 3 + 1) * height);
 for (const bytes of [valid, fixturePNG(row, 4), pack([chunk('IDAT', compressed.subarray(0, 5)), chunk('IDAT', compressed.subarray(5))])]) assert.deepEqual(validateDialogPNG(bytes, row.width, row.height), { width, height });
 const filtered = Buffer.from(raw); for (let n = 0; n < height; n++) filtered[n * (width * 3 + 1)] = n % 5;
 validateDialogPNG(withData(deflateSync(filtered)), row.width, row.height);
 const badHeaderCRC = Buffer.from(valid); badHeaderCRC[29] ^= 1;
 const badDataCRC = Buffer.from(valid); badDataCRC[41 + compressed.length] ^= 1;
 const badEndCRC = Buffer.from(valid); badEndCRC[badEndCRC.length - 1] ^= 1;
 const badLength = Buffer.from(valid); badLength.writeUInt32BE(0xffffffff, 33);
 const badStream = Buffer.from(compressed); badStream[badStream.length - 1] ^= 1;
 const badFilter = Buffer.from(raw); badFilter[0] = 5;
 const forged = Buffer.alloc(24); signature.copy(forged); forged.writeUInt32BE(1, 16); forged.writeUInt32BE(1, 20);
 const cases = [
  ['fake header', forged], ['missing IDAT', pack([])], ['empty IDAT', withData(Buffer.alloc(0))],
  ['truncated zlib', withData(compressed.subarray(0, -1))], ['corrupt zlib with valid CRC', withData(badStream)],
  ['non-deflate data', withData(Buffer.from('not pixel data'))], ['trailing compressed bytes', withData(Buffer.concat([compressed, Buffer.from([0])]))],
  ['concatenated zlib streams', withData(Buffer.concat([compressed, compressed]))], ['short output', withData(deflateSync(raw.subarray(1)))],
  ['excess output', withData(deflateSync(Buffer.alloc(raw.length + 1)))], ['inflation bomb', withData(deflateSync(Buffer.alloc(7 << 20)))],
  ['invalid filter', withData(deflateSync(badFilter))], ['IHDR CRC', badHeaderCRC], ['IDAT CRC', badDataCRC], ['IEND CRC', badEndCRC],
  ['chunk length overflow', badLength], ['truncated chunk', valid.subarray(0, -1)], ['missing IEND', valid.subarray(0, -12)],
  ['trailing file bytes', Buffer.concat([valid, Buffer.from([0])])], ['duplicate IHDR', pack([chunk('IHDR', header), chunk('IDAT', compressed)])],
  ['private ancillary chunk', pack([chunk('tEXt', Buffer.from('unexported')), chunk('IDAT', compressed)])], ['oversized input', Buffer.alloc((8 << 20) + 1)],
 ];
 for (const [name, index, value] of [['bit depth', 8, 16], ['palette', 9, 3], ['compression', 10, 1], ['filter method', 11, 1], ['interlace', 12, 1]]) {
  const changed = Buffer.from(header); changed[index] = value; cases.push([name, pack([chunk('IDAT', compressed)], changed)]);
 }
 for (const [name, bytes] of cases) assert.throws(() => validateDialogPNG(bytes, row.width, row.height), name);
 const hugeHeader = Buffer.from(header); hugeHeader.writeUInt32BE(0xffffffff); assert.throws(() => validateDialogPNG(pack([chunk('IDAT', compressed)], hugeHeader), row.width, row.height));
 assert.throws(() => validateDialogPNG(valid, 1, 1));
});
test('the complete evidence path rejects all eight forged 24-byte images before any Git acceptance', async () => {
 const output = await mkdtemp(path.join(os.tmpdir(), 'windows-forged-evidence-'));
 try {
  const current = manifest();
  current.captures = await Promise.all(captureMatrix.map(async (row, index) => {
   const bytes = Buffer.alloc(24); Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]).copy(bytes); bytes.writeUInt32BE(1, 16); bytes.writeUInt32BE(1, 20);
   await writeFile(path.join(output, row.file), bytes); return captureRow(index, bytes);
  }));
  await writeFile(path.join(output, 'windows-enrollment-results.json'), JSON.stringify(successfulReport(sourceSha), null, 2) + '\n');
  await writeFile(path.join(output, 'windows-enrollment-manifest.json'), JSON.stringify(current, null, 2) + '\n');
  await assert.rejects(() => validateEvidence(output, sourceSha), /Invalid PNG evidence/);
 } finally { await rm(output, { recursive: true, force: true }); }
});
test('production Inter inputs and exact non-inherited compiler config are included before bundling', async () => {
 const sourceMap = new Map(compiled.sourceInputs.map(row => [row.file, row.sha256]));
 for (const file of ['web/src/main.tsx', 'web/tsconfig.json', 'web/package.json', 'web/package-lock.json']) assert.equal(sourceMap.get(file), createHash('sha256').update(await readFile(new URL('../' + file.slice(4), import.meta.url))).digest('hex'));
 assert.equal(compiled.dependencyInputs.length, 13);
 for (const weight of fontWeights) for (const suffix of [`latin-${weight}.css`, `files/inter-latin-${weight}-normal.woff`, `files/inter-latin-${weight}-normal.woff2`]) assert(compiled.dependencyInputs.some(row => row.file === `web/node_modules/@fontsource/inter/${suffix}`));
 const css = compiled.assets.get('/app.css').body.toString(); assert.equal((css.match(/@font-face/g) || []).length, 4); assert.match(css, /data:font\/woff2;base64,/);
 for (const weight of fontWeights) assert(css.includes(`font-weight:${weight}`));
 const config = { compilerOptions: { jsx: 'react-jsx' } }; assert.deepEqual(compilerConfiguration(Buffer.from(JSON.stringify(config))), config);
 for (const value of [{ ...config, extends: './private-config.json' }, [], null, {}, '{']) assert.throws(() => compilerConfiguration(Buffer.from(typeof value === 'string' ? value : JSON.stringify(value))));
 const recipe = await readFile(new URL('./capture-windows-enrollment.mjs', import.meta.url), 'utf8');
 for (const text of ['tsconfigRaw, define:', "build.onLoad({ filter: /.*/, namespace: 'file' }", 'document.fonts.load', "face.status === 'loaded'", "getComputedStyle(sample).fontFamily", 'productionFontsLoaded: true']) assert(recipe.includes(text));
});
test('descriptor-bound reads reject oversize, empty, directories and symlinked file/parent inputs', async () => {
 const directory = await mkdtemp(path.join(os.tmpdir(), 'windows-bounded-read-')), file = path.join(directory, 'input');
 try {
  await writeFile(file, 'abc'); assert.equal((await boundedRegular(file, 3)).toString(), 'abc');
  await assert.rejects(() => boundedRegular(file, 2)); await assert.rejects(() => boundedRegular(directory, 100));
  await symlink(file, path.join(directory, 'link')); await assert.rejects(() => boundedRegular(path.join(directory, 'link'), 3));
  await symlink(directory, path.join(directory, 'parent')); await assert.rejects(() => boundedRegular(path.join(directory, 'parent/input'), 3));
  await writeFile(file, ''); await assert.rejects(() => boundedRegular(file, 3));
 } finally { await rm(directory, { recursive: true, force: true }); }
});
test('bounded reader fails closed on descriptor swaps, changed metadata, extra bytes and short reads', async () => {
 const source = await readFile(new URL('./windows-enrollment-contract.mjs', import.meta.url), 'utf8');
 const body = source.slice(source.indexOf('export async function boundedRegular'), source.indexOf('let pngDecoder')).replace('export async function', 'async function');
 for (const mode of ['pass', 'swapped-open', 'wrong-descriptor-path', 'growth', 'metadata-change', 'short-read']) {
  let closed = false, stats = 0, reads = 0;
  const info = { dev: 1n, ino: 2n, size: 3n, mtimeNs: 1n, ctimeNs: 1n, mode: 33188n, isFile: () => true, isSymbolicLink: () => false };
  const handle = { fd: 7, stat: async () => ({ ...info, ino: mode === 'swapped-open' ? 3n : 2n, mtimeNs: ++stats > 1 && mode === 'metadata-change' ? 2n : 1n }), read: async buffer => { const count = reads++ ? 0 : mode === 'short-read' ? 2 : mode === 'growth' ? 4 : 3; buffer.fill(97); return { bytesRead: count }; }, close: async () => { closed = true; } };
  const reader = new Function('assert', 'path', 'lstat', 'open', 'realpath', 'constants', 'process', `${body}; return boundedRegular;`)(assert, path, async () => info, async () => handle, async value => value === '/proc/self/fd/7' ? mode === 'wrong-descriptor-path' ? '/other/private' : '/fixture/input' : value, { O_RDONLY: 0, O_NOFOLLOW: 1, O_NONBLOCK: 2 }, { platform: 'linux' });
  if (mode === 'pass') assert.equal((await reader('/fixture/input', 3)).toString(), 'aaa'); else await assert.rejects(() => reader('/fixture/input', 3), mode);
  assert(closed);
 }
});
