/** Inert contracts only: no browser, host action, listener or external request. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { crc32, deflateSync } from 'node:zlib';
import { test } from 'node:test';
import { assertPublicSafe, capture, captureMatrix, compile, compilerConfiguration, disclosure, fontWeights, origin, routeFixture, routeState, viewports } from './capture-windows-enrollment.mjs';
import { boundedRegular, diagnostic, publicSafeFailures, stages, requireHosted, validateDialogPNG, visibilityControlCases, visibilityControlPhases, visibilityControlStage } from './windows-enrollment-contract.mjs';
import { approvedBody, creation, csrf, invitation, secret } from './windows-enrollment-fixtures.mjs';
import { controlHTML, controlRoute, controlURL, runVisibilityControls } from './windows-enrollment-visibility-controls.mjs';
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
const manifest = () => ({ sourceSha, sourceInputs: compiled.sourceInputs, dependencyInputs: compiled.dependencyInputs, sourceDigest: compiled.sourceDigest, captures: captureMatrix.map((_, index) => captureRow(index)), visibilityControls: { contexts: 1, cases: 6, passed: true, closedBodyRange: 'positive', screenshots: 0, syntheticDocumentRequests: 1, requestsToRealAPI: 0, actualMutationRequests: 0 }, disclosure, browserExecuted: true, appMounted: false, nativeAcceptance: false, actualMutationRequests: 0, requestsToRealAPI: 0 });

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
 try { delete process.env.GITHUB_ACTIONS; delete process.env.RUNNER_ENVIRONMENT; assert.throws(() => requireHosted(), /Hosted CI only/); await assert.rejects(() => capture({ browser: null, expect: null, output: '/unused' }), /Hosted CI only/); await assert.rejects(() => runVisibilityControls({ browser: null, expect: null, assertPublicSafe: null }), /Hosted CI only/); }
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
 for (const change of [{ captures: [] }, { sourceDigest: 'b'.repeat(64) }, { sourceInputs: [] }, { dependencyInputs: [] }, { appMounted: true }, { browserExecuted: false }, { rawInvitation: invitation }, { visibilityControls: null }, { visibilityControls: { ...manifest().visibilityControls, closedBodyRange: 'unknown' } }, { visibilityControls: { ...manifest().visibilityControls, passed: false } }, { visibilityControls: { ...manifest().visibilityControls, screenshots: 1 } }, { visibilityControls: { ...manifest().visibilityControls, raw: secret } }]) assert.throws(() => validateMetadata(successfulReport(sourceSha), { ...manifest(), ...change }, sourceSha, compiled));
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
 for (const pattern of ["dialog.locator('.enrollment-windows-install')", "window.dispatchEvent(new Event('pagehide'))", "window.dispatchEvent(new Event('pageshow'))", "await expect(input).toHaveCount(0)", "element.closest('[role=\"dialog\"]')", 'dialog.scrollTo', 'await assertPublicSafe(page, dialog, expect, stage => mark(stage, matrixIndex))', 'await dialog.screenshot(', 'await expect(target).toBeInViewport({ ratio: 1 })']) assert(source.includes(pattern), pattern);
 assert.doesNotMatch(source, /page\.setContent|innerHTML\s*=|outerHTML\s*=|page\.addStyleTag|mask:|maskColor:|visibility: hidden|\.fill\(|\.type\(|\.pressSequentially\(/);
});
test('existing hosted browser job runs the strict capture gate and uploads its eight exact images', async () => {
 const workflow = await readFile(new URL('../../.github/workflows/pr-checks.yml', import.meta.url), 'utf8');
 assert.match(workflow, /runs-on: ubuntu-24\.04/); assert.match(workflow, /contents: read/); assert.match(workflow, /persist-credentials: false/);
 for (const row of captureMatrix) assert(workflow.includes(`artifacts/review/${row.file}`));
 assert.match(workflow, /if: success\(\)/); assert.match(workflow, /node web\/scripts\/run-windows-enrollment-ci\.mjs/);
 assert.doesNotMatch(workflow, /workflow_dispatch|pull_request_target|secrets\.|ignoreHTTPSErrors|windows-inventory-browser|macos-enrollment/);
 const browserJob = workflow.split('\n  browser:\n')[1]?.split('\n  focused:\n')[0]; assert(browserJob);
 const expectedStep = '      - name: Verify synthetic Windows created-stage instructions\n' + `        if: ${independentGateCondition}\n` + '        run: |\n          node web/scripts/capture-windows-enrollment.mjs --check\n          node --test web/scripts/windows-enrollment-capture.node.mjs\n          node web/scripts/run-windows-enrollment-ci.mjs\n';
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

// Read-only DOM/geometry model, not a browser or a claim about Chromium layout.
function publicSafetyHarness({ text = 'Reviewed setup instructions', rectangles = [{ width: 1, height: 1 }], ancestry = 'ordinary', inputs = [], href = origin + '/', local = {}, session = {}, protectedCount = 0, inspectionError = false, returnedFailure, nativeOutcome = false } = {}) {
 const element = (kind, parentElement = null) => ({
  kind, parentElement,
  matches(selector) { assert.equal(selector, 'details:not([open])'); return this.kind === 'closed-details'; },
  querySelector(selector) { assert.equal(selector, ':scope > summary'); return this.summary ?? null; },
  contains(target) { for (let node = target; node; node = node.parentElement) if (node === this) return true; return false; },
  closest(selector) { assert.equal(selector, 'script,style'); return ['script', 'style'].includes(this.kind) ? this : null; },
 });
 const root = element('dialog'); let parent = element('ordinary', root);
 if (['closed-body', 'closed-summary', 'open-body', 'nested-closed-body'].includes(ancestry)) {
  const details = element(ancestry === 'open-body' ? 'open-details' : 'closed-details', root);
  details.summary = element('summary', details);
  parent = ancestry === 'closed-summary' ? details.summary : element('body', details);
  if (ancestry === 'nested-closed-body') parent = element('ordinary', parent);
 } else if (ancestry === 'script' || ancestry === 'style') parent = element(ancestry, root);
 else if (ancestry === 'detached') parent = null;
 const textNode = { textContent: text, parentElement: parent }, events = []; let inspected = false;
 const document = {
  createTreeWalker(target, filter) { assert.equal(target, root); assert.equal(filter, 4); let used = false; return { nextNode: () => used ? null : (used = true, textNode) }; },
  createRange() { return { selectNodeContents: node => assert.equal(node, textNode), getClientRects: () => rectangles }; },
  querySelectorAll(selector) { assert.equal(selector, 'input'); return inputs.map(value => ({ value })); },
 };
 const Element = function() {};
 if (nativeOutcome !== 'unavailable') Element.prototype.checkVisibility = function() { assert.equal(this, parent); if (nativeOutcome === 'throw') throw new Error('unexported native error'); return nativeOutcome; };
 const evaluate = callback => new Function('document', 'NodeFilter', 'location', 'localStorage', 'sessionStorage', 'Element', `return (${callback.toString()});`)(document, { SHOW_TEXT: 4 }, { href }, local, session, Element)(root, { secret, invitation });
 const page = { locator(selector) { assert.equal(selector, '.enrollment-secret, .enrollment-fingerprint, .enrollment-comparison'); return { protectedCount }; } };
 const dialog = { async evaluate(callback, values) { inspected = true; assert.deepEqual(values, { secret, invitation }); if (inspectionError) throw new Error('unexported synthetic diagnostic'); if (returnedFailure !== undefined) return returnedFailure; return evaluate(callback); } };
 const expect = locator => ({ async toHaveCount(count) { assert.equal(count, 0); assert.equal(locator.protectedCount, count); } });
 return { page, dialog, expect, events, evaluate, inspected: () => inspected, run: () => assertPublicSafe(page, dialog, expect, stage => events.push(diagnostic(stage, 0))) };
}
// Exact former boolean predicate, retained solely to prove its acceptance set.
function originalPublicSafetyPredicate(dialog, { secret, invitation }) {
 const identifier = /(?:invite|manager|request|claim|agent)_[a-f0-9]{32}|(?:ab){32}|(?:12ab){8}/;
 const walker = document.createTreeWalker(dialog, NodeFilter.SHOW_TEXT); let node;
 while ((node = walker.nextNode())) {
  const parent = node.parentElement;
  if (!parent || parent.closest('script,style')) continue;
  const range = document.createRange(); range.selectNodeContents(node);
  if ([...range.getClientRects()].some(rect => rect.width > 0 && rect.height > 0) && (node.textContent.includes(secret) || identifier.test(node.textContent))) return false;
 }
 return ![...document.querySelectorAll('input')].some(input => input.value.includes(secret) || identifier.test(input.value)) && !location.href.includes(secret) && !location.href.includes(invitation) && !JSON.stringify({ ...localStorage, ...sessionStorage }).includes(secret);
}
test('public-safety branches retain exact original acceptance across read-only DOM/geometry models', async () => {
 let cases = 0;
 for (const text of ['Reviewed instructions', secret, invitation, `manager_${'2'.repeat(32)}`, 'ab'.repeat(32), '12ab'.repeat(8)]) {
  for (const rectangles of [[], [{ width: 0, height: 1 }], [{ width: 1, height: 0 }], [{ width: 1, height: 1 }]]) {
   for (const ancestry of ['ordinary', 'closed-body', 'closed-summary', 'open-body', 'nested-closed-body', 'script', 'style', 'detached']) {
    for (const extra of [{}, { inputs: [secret] }, { inputs: [invitation] }, { href: origin + '/#' + secret }, { href: origin + '/#' + invitation }, { local: { value: secret } }, { session: { value: secret } }]) for (const nativeOutcome of [false, true, 'unavailable', 'throw']) {
     const h = publicSafetyHarness({ text, rectangles, ancestry, nativeOutcome, ...extra }), expected = h.evaluate(originalPublicSafetyPredicate);
     if (expected) await h.run(); else await assert.rejects(() => h.run(), /Unsafe public capture surface/);
     assert(h.events.every(row => Object.keys(row).join(',') === 'stage,scene,locale,width'));
     assert(h.events.every(row => row.scene === 'instructions' && row.locale === 'en' && row.width === 1440));
     const serialized = JSON.stringify(h.events); assert(!serialized.includes(secret)); assert(!serialized.includes(invitation)); cases++;
    }
   }
  }
 }
 assert.equal(cases, 5376);
});
test('public-safety diagnostics identify fixed branches without exempting closed disclosure text', async () => {
 const cases = [
  [{ text: invitation }, 'public-safe-text'],
  [{ text: invitation, ancestry: 'closed-body' }, 'public-safe-text-closed-details-native-false'],
  [{ text: secret, ancestry: 'nested-closed-body' }, 'public-safe-text-closed-details-native-false'],
  [{ text: invitation, ancestry: 'closed-summary' }, 'public-safe-text'],
  [{ text: invitation, ancestry: 'open-body' }, 'public-safe-text'],
  [{ inputs: [secret] }, 'public-safe-inputs'],
  [{ href: origin + '/#' + invitation }, 'public-safe-location'],
  [{ local: { value: secret } }, 'public-safe-storage'],
  [{ session: { value: secret } }, 'public-safe-storage'],
 ];
 assert.deepEqual(publicSafeFailures, ['public-safe-text', 'public-safe-text-closed-details-native-true', 'public-safe-text-closed-details-native-false', 'public-safe-text-closed-details-native-unavailable', 'public-safe-text-closed-details-native-error', 'public-safe-inputs', 'public-safe-location', 'public-safe-storage']);
 for (const [options, failure] of cases) {
  const h = publicSafetyHarness(options); await assert.rejects(() => h.run(), /Unsafe public capture surface/);
  assert.deepEqual(h.events.map(row => row.stage), ['public-safe-elements', 'public-safe-inspection', failure]);
 }
 const h = publicSafetyHarness({ text: invitation, ancestry: 'closed-body', rectangles: [] }); await h.run();
 assert.deepEqual(h.events.map(row => row.stage), ['public-safe-elements', 'public-safe-inspection']);
});
test('protected elements, inspection errors and unexpected diagnostic values fail closed with fixed checkpoints', async () => {
 const protectedElement = publicSafetyHarness({ protectedCount: 1 }); await assert.rejects(() => protectedElement.run());
 assert.equal(protectedElement.inspected(), false); assert.deepEqual(protectedElement.events, [diagnostic('public-safe-elements', 0)]);
 const inspection = publicSafetyHarness({ inspectionError: true }); await assert.rejects(() => inspection.run());
 assert.deepEqual(inspection.events, [diagnostic('public-safe-elements', 0), diagnostic('public-safe-inspection', 0)]);
 for (const returnedFailure of [secret, invitation, { text: secret }, false, true, 1, '']) {
  const h = publicSafetyHarness({ returnedFailure }); await assert.rejects(() => h.run(), /Invalid public-safety diagnostic/);
  assert.deepEqual(h.events, [diagnostic('public-safe-elements', 0), diagnostic('public-safe-inspection', 0)]);
 }
});
test('production prerequisites and privacy assertions still precede every screenshot with unchanged runner redaction', async () => {
 const recipe = await readFile(new URL('./capture-windows-enrollment.mjs', import.meta.url), 'utf8');
 const sequence = ["mark('secret-masked'", "mark('interrupt-clear'", 'await expect(input).toHaveCount(0)', "mark('refresh-restored'", "mark('instructions'", "mark('fonts'", "mark('scroll'", "mark('public-safe'", 'await assertPublicSafe(page, dialog, expect, stage => mark(stage, matrixIndex))', "mark('screenshot'"];
 let offset = -1; for (const item of sequence) { const next = recipe.indexOf(item); assert(next > offset, item); offset = next; }
 assert.equal((recipe.match(/\.screenshot\(/g) || []).length, 1);
 const runner = await readFile(new URL('./run-windows-enrollment-ci.mjs', import.meta.url), 'utf8');
 assert(runner.includes('} catch { failure = tag; }')); assert(runner.includes('JSON.stringify(report.failure)')); assert(runner.includes('raw diagnostics withheld.'));
 assert.doesNotMatch(runner, /console\.(?:error|debug|trace)|error\.message|error\.stack|\.innerText\(|\.textContent\(/);
});

test('native parent-box subcategories never exempt matching closed-disclosure text', async () => {
 for (const [nativeOutcome, suffix] of [[true, 'true'], [false, 'false'], ['unavailable', 'unavailable'], ['throw', 'error'], ['not-a-boolean', 'error']]) {
  const h = publicSafetyHarness({ text: invitation, ancestry: 'closed-body', nativeOutcome }); await assert.rejects(() => h.run(), /Unsafe public capture surface/);
  assert.equal(h.events.at(-1).stage, `public-safe-text-closed-details-native-${suffix}`);
 }
 const h = publicSafetyHarness({ text: secret, nativeOutcome: false }); await assert.rejects(() => h.run(), /Unsafe public capture surface/); assert.equal(h.events.at(-1).stage, 'public-safe-text');
});
test('isolated control route serves only its one known document and never production or external routes', async () => {
 const request = (url = controlURL, method = 'GET', body = null, headers = {}) => ({ url: () => url, method: () => method, postData: () => body, headers: () => headers });
 for (const args of [[origin + '/'], [origin + '/api/session'], [origin + '/api/windows/enrollment/invitations', 'POST', '{}'], ['https://external.invalid/'], [controlURL + '?extra'], [controlURL, 'POST'], [controlURL, 'GET', '{}'], [controlURL, 'GET', null, { cookie: 'invented' }], [controlURL, 'GET', null, { authorization: 'invented' }]]) {
  const state = { documents: 0, blocked: 0 }; let aborted = false;
  await controlRoute(state)({ request: () => request(...args), abort: () => { aborted = true; }, fulfill: () => assert.fail('Unexpected fulfillment') }); assert(aborted); assert.deepEqual(state, { documents: 0, blocked: 1 });
 }
 const state = { documents: 0, blocked: 0 }, route = controlRoute(state); let received, aborted = false;
 await route({ request: () => request(), fulfill: value => { received = value; }, abort: () => assert.fail('Expected fixture') }); assert.equal(received.body, controlHTML); assert.equal(received.contentType, 'text/html');
 await route({ request: () => request(), abort: () => { aborted = true; }, fulfill: () => assert.fail('Duplicate document') }); assert(aborted); assert.deepEqual(state, { documents: 1, blocked: 1 });
 assert.doesNotMatch(controlHTML, /<script|<iframe|<img|<form|https?:|src=/i); assert.match(controlHTML, /<p data-probe style="display:contents">SYNTHETIC_ONLY_NOT_AN_INVITATION_1234567890<\/p>/);
});
function visibilityControlHarness(mode = 'positive', fault = {}) {
 const calls = [], marks = []; let handler, pageError, closed = false, url = fault.setup === 'blank' ? 'unexpected synthetic URL' : 'about:blank';
 const page = {
  url: () => url, on: (event, callback) => { assert.equal(event, 'pageerror'); pageError = callback; },
  async goto(target) { if (fault.setup === 'document') throw new Error('unexported synthetic error'); calls.push(['control-goto', target]); assert.equal(target, controlURL); await handler({ request: () => ({ url: () => target, method: () => 'GET', postData: () => null, headers: () => ({}) }), fulfill: response => assert.equal(response.body, controlHTML), abort: () => assert.fail('Control navigation blocked') }); url = target; if (fault.setup === 'runtime-errors') pageError(); if (fault.setup === 'route-boundary') await handler({ request: () => ({ url: () => origin + '/api/session', method: () => 'GET', postData: () => null, headers: () => ({}) }), abort: () => {}, fulfill: () => assert.fail('Unexpected fulfillment') }); },
  locator(selector) { const name = selector.slice(1); assert(['clear', 'visible', 'closed-body', 'closed-summary', 'open-body', 'contents'].includes(name)); return { name, owner: page, locator: inner => { assert.equal(inner, '[data-probe]'); return { name, owner: page, evaluate: async callback => { assert.match(callback.toString(), /Element\.prototype\.checkVisibility\.call\(element\)/); if (name === fault.caseName && fault.measureError) throw new Error('unexported synthetic error'); if (name === fault.caseName && 'observation' in fault) return fault.observation; return { positiveRange: name !== 'closed-body' || mode !== 'empty', native: mode === 'wrong-native' ? false : name !== 'closed-body' && name !== 'contents' }; } }; } }; },
 };
 const context = { route: async (pattern, fn) => { if (fault.setup === 'route') throw new Error('unexported synthetic error'); assert.equal(pattern, '**/*'); handler = fn; calls.push(['control-route']); }, newPage: async () => { if (fault.setup === 'page') throw new Error('unexported synthetic error'); calls.push(['new-control-page']); return page; }, close: async () => { closed = true; calls.push(['close-control-context']); if (fault.setup === 'close') throw new Error('unexported synthetic error'); } };
 const browser = { newContext: async options => { calls.push(['new-control-context', options]); return context; } };
 const expect = probe => ({ toBeHidden: async () => { if (probe.name === fault.caseName && fault.playwrightError) throw new Error('unexported synthetic error'); assert.equal(probe.name, 'closed-body'); }, toBeVisible: async () => { if (probe.name === fault.caseName && fault.playwrightError) throw new Error('unexported synthetic error'); assert.notEqual(probe.name, 'closed-body'); } });
 const inspect = async (givenPage, region, givenExpect, mark) => {
  assert.equal(givenPage, page); assert.equal(region.owner, page); assert.equal(givenExpect, expect); calls.push(['privacy', region.name]);
  if (region.name === fault.caseName && fault.privacyStages) { for (const stage of fault.privacyStages) mark(stage); if (fault.privacyRejected) throw new Error('unexported synthetic error'); return; }
  mark('public-safe-elements'); mark('public-safe-inspection');
  if (mode === 'accept-all' || region.name === 'clear' || region.name === 'closed-body' && mode === 'empty') return;
  mark(region.name === 'closed-body' ? 'public-safe-text-closed-details-native-false' : 'public-safe-text'); throw new Error('Expected synthetic rejection');
 };
 return { browser, expect, assertPublicSafe: inspect, mark: stage => marks.push(diagnostic(stage)), calls, marks, closed: () => closed };
}
async function withHostedFixture(run) {
 const before = { actions: process.env.GITHUB_ACTIONS, runner: process.env.RUNNER_ENVIRONMENT };
 try { process.env.GITHUB_ACTIONS = 'true'; process.env.RUNNER_ENVIRONMENT = 'github-hosted'; return await run(); }
 finally { if (before.actions === undefined) delete process.env.GITHUB_ACTIONS; else process.env.GITHUB_ACTIONS = before.actions; if (before.runner === undefined) delete process.env.RUNNER_ENVIRONMENT; else process.env.RUNNER_ENVIRONMENT = before.runner; }
}
test('native control driver owns one separate context/page and always closes it; only inert adapters execute here', async () => {
 for (const mode of ['positive', 'empty', 'wrong-native', 'accept-all']) {
  const h = visibilityControlHarness(mode);
  if (mode === 'positive' || mode === 'empty') {
   const result = await withHostedFixture(() => runVisibilityControls(h)); assert.deepEqual(result, { contexts: 1, cases: 6, passed: true, closedBodyRange: mode, screenshots: 0, syntheticDocumentRequests: 1, requestsToRealAPI: 0, actualMutationRequests: 0 }); assert.equal(h.calls.filter(row => row[0] === 'privacy').length, 6);
  } else await assert.rejects(() => withHostedFixture(() => runVisibilityControls(h)));
  assert(h.closed()); assert.equal(h.calls.filter(row => row[0] === 'new-control-context').length, 1); assert.deepEqual(h.calls[0][1], { viewport: { width: 800, height: 600 }, locale: 'en-US', reducedMotion: 'reduce', serviceWorkers: 'block' }); assert.equal(h.calls.filter(row => row[0] === 'new-control-page').length, 1); assert.deepEqual(h.calls.filter(row => row[0] === 'control-goto'), [['control-goto', controlURL]]); assert(h.calls.findIndex(row => row[0] === 'control-route') < h.calls.findIndex(row => row[0] === 'new-control-page'));
 }
 const source = await readFile(new URL('./windows-enrollment-visibility-controls.mjs', import.meta.url), 'utf8'); assert.doesNotMatch(source, /\.screenshot\(|\.setContent\(|innerHTML\s*=|outerHTML\s*=|\.addStyleTag\(|\.continue\(|routeFixture/);
 const recipe = await readFile(new URL('./capture-windows-enrollment.mjs', import.meta.url), 'utf8'); assert(recipe.indexOf('await runVisibilityControls({ browser, expect, assertPublicSafe, mark })') < recipe.indexOf('for (const [viewIndex,')); assert(compiled.sourceInputs.some(row => row.file === 'web/scripts/windows-enrollment-visibility-controls.mjs'));
});
test('every isolated control assertion has a fixed failure phase without exporting observed values', async () => {
 const raw = 'UNTRUSTED_SYNTHETIC_DIAGNOSTIC_MUST_NOT_ESCAPE';
 const check = async (caseName, fault, phase, mode = 'positive') => {
  const h = visibilityControlHarness(mode, { caseName, ...fault });
  await assert.rejects(() => withHostedFixture(() => runVisibilityControls(h)));
  assert(h.closed()); assert.equal(h.marks.at(-1).stage, visibilityControlStage(caseName, phase));
  assert(!JSON.stringify(h.marks).includes(raw));
  for (const row of h.marks) assert.deepEqual(Object.keys(row), ['stage', 'scene', 'locale', 'width']);
 };
 for (const caseName of visibilityControlCases) {
  const native = caseName !== 'closed-body' && caseName !== 'contents';
  await check(caseName, { measureError: true }, 'measure');
  for (const observation of [null, {}, { native, positiveRange: true, extra: raw }]) await check(caseName, { observation }, 'observation-shape');
  await check(caseName, { observation: { native, positiveRange: raw } }, 'range-type');
  await check(caseName, { observation: { native: !native, positiveRange: true } }, `native-${!native}-range-positive`);
  await check(caseName, { observation: { native: raw, positiveRange: true } }, 'native-invalid-range-positive');
  if (caseName !== 'closed-body') await check(caseName, { observation: { native, positiveRange: false } }, 'range-empty');
  await check(caseName, { playwrightError: true }, caseName === 'closed-body' ? 'playwright-hidden-range-positive' : 'playwright-visible');
  const privacyStages = ['public-safe-elements', 'public-safe-inspection'];
  await check(caseName, { privacyStages, privacyRejected: caseName === 'clear' }, `privacy-${caseName === 'clear' ? 'rejected' : 'accepted'}-last-public-safe-inspection-range-positive`);
  for (const last of ['none', 'public-safe-elements', 'public-safe-inputs', 'invalid']) {
   const faultyStages = last === 'none' ? [] : last === 'public-safe-elements' ? ['public-safe-elements'] : [...privacyStages, last === 'invalid' ? raw : last];
   await check(caseName, { privacyStages: faultyStages, privacyRejected: caseName !== 'clear' }, `privacy-sequence-last-${last}-range-positive`);
  }
 }
 await check('closed-body', { observation: { native: true, positiveRange: false } }, 'native-true-range-empty', 'empty');
 await check('closed-body', { playwrightError: true }, 'playwright-hidden-range-empty', 'empty');
 await check('closed-body', { privacyStages: ['public-safe-elements', 'public-safe-inspection'], privacyRejected: true }, 'privacy-rejected-last-public-safe-inspection-range-empty', 'empty');
});
test('isolated control setup, cleanup and final boundaries retain separate fail-closed checkpoints', async () => {
 for (const setup of ['route', 'page', 'blank', 'document', 'runtime-errors', 'route-boundary', 'close']) {
  const h = visibilityControlHarness('positive', { setup }); await assert.rejects(() => withHostedFixture(() => runVisibilityControls(h)));
  assert(h.closed()); assert.equal(h.marks.at(-1).stage, `visibility-control-${setup}`);
 }
});
test('synthetic visibility control diagnostic vocabulary is closed and has no raw-value extension', () => {
 assert.equal(new Set(stages).size, stages.length);
 for (const name of visibilityControlCases) for (const phase of visibilityControlPhases) {
  const stage = visibilityControlStage(name, phase); assert.deepEqual(diagnostic(stage), { stage, scene: null, locale: null, width: null });
 }
 for (const value of ['raw DOM', secret, invitation, {}, null, undefined]) {
  assert.throws(() => visibilityControlStage(value, 'measure'));
  assert.throws(() => visibilityControlStage('closed-body', value));
 }
});
test('success counts explicitly separate one control context from four unchanged capture contexts', () => {
 const report = successfulReport(sourceSha); assert.equal(report.contexts, 5); assert.equal(report.captureContexts, 4); assert.equal(report.controlContexts, 1); assert.equal(report.controlCases, 6); assert.equal(report.syntheticCreates, 4); assert.equal(report.screenshots, 8);
 for (const closedBodyRange of ['positive', 'empty']) { const current = manifest(); current.visibilityControls.closedBodyRange = closedBodyRange; validateMetadata(report, current, sourceSha, compiled); }
 for (const field of ['contexts', 'cases', 'passed', 'screenshots', 'syntheticDocumentRequests', 'requestsToRealAPI', 'actualMutationRequests']) { const current = manifest(); current.visibilityControls[field] = field === 'passed' ? false : 99; assert.throws(() => validateMetadata(report, current, sourceSha, compiled)); }
});


const independentGateCondition = "${{ !cancelled() && steps.browser_runtime.outcome == 'success' }}";
async function independentGateWorkflow() {
 const workflow = await readFile(new URL('../../.github/workflows/pr-checks.yml', import.meta.url), 'utf8');
 const browser = workflow.split('  browser:\n')[1]?.split('  focused:\n')[0];
 assert(browser, 'Existing browser job must be present');
 const setup = browser.split('      - name: Build whole UI and prepare existing browser runtime\n')[1]?.split('      - name:')[0];
 const gate = browser.split('      - name: Verify synthetic Windows created-stage instructions\n')[1]?.split('      - name:')[0];
 assert(setup && gate, 'Existing setup and Windows gate must be present');
 assert.match(setup, /^        id: browser_runtime\n/);
 assert.equal(browser.match(/^        id: browser_runtime$/gm)?.length, 1);
 assert.equal(gate.match(/^        if: (.+)$/m)?.[1], independentGateCondition);
 assert.equal(gate.split('        run: |\n')[1], '          node web/scripts/capture-windows-enrollment.mjs --check\n          node --test web/scripts/windows-enrollment-capture.node.mjs\n          node web/scripts/run-windows-enrollment-ci.mjs\n');
 assert.doesNotMatch(browser, /continue-on-error|secrets:|environment:|permissions:/);
 assert.match(browser, /TRACEBOLT_SOURCE_SHA: \$\{\{ github\.sha \}\}/);
 assert.match(browser, /      - name: Keep successful focused public-safe screenshots only\n        if: success\(\)\n/);
 assert.match(workflow, /^permissions:\n  contents: read$/m);
 return { workflow, browser, setup, gate };
}

test('independent Windows UI gate retains exact setup, source, commands and success-only artifact boundaries', async () => {
 const { setup, browser } = await independentGateWorkflow();
 assert.match(setup, /npm ci\n          npm run build\n          npx playwright install --with-deps chromium/);
 assert.match(browser, /      - name: Authenticated smoke and affected existing browser flows\n        run: python3 -I -B tests\/security\/pr_checks\.py browser/);
 assert(browser.indexOf('id: browser_runtime') < browser.indexOf('Verify synthetic Windows created-stage instructions'));
});

test('the exact documented gate condition refuses cancellation and every non-success setup outcome', async () => {
 await independentGateWorkflow();
 // This is a finite model of the exact source-bound GitHub expression, not an Actions runtime.
 // cancelled() overrides implicit success(); outcome is the value before continue-on-error.
 for (const cancelled of [false, true]) for (const setup of ['success', 'failure', 'cancelled', 'skipped', '', null, undefined]) for (const previous of ['success', 'failure']) {
  const scheduled = !cancelled && setup === 'success';
  assert.equal(scheduled, cancelled ? false : setup === 'success');
  if (cancelled || setup !== 'success') assert.equal(scheduled, false);
  if (!cancelled && setup === 'success' && previous === 'failure') assert.equal(scheduled, true);
 }
});

test('the unchanged real aggregate still rejects prior failure, cancellation, skip or missing prerequisites', async () => {
 const { workflow } = await independentGateWorkflow();
 const aggregate = workflow.split('  focused:\n')[1];
 assert.match(aggregate, /    if: \$\{\{ always\(\) \}\}\n    needs: \[select, backend, frontend, browser\]/);
 assert.doesNotMatch(aggregate, /continue-on-error/);
 const script = aggregate.split("          python3 - <<'PY'\n")[1]?.split('          PY')[0].split('\n').map(line => line.startsWith('          ') ? line.slice(10) : line).join('\n');
 assert(script && script.startsWith('import json, os\n'));
 const success = () => Object.fromEntries(['select', 'backend', 'frontend', 'browser'].map(name => [name, { result: 'success' }]));
 const run = results => spawnSync('python3', ['-I', '-B', '-c', script], { encoding: 'utf8', timeout: 10000, env: { PATH: process.env.PATH, RESULTS: JSON.stringify(results) } });
 const accepted = run(success()); assert.equal(accepted.error, undefined); assert.equal(accepted.status, 0); assert.match(accepted.stdout, /^PASS: focused source tier only;/);
 for (const name of ['select', 'backend', 'frontend', 'browser']) for (const result of ['failure', 'cancelled', 'skipped', null]) {
  const results = success(); results[name].result = result; const rejected = run(results);
  assert.equal(rejected.error, undefined); assert.equal(rejected.status, 1); assert.match(rejected.stderr, /focused prerequisite failed, skipped, cancelled or missing/);
 }
 for (const results of [{ ...success(), extra: { result: 'success' } }, { backend: { result: 'success' }, frontend: { result: 'success' }, browser: { result: 'success' } }]) assert.equal(run(results).status, 1);
});
