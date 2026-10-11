/** Portable logic/contract checks only. These never launch a browser, Windows
 * process or manager and are not native/read-scope/real-browser evidence. */
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { rootCertificates } from 'node:tls';
import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readFile, mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { SCHEMA, CHECKS, REASONS, Refusal, validateSpec, validateResult, resultSummary, finishSummary, freshCapture, fiveScopeBaseline, advancingSample, sameIdentity, sameEvent, syntheticMessage, usableUpdates, renderedUpdatesMatch, inspectRequest, budget, canonicalJSON, validateBootstrap, validateEndpointBinding, observe, loadValidators, pinnedDependencies, guardedResponseBody, closeBrowserObserved } from './browser.mjs';
const hash = value => createHash('sha256').update(value).digest('hex');
function spec() {
  return { schema: SCHEMA, runId: 'portable-only-13', planSHA256: hash('plan'), source: { commit: 'ab'.repeat(20), tree: 'cd'.repeat(20), inventorySHA256: hash('source') }, expiresUnix: Math.floor(Date.now() / 1000) + 600, operatorOrigin: 'https://manager.test:8443', agentOrigin: 'https://manager.test:9443', managerInstanceId: `manager_${'ab'.repeat(16)}`, issuerFingerprint: hash('issuer'), bootstrapServerCASHA256: hash('server ca'), bootstrapIssuerRootSHA256: hash('issuer root'), windowsBindingPath: '/tmp/private/portable-only-13-windows-binding.json', windowsTargetId: 'approved-test-vm', windowsMachineIdSHA256: hash('windows machine'), setupSHA256: hash('setup'), serviceSHA256: hash('service'), chromium: { path: '/tmp/browser', sha256: hash('browser') }, browserRoot: '/tmp/runtime', syntheticEvent: { source: 'TraceboltParity-portable-only-13', eventId: 123, messageSHA256: hash(syntheticMessage('portable-only-13')) }, outputPath: '/tmp/private/result.json', workspace: '/tmp/private' };
}
const rejects = (fn, reason) => assert.throws(fn, error => error instanceof Refusal && (!reason || error.reason === reason));
function selected() { return { channel: 'Application', recordId: '18446744073709551614', eventId: 123, level: 4, provider: 'TraceboltParity-portable-only-13', timestamp: new Date().toISOString() }; }
function requestCase() {
  const s = selected(), start = Date.now() - 1000;
  const binding = { certificateHash: hash('certificate'), deviceId: `agent_${'ab'.repeat(16)}`, grantId: 'bc'.repeat(16), floor: '0', phaseStarted: start, selection: s };
  const posted = { expectedFloor: '0', expectedHeaderGenerationId: `sample_${'cd'.repeat(16)}`, expectedHeaderSnapshotDigest: `sha256:${hash('headers')}`, selections: [{ channel: s.channel, recordId: s.recordId }], acknowledgeContent: true, acknowledgePlaintext: false };
  const description = { deviceId: binding.deviceId, certificateHash: binding.certificateHash, grantId: binding.grantId, headerGenerationId: posted.expectedHeaderGenerationId, headerSnapshotDigest: posted.expectedHeaderSnapshotDigest, headerCollectedAt: new Date(start).toISOString(), identity: { id: `winevent_${'de'.repeat(16)}`, sequence: '1', queryDigest: `sha256:${hash('query')}` }, query: { events: [s] }, createdAt: new Date(start + 1).toISOString(), expiresAt: new Date(Date.now() + 60000).toISOString() };
  return { binding, posted, description };
}
test('strict spec binds known synthetic content and source without any auth field', () => {
  const s = spec(); assert.equal(validateSpec(s), s);
  for (const key of ['password', 'cookie', 'storageState', 'approval', 'ignoreHTTPSErrors', 'fixtureURL']) rejects(() => validateSpec({ ...s, [key]: 'anything' }));
  for (const key of ['messageSHA256', 'source', 'eventId']) { const bad = structuredClone(s); bad.syntheticEvent[key] = 'invalid'; rejects(() => validateSpec(bad)); }
});
test('wrong-origin, credentials, path, default TLS port and loopback specifications are refused', () => {
  for (const origin of ['http://manager.test:8443', 'https://user:secret@manager.test:8443', 'https://manager.test:8443/', 'https://manager.test:8443/path', 'https://manager.test:8443?token=secret', 'https://localhost:8443', 'https://127.0.0.1:8443', 'https://[::1]:8443', 'https://manager.test', 'https://host.invalid:8443']) rejects(() => validateSpec({ ...spec(), operatorOrigin: origin }), 'wrong_origin');
});
test('expiry and unbounded run time cannot be accepted', () => {
  const now = Date.now(); for (const expiresUnix of [0, Math.floor(now / 1000), Math.floor(now / 1000) + 7201, NaN, Infinity, '999']) rejects(() => validateSpec({ ...spec(), expiresUnix }, now), 'deadline');
  rejects(budget(Math.floor(now / 1000) - 1), 'deadline');
});
test('paths must be absolute, canonical, and result must be a child of the private workspace', () => {
  for (const path of ['relative', '/tmp/a/../result', '/tmp/private/child/result', '/tmp/private/result\n']) rejects(() => validateSpec({ ...spec(), outputPath: path }));
});
test('canonical stdin format rejects duplicate keys, trailing objects, invalid and oversized specs without output', () => {
  const script = fileURLToPath(new URL('./browser.mjs', import.meta.url));
  for (const input of ['{}\n', '{"schema":"bad","schema":"bad"}\n', canonicalJSON(spec()) + '{}', 'x'.repeat(32769)]) {
    const run = spawnSync(process.execPath, [script], { input, encoding: 'utf8', timeout: 10000 });
    assert.equal(run.status, 2); assert.equal(run.stdout, ''); assert.equal(run.stderr, '');
  }
  assert.equal(canonicalJSON({ z: 'ü', a: 1 }), '{"a":1,"z":"\\u00fc"}\n');
});
test('fresh capture uses original source time, not receipt or a recent server read', () => {
  const now = Date.now(), iso = n => new Date(n).toISOString();
  assert.equal(freshCapture(iso(now - 1000), iso(now), now - 2000, now), true);
  assert.equal(freshCapture(iso(now - 121000), iso(now), now - 200000, now), false);
  assert.equal(freshCapture(iso(now + 1), iso(now), now - 2000, now), false);
  assert.equal(freshCapture(iso(now - 1000), iso(now), now, now), false);
  assert.equal(freshCapture(iso(now - 3600000), iso(now - 3600000), 0, now), false);
  assert.equal(freshCapture('invalid', iso(now), 0, now), false);
});
test('baseline requires two advancing sequence, generation and original capture tuples', () => {
  const before = { sequence: 1, snapshot: { generationId: 'sample_a', collectedAt: '2026-10-11T01:00:00.000Z' } };
  const after = { sequence: 2, snapshot: { generationId: 'sample_b', collectedAt: '2026-10-11T01:00:01.000Z' } };
  assert.equal(advancingSample(before, after), true);
  assert.equal(advancingSample(before, before), false);
  assert.equal(advancingSample(before, { ...after, sequence: 1 }), false);
  assert.equal(advancingSample(before, { ...after, snapshot: { ...after.snapshot, generationId: 'sample_a' } }), false);
  assert.equal(advancingSample(before, { ...after, snapshot: { ...after.snapshot, collectedAt: before.snapshot.collectedAt } }), false);
});
test('exact event identity retains full-width record id and all six original fields', () => {
  const event = selected(); assert.equal(sameEvent(event, structuredClone(event)), true);
  for (const key of Object.keys(event)) assert.equal(sameEvent(event, { ...event, [key]: 'changed' }), false);
  assert.equal(sameIdentity({ id: 'a', sequence: '1', queryDigest: 'd' }, { id: 'a', sequence: '2', queryDigest: 'd' }), false);
});
test('request observation requires human acknowledgements and exact request/selection/certificate binding', () => {
  const { binding, posted, description } = requestCase(); inspectRequest(description, posted, binding);
  for (const key of ['certificateHash', 'deviceId', 'grantId', 'headerGenerationId', 'headerSnapshotDigest']) rejects(() => inspectRequest({ ...description, [key]: 'wrong' }, posted, binding), 'identity_mismatch');
  rejects(() => inspectRequest(description, { ...posted, acknowledgeContent: false }, binding), 'identity_mismatch');
  rejects(() => inspectRequest(description, { ...posted, acknowledgePlaintext: true }, binding), 'identity_mismatch');
  rejects(() => inspectRequest(description, { ...posted, selections: [...posted.selections, ...posted.selections] }, binding), 'identity_mismatch');
  rejects(() => inspectRequest({ ...description, expiresAt: new Date(Date.now() - 1).toISOString() }, posted, binding), 'stale_capture');
  rejects(() => inspectRequest({ ...description, query: { events: [] } }, posted, binding), 'identity_mismatch');
});
test('unknown cache and denied/unavailable observations never turn into patched success', () => {
  assert.equal(usableUpdates({ cacheFreshness: 'unknown', quality: 'observed', rows: [] }), true);
  assert.equal(usableUpdates({ cacheFreshness: 'unknown', quality: 'partial', rows: [{}] }), true);
  for (const quality of ['partial', 'denied', 'unavailable']) assert.equal(usableUpdates({ cacheFreshness: 'unknown', quality, rows: [] }), false);
  assert.equal(usableUpdates({ cacheFreshness: 'fresh', quality: 'observed', rows: [] }), false);
});
test('finite result schema forbids content, identifiers, invented outcomes, and full acceptance', () => {
  const s = spec(), report = resultSummary(s); validateResult(report, s);
  for (const key of ['cookie', 'message', 'screenshot', 'deviceId', 'error']) rejects(() => validateResult({ ...report, [key]: 'private' }, s));
  rejects(() => validateResult({ ...report, fullAcceptance: true }, s));
  rejects(() => validateResult({ ...report, status: 'passed', reason: 'complete' }, s));
  rejects(() => validateResult({ ...report, reason: 'raw OS error' }, s));
  assert.ok(REASONS.every(reason => /^[a-z_]+$/.test(reason)));
});
test('every observed check is required; result schema alone is never browser evidence', () => {
  const s = spec(), report = resultSummary(s);
  report.nativeExecution = true; for (const key of CHECKS) report.checks[key] = true;
  report.observations.eventQuality = 'observed'; report.observations.updatesQuality = 'observed'; report.observations.updatesCountExact = true; report.observations.updatesRendering = 'empty_state_only';
  finishSummary(report); validateResult(report, s); assert.equal(report.status, 'passed'); assert.equal(report.fullAcceptance, false); assert.equal(report.observations.patchCoverage, 'not_assessed');
  for (const key of CHECKS) { const incomplete = structuredClone(report); incomplete.checks[key] = false; finishSummary(incomplete); assert.equal(incomplete.status, 'blocked'); }
  const falseContent = structuredClone(report); falseContent.observations.eventQuality = 'unavailable'; rejects(() => validateResult(falseContent, s));
  const falseUpdates = structuredClone(report); falseUpdates.observations.updatesQuality = 'denied'; rejects(() => validateResult(falseUpdates, s));
});
test('source contains production UI route and human handoff but no route mocks, clocks or auth persistence', async () => {
  const source = await readFile(new URL('./browser.mjs', import.meta.url), 'utf8');
  for (const forbidden of [/\.route\(/, /\.fulfill\(/, /\.clock\./, /\.storageState\(/, /\.screenshot\(/, /\.tracing\./, /launchPersistentContext\(/, /\.cookies\(/, /\.addCookies\(/, /getByRole\([^\n]*Request messages once[^\n]*\.click/]) assert.equal(forbidden.test(source), false, String(forbidden));
  assert.match(source, /PARITY_BROWSER_EVENT_REQUEST_HANDOFF/); assert.match(source, /headless: false, chromiumSandbox: true/); assert.match(source, /credentials: 'same-origin'/); assert.match(source, /redirect: 'error'/); assert.match(source, /await loadValidators\(root, spec.browserRoot\)/);
});

test('public bootstrap is exact, pinned, TLS Windows-only, and contains no invitation secret', () => {
  // Built-in public root is only a parser fixture; no trust is installed and no
  // endpoint/manager identity, certificate, or key is created by this test.
  const pem = rootCertificates[0], cert = new X509Certificate(pem), s = spec(), invitationId = `invite_${'bc'.repeat(16)}`;
  s.issuerFingerprint = hash(cert.raw); s.bootstrapServerCASHA256 = hash(pem); s.bootstrapIssuerRootSHA256 = hash(pem);
  const value = { schemaVersion: 'tracebolt.enrollment-bootstrap.v2', managerInstanceId: s.managerInstanceId, profile: 'tls', enrollmentOrigin: s.operatorOrigin, agentOrigin: s.agentOrigin, collectionProfile: 'windows-inventory-v1', invitationId, serverCaPem: pem, issuerRootPem: pem, issuerPem: pem };
  assert.equal(validateBootstrap(value, s, invitationId), value);
  for (const key of ['invitationSecret', 'password', 'privateKey']) rejects(() => validateBootstrap({ ...value, [key]: 'secret' }, s, invitationId), 'invalid_response');
  for (const key of ['managerInstanceId', 'profile', 'enrollmentOrigin', 'agentOrigin', 'collectionProfile', 'invitationId']) rejects(() => validateBootstrap({ ...value, [key]: 'wrong' }, s, invitationId), 'identity_mismatch');
  for (const key of ['issuerFingerprint', 'bootstrapServerCASHA256', 'bootstrapIssuerRootSHA256']) rejects(() => validateBootstrap(value, { ...s, [key]: hash('wrong') }, invitationId), 'identity_mismatch');
  rejects(() => validateBootstrap({ ...value, issuerPem: pem + '\nprivate data' }, s, invitationId), 'invalid_response');
});

test('tool-produced endpoint binding must match exact target/artifacts and observed identity', () => {
  const s = spec(), identity = { deviceId: `agent_${'cd'.repeat(16)}`, certificateHash: hash('certificate'), invitationId: `invite_${'bc'.repeat(16)}` }, bootstrapSHA256 = hash('public bootstrap');
  const value = { schema: 'tracebolt.windows-linux-native-parity.endpoint-binding.v1', runId: s.runId, planSHA256: s.planSHA256, source: { ...s.source }, windowsTargetId: s.windowsTargetId, windowsMachineIdSHA256: s.windowsMachineIdSHA256, setupSHA256: s.setupSHA256, serviceSHA256: s.serviceSHA256, deviceId: identity.deviceId, certificateHash: identity.certificateHash, invitationIdSHA256: hash(identity.invitationId), bootstrapSHA256 };
  validateEndpointBinding(value, s, identity, bootstrapSHA256);
  for (const key of ['runId', 'planSHA256', 'windowsTargetId', 'windowsMachineIdSHA256', 'setupSHA256', 'serviceSHA256', 'deviceId', 'certificateHash', 'invitationIdSHA256', 'bootstrapSHA256']) rejects(() => validateEndpointBinding({ ...value, [key]: 'wrong' }, s, identity, bootstrapSHA256), 'identity_mismatch');
  rejects(() => validateEndpointBinding({ ...value, passed: true }, s, identity, bootstrapSHA256), 'invalid_response');
});
// An in-process fake *driver*, not a server/route/page fixture. It cannot render
// an app or supply accepted evidence; these tests stop before enrollment and
// exercise the actual observer's refusal and lifecycle code without Chromium.
function fakeDriver({ wrongOrigin = false, pendingRead = false, contextCloseHangs = false, browserCloseRejects = false } = {}) {
  const state = { browserClosed: 0, contextClosed: 0, reads: 0, resolveRead: null, validations: 0 };
  class Page extends EventEmitter {
    closed = false; current = 'about:blank';
    setDefaultTimeout() {} setDefaultNavigationTimeout() {} isClosed() { return this.closed; } url() { return this.current; }
    mainFrame() { return this; }
    async goto(url) { this.current = wrongOrigin ? 'https://unexpected.test:8443/' : url; this.emit('framenavigated', this); }
    async evaluate() { state.reads++; if (pendingRead) return new Promise(resolve => { state.resolveRead = resolve; }); return { status: 401, value: null }; }
  }
  const page = new Page(), context = new EventEmitter(); context.newPage = async () => page;
  context.close = async () => { state.contextClosed++; if (contextCloseHangs) await new Promise(() => {}); };
  const browser = { newContext: async () => context, close: async () => {
    state.browserClosed++;
    if (browserCloseRejects) throw new Error('inert close failure');
    page.closed = true; state.resolveRead?.({ status: 200, value: { mustNeverValidateAfterClose: true } });
  } };
  const validators = { validEnrollmentList() { state.validations++; throw new Error('late response validated'); } };
  return { chromium: { launch: async () => browser }, state, validators };
}
test('actual observer rejects wrong-origin navigation and closes its owned fake browser', async () => {
  const s = spec(), report = resultSummary(s), driver = fakeDriver({ wrongOrigin: true }), markers = [];
  await assert.rejects(observe(s, report, driver.validators, driver.chromium, marker => markers.push(marker)), error => error.reason === 'wrong_origin');
  assert.equal(driver.state.browserClosed, 1); assert.equal(driver.state.contextClosed, 0); assert.equal(driver.state.reads, 0); assert.equal(markers.length, 0); assert.equal(report.status, 'blocked');
});
test('actual observer handles SIGTERM during pending read and rejects the late response', async () => {
  const s = spec(), report = resultSummary(s), driver = fakeDriver({ pendingRead: true });
  const run = observe(s, report, driver.validators, driver.chromium, () => {});
  while (!driver.state.resolveRead) await new Promise(resolve => setTimeout(resolve, 1));
  process.emit('SIGTERM');
  await assert.rejects(run, error => error.reason === 'browser_unavailable');
  assert.equal(driver.state.browserClosed, 1); assert.equal(driver.state.contextClosed, 0); assert.equal(driver.state.validations, 0); assert.ok(CHECKS.filter(key => key !== 'browserClosed').every(key => report.checks[key] === false)); assert.equal(report.checks.browserClosed, true);
});
test('actual observer expires a real-clock pending run and releases owned fake context', async () => {
  const s = spec(); s.expiresUnix = Math.floor(Date.now() / 1000) + 1;
  const report = resultSummary(s), driver = fakeDriver({ pendingRead: true });
  await assert.rejects(observe(s, report, driver.validators, driver.chromium, () => {}), error => error.reason === 'deadline');
  assert.equal(driver.state.browserClosed, 1); assert.equal(driver.state.contextClosed, 0); assert.equal(driver.state.validations, 0); assert.equal(report.fullAcceptance, false);
});
test('production validator bundle is loaded from installed pinned dependencies; invalid DTOs refused', async t => {
  const sourceRoot = fileURLToPath(new URL('../../', import.meta.url));
  const dependencies = process.env.TRACEBOLT_BROWSER_TEST_DEPENDENCIES || resolve(sourceRoot, 'web');
  if (!existsSync(resolve(dependencies, 'node_modules/esbuild/package.json'))) { t.skip('Pinned web dependencies not installed; no native/browser evidence claimed.'); return; }
  const validators = await loadValidators(sourceRoot, dependencies);
  for (const name of ['validWindowsInventoryView', 'validEventContentView', 'validEventContentResult', 'validEnrollmentList', 'validSelectedEvent', 'eventContentNanos']) assert.equal(typeof validators[name], 'function');
  assert.equal(validators.validWindowsInventoryView({}, `agent_${'ab'.repeat(16)}`), false);
  assert.equal(validators.validEventContentView({}, `agent_${'ab'.repeat(16)}`, null), false);
  assert.equal(validators.validEventContentResult({}, { receipt: null }), false);
  assert.equal(validators.validEnrollmentList({}, 'windows'), false);
  assert.equal(validators.validSelectedEvent({}), false);
});

test('dependency loader refuses an empty runtime even when ancestor packages are resolvable', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'tracebolt-observer-dependency-test-'));
  try {
    const root = join(temp, 'source'), runtime = join(temp, 'nested/runtime');
    await mkdir(join(root, 'web'), { recursive: true }); await mkdir(runtime, { recursive: true });
    await writeFile(join(runtime, 'package.json'), '{}');
    await mkdir(join(temp, 'node_modules/esbuild'), { recursive: true });
    await writeFile(join(temp, 'node_modules/esbuild/package.json'), JSON.stringify({ name: 'esbuild', version: '0.28.2', main: 'index.js' }));
    await writeFile(join(temp, 'node_modules/esbuild/index.js'), 'throw new Error("must never load ancestor dependency");');
    await writeFile(join(root, 'web/package-lock.json'), JSON.stringify({ packages: { 'node_modules/esbuild': { version: '0.28.2' } } }));
    await assert.rejects(pinnedDependencies(root, runtime));
  } finally { await rm(temp, { recursive: true, force: true }); }
});
test('explicit esbuild native override is refused before loading dependency code', async () => {
  const had = Object.hasOwn(process.env, 'ESBUILD_BINARY_PATH'), before = process.env.ESBUILD_BINARY_PATH;
  try { process.env.ESBUILD_BINARY_PATH = '/unapproved/binary'; await assert.rejects(pinnedDependencies('/unused', '/unused'), error => error.reason === 'dependency_unavailable'); }
  finally { if (had) process.env.ESBUILD_BINARY_PATH = before; else delete process.env.ESBUILD_BINARY_PATH; }
});

test('visible update rows must be unique exact first-page rows, including metadata cells', () => {
  const a = { title: 'A', updateId: 'one', revision: 1, kbArticleIds: ['KB12'], severity: 'important', downloaded: false }, b = { ...a, title: 'B', updateId: 'two' };
  const updates = { rows: [b, a] };
  const rows = [a, b].map(value => ({ title: value.title, updateId: value.updateId, revision: 'Revision 1', kb: 'KB12', severity: 'Important', downloaded: 'No' }));
  assert.equal(renderedUpdatesMatch(updates, rows, 'en'), true);
  assert.equal(renderedUpdatesMatch(updates, [rows[0], rows[0]], 'en'), false);
  assert.equal(renderedUpdatesMatch(updates, [...rows].reverse(), 'en'), false);
  assert.equal(renderedUpdatesMatch(updates, [rows[0], { ...rows[1], kb: 'KB999' }], 'en'), false);
  assert.equal(renderedUpdatesMatch(updates, [rows[0], { ...rows[1], downloaded: 'Yes' }], 'en'), false);
  assert.equal(renderedUpdatesMatch({ rows: [] }, [], 'en'), true);
});

test('event response body completing after cancellation cannot be admitted', async () => {
  let release, canceled = false, checks = 0;
  const body = new Promise(resolve => { release = resolve; });
  const guard = () => { checks++; if (canceled) throw new Refusal('deadline'); };
  const run = guardedResponseBody({ body: () => body }, 1024, guard);
  canceled = true; release(Buffer.from('{"untrustedLateResponse":true}'));
  await assert.rejects(run, error => error.reason === 'deadline'); assert.equal(checks, 2);
});

test('supported browser close is reached without waiting for a hung context close', async () => {
  const s = spec(), report = resultSummary(s), driver = fakeDriver({ wrongOrigin: true, contextCloseHangs: true });
  await assert.rejects(observe(s, report, driver.validators, driver.chromium, () => {}), error => error.reason === 'wrong_origin');
  assert.equal(driver.state.contextClosed, 0); assert.equal(driver.state.browserClosed, 1); assert.equal(report.checks.browserClosed, true); assert.equal(report.reason, 'wrong_origin');
});
test('failed supported browser close remains unverified without erasing earlier refusal', async () => {
  const s = spec(), report = resultSummary(s), driver = fakeDriver({ wrongOrigin: true, browserCloseRejects: true });
  await assert.rejects(observe(s, report, driver.validators, driver.chromium, () => {}), error => error.reason === 'wrong_origin');
  assert.equal(driver.state.browserClosed, 1); assert.equal(report.checks.browserClosed, false); assert.equal(report.status, 'blocked'); assert.equal(report.reason, 'wrong_origin');
});
test('bounded close completion is recorded only on time and late completion cannot amend evidence', async () => {
  const report = resultSummary(spec()); report.reason = 'deadline'; let release;
  const closed = closeBrowserObserved({ close: () => new Promise(resolve => { release = resolve; }) }, report, 10);
  assert.equal(await closed, false); assert.equal(report.checks.browserClosed, false);
  release(); await new Promise(resolve => setTimeout(resolve, 1));
  assert.equal(report.checks.browserClosed, false); assert.equal(report.reason, 'deadline');
});
test('completed observation booleans cannot pass without supported browser close evidence', () => {
  const s = spec(), report = resultSummary(s); report.nativeExecution = true;
  for (const key of CHECKS) report.checks[key] = key !== 'browserClosed';
  report.observations.eventQuality = 'observed'; report.observations.updatesQuality = 'observed'; report.observations.updatesCountExact = true; report.observations.updatesRendering = 'empty_state_only';
  finishSummary(report); assert.equal(report.status, 'blocked');
  rejects(() => validateResult({ ...report, status: 'passed', reason: 'complete' }, s));
});

test('five-scope baseline requires four independent fresh siblings without upgrading denied quality', () => {
  const now = Date.now(), captured = new Date(now - 500).toISOString();
  const view = { serverNow: new Date(now).toISOString(), snapshot: { collectedAt: captured } };
  assert.equal(fiveScopeBaseline(view, now - 1000, now), false);
  for (const [i, key] of ['events', 'volumes', 'processMetrics', 'network'].entries()) view[key] = { grantId: String(i + 1).repeat(32), collectedAt: captured, quality: 'denied' };
  assert.equal(fiveScopeBaseline(view, now - 1000, now), true);
  assert.equal(view.volumes.quality, 'denied');
  for (const key of ['events', 'volumes', 'processMetrics', 'network']) {
    const missing = structuredClone(view); delete missing[key]; assert.equal(fiveScopeBaseline(missing, now - 1000, now), false);
    const stale = structuredClone(view); stale[key].collectedAt = new Date(now - 121000).toISOString(); assert.equal(fiveScopeBaseline(stale, now - 122000, now), false);
  }
  const reused = structuredClone(view); reused.network.grantId = reused.events.grantId; assert.equal(fiveScopeBaseline(reused, now - 1000, now), false);
});

test('direct main refuses every CI marker before input or native work while pure helpers remain usable', () => {
  const moduleURL = new URL('./browser.mjs', import.meta.url).href;
  const flags = ['CI', 'GITHUB_ACTIONS', 'TF_BUILD', 'BUILD_BUILDID'];
  // The stdin sentinel proves refusal precedes even reading the valid supplied
  // spec, and therefore precedes filesystem checks/dependency/native launch.
  const program = `import { main, validateSpec } from ${JSON.stringify(moduleURL)};
    validateSpec(${JSON.stringify(spec())});
    let inputRead = false;
    process.stdin[Symbol.asyncIterator] = async function* () { inputRead = true; throw new Error('input sentinel must not run'); };
    process.argv = [process.execPath, 'browser.mjs'];
    const status = await main();
    process.stdout.write(JSON.stringify({ status, inputRead }));`;
  for (const flag of flags) for (const value of ['1', '']) {
    const env = { ...process.env }; for (const key of flags) delete env[key]; env[flag] = value;
    const run = spawnSync(process.execPath, ['--input-type=module', '-e', program], { env, input: canonicalJSON(spec()), encoding: 'utf8', timeout: 10000 });
    assert.equal(run.status, 0, flag); assert.equal(run.stderr, '', flag);
    assert.deepEqual(JSON.parse(run.stdout), { status: 2, inputRead: false }, flag);
  }
});
