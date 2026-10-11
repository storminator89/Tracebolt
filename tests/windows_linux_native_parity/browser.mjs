#!/usr/bin/env node
/** Manually authorized native gate only. No fixture server, response substitution,
 * stored login, automatic invitation/approval, content consent, or source grant.
 * The stdin spec binds an already approved run; it is not permission to run it.
 * stdout is a finite marker protocol. All private observations remain in memory.
 */
import { createHash, X509Certificate } from 'node:crypto';
import { readFile, lstat, open, realpath } from 'node:fs/promises';
import { isAbsolute, dirname, resolve, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';

export const SCHEMA = 'tracebolt.windows-linux-native-parity.browser.v1';
export const REASONS = ['complete', 'contract_rejected', 'deadline', 'clock_changed', 'wrong_origin', 'artifact_mismatch', 'private_path_rejected', 'dependency_unavailable', 'browser_unavailable', 'session_lost', 'identity_mismatch', 'invalid_response', 'stale_capture', 'request_conflict', 'event_unknown', 'updates_unknown', 'ui_unavailable', 'cleanup_unverified'];
export const OMITTED = ['baseline_source_completeness', 'health_policy_lifecycle', 'worker_faults_and_replay', 'online_updates', 'update_installation', 'service_actions', 'reboot', 'upgrade_repair'];
export const CHECKS = ['publicBootstrapSaved', 'endpointBindingObserved', 'singleFreshWindowsIdentity', 'baselineDefaultOff', 'syntheticHeaderObserved', 'eventRequestObserved', 'eventResultObserved', 'eventMessageRendered', 'updatesObserved', 'updatesRendered', 'eventDisabledObserved', 'updatesDisabledObserved', 'browserClosed'];
const MARKERS = new Set(['PARITY_BROWSER_SECURE_LOGIN_HANDOFF', 'PARITY_BROWSER_BASELINE_OBSERVED', 'PARITY_BROWSER_EVENT_ENABLE_READY', 'PARITY_BROWSER_EVENT_REQUEST_HANDOFF', 'PARITY_BROWSER_UPDATES_ENABLE_READY', 'PARITY_BROWSER_EVENT_DISABLE_READY', 'PARITY_BROWSER_UPDATES_DISABLE_READY']);
const hex = (value, n = 64) => typeof value === 'string' && new RegExp(`^[a-f0-9]{${n}}$`).test(value);
const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const hash = value => createHash('sha256').update(value).digest('hex');
export class Refusal extends Error { constructor(reason) { super(REASONS.includes(reason) ? reason : 'contract_rejected'); this.reason = this.message; } }
export function need(ok, reason = 'contract_rejected') { if (!ok) throw new Refusal(reason); }
export const syntheticMessage = runId => `Tracebolt native parity synthetic Application event ${runId}`;
export function validateSpec(spec, now = Date.now()) {
  need(exact(spec, ['schema', 'runId', 'planSHA256', 'source', 'expiresUnix', 'operatorOrigin', 'agentOrigin', 'managerInstanceId', 'issuerFingerprint', 'bootstrapServerCASHA256', 'bootstrapIssuerRootSHA256', 'windowsBindingPath', 'windowsTargetId', 'windowsMachineIdSHA256', 'setupSHA256', 'serviceSHA256', 'chromium', 'browserRoot', 'syntheticEvent', 'outputPath', 'workspace']));
  need(spec.schema === SCHEMA && typeof spec.runId === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}$/.test(spec.runId) && hex(spec.planSHA256));
  need(exact(spec.source, ['commit', 'tree', 'inventorySHA256']) && hex(spec.source.commit, 40) && hex(spec.source.tree, 40) && hex(spec.source.inventorySHA256));
  need(Number.isSafeInteger(spec.expiresUnix) && spec.expiresUnix * 1000 > now && spec.expiresUnix * 1000 - now <= 7200000, 'deadline');
  let origin; try { origin = new URL(spec.operatorOrigin); } catch { throw new Refusal('wrong_origin'); }
  need(origin.protocol === 'https:' && origin.origin === spec.operatorOrigin && !origin.username && !origin.password && Number(origin.port) >= 1024 && !['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname) && !origin.hostname.endsWith('.invalid') && !origin.hostname.endsWith('.example'), 'wrong_origin');
  let agent; try { agent = new URL(spec.agentOrigin); } catch { throw new Refusal('wrong_origin'); }
  need(agent.protocol === 'https:' && agent.origin === spec.agentOrigin && agent.origin !== origin.origin && !agent.username && !agent.password && Number(agent.port) >= 1024 && !['localhost', '127.0.0.1', '[::1]'].includes(agent.hostname), 'wrong_origin');
  need(/^manager_[a-f0-9]{32}$/.test(spec.managerInstanceId) && hex(spec.issuerFingerprint) && hex(spec.bootstrapServerCASHA256) && hex(spec.bootstrapIssuerRootSHA256));
  need(exact(spec.chromium, ['path', 'sha256']) && hex(spec.chromium.sha256));
  need(typeof spec.windowsTargetId === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}$/.test(spec.windowsTargetId) && [spec.windowsMachineIdSHA256, spec.setupSHA256, spec.serviceSHA256].every(value => hex(value)));
  need(spec.windowsBindingPath === join(spec.workspace, `${spec.runId}-windows-binding.json`), 'private_path_rejected');
  for (const value of [spec.chromium.path, spec.browserRoot, spec.outputPath, spec.workspace, spec.windowsBindingPath]) need(typeof value === 'string' && isAbsolute(value) && resolve(value) === value && !/[\0\r\n]/.test(value));
  need(dirname(spec.outputPath) === spec.workspace && spec.outputPath !== spec.workspace, 'private_path_rejected');
  need(exact(spec.syntheticEvent, ['source', 'eventId', 'messageSHA256']) && spec.syntheticEvent.source === `TraceboltParity-${spec.runId}` && Number.isSafeInteger(spec.syntheticEvent.eventId) && spec.syntheticEvent.eventId >= 1 && spec.syntheticEvent.eventId <= 65535 && spec.syntheticEvent.messageSHA256 === hash(syntheticMessage(spec.runId)));
  return spec;
}
export function sameIdentity(a, b) { return Boolean(a && b && a.id === b.id && a.sequence === b.sequence && a.queryDigest === b.queryDigest); }
export function sameEvent(a, b) { return Boolean(a && b && ['channel', 'recordId', 'eventId', 'level', 'provider', 'timestamp'].every(key => a[key] === b[key])); }
export function freshCapture(captured, server, minimum = 0, now = Date.now()) {
  const capture = Date.parse(captured), clock = Date.parse(server);
  return Number.isFinite(capture) && Number.isFinite(clock) && capture >= minimum && capture <= clock && clock - capture <= 120000 && Math.abs(clock - now) <= 30000 && now - capture <= 150000;
}
// Grant-bound presence/freshness only. Per-source partial/denied data stays
// partial/denied; baseline_source_completeness is an explicit report omission.
export function fiveScopeBaseline(view, minimum, now = Date.now()) {
  const scopes = [view?.events, view?.volumes, view?.processMetrics, view?.network];
  return Boolean(view?.snapshot && freshCapture(view.snapshot.collectedAt, view.serverNow, minimum, now) && scopes.every(scope => scope && hex(scope.grantId, 32) && freshCapture(scope.collectedAt, view.serverNow, minimum, now)) && new Set(scopes.map(scope => scope.grantId)).size === 4);
}
export function renderedUpdatesMatch(updates, visibleRows, locale) {
  if (!['en', 'de'].includes(locale) || visibleRows.length !== Math.min(25, updates.rows.length) || new Set(visibleRows.map(row => `${row.updateId}:${row.revision}`)).size !== visibleRows.length) return false;
  const expected = [...updates.rows].sort((a, b) => new Intl.Collator(locale).compare(a.title, b.title) || (a.updateId < b.updateId ? -1 : a.updateId > b.updateId ? 1 : a.revision - b.revision)).slice(0, 25);
  const severity = locale === 'de' ? { unspecified: 'Nicht angegeben', critical: 'Kritisch', important: 'Wichtig', moderate: 'Mittel', low: 'Niedrig' } : { unspecified: 'Unspecified', critical: 'Critical', important: 'Important', moderate: 'Moderate', low: 'Low' };
  return visibleRows.every((row, i) => row.title === expected[i].title && row.updateId === expected[i].updateId && row.revision === `Revision ${expected[i].revision}` && row.kb === (expected[i].kbArticleIds.length ? expected[i].kbArticleIds.join(', ') : locale === 'de' ? 'Keine gemeldet' : 'None reported') && row.severity === severity[expected[i].severity] && row.downloaded === (expected[i].downloaded ? locale === 'de' ? 'Ja' : 'Yes' : locale === 'de' ? 'Nein' : 'No'));
}
export function usableUpdates(updates) { return updates?.cacheFreshness === 'unknown' && (updates.quality === 'observed' || updates.quality === 'partial' && updates.rows.length > 0); }
export function resultSummary(spec) {
  return { schema: 'tracebolt.windows-linux-native-parity.browser-result.v1', runId: spec.runId, planSHA256: spec.planSHA256, source: { ...spec.source }, status: 'blocked', reason: 'browser_unavailable', fullAcceptance: false, nativeExecution: false,
    checks: Object.fromEntries(CHECKS.map(key => [key, false])), observations: { eventQuality: 'not_observed', updatesQuality: 'not_observed', updatesRows: 0, updatesCountExact: false, updatesTruncated: false, updatesRendering: 'not_observed', cacheFreshness: 'unknown', patchCoverage: 'not_assessed' },
    omissions: [...OMITTED] };
}
export function validateResult(report, spec) {
  need(exact(report, ['schema', 'runId', 'planSHA256', 'source', 'status', 'reason', 'fullAcceptance', 'nativeExecution', 'checks', 'observations', 'omissions']));
  need(report.schema === 'tracebolt.windows-linux-native-parity.browser-result.v1' && report.runId === spec.runId && report.planSHA256 === spec.planSHA256 && exact(report.source, ['commit', 'tree', 'inventorySHA256']) && ['commit', 'tree', 'inventorySHA256'].every(key => report.source[key] === spec.source[key]));
  need(['passed', 'blocked'].includes(report.status) && REASONS.includes(report.reason) && report.fullAcceptance === false && typeof report.nativeExecution === 'boolean');
  need(exact(report.checks, CHECKS) && CHECKS.every(key => typeof report.checks[key] === 'boolean'));
  const o = report.observations;
  need(exact(o, ['eventQuality', 'updatesQuality', 'updatesRows', 'updatesCountExact', 'updatesTruncated', 'updatesRendering', 'cacheFreshness', 'patchCoverage']) && ['not_observed', 'observed', 'bounded', 'partial', 'unavailable'].includes(o.eventQuality) && ['not_observed', 'observed', 'partial', 'denied', 'unavailable'].includes(o.updatesQuality) && Number.isSafeInteger(o.updatesRows) && o.updatesRows >= 0 && o.updatesRows <= 64 && typeof o.updatesCountExact === 'boolean' && typeof o.updatesTruncated === 'boolean' && ['not_observed', 'empty_state_only', 'rows_observed'].includes(o.updatesRendering) && o.cacheFreshness === 'unknown' && o.patchCoverage === 'not_assessed');
  need(Array.isArray(report.omissions) && report.omissions.length === OMITTED.length && report.omissions.every((value, index) => value === OMITTED[index]));
  need(!report.checks.eventResultObserved || o.eventQuality === 'observed');
  need(!report.checks.eventMessageRendered || report.checks.eventResultObserved);
  need(!report.checks.updatesRendered || o.updatesRendering === (o.updatesRows > 0 ? 'rows_observed' : 'empty_state_only'));
  need(!report.checks.updatesObserved || o.updatesQuality === 'observed' || o.updatesQuality === 'partial' && o.updatesRows > 0);
  need(report.status === 'passed' ? report.reason === 'complete' && report.nativeExecution && CHECKS.every(key => report.checks[key]) : report.reason !== 'complete');
  return report;
}
export function advancingSample(before, after, nanos = value => BigInt(Date.parse(value)) * 1000000n) {
  return Boolean(before && after && Number.isSafeInteger(before.sequence) && Number.isSafeInteger(after.sequence) && after.sequence > before.sequence && before.snapshot?.generationId !== after.snapshot?.generationId && nanos(after.snapshot.collectedAt) > nanos(before.snapshot.collectedAt));
}
export function inspectRequest(description, posted, binding) {
  need(description && exact(posted, ['expectedFloor', 'expectedHeaderGenerationId', 'expectedHeaderSnapshotDigest', 'selections', 'acknowledgeContent', 'acknowledgePlaintext']), 'invalid_response');
  need(description.certificateHash === binding.certificateHash && description.deviceId === binding.deviceId && description.grantId === binding.grantId && description.headerGenerationId === posted.expectedHeaderGenerationId && description.headerSnapshotDigest === posted.expectedHeaderSnapshotDigest && Date.parse(description.headerCollectedAt) >= binding.phaseStarted && posted.expectedFloor === binding.floor && BigInt(description.identity.sequence) === BigInt(binding.floor) + 1n && description.query.events.length === 1 && sameEvent(description.query.events[0], binding.selection), 'identity_mismatch');
  need(posted.acknowledgeContent === true && posted.acknowledgePlaintext === false && Array.isArray(posted.selections) && posted.selections.length === 1 && exact(posted.selections[0], ['channel', 'recordId']) && posted.selections[0].channel === binding.selection.channel && posted.selections[0].recordId === binding.selection.recordId, 'identity_mismatch');
  need(Date.parse(description.createdAt) >= binding.phaseStarted && Date.parse(description.expiresAt) > Date.now(), 'stale_capture');
}
export function finishSummary(report) {
  if (report.nativeExecution && CHECKS.every(key => report.checks[key] === true)) { report.status = 'passed'; report.reason = 'complete'; }
  else { report.status = 'blocked'; report.reason = !report.checks.eventResultObserved || !report.checks.eventMessageRendered ? 'event_unknown' : 'updates_unknown'; }
  return report;
}
// Keep wall and monotonic clocks real. Large clock changes fail closed rather
// than extending the approved run, source freshness, or original request expiry.
export function budget(expiresUnix) {
  const wall = Date.now(), mono = performance.now();
  return () => { need(Math.abs((Date.now() - wall) - (performance.now() - mono)) <= 1500, 'clock_changed'); need(Date.now() < expiresUnix * 1000, 'deadline'); };
}
async function noLinks(path) { let current = path; for (;;) { need(!(await lstat(current)).isSymbolicLink(), 'private_path_rejected'); const parent = dirname(current); if (parent === current) break; current = parent; } need(await realpath(path) === path, 'private_path_rejected'); }
async function validateFiles(spec) {
  need(process.platform === 'linux' && typeof process.geteuid === 'function', 'contract_rejected');
  for (const path of [spec.workspace, spec.browserRoot, spec.chromium.path]) await noLinks(path);
  const workspace = await lstat(spec.workspace);
  need(workspace.isDirectory() && workspace.uid === process.geteuid() && (workspace.mode & 0o777) === 0o700, 'private_path_rejected');
  for (let p = dirname(spec.workspace);; p = dirname(p)) { const s = await lstat(p); need([0, process.geteuid()].includes(s.uid) && (!(s.mode & 0o022) || s.uid === 0 && Boolean(s.mode & 0o1000)), 'private_path_rejected'); if (dirname(p) === p) break; }
  const chromium = await lstat(spec.chromium.path); need(chromium.isFile() && chromium.nlink === 1 && chromium.size > 0 && chromium.size <= 512 * 1024 * 1024, 'artifact_mismatch');
  need(hash(await readFile(spec.chromium.path)) === spec.chromium.sha256, 'artifact_mismatch');
}
export async function pinnedDependencies(root, dependencyRoot) {
  need(!Object.hasOwn(process.env, 'ESBUILD_BINARY_PATH'), 'dependency_unavailable');
  need(process.platform === 'linux' && process.arch === 'x64', 'dependency_unavailable');
  const require = createRequire(join(dependencyRoot, 'package.json'));
  const lock = JSON.parse(await readFile(join(root, 'web/package-lock.json'), 'utf8'));
  const entries = {};
  for (const name of ['esbuild', '@playwright/test', 'playwright', 'playwright-core', '@esbuild/linux-x64']) {
    const packageRoot = join(dependencyRoot, 'node_modules', name), packageFile = join(packageRoot, 'package.json');
    await noLinks(packageFile);
    const value = JSON.parse(await readFile(packageFile, 'utf8'));
    need(value.name === name && value.version === lock.packages?.[`node_modules/${name}`]?.version, 'dependency_unavailable');
    const request = name === '@esbuild/linux-x64' ? '@esbuild/linux-x64/bin/esbuild' : name;
    let entry; try { entry = require.resolve(request); } catch { throw new Refusal('dependency_unavailable'); }
    need(entry.startsWith(packageRoot + '/'), 'dependency_unavailable'); await noLinks(entry); entries[name] = entry;
  }
  // Assert transitive resolution as the packages themselves perform it, not
  // merely the top-level require: no ancestor or ambient dependency fallback.
  for (const [from, request, target] of [['@playwright/test', 'playwright/test', 'playwright'], ['playwright', 'playwright-core', 'playwright-core'], ['esbuild', '@esbuild/linux-x64/bin/esbuild', '@esbuild/linux-x64']]) {
    need(createRequire(entries[from]).resolve(request).startsWith(join(dependencyRoot, 'node_modules', target) + '/'), 'dependency_unavailable');
  }
  return require;
}
export async function loadValidators(root, dependencyRoot) {
  // Compile the real production validators in memory. No generated fixture DTOs
  // or weakened parallel wire contract can turn an invalid response into a pass.
  const require = await pinnedDependencies(root, dependencyRoot);
  const esbuild = require('esbuild');
  const source = ['windows-inventory-types', 'windows-event-content-types', 'enrollment-types'].map(name => `export * from ${JSON.stringify(join(root, 'web/src', `${name}.ts`))};`).join('\n');
  const built = await esbuild.build({ stdin: { contents: source, resolveDir: root, loader: 'ts' }, bundle: true, write: false, platform: 'node', format: 'esm', logLevel: 'silent' });
  return import(`data:text/javascript;base64,${Buffer.from(built.outputFiles[0].text).toString('base64')}`);
}
export function validateEndpointBinding(value, spec, identity, bootstrapSHA256) {
  need(exact(value, ['schema', 'runId', 'planSHA256', 'source', 'windowsTargetId', 'windowsMachineIdSHA256', 'setupSHA256', 'serviceSHA256', 'deviceId', 'certificateHash', 'invitationIdSHA256', 'bootstrapSHA256']), 'invalid_response');
  need(value.schema === 'tracebolt.windows-linux-native-parity.endpoint-binding.v1' && value.runId === spec.runId && value.planSHA256 === spec.planSHA256 && exact(value.source, ['commit', 'tree', 'inventorySHA256']) && ['commit', 'tree', 'inventorySHA256'].every(key => value.source[key] === spec.source[key]), 'identity_mismatch');
  need(['windowsTargetId', 'windowsMachineIdSHA256', 'setupSHA256', 'serviceSHA256'].every(key => value[key] === spec[key]) && value.deviceId === identity.deviceId && value.certificateHash === identity.certificateHash && value.invitationIdSHA256 === hash(identity.invitationId) && value.bootstrapSHA256 === bootstrapSHA256, 'identity_mismatch');
  return value;
}
async function endpointBinding(spec, identity, bootstrapSHA256) {
  let info; try { info = await lstat(spec.windowsBindingPath); } catch (error) { if (error.code === 'ENOENT') return false; throw new Refusal('private_path_rejected'); }
  need(info.isFile() && !info.isSymbolicLink() && info.nlink === 1 && info.size > 0 && info.size <= 32768 && info.uid === process.geteuid() && (info.mode & 0o777) === 0o600, 'private_path_rejected');
  const raw = await readFile(spec.windowsBindingPath); need(raw.length === info.size, 'private_path_rejected');
  let value; try { value = JSON.parse(raw.toString('utf8')); } catch { throw new Refusal('invalid_response'); }
  need(canonicalJSON(value) === raw.toString('utf8'), 'invalid_response');
  validateEndpointBinding(value, spec, identity, bootstrapSHA256); return true;
}
export function validateBootstrap(value, spec, invitationId) {
  need(exact(value, ['schemaVersion', 'managerInstanceId', 'profile', 'enrollmentOrigin', 'agentOrigin', 'collectionProfile', 'invitationId', 'serverCaPem', 'issuerRootPem', 'issuerPem']), 'invalid_response');
  need(value.schemaVersion === 'tracebolt.enrollment-bootstrap.v2' && value.managerInstanceId === spec.managerInstanceId && value.profile === 'tls' && value.enrollmentOrigin === spec.operatorOrigin && value.agentOrigin === spec.agentOrigin && value.collectionProfile === 'windows-inventory-v1' && value.invitationId === invitationId && /^invite_[a-f0-9]{32}$/.test(invitationId), 'identity_mismatch');
  const certificates = (pem, max) => {
    need(typeof pem === 'string' && Buffer.byteLength(pem) <= 16384, 'invalid_response');
    const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\r\n\t ]+[A-Za-z0-9+/=\r\n\t ]+-----END CERTIFICATE-----/g);
    need(blocks && blocks.length >= 1 && blocks.length <= max && pem.replace(/-----BEGIN CERTIFICATE-----[\r\n\t ]+[A-Za-z0-9+/=\r\n\t ]+-----END CERTIFICATE-----/g, '').trim() === '', 'invalid_response');
    try { return blocks.map(block => new X509Certificate(block)); } catch { throw new Refusal('invalid_response'); }
  };
  certificates(value.serverCaPem, 8); const roots = certificates(value.issuerRootPem, 1), issuers = certificates(value.issuerPem, 1);
  need(hash(value.serverCaPem) === spec.bootstrapServerCASHA256 && hash(value.issuerRootPem) === spec.bootstrapIssuerRootSHA256 && hash(issuers[0].raw) === spec.issuerFingerprint, 'identity_mismatch');
  need(roots[0].ca && issuers[0].ca && issuers[0].verify(roots[0].publicKey), 'identity_mismatch');
  return value;
}
export function canonicalJSON(value) {
  const sorted = item => Array.isArray(item) ? item.map(sorted) : item && typeof item === 'object' ? Object.fromEntries(Object.keys(item).sort().map(key => [key, sorted(item[key])])) : item;
  return JSON.stringify(sorted(value)).replace(/[\u007f-\uffff]/g, char => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`) + '\n';
}
async function readSpec() {
  need(!process.stdin.isTTY); let raw = Buffer.alloc(0);
  const timer = setTimeout(() => process.stdin.destroy(new Refusal('deadline')), 10000);
  try { for await (const chunk of process.stdin) { need(raw.length + chunk.length <= 32768); raw = Buffer.concat([raw, chunk]); } } finally { clearTimeout(timer); }
  let spec; try { spec = JSON.parse(raw.toString('utf8')); } catch { throw new Refusal('contract_rejected'); }
  need(raw.toString('utf8') === canonicalJSON(spec), 'contract_rejected');
  validateSpec(spec); return spec;
}
async function writeSummary(spec, report) {
  validateResult(report, spec); const raw = JSON.stringify(report) + '\n'; need(Buffer.byteLength(raw) <= 32768);
  const file = await open(spec.outputPath, 'wx', 0o600);
  try { await file.writeFile(raw); await file.sync(); } finally { await file.close(); }
}

export async function guardedResponseBody(response, maximum, guard) {
  guard(); const raw = await response.body(); guard();
  need(raw.length <= maximum, 'invalid_response'); return raw;
}
export async function closeBrowserObserved(browser, report, timeoutMS = 35000) {
  if (!browser) return false;
  let timer;
  try {
    // Browser.close owns all contexts and reaches pinned Playwright's 30-second
    // close-or-kill fallback for its detached Chromium process group. Never wait
    // for context.close first: that could prevent the supported fallback.
    const closed = await Promise.race([
      Promise.resolve().then(() => browser.close()).then(() => true, () => false),
      new Promise(resolve => { timer = setTimeout(() => resolve(false), timeoutMS); }),
    ]);
    // A late resolution after our bound must not retroactively claim cleanup.
    if (closed) report.checks.browserClosed = true;
    return closed;
  } finally { clearTimeout(timer); }
}
export async function observe(spec, report, validators, chromium, emit = line => process.stdout.write(line)) {
  const checkTime = budget(spec.expiresUnix), began = Date.now(); let browser, context, page, fatal = null;
  const emitted = new Set();
  const marker = name => { guard(); need(MARKERS.has(name) && !emitted.has(name)); emitted.add(name); emit(`${name}\n`); };
  let closing = null;
  const closeOwned = () => browser ? closing ??= closeBrowserObserved(browser, report) : Promise.resolve(false);
  const stop = () => { fatal ??= new Refusal('browser_unavailable'); void closeOwned(); };
  process.once('SIGTERM', stop); process.once('SIGINT', stop);
  const expiryTimer = setInterval(() => { try { checkTime(); } catch (error) { fatal = error; stop(); } }, 500);

  const guard = () => { checkTime(); if (fatal) throw fatal; need(page && !page.isClosed(), 'browser_unavailable'); need(new URL(page.url()).origin === spec.operatorOrigin, 'wrong_origin'); };
  const pause = () => new Promise(resolve => setTimeout(resolve, 750));
  const until = async operation => { for (;;) { guard(); const value = await operation(); if (value) return value; await pause(); } };
  // GET only, fixed same-origin routes, bounded streaming and redirect refusal.
  // Cookies remain in the nonpersistent browser context and are never returned.
  const read = async (path, limit = 128 * 1024) => {
    guard(); need(/^\/api\/(windows\/enrollment|devices\/agent_[a-f0-9]{32}\/(windows-inventory|windows-event-content))$/.test(path));
    const result = await page.evaluate(async ({ path, limit, origin }) => {
      if (location.origin !== origin) return { status: 0, value: null };
      const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 10000);
      try {
        const response = await fetch(path, { method: 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal });
        if (response.status !== 200) return { status: response.status, value: null };
        if (!response.body || Number(response.headers.get('content-length')) > limit) return { status: 0, value: null };
        const reader = response.body.getReader(); let size = 0; const chunks = [];
        try { for (;;) { const part = await reader.read(); if (part.done) break; size += part.value.length; if (size > limit) { await reader.cancel(); return { status: 0, value: null }; } chunks.push(part.value); } } finally { reader.releaseLock(); }
        const bytes = new Uint8Array(size); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
        return { status: 200, value: JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) };
      } catch { return { status: 0, value: null }; } finally { clearTimeout(timer); }
    }, { path, limit, origin: spec.operatorOrigin });
    guard(); return result;
  };
  const visible = async locator => locator.isVisible().catch(() => false);
  try {
    // No user-data directory, storageState, trace, video, screenshot, remote
    // debugging connection, browser args or ignoreHTTPSErrors escape hatch.
    browser = await chromium.launch({ executablePath: spec.chromium.path, headless: false, chromiumSandbox: true, env: Object.fromEntries(['DISPLAY', 'WAYLAND_DISPLAY', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS', 'HOME', 'TMPDIR', 'LANG'].filter(key => process.env[key]).map(key => [key, process.env[key]])) });
    report.nativeExecution = true;
    if (fatal) { await closeOwned(); throw fatal; }
    context = await browser.newContext({ acceptDownloads: true, serviceWorkers: 'block', ignoreHTTPSErrors: false });
    page = await context.newPage(); page.setDefaultTimeout(10000); page.setDefaultNavigationTimeout(30000);
    context.on('page', other => { if (other !== page) { fatal = new Refusal('wrong_origin'); void other.close().catch(() => {}); } });
    page.on('framenavigated', frame => { try { if (frame === page.mainFrame() && new URL(frame.url()).origin !== spec.operatorOrigin) fatal = new Refusal('wrong_origin'); } catch { fatal = new Refusal('wrong_origin'); } });
    page.on('crash', () => { fatal = new Refusal('browser_unavailable'); });
    let bootstrapInvitation = null, bootstrapSHA256 = null, downloadCount = 0, downloadPending = null;
    page.on('download', download => {
      downloadPending = (async () => {
        downloadCount++; need(downloadCount === 1 && new URL(download.url()).protocol === 'blob:' && new URL(download.url()).origin === spec.operatorOrigin, 'invalid_response');
        const listing = await read('/api/windows/enrollment');
        need(listing.status === 200 && validators.validEnrollmentList(listing.value, 'windows') && listing.value.items.length === 1, 'identity_mismatch');
        const row = listing.value.items[0];
        need(row.state === 'created' && row.createdAt * 1000 >= Math.floor(began / 1000) * 1000 && row.binding.instanceID === spec.managerInstanceId && row.binding.issuerFingerprint === spec.issuerFingerprint, 'identity_mismatch');
        need(download.suggestedFilename() === `tracebolt-bootstrap-${row.invitationID}.json`, 'invalid_response');
        const stream = await download.createReadStream(); need(stream, 'invalid_response'); let raw = Buffer.alloc(0);
        try { for await (const chunk of stream) { need(raw.length + chunk.length <= 65536, 'invalid_response'); raw = Buffer.concat([raw, chunk]); } } finally { stream.destroy(); }
        const value = JSON.parse(raw.toString('utf8')); validateBootstrap(value, spec, row.invitationID); guard();
        // Re-encode the validated public-only shape, never arbitrary downloaded
        // bytes or the invitation response. This file is outside source/evidence.
        const file = await open(join(spec.workspace, `${spec.runId}-public-bootstrap.json`), 'wx', 0o600);
        try { const bytes = JSON.stringify(value) + '\n'; await file.writeFile(bytes); await file.sync(); bootstrapSHA256 = hash(bytes); } finally { await file.close(); }
        bootstrapInvitation = row.invitationID; report.checks.publicBootstrapSaved = true;
      })().catch(error => { fatal = error instanceof Refusal ? error : new Refusal('invalid_response'); stop(); }).finally(() => download.delete().catch(() => {}));
    });
    await page.goto(`${spec.operatorOrigin}/#/devices`, { waitUntil: 'domcontentloaded' });
    marker('PARITY_BROWSER_SECURE_LOGIN_HANDOFF');
    // Human signs in, creates one invitation, checks comparison and approves in
    // the production UI. Neither input nor invitation responses are inspected.
    let emptyObserved = false, identity = null;
    identity = await until(async () => {
      const response = await read('/api/windows/enrollment'); if (response.status === 401 || response.status === 403) return null;
      if (response.status !== 200) return null;
      const list = response.value; need(validators.validEnrollmentList(list, 'windows') && list.enabled, 'invalid_response');
      need(Math.abs(Date.parse(list.serverNow) - Date.now()) <= 30000, 'stale_capture');
      if (list.items.length === 0) { emptyObserved = true; return null; }
      need(emptyObserved && list.items.length === 1, 'identity_mismatch');
      const row = list.items[0]; need(row.binding.instanceID === spec.managerInstanceId && row.binding.issuerFingerprint === spec.issuerFingerprint, 'identity_mismatch'); need(row.createdAt * 1000 >= Math.floor(began / 1000) * 1000 && row.binding.profile === 'tls' && row.binding.origin === spec.operatorOrigin && row.platform === 'windows', 'identity_mismatch');
      if (row.state !== 'activated') { need(!['expired', 'canceled', 'rejected', 'revoked'].includes(row.state), 'identity_mismatch'); return null; }
      if (downloadPending) await downloadPending; need(report.checks.publicBootstrapSaved && bootstrapInvitation === row.invitationID, 'identity_mismatch');
      need(/^agent_[a-f0-9]{32}$/.test(row.approval.deviceID) && row.intent.deviceID === row.approval.deviceID && hex(row.issuance.certificateHash) && row.activation.at >= row.createdAt, 'identity_mismatch');
      return { deviceId: row.approval.deviceID, certificateHash: row.issuance.certificateHash, invitationId: row.invitationID };
    });
    await until(() => endpointBinding(spec, identity, bootstrapSHA256));
    report.checks.endpointBindingObserved = true; report.checks.singleFreshWindowsIdentity = true;
    const inventoryPath = `/api/devices/${identity.deviceId}/windows-inventory`, contentPath = `/api/devices/${identity.deviceId}/windows-event-content`;
    let sessionBinding = null, sessionExpires = null, floor = 0n, captureFloor = -Infinity, sequence = 0;
    const content = async () => {
      const response = await read(contentPath, 64 * 1024); need(response.status !== 401 && response.status !== 403, 'session_lost'); if (response.status !== 200) return null;
      const view = response.value; need(validators.validEventContentView(view, identity.deviceId, sessionExpires), 'invalid_response');
      need(!sessionBinding || sessionBinding === view.sessionBinding, 'session_lost'); sessionBinding ??= view.sessionBinding; sessionExpires ??= view.sessionExpiresAt;
      need(BigInt(view.expectedFloor) >= floor, 'request_conflict'); floor = BigInt(view.expectedFloor);
      need(Math.abs(Date.parse(view.serverNow) - Date.now()) <= 30000 && Date.parse(view.sessionExpiresAt) > Date.now(), 'stale_capture');
      if (view.request) need(view.request.description.certificateHash === identity.certificateHash, 'identity_mismatch');
      return view;
    };
    const inventory = async minimum => {
      const response = await read(inventoryPath, 74 * 1024); need(response.status !== 401 && response.status !== 403, 'session_lost'); if (response.status !== 200) return null;
      const view = response.value; need(validators.validWindowsInventoryView(view, identity.deviceId), 'invalid_response');
      need(!['revoked', 'not_configured'].includes(view.status), 'identity_mismatch'); if (!view.snapshot || view.status !== 'fresh' || !freshCapture(view.snapshot.collectedAt, view.serverNow, minimum)) return null;
      const captured = validators.eventContentNanos(view.snapshot.collectedAt); need(captureFloor === -Infinity || captured >= captureFloor, 'stale_capture'); need(view.sequence >= sequence, 'stale_capture'); captureFloor = captured; sequence = view.sequence;
      return view;
    };
    const checkIdentity = async () => {
      const response = await read('/api/windows/enrollment'); need(response.status === 200 && validators.validEnrollmentList(response.value, 'windows'), 'session_lost');
      const rows = response.value.items; need(rows.length === 1 && rows[0].state === 'activated' && rows[0].invitationID === identity.invitationId && rows[0].approval.deviceID === identity.deviceId && rows[0].issuance.certificateHash === identity.certificateHash, 'identity_mismatch');
    };
    await page.goto(`${spec.operatorOrigin}/#/devices/${identity.deviceId}/logs`, { waitUntil: 'domcontentloaded' });
    let baselineFirst = null;
    await until(async () => {
      const [inv, view] = await Promise.all([inventory(began), content()]); if (!inv || !view || !await visible(page.locator('.windows-logs'))) return false;
      if (!fiveScopeBaseline(inv, began)) return false;
      need(!inv.updates && view.localStatus !== 'enabled' && !view.capability?.enabled && view.request === null && view.expectedFloor === '0', 'request_conflict');
      if (!['unavailable', 'disabled'].includes(view.localStatus)) return false;
      need(await page.locator('.windows-event-message').count() === 0, 'request_conflict');
      if (!baselineFirst) { baselineFirst = inv; return false; }
      return advancingSample(baselineFirst, inv, validators.eventContentNanos);
    });
    report.checks.baselineDefaultOff = true; marker('PARITY_BROWSER_BASELINE_OBSERVED'); const eventPhase = Date.now(); marker('PARITY_BROWSER_EVENT_ENABLE_READY');
    let selection, approvedView;
    await until(async () => {
      const [inv, view] = await Promise.all([inventory(eventPhase), content()]); if (!inv || !view || !inv.events || view.localStatus !== 'enabled' || !view.capability?.enabled || !view.headers) return false;
      need(!inv.updates && view.request === null && view.expectedFloor === '0', 'request_conflict');
      if (!freshCapture(view.capability.reportedAt, view.serverNow, eventPhase) || !freshCapture(inv.events.collectedAt, inv.serverNow, eventPhase)) return false;
      if (view.headers.generationId !== inv.events.generationId || view.headers.collectedAt !== inv.events.collectedAt) return false;
      const found = inv.events.channels.flatMap(channel => channel.rows.map(row => ({ ...row, channel: channel.channel }))).filter(row => row.channel === 'Application' && row.provider === spec.syntheticEvent.source && row.eventId === spec.syntheticEvent.eventId && Date.parse(row.timestamp) >= eventPhase);
      need(found.length <= 1, 'identity_mismatch'); if (!found.length) return false;
      need(validators.validSelectedEvent(found[0]), 'invalid_response'); selection = found[0]; approvedView = view; return true;
    });
    await checkIdentity();
    // Refresh only the existing accepted sample. Filters never read the source.
    await page.locator('.windows-logs').getByRole('button', { name: /^(Refresh sample|Stichprobe aktualisieren)$/ }).click();
    await page.locator('.windows-event-content').getByRole('button', { name: /^(Check content status|Inhaltsstatus prüfen)$/ }).click();
    await page.locator('.windows-logs-filters').getByLabel('Provider', { exact: true }).fill(spec.syntheticEvent.source);
    await page.locator('.windows-logs-filters').getByLabel(/^(Event ID|Ereignis-ID)$/).fill(String(spec.syntheticEvent.eventId));
    const selectedBox = page.locator('.windows-logs').getByRole('checkbox', { name: new RegExp(`^(Select|Auswählen) Application ${selection.recordId}$`) });
    await selectedBox.check(); report.checks.syntheticHeaderObserved = true;
    await page.locator('.windows-event-content').getByRole('button', { name: /^(Review selection|Auswahl prüfen)$/ }).click();
    need(await visible(page.locator('.windows-event-content-review')), 'ui_unavailable');
    let requestRecord = null, resultSeen = null, createCount = 0, responseTail = Promise.resolve();
    const onResponse = response => {
      // Only the reviewed production UI create/query are observed. Auth/login
      // and invitation bodies, request headers and cookies are never inspected.
      responseTail = responseTail.then(async () => {
        const url = new URL(response.url()); if (url.origin !== spec.operatorOrigin || ![`${contentPath}/create`, `${contentPath}/query`].includes(url.pathname) || url.search) return;
        guard(); need(response.request().method() === 'POST', 'invalid_response');
        if (url.pathname.endsWith('/create')) { createCount++; need(createCount === 1, 'request_conflict'); }
        need(response.status() === 200, 'request_conflict');
        const raw = await guardedResponseBody(response, (url.pathname.endsWith('/query') ? 512 : 64) * 1024, guard);
        const value = JSON.parse(raw.toString('utf8'));
        if (url.pathname.endsWith('/create')) {
          need(validators.validEventContentView(value, identity.deviceId, sessionExpires) && value.sessionBinding === sessionBinding, 'invalid_response');
          const record = value.request, description = record?.description;
          const postedText = response.request().postData(); need(typeof postedText === 'string' && Buffer.byteLength(postedText) <= 8192, 'invalid_response');
          inspectRequest(description, JSON.parse(postedText), { ...identity, grantId: approvedView.capability.grantId, floor: approvedView.expectedFloor, phaseStarted: eventPhase, selection });
          requestRecord = record; report.checks.eventRequestObserved = true;
        } else {
          need(requestRecord, 'request_conflict'); const status = await content();
          need(status?.request?.state === 'accepted' && sameIdentity(status.request.description.identity, requestRecord.description.identity) && status.request.description.expiresAt === requestRecord.description.expiresAt && validators.validEventContentResult(value, status.request, sessionExpires), 'invalid_response');
          need(Date.parse(value.expiresAt) > Date.now() && value.report.events.length === 1 && sameEvent(value.report.events[0].event, selection), 'identity_mismatch');
          report.observations.eventQuality = value.report.quality;
          if (value.report.quality === 'observed') { need(value.report.complete && !value.report.truncated && value.report.events[0].quality === 'observed' && hash(value.report.events[0].message) === spec.syntheticEvent.messageSHA256, 'identity_mismatch'); report.checks.eventResultObserved = true; }
          resultSeen = value;
        }
      }).catch(error => { fatal ??= error instanceof Refusal ? error : new Refusal('invalid_response'); });
    };
    page.on('response', onResponse); marker('PARITY_BROWSER_EVENT_REQUEST_HANDOFF');
    // The operator reads the real selection and warnings, ticks consent, and
    // presses Request messages once. The observer never performs these writes.
    await until(async () => { await responseTail;
      if (!resultSeen) {
        if (!requestRecord) return false;
        const view = await content();
        need(!view?.request || sameIdentity(view.request.description.identity, requestRecord.description.identity), 'request_conflict');
        if (view && (['denied', 'reader_unavailable', 'result_lost', 'expired', 'canceled', 'disabled'].includes(view.endpointStatus) || ['result_lost', 'expired', 'canceled'].includes(view.contentStatus))) { report.observations.eventQuality = 'unavailable'; return true; }
        return false;
      }
      if (!report.checks.eventResultObserved) return true;
      const messages = page.locator('.windows-event-content-result .windows-event-message'); if (await messages.count() !== 1 || !await visible(messages)) return false;
      const text = await messages.textContent(); need(hash(text ?? '') === spec.syntheticEvent.messageSHA256, 'identity_mismatch');
      need(await messages.locator('*').count() === 0, 'invalid_response'); report.checks.eventMessageRendered = true; return true;
    });
    page.off('response', onResponse); resultSeen = null; requestRecord = null; selection = null; approvedView = null;
    // Leaving Logs invokes the production UI's content-discard lifecycle.
    await page.locator('#tab-inventory').click(); await page.locator('.windows-inventory-tabs').getByRole('tab', { name: 'Updates', exact: true }).click();
    const updatesPhase = Date.now(); marker('PARITY_BROWSER_UPDATES_ENABLE_READY');
    let updatesCapture = null;
    await until(async () => {
      const inv = await inventory(updatesPhase); if (!inv?.updates) return false;
      const panel = page.locator('.windows-updates'); if (!await visible(panel)) return false;
      // Read the UI's real refreshed resource, not an injected DOM assertion.
      const time = panel.locator('time'); if (await time.count() !== 1 || await time.getAttribute('datetime') !== inv.updates.collectedAt) return false;
      const quality = inv.updates.quality, expected = { observed: inv.updates.truncated ? /^(Bounded cached result|Begrenztes Cache-Ergebnis)$/ : /^(Cached result observed|Cache-Ergebnis beobachtet)$/, partial: /^(Partial cached result|Teilweises Cache-Ergebnis)$/, denied: /^(Access denied|Zugriff verweigert)$/, unavailable: /^(Unavailable|Nicht verfügbar)$/ }[quality];
      const qualityNode = panel.locator('.windows-inventory-quality'); if (!expected || !expected.test(await qualityNode.textContent() ?? '')) return false;
      need((await panel.locator('.windows-inventory-caution').first().textContent() ?? '').includes('Cache'), 'ui_unavailable');
      const updates = inv.updates;
      const visibleRows = await panel.locator('tbody tr').evaluateAll(rows => rows.map(row => {
        const cells = row.querySelectorAll('td');
        return { title: cells[0]?.querySelector('span')?.firstChild?.textContent ?? '', updateId: cells[4]?.querySelector('span')?.firstChild?.textContent ?? '', revision: cells[4]?.querySelector('small')?.textContent ?? '', kb: cells[1]?.textContent ?? '', severity: cells[2]?.textContent ?? '', downloaded: cells[3]?.textContent ?? '' };
      }));
      if (visibleRows.length !== Math.min(25, updates.rows.length)) return false;
      const locale = await page.locator('html').getAttribute('lang');
      need(renderedUpdatesMatch(updates, visibleRows, locale), 'invalid_response');
      if (updates.rows.length === 0) {
        const emptyText = await panel.locator('.windows-inventory-empty').textContent();
        const emptySuccess = updates.quality === 'observed' && updates.observedCount === 0;
        need(emptySuccess ? /does not establish current patch coverage|keine aktuelle Patch-Abdeckung/.test(emptyText ?? '') : /does not establish an empty cache|weder einen leeren Cache/.test(emptyText ?? ''), 'ui_unavailable');
      }
      report.observations.updatesQuality = quality; report.observations.updatesRows = updates.rows.length; report.observations.updatesCountExact = updates.countExact; report.observations.updatesTruncated = updates.truncated; report.observations.updatesRendering = updates.rows.length > 0 ? 'rows_observed' : 'empty_state_only';
      report.checks.updatesObserved = usableUpdates(updates); report.checks.updatesRendered = true; updatesCapture = updates.collectedAt; return true;
    });
    await checkIdentity();
    const eventDisablePhase = Date.now(); marker('PARITY_BROWSER_EVENT_DISABLE_READY');
    await until(async () => { const view = await content(); return Boolean(view?.localStatus === 'disabled' && view.capability?.enabled === false && freshCapture(view.capability.reportedAt, view.serverNow, eventDisablePhase) && view.contentStatus !== 'available'); });
    await page.locator('#tab-logs').click();
    await until(async () => {
      const panel = page.locator('.windows-event-content'); if (!await visible(panel)) return false;
      const view = await content(); if (view?.localStatus !== 'disabled' || view.capability?.enabled !== false) return false;
      const text = await panel.textContent();
      if (!/A separate enabled local content grant|Eine separate, aktivierte lokale Inhaltsfreigabe/.test(text ?? '')) return false;
      const review = panel.getByRole('button', { name: /^(Review selection|Auswahl prüfen)$/ });
      return await review.isDisabled() && await panel.locator('.windows-event-message').count() === 0 && await panel.locator('.windows-event-content-result').count() === 0;
    });
    report.checks.eventDisabledObserved = true;
    await page.locator('#tab-inventory').click(); await page.locator('.windows-inventory-tabs').getByRole('tab', { name: 'Updates', exact: true }).click();
    const updatesDisablePhase = Date.now(); marker('PARITY_BROWSER_UPDATES_DISABLE_READY');
    await until(async () => { const inv = await inventory(updatesDisablePhase); if (!inv || inv.updates || validators.eventContentNanos(inv.snapshot.collectedAt) <= validators.eventContentNanos(updatesCapture)) return false;
      const panel = page.locator('.windows-updates'); if (!await visible(panel) || await panel.locator('time').count() !== 0 || await panel.locator('tbody tr').count() !== 0) return false;
      const text = await panel.locator('.windows-inventory-empty').textContent(); return /not included in this report|in dieser Meldung nicht enthalten/.test(text ?? '');
    });
    report.checks.updatesDisabledObserved = true; await checkIdentity();
  } catch (error) {
    fatal ??= error instanceof Refusal ? error : new Refusal('browser_unavailable');
    report.status = 'blocked'; report.reason = fatal.reason; throw fatal;
  } finally {
    clearInterval(expiryTimer);
    const closed = await closeOwned();
    process.removeListener('SIGTERM', stop); process.removeListener('SIGINT', stop);
    if (browser && !closed) { report.status = 'blocked'; if (!fatal) report.reason = 'cleanup_unverified'; }
  }
  if (fatal) throw fatal;
  need(report.checks.browserClosed, 'cleanup_unverified');
  return finishSummary(report);
}
export async function main() {
  let spec, report, safeOutput = false;
  try {
    // Direct native entry is interactive-only. Keep module imports and pure
    // source tests available in CI; the private child stdin is intentionally a pipe.
    need(!['CI', 'GITHUB_ACTIONS', 'TF_BUILD', 'BUILD_BUILDID'].some(key => Object.hasOwn(process.env, key)));
    need(process.argv.length === 2); spec = await readSpec(); report = resultSummary(spec); await validateFiles(spec); safeOutput = true;
    const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
    let validators, chromium;
    try { validators = await loadValidators(root, spec.browserRoot); ({ chromium } = createRequire(join(spec.browserRoot, 'package.json'))('@playwright/test')); }
    catch { throw new Refusal('dependency_unavailable'); }
    await observe(spec, report, validators, chromium);
  } catch (error) { if (report) report.reason = error instanceof Refusal ? error.reason : 'browser_unavailable'; }
  if (safeOutput) { try { await writeSummary(spec, report); } catch { return 2; } }
  return report?.status === 'passed' ? 0 : 2;
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) process.exitCode = await main();
