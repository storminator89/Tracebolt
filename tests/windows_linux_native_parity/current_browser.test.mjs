/** Portable synthetic contract tests. No Chromium, manager or native endpoint. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import { rootCertificates } from 'node:tls';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { CURRENT_SCHEMA, CURRENT_PROFILE, CURRENT_SCOPES, CURRENT_CHECKS, CURRENT_OMITTED, SOURCE_OUTCOMES, INVENTORY_SCOPE_FIELDS, validateCurrentProfile, approvedHistorySearch, sourceOutcome, recordCurrentOutcomes, validateCurrentEndpointBinding, validateCurrentCredential, validateCurrentInventoryBindings, inspectHistorySearch, inspectHistoryMessages, validateRestartBinding } from './current_browser.mjs';
import { Refusal, validateSpec, resultSummary, validateResult, finishSummary, validateBootstrap, canonicalJSON, syntheticMessage } from './browser.mjs';
const hash = value => createHash('sha256').update(value).digest('hex');
const rejects = (fn, reason) => assert.throws(fn, error => error instanceof Refusal && (!reason || error.reason === reason));
const now = Date.now();
function spec() {
  return { schema: CURRENT_SCHEMA, currentProfile: { ...CURRENT_PROFILE }, runId: 'portable-current-1', planSHA256: hash('plan'), source: { commit: 'ab'.repeat(20), tree: 'cd'.repeat(20), inventorySHA256: hash('source') }, expiresUnix: Math.floor(now / 1000) + 900, operatorOrigin: 'https://manager.test:8443', agentOrigin: 'https://manager.test:9443', managerInstanceId: `manager_${'ab'.repeat(16)}`, issuerFingerprint: hash('issuer'), bootstrapServerCASHA256: hash('ca'), bootstrapIssuerRootSHA256: hash('root'), windowsBindingPath: '/tmp/private/portable-current-1-windows-binding.json', windowsTargetId: 'win11-disposable', windowsPlatform: 'windows-11-x64', windowsMachineIdSHA256: hash('machine'), setupSHA256: hash('setup'), serviceSHA256: hash('service'), chromium: { path: '/tmp/browser', sha256: hash('browser') }, browserRoot: '/tmp/runtime', syntheticEvent: { source: 'TraceboltParity-portable-current-1', eventId: 321, messageSHA256: hash(syntheticMessage('portable-current-1')) }, historyQuery: { approvalRef: 'history-approved', messagesApprovalRef: 'messages-approved', channel: 'Application', eventId: 321, startUnix: Math.floor(now / 60000) * 60 - 120, endUnix: Math.floor(now / 60000) * 60, maxRows: 100, maxMessages: 1 }, outputPath: '/tmp/private/result.json', workspace: '/tmp/private' };
}
function bindingCase() {
  const s = spec(), identity = { deviceId: `agent_${'aa'.repeat(16)}`, certificateHash: hash('anchor'), invitationId: `invite_${'ab'.repeat(16)}` }, bootstrap = hash('bootstrap');
  const grants = CURRENT_SCOPES.slice(1).map((scope, i) => ({ scope, grantId: hash(`grant-${i === 18 ? 6 : i}`).slice(0, 32) }));
  const binding = { schema: 'tracebolt.windows-linux-native-parity.endpoint-binding.v2', runId: s.runId, planSHA256: s.planSHA256, source: s.source, currentProfile: s.currentProfile, windowsTargetId: s.windowsTargetId, windowsPlatform: s.windowsPlatform, windowsMachineIdSHA256: s.windowsMachineIdSHA256, setupSHA256: s.setupSHA256, serviceSHA256: s.serviceSHA256, deviceId: identity.deviceId, certificateHash: identity.certificateHash, invitationIdSHA256: hash(identity.invitationId), bootstrapSHA256: bootstrap, senderBinding: hash('sender'), receiptSHA256: hash('receipt12'), consentSHA256: hash('consent14'), publicIdentitySHA256: hash('public identity'), credentialManifestSHA256: hash('manifest'), scopes: [...CURRENT_SCOPES], grantIds: grants, grantDigests: grants.map((g, i) => ({ scope: g.scope, sha256: hash(`digest-${i === 18 ? 6 : i}`) })), identityGeneration: `identity_${'aa'.repeat(16)}`, credentialGeneration: 1, credentialRevision: 1, currentCertificateHash: identity.certificateHash, keyFingerprint: hash('key'), authorityExpiresUnix: Math.floor(now / 1000) + 864000, currentCertificateExpiresUnix: Math.floor(now / 1000) + 604800 };
  return { s, identity, bootstrap, binding };
}
function requests() {
  const { s, binding } = bindingCase(), search = approvedHistorySearch(s), createdAt = new Date(now - 1000).toISOString(), expiresAt = new Date(now + 899000).toISOString();
  const local = { ...binding, grantId: binding.grantIds.at(-1).grantId, floor: '0', phaseStarted: now - 2000 };
  const description = { deviceId: binding.deviceId, certificateHash: binding.certificateHash, grantId: local.grantId, identity: { id: `winhistory_${'1'.repeat(32)}`, sequence: '1', queryDigest: `sha256:${hash('query')}` }, headerGenerationId: `sample_${'2'.repeat(32)}`, headerCollectedAt: createdAt, headerSnapshotDigest: `sha256:${hash('search')}`, query: { events: [], search }, createdAt, expiresAt };
  const posted = { expectedFloor: '0', search, acknowledgeHistory: true, acknowledgePlaintext: false };
  const receipt = { identity: description.identity, policyDigest: `sha256:${hash('policy')}`, resultDigest: `sha256:${hash('result')}`, acceptedAt: createdAt, expiresAt };
  const result = { receipt }, record = { description, receipt };
  const selected = { channel: 'Application', recordId: '18446744073709551614', eventId: 321, level: 4, provider: s.syntheticEvent.source, timestamp: search.start };
  const followup = { ...description, identity: { id: `winhistory_${'3'.repeat(32)}`, sequence: '2', queryDigest: `sha256:${hash('messages')}` }, sourceSearch: search, searchReceipt: receipt, query: { events: [selected] } };
  const messagePost = { expectedFloor: '1', receipt, selections: [{ channel: 'Application', recordId: selected.recordId }], acknowledgeContent: true, acknowledgePlaintext: false };
  return { s, local, description, posted, result, record, selected, followup, messagePost };
}
test('v2 has an explicit current profile and two bounded human approval references', () => {
  const s = spec(); assert.equal(validateSpec(s, now), s);
  for (const [key, value] of [['receiptVersion', 11], ['consentVersion', 'tracebolt.windows-capability-consent.v13'], ['renewal', false], ['setupContract', 'fresh-twenty']]) rejects(() => validateSpec({ ...s, currentProfile: { ...s.currentProfile, [key]: value } }, now));
  for (const [key, value] of [['channel', 'Security'], ['maxMessages', 2], ['maxRows', 101], ['eventId', 322], ['messagesApprovalRef', s.historyQuery.approvalRef], ['startUnix', s.historyQuery.startUnix + 1], ['endUnix', s.expiresUnix]]) rejects(() => validateSpec({ ...s, historyQuery: { ...s.historyQuery, [key]: value } }, now));
  rejects(() => validateSpec({ ...s, windowsPlatform: 'windows/arm64' }, now));
  rejects(() => validateSpec({ ...s, schema: 'tracebolt.windows-linux-native-parity.browser.v1' }, now));
  rejects(() => validateCurrentProfile({ ...CURRENT_PROFILE, approved: true }));
});
test('exact approved query maps UTC minutes without widening or adding filters', () => {
  const s = spec(), query = approvedHistorySearch(s); assert.equal(Date.parse(query.start), s.historyQuery.startUnix * 1000); assert.equal(Date.parse(query.end), s.historyQuery.endUnix * 1000);
  assert.deepEqual(Object.keys(query), ['channel', 'start', 'end', 'eventId']);
});
test('renewable public bootstrap refuses silent legacy/HTTP promotion', () => {
  const s = spec(), pem = rootCertificates[0], cert = new X509Certificate(pem), invitationId = `invite_${'bc'.repeat(16)}`;
  s.issuerFingerprint = hash(cert.raw); s.bootstrapServerCASHA256 = hash(pem); s.bootstrapIssuerRootSHA256 = hash(pem);
  const bootstrap = { schemaVersion: 'tracebolt.enrollment-bootstrap.renewable.v1', renewalPolicy: 'same-key-v1', managerInstanceId: s.managerInstanceId, profile: 'tls', enrollmentOrigin: s.operatorOrigin, agentOrigin: s.agentOrigin, collectionProfile: 'windows-inventory-v1', invitationId, serverCaPem: pem, issuerRootPem: pem, issuerPem: pem };
  validateBootstrap(bootstrap, s, invitationId);
  for (const change of [{ schemaVersion: 'tracebolt.enrollment-bootstrap.v2' }, { renewalPolicy: 'automatic' }, { profile: 'http-test' }, { invitationSecret: 'must-never-be-copied' }]) rejects(() => validateBootstrap({ ...bootstrap, ...change }, s, invitationId));
});
test('all 21 scopes and 20 ordered grant proofs are required, with software history same-parent binding', () => {
  const { s, identity, bootstrap, binding } = bindingCase(); validateCurrentEndpointBinding(binding, s, identity, bootstrap);
  assert.equal(CURRENT_SCOPES.length, 21); assert.equal(new Set(CURRENT_SCOPES).size, 21);
  for (const key of ['scopes', 'grantDigests', 'grantIds']) { const bad = structuredClone(binding); bad[key].pop(); rejects(() => validateCurrentEndpointBinding(bad, s, identity, bootstrap), 'identity_mismatch'); }
  for (const key of ['scopes', 'grantDigests', 'grantIds']) { const bad = structuredClone(binding); bad[key].reverse(); rejects(() => validateCurrentEndpointBinding(bad, s, identity, bootstrap), 'identity_mismatch'); }
  const bad = structuredClone(binding); bad.grantIds[18].grantId = hash('different').slice(0, 32); rejects(() => validateCurrentEndpointBinding(bad, s, identity, bootstrap), 'identity_mismatch');
  for (const key of ['publicIdentitySHA256', 'credentialManifestSHA256']) rejects(() => validateCurrentEndpointBinding({ ...binding, [key]: 'missing' }, s, identity, bootstrap), 'identity_mismatch');
  rejects(() => validateCurrentEndpointBinding({ ...binding, windowsPlatform: 'windows-server-2025-x64' }, s, identity, bootstrap), 'identity_mismatch');
});
test('anchor is immutable while a renewed current leaf is separately identified', () => {
  const { s, identity, bootstrap, binding } = bindingCase();
  rejects(() => validateCurrentEndpointBinding({ ...binding, currentCertificateHash: hash('new leaf') }, s, identity, bootstrap), 'identity_mismatch');
  validateCurrentEndpointBinding({ ...binding, currentCertificateHash: hash('new leaf'), credentialGeneration: 2, credentialRevision: 4 }, s, identity, bootstrap);
  rejects(() => validateCurrentEndpointBinding({ ...binding, certificateHash: hash('new leaf'), currentCertificateHash: hash('new leaf'), credentialGeneration: 2 }, s, identity, bootstrap), 'identity_mismatch');
});
test('live manager credential metadata must match current generation and original authority expiry', () => {
  const { binding } = bindingCase(), expiry = new Date(binding.currentCertificateExpiresUnix * 1000).toISOString();
  const device = { id: binding.deviceId, platform: 'windows', source: 'lan', synthetic: false, agentCertificate: { source: 'guided-enrollment', expiresAt: expiry, checkedAt: new Date(now).toISOString(), renewal: { status: 'healthy', enabled: true, identityGeneration: binding.identityGeneration, credentialGeneration: 1, currentNotAfter: expiry, authorityExpiresAt: new Date(binding.authorityExpiresUnix * 1000).toISOString() } } };
  validateCurrentCredential(device, binding, now);
  for (const change of [{ identityGeneration: `identity_${'bb'.repeat(16)}` }, { enabled: false }, { credentialGeneration: 2 }, { status: 'revoked' }, { currentNotAfter: new Date(now + 1000).toISOString() }]) rejects(() => validateCurrentCredential({ ...device, agentCertificate: { ...device.agentCertificate, renewal: { ...device.agentCertificate.renewal, ...change } } }, binding, now));
  rejects(() => validateCurrentCredential({ ...device, agentCertificate: { ...device.agentCertificate, checkedAt: new Date(now - 31000).toISOString() } }, binding, now), 'stale_capture');
});
test('rotating absent contexts do not invalidate fresh primary; every present current/retained grant stays bound', () => {
  const { binding } = bindingCase(), view = { status: 'fresh', serverNow: new Date(now).toISOString(), snapshot: { collectedAt: new Date(now - 500).toISOString() } };
  assert.equal(validateCurrentInventoryBindings(view, binding, now - 1000, now), true);
  for (const [field, scope] of Object.entries(INVENTORY_SCOPE_FIELDS)) {
    const grantId = binding.grantIds.find(g => g.scope === scope).grantId, value = { grantId, collectedAt: new Date(now - 500).toISOString(), quality: 'denied' };
    assert.equal(validateCurrentInventoryBindings({ ...view, [field]: value }, binding, now - 1000, now), true);
    rejects(() => validateCurrentInventoryBindings({ ...view, [field]: { ...value, grantId: '0'.repeat(32) } }, binding, now - 1000, now), 'identity_mismatch');
    rejects(() => validateCurrentInventoryBindings({ ...view, retainedContext: { [field]: { ...value, grantId: '0'.repeat(32) } } }, binding, now - 1000, now), 'identity_mismatch');
  }
});
test('finite scope outcomes preserve denied, unsupported, budgets, bounded and partial truth', () => {
  for (const [value, expected] of [[null, 'not_observed'], [{ quality: 'denied', rows: [] }, 'denied'], [{ quality: 'unavailable', reason: 'source_unsupported' }, 'unsupported'], [{ quality: 'unavailable', reason: 'context deadline exceeded' }, 'budget_exceeded'], [{ quality: 'bounded', rows: [] }, 'partial'], [{ quality: 'observed', rows: [], countExact: true, observedCount: 0, complete: true, truncated: false }, 'legitimately_absent'], [{ a: { quality: 'observed' }, b: { quality: 'denied' } }, 'partial'], [{ rows: [{ cpuQuality: 'denied', memoryQuality: 'denied' }] }, 'denied'], [{ rows: [{ startupQuality: 'unavailable' }] }, 'unavailable']]) assert.equal(sourceOutcome(value), expected);
  assert.ok(SOURCE_OUTCOMES.includes('partial'));
});
test('outcomes accumulate actual fresh scopes without relabeling stale retained originals', () => {
  const report = resultSummary(spec()), serverNow = new Date(now).toISOString();
  recordCurrentOutcomes(report, { serverNow, snapshot: { services: { quality: 'denied' } }, securityCoverage: { collectedAt: serverNow, quality: 'unavailable', reason: 'unsupported' } }, now - 1000, now);
  assert.equal(report.observations.scopeOutcomes[CURRENT_SCOPES[0]], 'denied'); assert.equal(report.observations.scopeOutcomes[CURRENT_SCOPES[14]], 'unsupported'); assert.equal(report.observations.coverage, 'partial');
  recordCurrentOutcomes(report, { serverNow, snapshot: { services: { quality: 'denied' } }, securityCoverage: { collectedAt: new Date(now - 86400000).toISOString(), quality: 'observed' } }, now - 1000, now);
  assert.equal(report.observations.scopeOutcomes[CURRENT_SCOPES[14]], 'unsupported'); assert.equal(report.observations.scopeOutcomes[CURRENT_SCOPES[15]], 'not_observed');
});
test('history creation matches only the exact approved synthetic search and human acknowledgement', () => {
  const c = requests(); inspectHistorySearch(c.description, c.posted, c.local, c.posted.search, now);
  for (const changed of [{ acknowledgeHistory: false }, { acknowledgePlaintext: true }, { expectedFloor: '1' }, { search: { ...c.posted.search, channel: 'System' } }]) rejects(() => inspectHistorySearch(c.description, { ...c.posted, ...changed }, c.local, c.posted.search, now), 'identity_mismatch');
  for (const changed of [{ certificateHash: hash('current leaf') }, { grantId: 'f'.repeat(32) }, { deviceId: `agent_${'f'.repeat(32)}` }]) rejects(() => inspectHistorySearch({ ...c.description, ...changed }, c.posted, c.local, c.posted.search, now), 'identity_mismatch');
});
test('selected messages preserve the exact search receipt, full-width row identity and original lifetime', () => {
  const c = requests(), local = { ...c.local, floor: '1' };
  const run = (description = c.followup, posted = c.messagePost) => inspectHistoryMessages(description, posted, local, c.record, c.result, c.selected, now);
  run();
  for (const change of [{ acknowledgeContent: false }, { acknowledgePlaintext: true }, { receipt: { ...c.messagePost.receipt, resultDigest: `sha256:${hash('other')}` } }, { selections: [{ channel: 'Application', recordId: '18446744073709551615' }] }]) rejects(() => run(c.followup, { ...c.messagePost, ...change }), 'identity_mismatch');
  for (const key of ['createdAt', 'expiresAt', 'headerCollectedAt']) rejects(() => run({ ...c.followup, [key]: new Date(now + 1800000).toISOString() }), 'stale_capture');
  for (const key of Object.keys(c.selected)) rejects(() => run({ ...c.followup, query: { events: [{ ...c.selected, [key]: 'changed' }] } }), 'identity_mismatch');
  rejects(() => run({ ...c.followup, sourceSearch: { ...c.posted.search, start: new Date(now - 86400000).toISOString() } }), 'identity_mismatch');
});
test('restart envelope requires the canonical exact endpoint proof and post-handoff real time', () => {
  const { s, binding } = bindingCase(), value = { schema: 'tracebolt.windows-linux-native-parity.restart-binding.v1', runId: s.runId, planSHA256: s.planSHA256, endpointBindingSHA256: hash(canonicalJSON(binding)), observedUnix: Math.floor(now / 1000), ownRestartObserved: true };
  validateRestartBinding(value, s, binding, now, now);
  for (const change of [{ endpointBindingSHA256: hash('other') }, { ownRestartObserved: false }, { runId: 'different' }]) rejects(() => validateRestartBinding({ ...value, ...change }, s, binding, now, now), 'identity_mismatch');
  for (const observedUnix of [value.observedUnix - 1, value.observedUnix + 2]) rejects(() => validateRestartBinding({ ...value, observedUnix }, s, binding, now, now), 'stale_capture');
});
test('v2 report is a finite sanitized projection and all checks remain necessary without coverage promotion', () => {
  const s = spec(), report = resultSummary(s); validateResult(report, s);
  for (const key of ['message', 'rows', 'screenshot', 'username', 'certificate']) rejects(() => validateResult({ ...report, [key]: 'private' }, s));
  const pass = structuredClone(report); pass.nativeExecution = true; for (const key of CURRENT_CHECKS) pass.checks[key] = true;
  Object.assign(pass.observations, { scopeCount: 21, grantCount: 20, coverage: 'partial', historySearchQuality: 'bounded', historySearchRows: 1, historySearchComplete: false, historySearchTruncated: true, historyMessageQuality: 'observed' });
  pass.observations.scopeOutcomes[CURRENT_SCOPES[14]] = 'unsupported'; finishSummary(pass); validateResult(pass, s); assert.equal(pass.status, 'passed'); assert.equal(pass.fullAcceptance, false); assert.deepEqual(pass.omissions, CURRENT_OMITTED);
  for (const key of CURRENT_CHECKS) { const missing = structuredClone(pass); missing.checks[key] = false; finishSummary(missing); assert.equal(missing.status, 'blocked', key); }
  for (const change of [{ coverage: 'complete' }, { historyMessageQuality: 'unavailable' }, { renewalExecution: 'renewed' }, { scopeCount: 20 }, { scopeOutcomes: { [CURRENT_SCOPES[0]]: 'observed' } }]) rejects(() => validateResult({ ...pass, observations: { ...pass.observations, ...change } }, s));
});
test('current main is inert under every CI marker before input or dependency/native access', () => {
  const moduleURL = new URL('./browser.mjs', import.meta.url).href;
  const program = `import {main} from ${JSON.stringify(moduleURL)}; process.argv=[process.execPath,'browser.mjs','--current-profile']; let inputRead=false; process.stdin[Symbol.asyncIterator]=async function*(){inputRead=true;throw new Error('must never read');}; process.stdout.write(JSON.stringify({status:await main(),inputRead}));`;
  for (const flag of ['CI', 'GITHUB_ACTIONS', 'TF_BUILD', 'BUILD_BUILDID']) {
    const env = { ...process.env, [flag]: '' }; const run = spawnSync(process.execPath, ['--input-type=module', '-e', program], { env, encoding: 'utf8', timeout: 10000 });
    assert.equal(run.status, 0); assert.equal(run.stderr, ''); assert.deepEqual(JSON.parse(run.stdout), { status: 2, inputRead: false });
  }
});
test('current source uses production UI handoffs and no content read mutation or invented browser evidence', async () => {
  const source = await readFile(new URL('./current_browser.mjs', import.meta.url), 'utf8');
  for (const forbidden of [/\.route\(/, /\.fulfill\(/, /\.clock\./, /\.screenshot\(/, /\.tracing\./, /\.storageState\(/, /\.addCookies\(/, /fetch\(/, /getByRole\([^\n]*(Search once|Read 1 messages)[^\n]*\.click/]) assert.equal(forbidden.test(source), false, String(forbidden));
  for (const required of ['PARITY_BROWSER_HISTORY_SEARCH_HANDOFF', 'PARITY_BROWSER_HISTORY_MESSAGES_HANDOFF', 'PARITY_BROWSER_OWN_RESTART_READY', "'.history-messages pre'", 'validEventHistoryResult', 'validEventHistoryView', 'readPrivateEvidence']) assert.ok(source.includes(required), required);
});

test('actual production history validators and request fixtures interoperate with both observer phases', async t => {
  const { loadValidators, pinnedDependencies } = await import('./browser.mjs');
  const { fileURLToPath } = await import('node:url'); const { resolve } = await import('node:path');
  const root = fileURLToPath(new URL('../../', import.meta.url)), dependencies = process.env.TRACEBOLT_BROWSER_TEST_DEPENDENCIES || resolve(root, 'web');
  if (!existsSync(resolve(dependencies, 'node_modules/esbuild/package.json'))) { t.skip('Pinned dependencies not installed; no native/browser evidence claimed.'); return; }
  const validators = await loadValidators(root, dependencies), require = await pinnedDependencies(root, dependencies);
  const source = `export * from ${JSON.stringify(resolve(root, 'web/src/windows-event-history-fixture.ts'))};`;
  const built = await require('esbuild').build({ stdin: { contents: source, resolveDir: root, loader: 'ts' }, bundle: true, write: false, platform: 'node', format: 'esm', logLevel: 'silent' });
  const fixture = await import(`data:text/javascript;base64,${Buffer.from(built.outputFiles[0].text).toString('base64')}`);
  const s = spec(), query = approvedHistorySearch(s), at = new Date(now).toISOString(), view = fixture.historyView(at, new Date(now + 3600000).toISOString());
  assert.equal(validators.validEventHistoryView(view, view.deviceId, null), true);
  const pending = fixture.historyRecord(view, query), accepted = fixture.historyAccepted(pending), result = fixture.historyResult(accepted, 1);
  const received = { ...view, request: accepted, expectedFloor: '1', contentStatus: 'available' };
  assert.equal(validators.validEventHistoryView(received, view.deviceId, view.sessionExpiresAt), true); assert.equal(validators.validEventHistoryResult(result, accepted, view.sessionExpiresAt), true);
  const local = { deviceId: view.deviceId, certificateHash: accepted.description.certificateHash, grantId: view.capability.grantId, floor: '0', phaseStarted: now - 1000 };
  inspectHistorySearch(pending.description, { expectedFloor: '0', search: query, acknowledgeHistory: true, acknowledgePlaintext: false }, local, query, now);
  const selected = result.report.events[0].event, messagePending = fixture.historyRecord(received, undefined, accepted, [selected]);
  inspectHistoryMessages(messagePending.description, { expectedFloor: '1', receipt: result.receipt, selections: [{ channel: selected.channel, recordId: selected.recordId }], acknowledgeContent: true, acknowledgePlaintext: false }, { ...local, floor: '1' }, accepted, result, selected, now);
  const messageAccepted = fixture.historyAccepted(messagePending), messages = fixture.historyResult(messageAccepted);
  const delivered = { ...view, request: messageAccepted, expectedFloor: '2', contentStatus: 'available' };
  assert.equal(validators.validEventHistoryView(delivered, view.deviceId, view.sessionExpiresAt), true); assert.equal(validators.validEventHistoryResult(messages, messageAccepted, view.sessionExpiresAt), true);
  const forged = structuredClone(messages); forged.report.events[0].event.provider = 'reinterpreted later telemetry'; assert.equal(validators.validEventHistoryResult(forged, messageAccepted, view.sessionExpiresAt), false);
});
