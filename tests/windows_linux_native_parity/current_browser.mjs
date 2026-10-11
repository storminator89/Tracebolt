/** Source-only adapter for a separately authorized fresh current-profile gate.
 * Importing this module never starts Chromium, grants a scope or reads a host.
 */
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { need, Refusal, freshCapture, sameEvent, sameIdentity, canonicalJSON, guardedResponseBody, advancingSample, readPrivateEvidence } from './browser.mjs';
export const CURRENT_SCHEMA = 'tracebolt.windows-linux-native-parity.browser.v2';
export const CURRENT_PROFILE = Object.freeze({ schema: 'tracebolt.windows-native-current-profile.v1', setupContract: 'fresh-twenty-one-read-admin-scopes-v1', consentVersion: 'tracebolt.windows-capability-consent.v14', receiptVersion: 12, renewal: true });
export const CURRENT_CHECKS = ['publicBootstrapSaved', 'endpointBindingObserved', 'singleFreshWindowsIdentity', 'currentScopeBindingsObserved', 'stableIdentityObserved', 'currentCredentialObserved', 'historyDefaultIdleObserved', 'historySearchRequestObserved', 'historySearchResultObserved', 'syntheticHistoryHeaderObserved', 'historyMessagesRequestObserved', 'historyMessageResultObserved', 'historyMessageRendered', 'privateHistoryDiscardObserved', 'ownRestartBindingObserved', 'postRestartInventoryObserved', 'browserClosed'];
export const CURRENT_OMITTED = ['baseline_source_completeness', 'retained_history_completeness', 'renewal_cutover', 'health_policy_lifecycle', 'worker_faults_and_replay', 'online_updates', 'update_installation', 'service_actions', 'reboot', 'upgrade_repair'];
export const CURRENT_MARKERS = ['PARITY_BROWSER_CURRENT_PROFILE_OBSERVED', 'PARITY_BROWSER_HISTORY_SEARCH_HANDOFF', 'PARITY_BROWSER_HISTORY_MESSAGES_HANDOFF', 'PARITY_BROWSER_OWN_RESTART_READY'];
export const SOURCE_OUTCOMES = ['not_observed', 'observed', 'partial', 'legitimately_absent', 'unsupported', 'denied', 'budget_exceeded', 'unavailable'];
const QUALITY = ['not_observed', 'observed', 'bounded', 'partial', 'unavailable'];
const ENDPOINT = ['not_observed', '', 'checking', 'disabled', 'denied', 'reader_unavailable', 'budget_exhausted', 'result_lost', 'expired', 'canceled'];
const exact = (v, keys) => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const hash = v => createHash('sha256').update(v).digest('hex');
const hex = (v, n = 64) => typeof v === 'string' && new RegExp(`^[a-f0-9]{${n}}$`).test(v);
const utcTime = v => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number.isFinite(Date.parse(v)) && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19);
const equal = (a, b) => { try { return canonicalJSON(a) === canonicalJSON(b); } catch { return false; } };
export const CURRENT_SCOPES = [
  'windows-inventory-v1', 'windows-application-system-event-headers-v1', 'windows-visible-volumes-v1', 'windows-process-metrics-v1', 'windows-network-endpoints-v1', 'windows-service-startup-v1', 'windows-complete-services-v1', 'windows-complete-machine-software-v1', 'windows-adapter-context-v1', 'windows-patch-context-v1', 'windows-security-posture-v1', 'windows-session-context-v1', 'windows-hardware-context-v1', 'windows-storage-context-v1', 'windows-security-coverage-v1', 'windows-complete-processes-v1', 'windows-network-context-v1', 'windows-resource-context-v1', 'windows-storage-io-v1', 'windows-machine-software-history-v1', 'windows-application-system-event-history-v1',
];
// This map covers the ordinary frame only. Independent full generations remain
// not_observed unless separately validated; an approved grant is not source data.
export const INVENTORY_SCOPE_FIELDS = { events: CURRENT_SCOPES[1], volumes: CURRENT_SCOPES[2], processMetrics: CURRENT_SCOPES[3], network: CURRENT_SCOPES[4], serviceStartup: CURRENT_SCOPES[5], adapterContext: CURRENT_SCOPES[8], patchContext: CURRENT_SCOPES[9], securityPosture: CURRENT_SCOPES[10], sessionContext: CURRENT_SCOPES[11], hardwareContext: CURRENT_SCOPES[12], storageContext: CURRENT_SCOPES[13], securityCoverage: CURRENT_SCOPES[14], resourceContext: CURRENT_SCOPES[17], storageIO: CURRENT_SCOPES[18] };
export function validateCurrentProfile(profile) { need(exact(profile, Object.keys(CURRENT_PROFILE)) && equal(profile, CURRENT_PROFILE)); }
export function validateHistoryQuery(query, spec, now = Date.now()) {
  need(exact(query, ['approvalRef', 'messagesApprovalRef', 'channel', 'eventId', 'startUnix', 'endUnix', 'maxRows', 'maxMessages']));
  need([query.approvalRef, query.messagesApprovalRef].every(v => typeof v === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}$/.test(v)) && query.approvalRef !== query.messagesApprovalRef);
  need(query.channel === 'Application' && query.eventId === spec.syntheticEvent.eventId && query.maxRows === 100 && query.maxMessages === 1);
  need([query.startUnix, query.endUnix].every(v => Number.isSafeInteger(v) && v > 0 && v % 60 === 0) && query.endUnix > query.startUnix && query.endUnix - query.startUnix <= 604800 && query.startUnix * 1000 >= now - 2592000000 && query.endUnix < spec.expiresUnix, 'deadline');
}
export const approvedHistorySearch = spec => ({ channel: 'Application', start: new Date(spec.historyQuery.startUnix * 1000).toISOString().replace('.000Z', 'Z'), end: new Date(spec.historyQuery.endUnix * 1000).toISOString().replace('.000Z', 'Z'), eventId: spec.syntheticEvent.eventId });
export function currentResultSummary(spec) {
  return { schema: 'tracebolt.windows-linux-native-parity.browser-result.v2', runId: spec.runId, planSHA256: spec.planSHA256, source: { ...spec.source }, currentProfile: { ...CURRENT_PROFILE }, status: 'blocked', reason: 'browser_unavailable', fullAcceptance: false, nativeExecution: false,
    checks: Object.fromEntries(CURRENT_CHECKS.map(k => [k, false])), observations: { scopeCount: 0, grantCount: 0, coverage: 'not_assessed', scopeOutcomes: Object.fromEntries(CURRENT_SCOPES.map(k => [k, 'not_observed'])), historySearchQuality: 'not_observed', historySearchRows: 0, historySearchComplete: false, historySearchTruncated: false, historyMessageQuality: 'not_observed', historyEndpointStatus: 'not_observed', retainedHistoryCoverage: 'not_assessed', patchCoverage: 'not_assessed', renewalExecution: 'not_observed' }, omissions: [...CURRENT_OMITTED] };
}
export function validateCurrentResult(report, spec, reasons) {
  need(exact(report, ['schema', 'runId', 'planSHA256', 'source', 'currentProfile', 'status', 'reason', 'fullAcceptance', 'nativeExecution', 'checks', 'observations', 'omissions']));
  need(report.schema === 'tracebolt.windows-linux-native-parity.browser-result.v2' && report.runId === spec.runId && report.planSHA256 === spec.planSHA256 && equal(report.source, spec.source)); validateCurrentProfile(report.currentProfile);
  need(['passed', 'blocked'].includes(report.status) && reasons.includes(report.reason) && report.fullAcceptance === false && typeof report.nativeExecution === 'boolean');
  need(exact(report.checks, CURRENT_CHECKS) && CURRENT_CHECKS.every(k => typeof report.checks[k] === 'boolean'));
  const o = report.observations;
  need(exact(o, ['scopeCount', 'grantCount', 'coverage', 'scopeOutcomes', 'historySearchQuality', 'historySearchRows', 'historySearchComplete', 'historySearchTruncated', 'historyMessageQuality', 'historyEndpointStatus', 'retainedHistoryCoverage', 'patchCoverage', 'renewalExecution']));
  need([0, 21].includes(o.scopeCount) && [0, 20].includes(o.grantCount) && (o.scopeCount === 21) === (o.grantCount === 20));
  need(['partial', 'not_assessed'].includes(o.coverage) && exact(o.scopeOutcomes, CURRENT_SCOPES) && Object.values(o.scopeOutcomes).every(v => SOURCE_OUTCOMES.includes(v)));
  need(QUALITY.includes(o.historySearchQuality) && QUALITY.includes(o.historyMessageQuality) && Number.isSafeInteger(o.historySearchRows) && o.historySearchRows >= 0 && o.historySearchRows <= 100 && typeof o.historySearchComplete === 'boolean' && typeof o.historySearchTruncated === 'boolean' && ENDPOINT.includes(o.historyEndpointStatus));
  need(o.retainedHistoryCoverage === 'not_assessed' && o.patchCoverage === 'not_assessed' && o.renewalExecution === 'not_observed' && equal(report.omissions, CURRENT_OMITTED));
  need(!report.checks.currentScopeBindingsObserved || o.scopeCount === 21 && o.grantCount === 20);
  need(!report.checks.historySearchResultObserved || o.historySearchQuality !== 'not_observed');
  need(!report.checks.syntheticHistoryHeaderObserved || report.checks.historySearchResultObserved && o.historySearchRows > 0);
  need(!report.checks.historyMessagesRequestObserved || report.checks.syntheticHistoryHeaderObserved);
  need(!report.checks.historyMessageResultObserved || report.checks.historyMessagesRequestObserved && o.historyMessageQuality === 'observed');
  need(!report.checks.historyMessageRendered || report.checks.historyMessageResultObserved);
  need(report.status === 'passed' ? report.reason === 'complete' && report.nativeExecution && CURRENT_CHECKS.every(k => report.checks[k]) : report.reason !== 'complete');
  return report;
}
export function finishCurrentSummary(report) {
  const passed = report.nativeExecution && CURRENT_CHECKS.every(k => report.checks[k]); report.status = passed ? 'passed' : 'blocked'; report.reason = passed ? 'complete' : 'event_unknown'; return report;
}
// Finite redacted outcomes only, derived from already production-validated DTOs.
// Mixed, bounded and unknown observations never become full source coverage.
export function sourceOutcome(value) {
  if (!value || typeof value !== 'object') return 'not_observed';
  const qualities = [], reasons = [];
  const walk = item => { if (!item || typeof item !== 'object') return; if (item.truncated === true) qualities.push('partial'); for (const [key, child] of Object.entries(item)) { if ((key === 'quality' || key.endsWith('Quality')) && typeof child === 'string' && child !== 'not-applicable') qualities.push(child); if (key === 'reason' && typeof child === 'string') reasons.push(child); if (Array.isArray(child)) child.forEach(walk); else if (child && typeof child === 'object') walk(child); } };
  walk(value);
  const kinds = new Set(qualities.map(q => ['healthy', 'observed'].includes(q) ? 'observed' : ['partial', 'bounded'].includes(q) ? 'partial' : q === 'denied' ? 'denied' : q === 'unsupported' ? 'unsupported' : 'unavailable'));
  if (reasons.some(r => /denied/.test(r))) kinds.add('denied');
  if (reasons.some(r => /unsupported/.test(r))) kinds.add('unsupported');
  if (reasons.some(r => /deadline|budget|resource_limit/.test(r))) kinds.add('budget_exceeded');
  if (kinds.has('observed') && (kinds.size > 1 || kinds.has('partial'))) return 'partial';
  if (kinds.has('partial')) return 'partial';
  for (const k of ['budget_exceeded', 'denied', 'unsupported', 'unavailable']) if (kinds.has(k)) return k;
  if (kinds.has('observed')) return Array.isArray(value.rows) && value.rows.length === 0 && value.observedCount === 0 && value.countExact === true && value.complete === true && value.truncated === false ? 'legitimately_absent' : 'observed';
  return 'not_observed';
}
export function recordCurrentOutcomes(report, view, minimum = 0, now = Date.now()) {
  report.observations.scopeOutcomes[CURRENT_SCOPES[0]] = sourceOutcome(view.snapshot);
  for (const [field, scope] of Object.entries(INVENTORY_SCOPE_FIELDS)) if (view[field] && freshCapture(view[field].collectedAt, view.serverNow, minimum, now)) report.observations.scopeOutcomes[scope] = sourceOutcome(view[field]);
  if (Object.values(report.observations.scopeOutcomes).some(v => v !== 'not_observed')) report.observations.coverage = 'partial';
}
export function sameHistoryReceipt(a, b) { return Boolean(a && b && sameIdentity(a.identity, b.identity) && ['policyDigest', 'resultDigest', 'acceptedAt', 'expiresAt'].every(k => a[k] === b[k])); }
export function inspectHistorySearch(description, posted, binding, search, now = Date.now()) {
  need(exact(posted, ['expectedFloor', 'search', 'acknowledgeHistory', 'acknowledgePlaintext']), 'invalid_response');
  need(description && description.deviceId === binding.deviceId && description.certificateHash === binding.certificateHash && description.grantId === binding.grantId && posted.expectedFloor === binding.floor && BigInt(description.identity.sequence) === BigInt(binding.floor) + 1n, 'identity_mismatch');
  need(equal(posted.search, search) && equal(description.query, { events: [], search }) && !description.searchReceipt && !description.sourceSearch && posted.acknowledgeHistory === true && posted.acknowledgePlaintext === false, 'identity_mismatch');
  need(Date.parse(description.createdAt) >= binding.phaseStarted && Date.parse(description.expiresAt) > now && Date.parse(description.expiresAt) - Date.parse(description.createdAt) === 900000, 'stale_capture');
}
export function inspectHistoryMessages(description, posted, binding, searchRecord, result, selection, now = Date.now()) {
  need(exact(posted, ['expectedFloor', 'receipt', 'selections', 'acknowledgeContent', 'acknowledgePlaintext']), 'invalid_response');
  need(description && description.deviceId === binding.deviceId && description.certificateHash === binding.certificateHash && description.grantId === binding.grantId && posted.expectedFloor === binding.floor && BigInt(description.identity.sequence) === BigInt(binding.floor) + 1n, 'identity_mismatch');
  need(sameHistoryReceipt(posted.receipt, result.receipt) && sameHistoryReceipt(description.searchReceipt, result.receipt) && equal(description.sourceSearch, searchRecord.description.query.search) && description.query.search === undefined && description.query.events.length === 1 && sameEvent(description.query.events[0], selection), 'identity_mismatch');
  need(posted.acknowledgeContent === true && posted.acknowledgePlaintext === false && equal(posted.selections, [{ channel: selection.channel, recordId: selection.recordId }]), 'identity_mismatch');
  need(['createdAt', 'expiresAt', 'headerGenerationId', 'headerCollectedAt', 'headerSnapshotDigest'].every(k => description[k] === searchRecord.description[k]) && description.expiresAt === result.receipt.expiresAt && Date.parse(description.expiresAt) > now, 'stale_capture');
}
export function validateCurrentEndpointBinding(value, spec, identity, bootstrapSHA256) {
  const keys = ['schema', 'runId', 'planSHA256', 'source', 'windowsTargetId', 'windowsMachineIdSHA256', 'setupSHA256', 'serviceSHA256', 'deviceId', 'certificateHash', 'invitationIdSHA256', 'bootstrapSHA256', 'currentProfile', 'windowsPlatform', 'senderBinding', 'receiptSHA256', 'consentSHA256', 'publicIdentitySHA256', 'credentialManifestSHA256', 'scopes', 'grantDigests', 'grantIds', 'identityGeneration', 'credentialGeneration', 'credentialRevision', 'currentCertificateHash', 'keyFingerprint', 'authorityExpiresUnix', 'currentCertificateExpiresUnix'];
  need(exact(value, keys), 'invalid_response'); validateCurrentProfile(value.currentProfile);
  need(value.schema === 'tracebolt.windows-linux-native-parity.endpoint-binding.v2' && value.runId === spec.runId && value.planSHA256 === spec.planSHA256 && equal(value.source, spec.source), 'identity_mismatch');
  need(['windowsTargetId', 'windowsMachineIdSHA256', 'setupSHA256', 'serviceSHA256'].every(k => value[k] === spec[k]) && value.deviceId === identity.deviceId && value.certificateHash === identity.certificateHash && value.invitationIdSHA256 === hash(identity.invitationId) && value.bootstrapSHA256 === bootstrapSHA256, 'identity_mismatch');
  need(value.windowsPlatform === spec.windowsPlatform && ['windows-11-x64', 'windows-server-2025-x64'].includes(value.windowsPlatform) && ['senderBinding', 'receiptSHA256', 'consentSHA256', 'publicIdentitySHA256', 'credentialManifestSHA256', 'currentCertificateHash', 'keyFingerprint'].every(k => hex(value[k])) && equal(value.scopes, CURRENT_SCOPES), 'identity_mismatch');
  need(/^identity_[a-f0-9]{32}$/.test(value.identityGeneration) && value.identityGeneration !== `identity_${'0'.repeat(32)}` && Number.isSafeInteger(value.credentialGeneration) && value.credentialGeneration >= 1 && Number.isSafeInteger(value.credentialRevision) && value.credentialRevision >= 1, 'identity_mismatch');
  need([value.authorityExpiresUnix, value.currentCertificateExpiresUnix].every(v => Number.isSafeInteger(v) && v * 1000 > Date.now()) && value.authorityExpiresUnix >= value.currentCertificateExpiresUnix, 'stale_capture');
  // Fresh initial native acceptance does not force an unobservable multi-day
  // renewal; generation 1 correctly has the same current and anchor leaf.
  need(value.credentialGeneration !== 1 || value.currentCertificateHash === value.certificateHash, 'identity_mismatch');
  need(Array.isArray(value.grantDigests) && value.grantDigests.length === 20 && value.grantDigests.every((g, i) => exact(g, ['scope', 'sha256']) && g.scope === CURRENT_SCOPES[i + 1] && hex(g.sha256)), 'identity_mismatch');
  need(Array.isArray(value.grantIds) && value.grantIds.length === 20 && value.grantIds.every((g, i) => exact(g, ['scope', 'grantId']) && g.scope === CURRENT_SCOPES[i + 1] && hex(g.grantId, 32)), 'identity_mismatch');
  need(value.grantDigests[6].sha256 === value.grantDigests[18].sha256 && value.grantIds[6].grantId === value.grantIds[18].grantId, 'identity_mismatch');
  need(new Set(value.grantIds.map(g => g.grantId)).size === 19, 'identity_mismatch');
  return value;
}
export function validateCurrentCredential(device, binding, now = Date.now()) {
  need(device && device.id === binding.deviceId && device.platform === 'windows' && device.source === 'lan' && device.synthetic === false, 'identity_mismatch');
  const c = device.agentCertificate, r = c?.renewal;
  need(exact(c, ['source', 'expiresAt', 'checkedAt', 'renewal']) && c.source === 'guided-enrollment' && exact(r, ['status', 'enabled', 'identityGeneration', 'credentialGeneration', 'currentNotAfter', 'authorityExpiresAt']), 'invalid_response');
  need(r.enabled === true && ['healthy', 'due', 'retrying'].includes(r.status) && r.identityGeneration === binding.identityGeneration && r.credentialGeneration === binding.credentialGeneration && c.expiresAt === r.currentNotAfter, 'identity_mismatch');
  need([c.checkedAt, c.expiresAt, r.authorityExpiresAt].every(utcTime) && Date.parse(c.expiresAt) === binding.currentCertificateExpiresUnix * 1000 && Date.parse(r.authorityExpiresAt) === binding.authorityExpiresUnix * 1000 && Math.abs(Date.parse(c.checkedAt) - now) <= 30000 && Date.parse(c.expiresAt) > now, 'stale_capture');
  return true;
}
export function validateCurrentInventoryBindings(view, binding, minimum, now = Date.now()) {
  if (!view.snapshot || view.status !== 'fresh' || !freshCapture(view.snapshot.collectedAt, view.serverNow, minimum, now)) return false;
  const grants = new Map(binding.grantIds.map(g => [g.scope, g.grantId]));
  // All scopes are bound by the complete local receipt. Ordinary frames rotate
  // optional providers: verify every present current/retained grant without
  // demanding all scopes in one frame or refreshing retained source timestamps.
  for (const [field, scope] of Object.entries(INVENTORY_SCOPE_FIELDS)) {
    for (const value of [view[field], view.retainedContext?.[field]]) if (value) need(value.grantId === grants.get(scope), 'identity_mismatch');
  }
  return true;
}
export function validateRestartBinding(value, spec, endpointProof, minimum, now = Date.now()) {
  need(exact(value, ['schema', 'runId', 'planSHA256', 'endpointBindingSHA256', 'observedUnix', 'ownRestartObserved']), 'invalid_response');
  need(value.schema === 'tracebolt.windows-linux-native-parity.restart-binding.v1' && value.runId === spec.runId && value.planSHA256 === spec.planSHA256 && value.endpointBindingSHA256 === hash(canonicalJSON(endpointProof)) && value.ownRestartObserved === true, 'identity_mismatch');
  need(Number.isSafeInteger(value.observedUnix) && value.observedUnix * 1000 >= Math.floor(minimum / 1000) * 1000 && value.observedUnix * 1000 <= now && value.observedUnix < spec.expiresUnix, 'stale_capture');
  return value;
}
export async function observeCurrentProfile({ spec, report, validators, page, identity, endpointProof, began, guard, until, read, visible, marker, fail }) {
  const inventoryPath = `/api/devices/${identity.deviceId}/windows-inventory`, historyPath = `/api/devices/${identity.deviceId}/windows-event-history`, devicePath = `/api/devices/${identity.deviceId}`;
  const grants = new Map(endpointProof.grantIds.map(g => [g.scope, g.grantId]));
  const historyGrant = grants.get(CURRENT_SCOPES[20]);
  let sessionBinding = null, sessionExpires = null, floor = 0n, lastInventory = null;
  const checkIdentity = async () => {
    const response = await read('/api/windows/enrollment'); need(response.status === 200 && validators.validEnrollmentList(response.value, 'windows'), 'session_lost');
    const rows = response.value.items, row = rows[0];
    need(rows.length === 1 && row.state === 'activated' && row.invitationID === identity.invitationId && row.approval.deviceID === identity.deviceId && row.issuance.certificateHash === identity.certificateHash && row.binding.instanceID === spec.managerInstanceId && row.binding.issuerFingerprint === spec.issuerFingerprint && [row.claim.keyFingerprint, row.approval.keyFingerprint, row.intent.keyFingerprint].every(k => k === endpointProof.keyFingerprint), 'identity_mismatch');
    const device = await read(devicePath); need(device.status === 200, 'session_lost'); validateCurrentCredential(device.value, endpointProof); report.checks.stableIdentityObserved = true; report.checks.currentCredentialObserved = true;
  };
  const history = async () => {
    const response = await read(historyPath, 64 * 1024); need(response.status !== 401 && response.status !== 403, 'session_lost'); if (response.status !== 200) return null;
    const view = response.value; need(validators.validEventHistoryView(view, identity.deviceId, sessionExpires), 'invalid_response');
    need(!sessionBinding || sessionBinding === view.sessionBinding, 'session_lost'); sessionBinding ??= view.sessionBinding; sessionExpires ??= view.sessionExpiresAt;
    need(BigInt(view.expectedFloor) >= floor, 'request_conflict'); floor = BigInt(view.expectedFloor);
    need(Math.abs(Date.parse(view.serverNow) - Date.now()) <= 30000 && Date.parse(view.sessionExpiresAt) > Date.now(), 'stale_capture');
    if (view.capability) need(view.capability.grantId === historyGrant, 'identity_mismatch');
    if (view.request) need(view.request.description.certificateHash === endpointProof.certificateHash && view.request.description.grantId === historyGrant, 'identity_mismatch');
    report.observations.historyEndpointStatus = view.endpointStatus ?? '';
    return view;
  };
  const inventory = async minimum => {
    const response = await read(inventoryPath, 160 * 1024); need(response.status !== 401 && response.status !== 403, 'session_lost'); if (response.status !== 200) return null;
    const view = response.value; need(validators.validWindowsInventoryView(view, identity.deviceId), 'invalid_response'); need(!['revoked', 'not_configured'].includes(view.status), 'identity_mismatch');
    if (!validateCurrentInventoryBindings(view, endpointProof, minimum)) return null;
    recordCurrentOutcomes(report, view, minimum);
    if (lastInventory) need(view.sequence >= lastInventory.sequence && validators.eventHistoryNanos(view.snapshot.collectedAt) >= validators.eventHistoryNanos(lastInventory.snapshot.collectedAt), 'stale_capture');
    lastInventory = view; return view;
  };
  await checkIdentity();
  await page.goto(`${spec.operatorOrigin}/#/devices/${identity.deviceId}/logs`, { waitUntil: 'domcontentloaded' });
  let first = null, initialHistory = null;
  await until(async () => {
    const [inv, view] = await Promise.all([inventory(began), history()]); if (!inv || !view || !await visible(page.locator('.windows-event-history'))) return false;
    need(view.request === null && view.expectedFloor === '0' && view.contentStatus === 'unavailable', 'request_conflict');
    if (view.localStatus !== 'enabled' || !view.capability?.enabled || !freshCapture(view.capability.reportedAt, view.serverNow, began)) return false;
    need(await page.locator('.history-messages pre').count() === 0, 'request_conflict');
    if (!first) { first = inv; return false; }
    if (!advancingSample(first, inv, validators.eventHistoryNanos)) return false;
    initialHistory = view; return true;
  });
  report.checks.currentScopeBindingsObserved = true; report.observations.scopeCount = 21; report.observations.grantCount = 20; report.checks.historyDefaultIdleObserved = true;
  marker('PARITY_BROWSER_CURRENT_PROFILE_OBSERVED');
  // No local grant is created here. One bounded search and its selected-message
  // followup are separately approved in the plan and separately submitted by a
  // human through the real production controls.
  const panel = page.locator('.windows-event-history'), search = approvedHistorySearch(spec), phaseStarted = Date.now();
  await until(async () => Date.now() >= spec.historyQuery.endUnix * 1000);
  await checkIdentity();
  await panel.getByRole('button', { name: /^(Check status|Status prüfen)$/ }).click();
  initialHistory = await history(); need(initialHistory?.request === null && initialHistory.expectedFloor === '0' && initialHistory.localStatus === 'enabled' && initialHistory.capability?.enabled, 'request_conflict');
  await panel.getByLabel(/^(Search channel|Suchkanal)$/).selectOption('Application');
  await panel.getByLabel(/^(From · UTC|Von · UTC)$/).fill(search.start.slice(0, 16));
  await panel.getByLabel(/^(Until · UTC|Bis · UTC)$/).fill(search.end.slice(0, 16));
  await panel.getByLabel(/^(Search level|Suchstufe)$/).selectOption('');
  await panel.getByLabel(/^(Search event ID|Gesuchte Ereignis-ID)$/).fill(String(search.eventId));
  need(!await panel.getByRole('checkbox', { name: /^(Read this time window for my private session\.|Diesen Zeitraum für meine private Sitzung lesen\.)$/ }).isChecked(), 'request_conflict');
  let searchRecord = null, searchResult = null, selection = null, messageRecord = null, messageResult = null, searchCreates = 0, messageCreates = 0, responseTail = Promise.resolve(), allowMessages = false;
  const onResponse = response => {
    let url; try { url = new URL(response.url()); } catch { return; }
    if (url.origin !== spec.operatorOrigin || ![`${historyPath}/create`, `${historyPath}/messages`, `${historyPath}/query`].includes(url.pathname)) return;
    responseTail = responseTail.then(async () => {
      guard(); need(!url.search && response.request().method() === 'POST', 'invalid_response');
      const action = url.pathname.split('/').at(-1);
      if (action === 'create') { searchCreates++; need(searchCreates === 1 && !messageRecord, 'request_conflict'); }
      if (action === 'messages') { messageCreates++; need(messageCreates === 1 && allowMessages && searchResult && selection, 'request_conflict'); }
      need(response.status() === 200, 'request_conflict');
      const raw = await guardedResponseBody(response, (action === 'query' ? 512 : 64) * 1024, guard), value = JSON.parse(raw.toString('utf8'));
      const text = response.request().postData(); need(typeof text === 'string' && Buffer.byteLength(text) <= 8192, 'invalid_response'); const posted = JSON.parse(text);
      if (action === 'create' || action === 'messages') {
        need(validators.validEventHistoryView(value, identity.deviceId, sessionExpires) && value.sessionBinding === sessionBinding && value.request, 'invalid_response');
        const binding = { ...identity, grantId: historyGrant, floor: action === 'create' ? initialHistory.expectedFloor : searchRecord.description.identity.sequence, phaseStarted };
        if (action === 'create') { inspectHistorySearch(value.request.description, posted, binding, search); searchRecord = value.request; report.checks.historySearchRequestObserved = true; }
        else { inspectHistoryMessages(value.request.description, posted, binding, searchRecord, searchResult, selection); messageRecord = value.request; report.checks.historyMessagesRequestObserved = true; }
      } else {
        const record = messageRecord ?? searchRecord; need(record && exact(posted, ['identity']) && sameIdentity(posted.identity, record.description.identity), 'request_conflict');
        const current = await history();
        need(current?.request?.state === 'accepted' && sameIdentity(current.request.description.identity, record.description.identity) && equal(current.request.description, record.description) && validators.validEventHistoryResult(value, current.request, sessionExpires), 'invalid_response');
        need(Date.parse(value.expiresAt) > Date.now() && Date.parse(value.report.collectedAt) >= phaseStarted, 'stale_capture');
        if (!messageRecord) {
          if (searchResult) need(equal(value, searchResult), 'identity_mismatch');
          searchRecord = current.request; searchResult = value;
          report.checks.historySearchResultObserved = true; const o = report.observations; o.historySearchQuality = value.report.quality; o.historySearchRows = value.report.events.length; o.historySearchComplete = value.report.complete; o.historySearchTruncated = value.report.truncated;
          o.scopeOutcomes[CURRENT_SCOPES[20]] = value.report.events.length === 0 && value.report.quality === 'observed' ? 'legitimately_absent' : sourceOutcome(value.report);
        } else {
          need(value.report.events.length === 1 && sameEvent(value.report.events[0].event, selection), 'identity_mismatch');
          if (messageResult) need(equal(value, messageResult), 'identity_mismatch');
          messageResult = value; report.observations.historyMessageQuality = value.report.quality;
          if (value.report.quality === 'observed') { need(value.report.complete && !value.report.truncated && value.report.events[0].quality === 'observed' && hash(value.report.events[0].message) === spec.syntheticEvent.messageSHA256, 'identity_mismatch'); report.checks.historyMessageResultObserved = true; }
        }
      }
    }).catch(fail);
  };
  const waitResult = async messages => {
    await until(async () => {
      await responseTail; guard(); if (messages ? messageResult : searchResult) return true;
      const record = messages ? messageRecord : searchRecord; if (!record) return false;
      const view = await history(); if (!view) return false;
      need(!view.request || sameIdentity(view.request.description.identity, record.description.identity), 'request_conflict');
      if (['denied', 'reader_unavailable', 'budget_exhausted', 'result_lost', 'expired', 'canceled', 'disabled'].includes(view.endpointStatus) || ['result_lost', 'expired', 'canceled'].includes(view.contentStatus)) {
        report.observations[messages ? 'historyMessageQuality' : 'historySearchQuality'] = 'unavailable';
        report.observations.scopeOutcomes[CURRENT_SCOPES[20]] = view.endpointStatus === 'denied' ? 'denied' : view.endpointStatus === 'budget_exhausted' ? 'budget_exceeded' : 'unavailable'; return true;
      }
      return false;
    });
  };
  page.on('response', onResponse);
  try {
    marker('PARITY_BROWSER_HISTORY_SEARCH_HANDOFF');
    // Human ticks history consent and presses Search once. The observer has no
    // click/check path to either history or sensitive-message acknowledgements.
    await waitResult(false);
    if (searchResult) {
      const matches = searchResult.report.events.map(row => row.event).filter(event => event.channel === 'Application' && event.provider === spec.syntheticEvent.source && event.eventId === spec.syntheticEvent.eventId);
      need(matches.length <= 1, 'identity_mismatch');
      if (matches.length === 1) {
        selection = matches[0]; need(Date.parse(selection.timestamp) >= began && Date.parse(selection.timestamp) >= spec.historyQuery.startUnix * 1000 && Date.parse(selection.timestamp) < spec.historyQuery.endUnix * 1000, 'stale_capture');
        await until(async () => await visible(panel.getByLabel(/^(Filter captured headers|Erfasste Ereignisse filtern)$/)));
        await panel.getByLabel(/^(Filter captured headers|Erfasste Ereignisse filtern)$/).fill(spec.syntheticEvent.source);
        const selected = panel.getByRole('checkbox', { name: new RegExp(`^(Select|Auswählen) Application ${selection.recordId}$`) });
        await selected.check();
        const row = panel.locator('tbody tr').filter({ has: page.getByRole('checkbox', { name: new RegExp(`^(Select|Auswählen) Application ${selection.recordId}$`) }) }); need(await row.count() === 1, 'ui_unavailable');
        const cells = await row.locator('td').allTextContents(); need(cells.length === 6 && cells[2] === selection.provider && cells[3] === String(selection.eventId) && cells[4] === String(selection.level) && cells[5] === selection.recordId, 'identity_mismatch');
        report.checks.syntheticHistoryHeaderObserved = true;
        need(!await panel.locator('.history-message-action').getByRole('checkbox').isChecked(), 'request_conflict');
        allowMessages = true; marker('PARITY_BROWSER_HISTORY_MESSAGES_HANDOFF');
        // Human independently acknowledges sensitive content and presses Read 1
        // messages. Selecting a row itself never creates a message request.
        await waitResult(true);
        if (report.checks.historyMessageResultObserved) {
          await until(async () => await panel.locator('.history-messages details').count() === 1);
          await panel.locator('.history-messages summary').click();
          const rendered = panel.locator('.history-messages pre'); await until(async () => await visible(rendered));
          need(await rendered.count() === 1 && hash(await rendered.textContent() ?? '') === spec.syntheticEvent.messageSHA256 && await rendered.locator('*').count() === 0, 'identity_mismatch'); report.checks.historyMessageRendered = true;
        }
      }
    }
    await checkIdentity();
    // Navigating invokes production cancellation/discard. Check the exact final
    // owned request; do not claim local DOM disappearance proves cache erasure.
    const owned = messageRecord ?? searchRecord;
    await page.locator('#tab-inventory').click();
    await until(async () => {
      const view = await history(); if (!view) return false;
      need(!view.request || !owned || sameIdentity(view.request.description.identity, owned.description.identity), 'request_conflict');
      return await page.locator('.history-messages pre').count() === 0 && view.contentStatus !== 'available' && (!owned || view.request?.state === 'canceled' || view.request?.state === 'expired');
    });
    report.checks.privateHistoryDiscardObserved = true;
  } finally { page.off('response', onResponse); searchResult = null; messageResult = null; selection = null; }
  const restartBegan = Date.now(), beforeRestart = lastInventory; marker('PARITY_BROWSER_OWN_RESTART_READY');
  const restart = await until(async () => {
    const value = await readPrivateEvidence(join(spec.workspace, `${spec.runId}-windows-restart.json`)); if (!value) return false;
    return validateRestartBinding(value, spec, endpointProof, restartBegan);
  });
  report.checks.ownRestartBindingObserved = true;
  let postRestartFirst = null;
  await until(async () => {
    const inv = await inventory(restart.observedUnix * 1000 + 1); if (!inv || Date.parse(inv.receivedAt) <= restart.observedUnix * 1000 || !advancingSample(beforeRestart, inv, validators.eventHistoryNanos)) return false;
    if (!postRestartFirst) { postRestartFirst = inv; return false; }
    return advancingSample(postRestartFirst, inv, validators.eventHistoryNanos);
  });
  await checkIdentity(); report.checks.postRestartInventoryObserved = true;
}
