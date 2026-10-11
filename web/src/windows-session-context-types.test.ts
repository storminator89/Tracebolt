import goFixture from '../../internal/windowssessions/testdata/snapshot.json';
import { describe, expect, it } from 'vitest';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import { windowsSessionContext, windowsSessionContextView } from './windows-session-context-fixture';
import { validWindowsSessionContext, WINDOWS_SESSION_STATES, type WindowsSessionContext } from './windows-session-context-types';
import { validWindowsInventoryView } from './windows-inventory-types';
import { windowsSecurityPosture } from './windows-security-posture-fixture';
import { windowsPatchContext } from './windows-patch-context-fixture';
import { windowsUpdates } from './windows-updates-fixture';
import { windowsAdapterContext } from './windows-adapter-context-fixture';
import { windowsNetwork } from './windows-network-fixture';
import { windowsVolumes } from './windows-volumes-fixture';
import { windowsEventsFixture } from './windows-events-fixture';
import { windowsServiceStartup } from './windows-service-startup-fixture';
const valid = (v: unknown) => validWindowsSessionContext(v, windowsView().snapshot!, windowsNow);
const observed = () => { const v = windowsSessionContext(); v.sessions.rows.pop(); Object.assign(v.sessions, { quality: 'observed', reason: '', observedCount: 2, retainedCount: 2 }); return v; };

describe('Strict private Windows session context', () => {
    it('accepts the canonical Go snapshot and exact original capture binding', () => {
        const snapshot = { ...windowsView().snapshot!, generationId: goFixture.generationId, collectedAt: goFixture.collectedAt }, serverNow = new Date(Date.parse(goFixture.collectedAt) + 1000).toISOString();
        expect(validWindowsSessionContext(goFixture, snapshot, serverNow)).toBe(true);
        expect(validWindowsInventoryView({ ...windowsView(), snapshot, serverNow, receivedAt: serverNow, sessionContext: goFixture }, windowsDeviceId)).toBe(true);
        expect(validWindowsSessionContext(goFixture, { ...snapshot, collectedAt: new Date(Date.parse(snapshot.collectedAt) + 1).toISOString() }, serverNow)).toBe(false);
    });
    it('preserves absent old scope views and permits independent sources together', () => {
        expect(validWindowsInventoryView(windowsView(), windowsDeviceId)).toBe(true);
        expect(validWindowsInventoryView({ ...windowsSessionContextView(), securityPosture: windowsSecurityPosture(), patchContext: windowsPatchContext(), updates: windowsUpdates(), adapterContext: windowsAdapterContext() }, windowsDeviceId)).toBe(true);
    });
    it('accepts observed-empty sessions and unjoined membership without inventing labels', () => {
        const v = windowsSessionContext(); Object.assign(v.sessions, { quality: 'observed', reason: '', observedCount: 0, retainedCount: 0, rows: [] }); v.join = { quality: 'observed', reason: '', status: 'unjoined', name: null }; expect(valid(v)).toBe(true);
    });
    it.each(['denied', 'unavailable'] as const)('accepts independent %s sources with unknown counts', quality => {
        const reason = quality === 'denied' ? 'windows_session_context_access_denied' : 'windows_session_context_unavailable';
        const v = windowsSessionContext(); v.sessions = { quality, reason, observedCount: null, retainedCount: 0, truncatedCount: null, rows: [] }; expect(valid(v)).toBe(true);
        v.join = { quality, reason, status: 'unknown', name: null }; expect(valid(v)).toBe(true);
        v.sessions = windowsSessionContext().sessions; expect(valid(v)).toBe(true);
    });
    it.each(WINDOWS_SESSION_STATES)('accepts the fixed %s state', state => { const v = windowsSessionContext(); v.sessions.rows[0].state = state; expect(valid(v)).toBe(true); });
    it('accepts partial known membership with unknown name and exact omitted count', () => {
        const v = windowsSessionContext(); Object.assign(v.sessions, { observedCount: 4096, truncatedCount: 4093 }); v.join = { quality: 'partial', reason: 'windows_session_context_invalid_metadata', status: 'domain', name: null }; expect(valid(v)).toBe(true);
        Object.assign(v.sessions, { retainedCount: 0, truncatedCount: 4096, rows: [] }); expect(valid(v)).toBe(true);
    });
    it('accepts bounded Unicode labels measured in UTF-16 units and uint32 session IDs', () => {
        const v = windowsSessionContext(); v.sessions.rows[1].userName = '😀'.repeat(32); v.sessions.rows[1].domainName = 'é'.repeat(64); v.join.name = '😀'.repeat(128); v.sessions.rows[2].sessionId = 4294967295; expect(valid(v)).toBe(true);
    });
    const mutations: [string, (v: WindowsSessionContext) => void][] = [
        ['extra root field', v => Object.assign(v, { raw: 'private' })], ['extra session field', v => Object.assign(v.sessions, { accounts: [] })], ['extra row field', v => Object.assign(v.sessions.rows[1], { clientName: 'private' })], ['extra membership field', v => Object.assign(v.join, { directory: 'private' })],
        ['wrong schema', v => Object.assign(v, { schemaVersion: 'tracebolt.windows-security-posture.v1' })], ['wrong scope', v => Object.assign(v, { scope: 'windows-security-posture-v1' })], ['uppercase grant', v => { v.grantId = 'F'.repeat(32); }], ['short grant', v => { v.grantId = 'a'; }], ['different generation', v => { v.generationId = `sample_${'8'.repeat(32)}`; }], ['different nanosecond capture', v => { v.collectedAt = '2026-10-07T12:00:00.000000001Z'; }],
        ['raw error', v => Object.assign(v.sessions, { reason: 'private exception' })], ['unknown quality', v => Object.assign(v.sessions, { quality: 'complete' })], ['partial without reason', v => { v.sessions.reason = ''; }], ['observed with unknown row', v => Object.assign(v.sessions, { quality: 'observed', reason: '' })], ['partial with no unknown or omitted rows', v => { v.sessions = observed().sessions; Object.assign(v.sessions, { quality: 'partial', reason: 'windows_session_context_partial_result' }); }],
        ['negative ID', v => { v.sessions.rows[0].sessionId = -1; }], ['negative-zero ID', v => { v.sessions.rows[0].sessionId = -0; }], ['fractional ID', v => { v.sessions.rows[0].sessionId = .5; }], ['uint32 overflow', v => { v.sessions.rows[2].sessionId = 4294967296; }], ['duplicate ID', v => { v.sessions.rows[2].sessionId = 1; }], ['unsorted IDs', v => { v.sessions.rows.reverse(); }],
        ['unknown session state', v => Object.assign(v.sessions.rows[1], { state: 'online' })], ['unknown protocol', v => Object.assign(v.sessions.rows[1], { protocol: 'ssh' })], ['unknown field quality', v => Object.assign(v.sessions.rows[1], { userQuality: 'hidden' })], ['observed null field', v => { v.sessions.rows[1].userName = null; }], ['observed empty string', v => { v.sessions.rows[1].userName = ''; }], ['denied supplied name', v => { v.sessions.rows[2].userName = 'private'; }], ['empty supplied domain', v => { v.sessions.rows[0].domainName = 'private'; }], ['unavailable supplied domain', v => { v.sessions.rows[2].domainName = 'private'; }],
        ['long user label', v => { v.sessions.rows[1].userName = 'a'.repeat(65); }], ['long domain label', v => { v.sessions.rows[1].domainName = 'a'.repeat(65); }], ['UTF-16 overflow', v => { v.sessions.rows[1].userName = '😀'.repeat(33); }], ['control character', v => { v.sessions.rows[1].userName = 'fixture\nuser'; }], ['C1 control', v => { v.sessions.rows[1].userName = 'fixture\u0085user'; }], ['replacement character', v => { v.sessions.rows[1].userName = 'fixture\ufffduser'; }], ['unpaired surrogate', v => { v.sessions.rows[1].userName = 'fixture\ud800'; }],
        ['unknown observed count', v => { v.sessions.observedCount = null; }], ['unknown omitted count', v => { v.sessions.truncatedCount = null; }], ['count overflow', v => Object.assign(v.sessions, { observedCount: 4097, truncatedCount: 4094 })], ['fractional count', v => { v.sessions.observedCount = 3.5; }], ['negative-zero count', v => { v.sessions.truncatedCount = -0; }], ['retained mismatch', v => { v.sessions.retainedCount = 2; }], ['omitted mismatch', v => { v.sessions.truncatedCount = 1; }], ['retained more than observed', v => { v.sessions.observedCount = 2; }], ['null rows', v => Object.assign(v.sessions, { rows: null })], ['33 rows', v => { v.sessions.rows = Array.from({ length: 33 }, (_, sessionId) => ({ ...v.sessions.rows[1], sessionId })); Object.assign(v.sessions, { observedCount: 33, retainedCount: 33, quality: 'observed', reason: '' }); }],
        ['denied with rows', v => Object.assign(v.sessions, { quality: 'denied', reason: 'windows_session_context_access_denied' })], ['denied claims zero observed', v => Object.assign(v.sessions, { quality: 'denied', reason: 'windows_session_context_access_denied', observedCount: 0, retainedCount: 0, truncatedCount: null, rows: [] })], ['unavailable claims zero omitted', v => Object.assign(v.sessions, { quality: 'unavailable', reason: 'windows_session_context_unavailable', observedCount: null, retainedCount: 0, truncatedCount: 0, rows: [] })], ['unavailable with denied reason', v => Object.assign(v.sessions, { quality: 'unavailable', reason: 'windows_session_context_access_denied', observedCount: null, retainedCount: 0, truncatedCount: null, rows: [] })],
        ['unjoined with label', v => { v.join.status = 'unjoined'; }], ['observed unknown membership', v => { v.join.status = 'unknown'; }], ['unknown membership status', v => Object.assign(v.join, { status: 'azure-ad' })], ['observed null membership', v => { v.join.name = null; }], ['empty membership label', v => { v.join.name = ''; }], ['long membership label', v => { v.join.name = 'x'.repeat(257); }], ['invalid membership label', v => { v.join.name = 'x\u0000'; }], ['observed membership reason', v => { v.join.reason = 'windows_session_context_partial_result'; }], ['partial membership known label', v => Object.assign(v.join, { quality: 'partial', reason: 'windows_session_context_partial_result' })], ['partial unknown membership', v => Object.assign(v.join, { quality: 'partial', reason: 'windows_session_context_partial_result', status: 'unknown', name: null })], ['partial unjoined membership', v => Object.assign(v.join, { quality: 'partial', reason: 'windows_session_context_partial_result', status: 'unjoined', name: null })], ['denied known membership', v => Object.assign(v.join, { quality: 'denied', reason: 'windows_session_context_access_denied' })], ['denied membership wrong reason', v => Object.assign(v.join, { quality: 'denied', reason: 'windows_session_context_unavailable', status: 'unknown', name: null })], ['unavailable membership empty reason', v => Object.assign(v.join, { quality: 'unavailable', reason: '', status: 'unknown', name: null })],
    ];
    it.each(mutations)('rejects %s', (_label, mutate) => { const v = windowsSessionContext(); mutate(v); expect(valid(v)).toBe(false); });
    it('enforces the Go HTML-escaped 24 KiB budget as well as row and field bounds', () => {
        const v = observed(); v.sessions.rows = Array.from({ length: 32 }, (_, sessionId) => ({ ...v.sessions.rows[1], sessionId, userName: '<'.repeat(64), domainName: '&'.repeat(64) })); Object.assign(v.sessions, { observedCount: 32, retainedCount: 32 }); expect(valid(v)).toBe(false);
        v.sessions.rows.forEach(row => { row.userName = 'a'.repeat(64); row.domainName = 'b'.repeat(64); }); expect(valid(v)).toBe(true);
    });
    it('requires calendar-valid UTC, exact capture, 30-second skew and less than 24 hours', () => {
        const v = windowsSessionContext(), snapshot = windowsView().snapshot!;
        expect(validWindowsSessionContext(v, snapshot, '2026-10-07T11:59:30Z')).toBe(true);
        expect(validWindowsSessionContext(v, snapshot, '2026-10-07T11:59:29.999999999Z')).toBe(false);
        expect(validWindowsSessionContext(v, snapshot, '2026-10-08T11:59:59.999999999Z')).toBe(true);
        expect(validWindowsSessionContext(v, snapshot, '2026-10-08T12:00:00Z')).toBe(false);
        for (const collectedAt of ['2026-02-30T12:00:00Z', '1969-12-31T23:59:59Z', '2026-10-07T12:00:00+00:00']) expect(validWindowsSessionContext({ ...v, collectedAt }, { ...snapshot, collectedAt }, collectedAt)).toBe(false);
    });
    it('rejects sibling grant collisions, null optional data and retained data without authority', () => {
        const v = { ...windowsSessionContextView(), securityPosture: windowsSecurityPosture(), patchContext: windowsPatchContext(), updates: windowsUpdates(), adapterContext: windowsAdapterContext(), network: windowsNetwork(), volumes: windowsVolumes(), events: windowsEventsFixture(), serviceStartup: windowsServiceStartup(windowsView().snapshot!), processMetrics: { schemaVersion: 'tracebolt.windows-process-metrics.v1', scope: 'windows-process-metrics-v1', grantId: '7'.repeat(32), generationId: windowsView().snapshot!.generationId, collectedAt: windowsView().snapshot!.collectedAt, observedCount: 1, truncated: false, rows: [{ pid: 44, cpuPercent: null, cpuQuality: 'first-sample', memoryBytes: '42', memoryQuality: 'observed' }] } };
        expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(true);
        for (const sibling of [v.securityPosture, v.patchContext, v.updates, v.adapterContext, v.network, v.volumes, v.events, v.serviceStartup, v.processMetrics]) { const fresh = structuredClone(v); fresh.sessionContext.grantId = sibling.grantId; expect(validWindowsInventoryView(fresh, windowsDeviceId)).toBe(false); }
        expect(validWindowsInventoryView({ ...v, sessionContext: null }, windowsDeviceId)).toBe(false);
        for (const status of ['revoked', 'unavailable', 'awaiting', 'not_configured']) expect(validWindowsInventoryView({ ...v, status, snapshot: null }, windowsDeviceId)).toBe(false);
    });
});
