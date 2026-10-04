import { JOURNAL_WARNING } from './journal-types';
import type { JournalIdentity, JournalPage, JournalView } from './journal-types';
export const journalDevice = `agent_${'a'.repeat(32)}`;
export const journalNow = '2026-10-04T12:00:00Z';
export const journalExpiry = '2026-10-04T12:15:00Z';
export const journalSessionExpiry = '2026-10-04T13:00:00Z';
export const journalIdentity: JournalIdentity = { id: `journal_${'b'.repeat(32)}`, sequence: '1', queryDigest: `sha256:${'c'.repeat(64)}` };
export const journalSession = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'synthetic-only', serverNow: journalNow, expiresAt: journalSessionExpiry, expiresInSeconds: 3600 };
export function journalView(state: 'awaiting' | 'pending' | 'claimed' | 'accepted' | 'expired' | 'canceled' = 'accepted'): JournalView {
    return { schemaVersion: 'tracebolt.journal-view.v1', deviceId: journalDevice, serverNow: state === 'expired' ? journalExpiry : journalNow, configured: true, expectedFloor: state === 'awaiting' ? '0' : '1', localStatus: 'unknown', contentStatus: state === 'accepted' ? 'available' : 'unavailable', request: state === 'awaiting' ? null : {
        description: { schemaVersion: 'tracebolt.journal-request.v1', identity: { ...journalIdentity }, deviceId: journalDevice, certificateHash: 'd'.repeat(64), query: { unit: 'fixture.service', start: '2026-10-04T11:45:00Z', end: journalNow, maxPriority: 6 }, budgets: { maxRows: 500, maxSnapshotBytes: 524288, maxMessageBytes: 4096, maxRawBytes: 8388608, maxLineBytes: 65536, maxScannedRows: 4096, timeoutMs: 4000 }, createdAt: journalNow, expiresAt: journalExpiry },
        state, contentStatus: state === 'accepted' ? 'available' : 'unavailable', receipt: state === 'accepted' ? { identity: { ...journalIdentity }, policyDigest: `sha256:${'e'.repeat(64)}`, resultDigest: `sha256:${'f'.repeat(64)}`, acceptedAt: journalNow, expiresAt: journalExpiry } : null,
    } };
}
export function journalPage(messages = ['Synthetic fixture message'], search = '', offset = 0, matchedRows = messages.length): JournalPage {
    const view = journalView(), rows = messages.map(message => ({ timestamp: '2026-10-04T11:59:00Z', unit: 'fixture.service', priority: 6, message }));
    return { schemaVersion: 'tracebolt.journal-page.v1', deviceId: journalDevice, serverNow: journalNow, expiresAt: journalExpiry, identity: { ...journalIdentity }, snapshotDigest: view.request!.receipt!.resultDigest, scope: 'agent-visible-system-journal-service-and-manager', query: view.request!.description.query, observedAt: journalNow, coverage: 'complete', reason: 'none', rows, observedCount: matchedRows, countExact: true, redactionApplied: false, redactionWarning: JOURNAL_WARNING, totalCapturedRows: matchedRows, matchedRows, search, searchScope: 'captured_snapshot_only', offset, nextOffset: offset + rows.length < matchedRows ? offset + rows.length : null };
}
