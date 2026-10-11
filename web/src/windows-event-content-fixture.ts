import { EVENT_CONTENT_WARNING } from './windows-event-content-types';
import type { EventContentRecord, EventContentResult, EventContentView, SelectedEvent } from './windows-event-content-types';
import { windowsEventsFixture } from './windows-events-fixture';
import { windowsDeviceId, windowsNow } from './windows-inventory-fixture';
export const eventContentSessionExpires = '2026-10-08T12:00:00Z';
/** Invented, memory-only UI fixtures. No native log or host authority. */
export function eventContentView(now = windowsNow): EventContentView {
    const headers = windowsEventsFixture();
    return { schemaVersion: 'tracebolt.windows-event-content-view.v1', deviceId: windowsDeviceId, serverNow: now, sessionBinding: '1'.repeat(64), sessionExpiresAt: eventContentSessionExpires, configured: true, expectedFloor: '0', localStatus: 'enabled', contentStatus: 'unavailable', capability: { enabled: true, grantId: '2'.repeat(32), reportedAt: '2026-10-07T12:00:00Z', expiresAt: '2026-10-07T12:05:00Z' }, headers: { generationId: headers.generationId, snapshotDigest: 'sha256:' + '3'.repeat(64), collectedAt: headers.collectedAt, expiresAt: '2026-10-08T12:00:02Z' }, request: null };
}
export function eventContentRecord(events: SelectedEvent[], view = eventContentView()): EventContentRecord {
    return { description: { schemaVersion: 'tracebolt.windows-event-content-request.v1', identity: { id: 'winevent_' + '4'.repeat(32), sequence: String(BigInt(view.expectedFloor) + 1n), queryDigest: 'sha256:' + '5'.repeat(64) }, deviceId: view.deviceId, certificateHash: '6'.repeat(64), grantId: view.capability!.grantId, headerGenerationId: view.headers!.generationId, headerCollectedAt: view.headers!.collectedAt, headerSnapshotDigest: view.headers!.snapshotDigest, query: { events: events.map(e => ({ ...e })) }, budgets: { maxSelectedEvents: 16, maxMessageBytes: 16384, maxTotalMessageBytes: 65536, timeoutMs: 5000 }, createdAt: view.serverNow, expiresAt: new Date(Date.parse(view.serverNow) + 900000).toISOString() }, state: 'pending', policyDigest: '', claimedAt: null, receipt: null, canceledAt: null, expiredAt: null };
}
export function eventContentAccepted(record: EventContentRecord): EventContentRecord {
    return { ...record, state: 'accepted', policyDigest: 'sha256:' + '7'.repeat(64), claimedAt: record.description.createdAt, receipt: { identity: record.description.identity, policyDigest: 'sha256:' + '7'.repeat(64), resultDigest: 'sha256:' + '8'.repeat(64), acceptedAt: record.description.createdAt, expiresAt: record.description.expiresAt } };
}
export function eventContentResult(record: EventContentRecord, messages?: string[]): EventContentResult {
    return { identity: record.description.identity, receipt: record.receipt!, expiresAt: record.description.expiresAt, report: { source: 'windows-event-log-message-content', warning: EVENT_CONTENT_WARNING, quality: 'observed', collectedAt: record.description.createdAt, complete: true, truncated: false, events: record.description.query.events.map((event, i) => ({ event, message: messages?.[i] ?? `Invented message ${i + 1}\n<img src=x onerror=alert(1)> https://invalid.example/secret\n  indentation stays`, quality: 'observed', complete: true, truncated: false })) } };
}
export function eventContentSession(now = windowsNow, insecure = false) { return { mode: 'lan', transport: insecure ? 'http' : 'https', insecureTestMode: insecure, transportWarning: insecure ? 'unencrypted_lan_test' : null, authenticationRequired: true, authenticated: true, csrfToken: 'synthetic-csrf', serverNow: now, expiresAt: eventContentSessionExpires, expiresInSeconds: 80000, loginMode: 'shared', actorId: null, capabilities: ['read'] }; }
