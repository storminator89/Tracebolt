import { EVENT_HISTORY_WARNING, eventHistoryTime } from './windows-event-history-types';
import type { EventHistoryRecord, EventHistoryResult, EventHistoryView, HistorySearch, SelectedEvent } from './windows-event-history-types';
import { windowsDeviceId } from './windows-inventory-fixture';
// Shift whole seconds without rounding Go RFC3339Nano timestamps to milliseconds.
// These fixtures use the same exact original-expiry checks as production responses.
function historyTimeAfter(value: string, seconds: number): string {
    if (!eventHistoryTime(value) || !Number.isSafeInteger(seconds)) throw new Error('Invalid synthetic history time');
    const shifted = new Date(Date.parse(value.slice(0, 19) + 'Z') + seconds * 1000).toISOString();
    return shifted.slice(0, 19) + (value.includes('.') ? value.slice(19) : '.000Z');
}
/** Invented metadata/text for source and hosted-browser fixtures only. */
export function historyView(now = '2026-10-07T12:00:00Z', expires = '2026-10-07T13:00:00Z'): EventHistoryView {
    return { schemaVersion: 'tracebolt.windows-event-history-view.v1', deviceId: windowsDeviceId, serverNow: now, sessionBinding: '1'.repeat(64), sessionExpiresAt: expires, configured: true, expectedFloor: '0', localStatus: 'enabled', contentStatus: 'unavailable', capability: { enabled: true, grantId: '2'.repeat(32), reportedAt: now, expiresAt: historyTimeAfter(now, 300) }, request: null };
}
export function historyRecord(view = historyView(), search?: HistorySearch, previous?: EventHistoryRecord, selected: SelectedEvent[] = []): EventHistoryRecord {
    const query = search ?? { channel: 'Application', start: historyTimeAfter(view.serverNow, -86400), end: view.serverNow };
    return { description: { schemaVersion: 'tracebolt.windows-event-history-request.v1', identity: { id: 'winhistory_' + (previous ? '9' : '4').repeat(32), sequence: String(BigInt(view.expectedFloor) + 1n), queryDigest: 'sha256:' + (previous ? 'a' : '5').repeat(64) }, deviceId: view.deviceId, certificateHash: '6'.repeat(64), grantId: view.capability!.grantId, headerGenerationId: previous?.description.headerGenerationId ?? 'sample_' + '7'.repeat(32), headerCollectedAt: previous?.description.createdAt ?? view.serverNow, headerSnapshotDigest: 'sha256:' + '3'.repeat(64), query: previous ? { events: selected.map(e => ({ ...e })) } : { events: [], search: query }, ...(previous ? { sourceSearch: previous.description.query.search, searchReceipt: previous.receipt! } : {}), budgets: { maxSearchEvents: 100, maxSearchBytes: 262144, maxRangeHours: 168, maxLookbackHours: 720, maxSelectedEvents: 16, maxMessageBytes: 16384, maxTotalMessageBytes: 65536, timeoutMs: 5000 }, createdAt: previous?.description.createdAt ?? view.serverNow, expiresAt: previous?.description.expiresAt ?? historyTimeAfter(view.serverNow, 900) }, state: 'pending', policyDigest: '', claimedAt: null, receipt: null, canceledAt: null, expiredAt: null };
}
export function historyAccepted(record: EventHistoryRecord, at = record.description.createdAt): EventHistoryRecord {
    return { ...record, state: 'accepted', policyDigest: 'sha256:' + '8'.repeat(64), claimedAt: at, receipt: { identity: record.description.identity, policyDigest: 'sha256:' + '8'.repeat(64), resultDigest: 'sha256:' + (record.description.query.search ? 'b' : 'c').repeat(64), acceptedAt: at, expiresAt: record.description.expiresAt } };
}
export function historyResult(record: EventHistoryRecord, count = 23): EventHistoryResult {
    const search = record.description.query.search;
    const events: SelectedEvent[] = search ? Array.from({ length: count }, (_, i) => ({ channel: search.channel, recordId: String(18446744073709551615n - BigInt(i)), eventId: search.eventId ?? 42 + i, level: search.level ?? 2, provider: `Synthetic Provider ${i + 1}`, timestamp: new Date(Date.parse(search.end) - (i + 1) * 1000).toISOString() })) : record.description.query.events;
    return { identity: record.description.identity, receipt: record.receipt!, expiresAt: record.description.expiresAt, report: { source: 'windows-event-log-bounded-history', warning: EVENT_HISTORY_WARNING, quality: 'observed', collectedAt: record.claimedAt!, complete: true, truncated: false, ...(search ? { search } : {}), events: events.map(event => ({ event, message: search ? '' : 'Invented historical event message\n<img src=x onerror=alert(1)>\n  Original whitespace stays.', quality: 'observed', complete: true, truncated: false })) } };
}
