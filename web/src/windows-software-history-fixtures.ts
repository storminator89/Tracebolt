import type { FullSoftwareRow } from './windows-full-software-types';
import type { SoftwareHistoryChange, SoftwareHistoryPage, SoftwareHistoryQuery } from './windows-software-history-types';

/** Invented transport vectors, not a live store or native Windows acceptance. */
export const softwareHistoryDevice = `agent_${'a'.repeat(32)}`;
export const softwareHistoryNow = '2026-10-11T06:00:10Z';
export const softwareHistoryQuery: SoftwareHistoryQuery = { search: '', sort: 'observed-desc', limit: 100, cursor: '' };
const row = (i: number): FullSoftwareRow => ({ registrationId: i.toString(16).padStart(64, '0'), registryView: i % 2 ? '32' : '64', name: `Fixture Software ${String(i).padStart(4, '0')}`, nameQuality: 'observed', version: '1.0', versionQuality: 'observed', publisher: 'Invented publisher', publisherQuality: 'observed' });
export function softwareHistoryRows(count = 205): SoftwareHistoryChange[] {
    return Array.from({ length: count }, (_, i) => {
        const before = row(i + 1), after = { ...before, version: '2.0' };
        const change: SoftwareHistoryChange = { id: (i + 1).toString(16).padStart(64, '0'), kind: 'metadata_changed', registrationId: before.registrationId, registryView: before.registryView, beforeObservedAt: '2026-10-11T05:00:01Z', afterObservedAt: '2026-10-11T06:00:01Z', expiresAt: '2026-10-18T05:00:00Z', before, after, changedFields: ['version'] };
        if (i === 0) { change.kind = 'registration_added'; change.before = null; change.changedFields = []; }
        if (i === 1) { change.kind = 'registration_removed'; change.after = null; change.changedFields = []; }
        if (i === 3) { before.version = null; before.versionQuality = 'unavailable'; after.name = 'Renamed registration'; change.changedFields = ['name']; }
        if (i === 4) { before.name = after.name = ''; before.publisher = after.publisher = null; before.publisherQuality = after.publisherQuality = 'unavailable'; }
        if (i === 204) after.publisher = '<img src=x onerror=alert(1)> [.*] ÄÖÜ 東京';
        if (i === 204) change.changedFields.push('publisher');
        return change;
    });
}
export function softwareHistoryPage(query: SoftwareHistoryQuery = softwareHistoryQuery, rows = softwareHistoryRows(), offset = 0): SoftwareHistoryPage {
    const matching = rows.filter(change => `${change.kind} ${change.registryView} ${change.registrationId} ${[change.before, change.after].flatMap(value => value ? [value.name, value.version, value.publisher] : []).join(' ')}`.toLocaleLowerCase('en').includes(query.search.toLocaleLowerCase('en')));
    const selected = matching.slice(offset, offset + query.limit);
    return { schemaVersion: 'tracebolt.windows-software-history-page.v1', deviceId: softwareHistoryDevice, serverNow: softwareHistoryNow, status: 'ready', authorityUntil: '2026-10-12T05:00:00Z', grantId: 'a'.repeat(32), grantRevision: 1, historyDigest: 'b'.repeat(64), comparison: { status: 'compared', reason: '', beforeObservedAt: '2026-10-11T05:00:01Z', afterObservedAt: '2026-10-11T06:00:01Z', expiresAt: '2026-10-18T05:00:00Z', observedChanges: rows.length }, latestAttempt: { sequence: 2, attemptedAt: '2026-10-11T06:00:00Z', status: 'complete', reason: '' }, gapCount: 0, omittedChanges: 0, expiredChanges: 0, retainedCount: rows.length, search: query.search, limit: query.limit, offset, matchingCount: matching.length, rows: selected, nextCursor: offset + selected.length < matching.length ? `history_${offset + selected.length}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` : '', cursorExpiresAt: '2026-10-11T06:15:10Z' };
}
export function softwareHistoryState(status: SoftwareHistoryPage['status'], query = softwareHistoryQuery): SoftwareHistoryPage {
    const p = softwareHistoryPage(query, []);
    return { ...p, status, authorityUntil: status === 'not_configured' ? null : p.authorityUntil, grantId: status === 'not_configured' ? null : p.grantId, grantRevision: status === 'not_configured' ? null : p.grantRevision, historyDigest: '', comparison: null, latestAttempt: null, cursorExpiresAt: null };
}
export function softwareHistoryScenario(name: string, query = softwareHistoryQuery, offset = 0): SoftwareHistoryPage {
    if (['not_configured', 'disabled', 'awaiting'].includes(name)) return softwareHistoryState(name as SoftwareHistoryPage['status'], query);
    const p = softwareHistoryPage(query, name === 'baseline' || name === 'expired-counts' ? [] : softwareHistoryRows(), offset);
    if (name === 'baseline') p.comparison = { status: 'baseline', reason: 'no_baseline', beforeObservedAt: null, afterObservedAt: '2026-10-11T06:00:01Z', expiresAt: '2026-10-18T06:00:00Z', observedChanges: 0 };
    if (['source_gap', 'incomparable', 'resource_limit'].includes(name)) { p.comparison = { ...p.comparison!, status: 'gap', reason: name as 'source_gap', observedChanges: name === 'resource_limit' ? 1500 : 0 }; p.gapCount = 1; p.omittedChanges = name === 'resource_limit' ? 1500 : 0; p.expiredChanges = 3; p.latestAttempt = { sequence: 3, attemptedAt: '2026-10-11T06:00:02Z', status: 'source_failed', reason: name === 'resource_limit' ? 'resource_limit' : 'access_denied' }; }
    if (name === 'expired-counts') { p.comparison = null; p.expiredChanges = 205; p.gapCount = 2; }
    return p;
}
