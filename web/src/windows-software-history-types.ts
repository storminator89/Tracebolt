import { inventoryAge } from './complete-packages-types';
import { fullSoftwareReasons, validFullSoftwareCursor, validFullSoftwareRow, validFullSoftwareSearch } from './windows-full-software-types';
import type { FullSoftwareAttempt, FullSoftwareRow } from './windows-full-software-types';
import { validWindowsDeviceId } from './windows-inventory-types';

export const SOFTWARE_HISTORY_PAGE_BYTES = 256 * 1024;
export const SOFTWARE_HISTORY_PAGE_ROWS = 100;
export interface SoftwareHistoryQuery { search: string; sort: 'observed-desc'; limit: number; cursor: string }
export interface SoftwareHistoryChange {
    id: string; kind: 'registration_added' | 'registration_removed' | 'metadata_changed'; registrationId: string; registryView: '32' | '64';
    beforeObservedAt: string; afterObservedAt: string; expiresAt: string; before: FullSoftwareRow | null; after: FullSoftwareRow | null; changedFields: ('name' | 'version' | 'publisher')[];
}
export interface SoftwareHistoryComparison {
    status: 'baseline' | 'compared' | 'gap'; reason: '' | 'no_baseline' | 'source_gap' | 'incomparable' | 'resource_limit';
    beforeObservedAt: string | null; afterObservedAt: string; expiresAt: string; observedChanges: number;
}
export interface SoftwareHistoryPage {
    schemaVersion: 'tracebolt.windows-software-history-page.v1'; deviceId: string; serverNow: string; status: 'not_configured' | 'disabled' | 'awaiting' | 'ready';
    authorityUntil: string | null; grantId: string | null; grantRevision: number | null; historyDigest: string; comparison: SoftwareHistoryComparison | null; latestAttempt: FullSoftwareAttempt | null;
    gapCount: number; omittedChanges: number; expiredChanges: number; retainedCount: number; search: string; limit: number; offset: number; matchingCount: number;
    rows: SoftwareHistoryChange[]; nextCursor: string; cursorExpiresAt: string | null;
}
const exact = (v: unknown, keys: readonly string[]): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const integer = (v: unknown, max = Number.MAX_SAFE_INTEGER): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v <= max;
const member = (v: unknown, set: readonly string[]): v is string => typeof v === 'string' && set.includes(v);
const digest = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const grant = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{32}$/.test(v);
const timestamp = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number.isFinite(Date.parse(v)) && Number(v.slice(0, 4)) >= 2020 && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19);
export const validSoftwareHistoryQuery = (q: SoftwareHistoryQuery) => validFullSoftwareSearch(q.search) && q.sort === 'observed-desc' && integer(q.limit, SOFTWARE_HISTORY_PAGE_ROWS) && q.limit > 0 && validFullSoftwareCursor(q.cursor);
export function validSoftwareHistoryChange(v: unknown, now: string): v is SoftwareHistoryChange {
    if (!exact(v, ['id', 'kind', 'registrationId', 'registryView', 'beforeObservedAt', 'afterObservedAt', 'expiresAt', 'before', 'after', 'changedFields']) || !digest(v.id) || !digest(v.registrationId) || !member(v.registryView, ['32', '64']) || !member(v.kind, ['registration_added', 'registration_removed', 'metadata_changed']) || !timestamp(v.beforeObservedAt) || !timestamp(v.afterObservedAt) || !timestamp(v.expiresAt) || inventoryAge(v.afterObservedAt, v.beforeObservedAt) < 0 || inventoryAge(now, v.afterObservedAt) < 0 || inventoryAge(v.expiresAt, now) <= 0 || inventoryAge(v.expiresAt, v.beforeObservedAt) > 604800000 || inventoryAge(v.expiresAt, v.beforeObservedAt) < 604785000 || !Array.isArray(v.changedFields)) return false;
    for (const row of [v.before, v.after]) if (row !== null && (!validFullSoftwareRow(row) || row.registrationId !== v.registrationId || row.registryView !== v.registryView)) return false;
    if (v.kind === 'registration_added') return v.before === null && v.after !== null && v.changedFields.length === 0;
    if (v.kind === 'registration_removed') return v.before !== null && v.after === null && v.changedFields.length === 0;
    if (v.before === null || v.after === null) return false;
    const before = v.before as FullSoftwareRow, after = v.after as FullSoftwareRow;
    // Unknown values must never be presented as observed metadata changes.
    const fields = (['name', 'version', 'publisher'] as const).filter(field => before[field] !== null && after[field] !== null && before[field] !== after[field]);
    return fields.length > 0 && JSON.stringify(v.changedFields) === JSON.stringify(fields);
}
function validComparison(v: unknown, now: string): v is SoftwareHistoryComparison {
    if (!exact(v, ['status', 'reason', 'beforeObservedAt', 'afterObservedAt', 'expiresAt', 'observedChanges']) || !member(v.status, ['baseline', 'compared', 'gap']) || !timestamp(v.afterObservedAt) || inventoryAge(now, v.afterObservedAt) < 0 || !timestamp(v.expiresAt) || inventoryAge(v.expiresAt, now) <= 0 || inventoryAge(v.expiresAt, v.afterObservedAt) > 604800000 || !integer(v.observedChanges, 65536) || !(v.beforeObservedAt === null || timestamp(v.beforeObservedAt) && inventoryAge(v.afterObservedAt, v.beforeObservedAt) >= 0)) return false;
    const earlier = (v.beforeObservedAt ?? v.afterObservedAt) as string;
    if (inventoryAge(v.expiresAt, earlier) > 604800000 || inventoryAge(v.expiresAt, earlier) < 604785000) return false;
    return v.status === 'baseline' ? v.reason === 'no_baseline' && v.beforeObservedAt === null && v.observedChanges === 0 : v.status === 'compared' ? v.reason === '' && v.beforeObservedAt !== null : member(v.reason, ['source_gap', 'incomparable', 'resource_limit']);
}
export function validSoftwareHistoryPage(v: unknown, deviceId: string, query: SoftwareHistoryQuery, expectedOffset: number): v is SoftwareHistoryPage {
    if (!validSoftwareHistoryQuery(query) || !exact(v, ['schemaVersion', 'deviceId', 'serverNow', 'status', 'authorityUntil', 'grantId', 'grantRevision', 'historyDigest', 'comparison', 'latestAttempt', 'gapCount', 'omittedChanges', 'expiredChanges', 'retainedCount', 'search', 'limit', 'offset', 'matchingCount', 'rows', 'nextCursor', 'cursorExpiresAt']) || v.schemaVersion !== 'tracebolt.windows-software-history-page.v1' || !validWindowsDeviceId(deviceId) || v.deviceId !== deviceId || !timestamp(v.serverNow) || !member(v.status, ['not_configured', 'disabled', 'awaiting', 'ready']) || v.search !== query.search || v.limit !== query.limit || !integer(v.offset, 1024) || !integer(v.matchingCount, 1024) || !integer(v.retainedCount, 1024) || !integer(v.gapCount) || !integer(v.omittedChanges) || !integer(v.expiredChanges) || !Array.isArray(v.rows) || v.rows.length > query.limit || !v.rows.every(row => validSoftwareHistoryChange(row, v.serverNow as string)) || !validFullSoftwareCursor(v.nextCursor)) return false;
    const authority = timestamp(v.authorityUntil) && inventoryAge(v.authorityUntil, v.serverNow) > 0 && grant(v.grantId) && integer(v.grantRevision) && v.grantRevision > 0;
    if (!authority && !(v.authorityUntil === null && v.grantId === null && v.grantRevision === null)) return false;
    if (v.comparison !== null && !validComparison(v.comparison, v.serverNow)) return false;
    if (v.latestAttempt !== null) {
        const a = v.latestAttempt;
        if (!exact(a, ['sequence', 'attemptedAt', 'status', 'reason']) || !integer(a.sequence) || a.sequence < 1 || !timestamp(a.attemptedAt) || inventoryAge(v.serverNow, a.attemptedAt) < 0 || !member(a.status, ['pending', 'complete', 'source_failed', 'expired']) || !(a.status === 'source_failed' ? member(a.reason, fullSoftwareReasons) : a.reason === '')) return false;
    }
    if (v.status !== 'ready') return v.rows.length === 0 && v.offset === 0 && v.matchingCount === 0 && v.nextCursor === '' && v.cursorExpiresAt === null && v.retainedCount === 0 && v.comparison === null && v.historyDigest === '' && v.gapCount === 0 && v.omittedChanges === 0 && v.expiredChanges === 0 && (v.status === 'not_configured' ? !authority && v.latestAttempt === null : authority) && (v.status !== 'disabled' || v.latestAttempt === null);
    if (!authority || !digest(v.historyDigest) || !timestamp(v.cursorExpiresAt) || inventoryAge(v.cursorExpiresAt, v.serverNow) <= 0 || inventoryAge(v.cursorExpiresAt, v.serverNow) > 900000 || inventoryAge(v.authorityUntil as string, v.cursorExpiresAt) < 0 || v.comparison !== null && inventoryAge((v.comparison as SoftwareHistoryComparison).expiresAt, v.cursorExpiresAt) < 0 || v.offset !== expectedOffset || v.matchingCount > v.retainedCount || v.offset > v.matchingCount || v.rows.length > v.matchingCount - v.offset || v.rows.length === 0 && v.offset < v.matchingCount || (v.nextCursor !== '') !== (v.offset + v.rows.length < v.matchingCount) || v.nextCursor !== '' && v.nextCursor === query.cursor || new Set(v.rows.map(row => row.id)).size !== v.rows.length || v.search === '' && v.matchingCount !== v.retainedCount) return false;
    const rows = v.rows as SoftwareHistoryChange[];
    return rows.every((row, i) => inventoryAge(row.expiresAt, v.cursorExpiresAt as string) >= 0 && (i === 0 || inventoryAge(rows[i - 1].afterObservedAt, row.afterObservedAt) > 0 || inventoryAge(rows[i - 1].afterObservedAt, row.afterObservedAt) === 0 && rows[i - 1].id < row.id));
}
export const sameSoftwareHistory = (a: SoftwareHistoryPage, b: SoftwareHistoryPage) => a.grantId === b.grantId && a.grantRevision === b.grantRevision && a.historyDigest === b.historyDigest && a.retainedCount === b.retainedCount && a.gapCount === b.gapCount && a.omittedChanges === b.omittedChanges && a.expiredChanges === b.expiredChanges && JSON.stringify(a.comparison) === JSON.stringify(b.comparison);
export function softwareHistoryVisible(page: SoftwareHistoryPage, elapsedMS: number): boolean {
    const deadlines = [page.authorityUntil, page.cursorExpiresAt, page.comparison?.expiresAt, ...page.rows.map(row => row.expiresAt)].filter((v): v is string => typeof v === 'string');
    return page.status === 'ready' && page.authorityUntil !== null && page.cursorExpiresAt !== null && Number.isFinite(elapsedMS) && elapsedMS >= 0 && deadlines.every(expiry => inventoryAge(expiry, page.serverNow) > elapsedMS);
}
