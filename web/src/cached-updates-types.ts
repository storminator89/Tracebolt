import { inventoryAge, inventorySequence } from './complete-packages-types';

export const CACHED_UPDATES_VIEW_BYTES = 4096, CACHED_UPDATES_SNAPSHOT_BYTES = 2048;
export const cachedUpdatesFailureReasons = ['not_supported', 'source_missing', 'cache_missing', 'permission_denied', 'read_failed', 'invalid_source', 'source_changed', 'timeout', 'collector_busy', 'byte_limit', 'work_limit'] as const;
export type CachedUpdatesReason = 'none' | 'item_limit' | 'candidate_unknown' | typeof cachedUpdatesFailureReasons[number];
export type CachedUpdatesStatus = 'not_collected' | 'fresh' | 'stale' | 'expired' | 'revoked' | 'unknown';
export interface CachedUpdateRow { name: string; architecture: string; installedVersion: string; candidateVersion: string; state: 'candidate_only' | 'held'; installability: 'not_evaluated' }
export interface CachedUpdatesSnapshot {
    schemaVersion: 'tracebolt.cached-apt-updates.v1'; scope: 'agent-visible-dpkg-and-existing-apt-cache'; generationId: string; collectedAt: string; durationMs: number;
    release: { id: string | null; versionId: string | null; versionCodename: string | null };
    coverage: 'complete' | 'partial' | 'unavailable'; reason: CachedUpdatesReason;
    metadata: { freshness: 'unknown' | 'stale'; oldestIndexModifiedAt: string | null; ageSeconds: number | null; ageBasis: 'oldest-local-package-index-mtime'; refresh: 'not_attempted' };
    installedCount: number | null; checkedCount: number | null; candidateCount: number | null; heldCount: number | null; unknownCount: number | null; truncated: boolean; items: CachedUpdateRow[];
}
export interface CachedUpdatesView {
    schemaVersion: 'tracebolt.cached-updates-view.v1'; deviceId: string; status: CachedUpdatesStatus; serverNow: string; maxAgeSeconds: 120;
    sequence: string | null; receivedAt: string | null; expiresAt: string | null; latest: CachedUpdatesSnapshot | null;
}
const record = (v: unknown, keys: readonly string[]): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const integer = (v: unknown, max = Number.MAX_SAFE_INTEGER): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v <= max;
const member = (v: unknown, list: readonly string[]): boolean => typeof v === 'string' && list.includes(v);
export const validCachedUpdatesDeviceId = (v: string): boolean => /^agent_[A-Za-z0-9_-]{1,120}$/.test(v);
const timestamp = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number.isFinite(Date.parse(v)) && Number(v.slice(0, 4)) >= 1970 && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19);
function metadataAgeSeconds(at: string, then: string): number {
    const nanos = (value: string) => BigInt(Date.parse(value.slice(0, 19) + 'Z')) * 1000000n + BigInt((value.includes('.') ? value.slice(20, -1) : '').padEnd(9, '0'));
    const difference = nanos(at) - nanos(then); return difference < 0n ? -1 : Number(difference / 1000000000n);
}
function debianParts(v: unknown): string[] | null {
    if (typeof v !== 'string' || !v.length || v.length > 512) return null;
    const parts = v.split(':'); if (parts.length > 2 || parts.length === 2 && (!/^\d+$/.test(parts[0]) || Number(parts[0]) > 2147483647)) return null;
    const value = parts.at(-1)!, hyphen = value.lastIndexOf('-'), upstream = hyphen < 0 ? value : value.slice(0, hyphen), revision = hyphen < 0 ? '0' : value.slice(hyphen + 1);
    return /^[0-9][A-Za-z0-9.+~-]*$/.test(upstream) && /^[A-Za-z0-9.+~]+$/.test(revision) ? [parts.length === 2 ? parts[0] : '0', upstream, revision] : null;
}
const decimalCompare = (a: string, b: string): number => { a = a.replace(/^0+/, ''); b = b.replace(/^0+/, ''); return a.length !== b.length ? Math.sign(a.length - b.length) : a < b ? -1 : a > b ? 1 : 0; };
function partCompare(a: string, b: string): number {
    const digit = (s: string) => /^[0-9]$/.test(s), order = (s: string) => s === '~' ? -1 : !s ? 0 : /^[A-Za-z]$/.test(s) ? s.charCodeAt(0) : s.charCodeAt(0) + 256;
    let i = 0, j = 0;
    while (i < a.length || j < b.length) {
        while (i < a.length && !digit(a[i]) || j < b.length && !digit(b[j])) {
            const x = i < a.length && !digit(a[i]) ? a[i] : '', y = j < b.length && !digit(b[j]) ? b[j] : '', n = order(x) - order(y);
            if (n) return Math.sign(n); if (x) i++; if (y) j++;
        }
        const startA = i, startB = j; while (i < a.length && digit(a[i])) i++; while (j < b.length && digit(b[j])) j++;
        const n = decimalCompare(a.slice(startA, i), b.slice(startB, j)); if (n) return n;
    }
    return 0;
}
export function cachedDebianCompare(a: unknown, b: unknown): number | null {
    const left = debianParts(a), right = debianParts(b); if (!left || !right) return null;
    return decimalCompare(left[0], right[0]) || partCompare(left[1], right[1]) || partCompare(left[2], right[2]);
}
export function validCachedUpdatesSnapshot(v: unknown): v is CachedUpdatesSnapshot {
    if (!record(v, ['schemaVersion', 'scope', 'generationId', 'collectedAt', 'durationMs', 'release', 'coverage', 'reason', 'metadata', 'installedCount', 'checkedCount', 'candidateCount', 'heldCount', 'unknownCount', 'truncated', 'items']) || v.schemaVersion !== 'tracebolt.cached-apt-updates.v1' || v.scope !== 'agent-visible-dpkg-and-existing-apt-cache' || typeof v.generationId !== 'string' || !/^sample_[a-f0-9]{32}$/.test(v.generationId) || !timestamp(v.collectedAt) || !integer(v.durationMs) || !Array.isArray(v.items) || v.items.length > 16 || typeof v.truncated !== 'boolean') return false;
    const r = v.release, m = v.metadata;
    if (!record(r, ['id', 'versionId', 'versionCodename']) || Object.values(r).some(x => x !== null && (typeof x !== 'string' || !/^[a-z0-9._-]{0,128}$/.test(x)))) return false;
    if (!record(m, ['freshness', 'oldestIndexModifiedAt', 'ageSeconds', 'ageBasis', 'refresh']) || !member(m.freshness, ['unknown', 'stale']) || m.ageBasis !== 'oldest-local-package-index-mtime' || m.refresh !== 'not_attempted' || (m.oldestIndexModifiedAt === null) !== (m.ageSeconds === null)) return false;
    if (m.oldestIndexModifiedAt !== null) {
        if (!timestamp(m.oldestIndexModifiedAt) || !integer(m.ageSeconds) || metadataAgeSeconds(v.collectedAt, m.oldestIndexModifiedAt) < 0 || m.ageSeconds !== metadataAgeSeconds(v.collectedAt, m.oldestIndexModifiedAt) || (m.freshness === 'stale') !== (m.ageSeconds >= 172800)) return false;
    } else if (m.freshness !== 'unknown') return false;
    if (v.coverage === 'unavailable') {
        if (!member(v.reason, cachedUpdatesFailureReasons) || [v.installedCount, v.checkedCount, v.candidateCount, v.heldCount, v.unknownCount].some(x => x !== null) || v.items.length || v.truncated) return false;
    } else {
        if (!(r.id === 'debian' && r.versionId === '13' && r.versionCodename === 'trixie' || r.id === 'ubuntu' && r.versionId === '24.04' && r.versionCodename === 'noble') || m.oldestIndexModifiedAt === null) return false;
        if (!integer(v.installedCount, 16384) || !integer(v.checkedCount, v.installedCount) || !integer(v.candidateCount, v.checkedCount) || !integer(v.heldCount, v.candidateCount) || !integer(v.unknownCount, v.installedCount) || v.checkedCount + v.unknownCount !== v.installedCount || v.items.length > v.candidateCount || v.truncated !== (v.items.length < v.candidateCount)) return false;
        if (v.coverage === 'complete' ? v.reason !== 'none' || v.truncated || v.unknownCount !== 0 : v.coverage !== 'partial' || !v.truncated && v.unknownCount === 0 || !member(v.reason, ['item_limit', 'byte_limit', 'candidate_unknown']) || !v.truncated && v.reason !== 'candidate_unknown' || v.reason === 'candidate_unknown' && v.unknownCount === 0) return false;
        let previous = '', held = 0;
        for (const row of v.items) {
            if (!record(row, ['name', 'architecture', 'installedVersion', 'candidateVersion', 'state', 'installability']) || typeof row.name !== 'string' || !/^[a-z0-9][a-z0-9+.-]{1,255}$/.test(row.name) || typeof row.architecture !== 'string' || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(row.architecture) || row.installability !== 'not_evaluated' || !member(row.state, ['candidate_only', 'held']) || cachedDebianCompare(row.installedVersion, row.candidateVersion) !== -1) return false;
            const key = `${row.name}\0${row.architecture}`; if (key <= previous) return false; previous = key; if (row.state === 'held') held++;
        }
        if (held > v.heldCount || v.heldCount - held > v.candidateCount - v.items.length) return false;
    }
    return new TextEncoder().encode(JSON.stringify(v)).byteLength <= CACHED_UPDATES_SNAPSHOT_BYTES;
}
export function cachedUpdatesAgeStatus(view: CachedUpdatesView, elapsed = 0): CachedUpdatesStatus {
    if (!Number.isFinite(elapsed) || elapsed < 0) return 'unknown';
    if (!view.latest || !['fresh', 'stale'].includes(view.status)) return view.status;
    const age = inventoryAge(view.serverNow, view.latest.collectedAt) + elapsed;
    return age < 0 ? 'unknown' : age >= 86400000 ? 'expired' : age > 120000 ? 'stale' : 'fresh';
}
export function cachedUpdatesSnapshotVisible(view: CachedUpdatesView, elapsed: number): boolean { return view.latest !== null && ['fresh', 'stale'].includes(cachedUpdatesAgeStatus(view, elapsed)); }
export function validCachedUpdatesView(v: unknown, deviceId: string): v is CachedUpdatesView {
    if (!record(v, ['schemaVersion', 'deviceId', 'status', 'serverNow', 'maxAgeSeconds', 'sequence', 'receivedAt', 'expiresAt', 'latest']) || v.schemaVersion !== 'tracebolt.cached-updates-view.v1' || !validCachedUpdatesDeviceId(deviceId) || v.deviceId !== deviceId || !member(v.status, ['not_collected', 'fresh', 'stale', 'expired', 'revoked', 'unknown']) || !timestamp(v.serverNow) || v.maxAgeSeconds !== 120) return false;
    const empty = v.sequence === null && v.receivedAt === null && v.expiresAt === null;
    if (!empty && (!inventorySequence(v.sequence) || !timestamp(v.receivedAt) || !timestamp(v.expiresAt) || inventoryAge(v.expiresAt, v.receivedAt) <= 0 || inventoryAge(v.expiresAt, v.receivedAt) > 86400000)) return false;
    if (v.status === 'not_collected' || v.status === 'revoked' || v.status === 'unknown') return empty && v.latest === null;
    if (v.status === 'expired') return v.latest === null && (empty || inventoryAge(v.serverNow, v.expiresAt as string) >= 0);
    if (empty || !validCachedUpdatesSnapshot(v.latest) || inventoryAge(v.receivedAt as string, v.latest.collectedAt) < 0 || inventoryAge(v.serverNow, v.receivedAt as string) < 0 || inventoryAge(v.expiresAt as string, v.latest.collectedAt) !== 86400000) return false;
    return cachedUpdatesAgeStatus(v as unknown as CachedUpdatesView) === v.status;
}
