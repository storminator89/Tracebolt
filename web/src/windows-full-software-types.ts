import { inventoryAge } from './complete-packages-types';
import { sha256Bytes } from './sha256';
import { validWindowsDeviceId } from './windows-inventory-types';

/** Independently authorized operator-only generations. Never telemetry or alarm input. */
export const FULL_SOFTWARE_PAGE_BYTES = 256 * 1024;
export const FULL_SOFTWARE_PAGE_ROWS = 100;
export const fullSoftwareSorts = ['name-asc', 'name-desc', 'version-asc', 'version-desc', 'publisher-asc', 'publisher-desc', 'view-asc', 'view-desc'] as const;
export type FullSoftwareSort = typeof fullSoftwareSorts[number];
export interface FullSoftwareRow {
    registrationId: string; registryView: '32' | '64';
    name: string | null; nameQuality: 'observed' | 'unavailable';
    version: string | null; versionQuality: 'observed' | 'unavailable';
    publisher: string | null; publisherQuality: 'observed' | 'unavailable';
}
export interface FullSoftwareManifest {
    schemaVersion: 'tracebolt.windows-complete-machine-software-manifest.v1'; scope: 'windows-complete-machine-software-v1'; source: 'hklm-uninstall-32-64'; coverage: 'caller_visible_machine_registrations_complete';
    deviceId: string; senderBinding: string; grantId: string; grantRevision: number; sequence: number; generationId: string;
    captureStartedAt: string; captureFinishedAt: string; expiresAt: string; rowCount: number; rowsBytes: number; rowsSha256: string; chunkCount: number;
}
export interface FullSoftwareComplete { manifest: FullSoftwareManifest; manifestSha256: string; receivedAt: string }
export const fullSoftwareReasons = ['access_denied', 'unavailable', 'unsupported', 'source_changed', 'malformed_source', 'resource_limit', 'deadline', 'canceled'] as const;
export interface FullSoftwareAttempt { sequence: number; attemptedAt: string; status: 'pending' | 'complete' | 'source_failed' | 'expired'; reason: '' | typeof fullSoftwareReasons[number] }
export interface FullSoftwareQuery { search: string; sort: FullSoftwareSort; limit: number; cursor: string }
export interface FullSoftwarePage {
    schemaVersion: 'tracebolt.windows-full-software-page.v1'; deviceId: string; serverNow: string;
    status: 'not_configured' | 'disabled' | 'awaiting' | 'ready' | 'unavailable'; authorityUntil: string | null; grantId: string | null; grantRevision: number | null;
    complete: FullSoftwareComplete | null; latestAttempt: FullSoftwareAttempt | null;
    search: string; sort: FullSoftwareSort; limit: number; offset: number; matchingCount: number; rows: FullSoftwareRow[]; nextCursor: string; cursorExpiresAt: string | null;
}
const exact = (v: unknown, keys: readonly string[]): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const integer = (v: unknown, max = Number.MAX_SAFE_INTEGER): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v <= max;
const positive = (v: unknown): v is number => integer(v) && v > 0;
const member = (v: unknown, set: readonly string[]): v is string => typeof v === 'string' && set.includes(v);
const text = (v: unknown, max: number): v is string => typeof v === 'string' && new TextEncoder().encode(v).byteLength <= max && !/[\u0000\uD800-\uDFFF]/u.test(v);
const digest = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const grantId = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{32}$/.test(v);
const generationId = (v: unknown): v is string => typeof v === 'string' && /^sample_[a-f0-9]{32}$/.test(v);
const timestamp = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number.isFinite(Date.parse(v)) && Number(v.slice(0, 4)) >= 2020 && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19);
export const validFullSoftwareSearch = (v: unknown): v is string => text(v, 256);
export const validFullSoftwareSort = (v: unknown): v is FullSoftwareSort => member(v, fullSoftwareSorts);
export const validFullSoftwareCursor = (v: unknown): v is string => typeof v === 'string' && v.length <= 4096 && (v === '' || /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/.test(v));
export function validFullSoftwareRow(v: unknown): v is FullSoftwareRow {
    if (!exact(v, ['registrationId', 'registryView', 'name', 'nameQuality', 'version', 'versionQuality', 'publisher', 'publisherQuality']) || !digest(v.registrationId) || !member(v.registryView, ['32', '64'])) return false;
    return (['name', 'version', 'publisher'] as const).every(field => v[`${field}Quality`] === 'observed' ? text(v[field], 2048) && (v[field] as string).length <= 512 : v[`${field}Quality`] === 'unavailable' && v[field] === null);
}
/** Go string/SQLite BINARY ordering is UTF-8 scalar order, not UTF-16
 * comparison or locale collation. Validate only the bounded returned page. */
function rawCompare(a: string, b: string): number {
    const left = a[Symbol.iterator](), right = b[Symbol.iterator]();
    for (;;) {
        const x = left.next(), y = right.next();
        if (x.done || y.done) return x.done === y.done ? 0 : x.done ? -1 : 1;
        const diff = x.value.codePointAt(0)! - y.value.codePointAt(0)!;
        if (diff) return diff;
    }
}
export function compareFullSoftwareRows(a: FullSoftwareRow, b: FullSoftwareRow, sort: FullSoftwareSort): number {
    const direction = sort.endsWith('desc') ? -1 : 1;
    const field = sort.startsWith('version') ? 'version' : sort.startsWith('publisher') ? 'publisher' : sort.startsWith('view') ? 'registryView' : 'name';
    const x = a[field], y = b[field], tie = rawCompare(a.registrationId, b.registrationId);
    if (x === null || y === null) return x === y ? tie : x === null ? 1 : -1;
    return rawCompare(x, y) * direction || tie;
}
const manifestKeys = ['schemaVersion', 'scope', 'source', 'coverage', 'deviceId', 'senderBinding', 'grantId', 'grantRevision', 'sequence', 'generationId', 'captureStartedAt', 'captureFinishedAt', 'expiresAt', 'rowCount', 'rowsBytes', 'rowsSha256', 'chunkCount'] as const;
export function fullSoftwareManifestHash(manifest: FullSoftwareManifest): string {
    const ordered = Object.fromEntries(manifestKeys.map(key => [key, manifest[key]]));
    return sha256Bytes(new TextEncoder().encode(`tracebolt.windows-complete-machine-software.manifest.v1\0${JSON.stringify(ordered)}`));
}
export function fullSoftwareGenerationId(deviceId: string, grant: string, sequence: number): string {
    const prefix = new TextEncoder().encode(`tracebolt.windows-complete-machine-software.generation.v1\0${deviceId}\0${grant}`);
    const bytes = new Uint8Array(prefix.length + 8); bytes.set(prefix); new DataView(bytes.buffer).setBigUint64(prefix.length, BigInt(sequence));
    return `sample_${sha256Bytes(bytes).slice(0, 32)}`;
}
export function validFullSoftwareComplete(v: unknown, deviceId: string, now: string): v is FullSoftwareComplete {
    if (!exact(v, ['manifest', 'manifestSha256', 'receivedAt']) || !digest(v.manifestSha256) || !timestamp(v.receivedAt) || inventoryAge(now, v.receivedAt) < 0 || !exact(v.manifest, manifestKeys)) return false;
    const m = v.manifest;
    if (m.schemaVersion !== 'tracebolt.windows-complete-machine-software-manifest.v1' || m.scope !== 'windows-complete-machine-software-v1' || m.source !== 'hklm-uninstall-32-64' || m.coverage !== 'caller_visible_machine_registrations_complete' || m.deviceId !== deviceId || !digest(m.senderBinding) || !grantId(m.grantId) || !positive(m.grantRevision) || !positive(m.sequence) || !generationId(m.generationId) || !timestamp(m.captureStartedAt) || !timestamp(m.captureFinishedAt) || !timestamp(m.expiresAt) || !integer(m.rowCount, 32768) || !integer(m.rowsBytes, 8 << 20) || m.rowsBytes < 2 || !digest(m.rowsSha256) || !integer(m.chunkCount, 512) || m.chunkCount < 1) return false;
    if (fullSoftwareManifestHash(m as unknown as FullSoftwareManifest) !== v.manifestSha256 || fullSoftwareGenerationId(deviceId, m.grantId, m.sequence) !== m.generationId) return false;
    const duration = inventoryAge(m.captureFinishedAt, m.captureStartedAt);
    return duration >= 0 && duration <= 15000 && inventoryAge(v.receivedAt, m.captureFinishedAt) >= 0 && inventoryAge(m.expiresAt, m.captureStartedAt) === 86400000 && inventoryAge(m.expiresAt, now) > 0 && (m.rowCount === 0 ? m.chunkCount === 1 && m.rowsBytes === 2 && m.rowsSha256 === sha256Bytes(new TextEncoder().encode('tracebolt.windows-complete-machine-software.rows.v1\0[]')) : m.chunkCount <= m.rowCount && m.rowCount <= m.chunkCount * 128 && m.rowsBytes > 0);
}
export function sameFullSoftwareComplete(a: FullSoftwareComplete, b: FullSoftwareComplete): boolean {
    return a.manifestSha256 === b.manifestSha256 && a.receivedAt === b.receivedAt && manifestKeys.every(k => a.manifest[k] === b.manifest[k]);
}
export function validFullSoftwarePage(v: unknown, deviceId: string, query: FullSoftwareQuery, expectedOffset: number): v is FullSoftwarePage {
    if (!exact(v, ['schemaVersion', 'deviceId', 'serverNow', 'status', 'authorityUntil', 'grantId', 'grantRevision', 'complete', 'latestAttempt', 'search', 'sort', 'limit', 'offset', 'matchingCount', 'rows', 'nextCursor', 'cursorExpiresAt']) || v.schemaVersion !== 'tracebolt.windows-full-software-page.v1' || !validWindowsDeviceId(deviceId) || v.deviceId !== deviceId || !timestamp(v.serverNow) || !member(v.status, ['not_configured', 'disabled', 'awaiting', 'ready', 'unavailable']) || !validFullSoftwareSearch(v.search) || v.search !== query.search || !validFullSoftwareSort(v.sort) || v.sort !== query.sort || v.limit !== query.limit || !integer(v.limit, FULL_SOFTWARE_PAGE_ROWS) || v.limit < 1 || !integer(v.offset, 32768) || !integer(v.matchingCount, 32768) || !Array.isArray(v.rows) || v.rows.length > query.limit || !v.rows.every(validFullSoftwareRow) || !validFullSoftwareCursor(v.nextCursor)) return false;
    const authority = timestamp(v.authorityUntil) && inventoryAge(v.authorityUntil, v.serverNow) > 0 && grantId(v.grantId) && positive(v.grantRevision);
    if (!authority && !(v.authorityUntil === null && v.grantId === null && v.grantRevision === null)) return false;
    if (v.latestAttempt !== null) {
        const a = v.latestAttempt;
        if (!exact(a, ['sequence', 'attemptedAt', 'status', 'reason']) || !positive(a.sequence) || !timestamp(a.attemptedAt) || inventoryAge(v.serverNow, a.attemptedAt) < 0 || !member(a.status, ['pending', 'complete', 'source_failed', 'expired']) || !(a.status === 'source_failed' ? member(a.reason, fullSoftwareReasons) : a.reason === '')) return false;
    }
    if (v.status !== 'ready') return v.complete === null && v.rows.length === 0 && v.offset === 0 && v.matchingCount === 0 && v.nextCursor === '' && v.cursorExpiresAt === null && (v.status !== 'not_configured' || v.latestAttempt === null) && (v.status !== 'awaiting' && v.status !== 'disabled' || authority);
    if (!authority || !validFullSoftwareComplete(v.complete, deviceId, v.serverNow) || !timestamp(v.cursorExpiresAt) || inventoryAge(v.cursorExpiresAt, v.serverNow) <= 0 || inventoryAge(v.cursorExpiresAt, v.serverNow) > 900000 || inventoryAge(v.complete.manifest.expiresAt, v.cursorExpiresAt) < 0 || inventoryAge(v.authorityUntil as string, v.cursorExpiresAt) < 0 || v.complete.manifest.grantId !== v.grantId || v.complete.manifest.grantRevision !== v.grantRevision || v.offset !== expectedOffset || v.matchingCount > v.complete.manifest.rowCount || v.offset > v.matchingCount || v.rows.length > Math.min(query.limit, v.matchingCount - v.offset) || v.rows.length === 0 && v.offset < v.matchingCount || (v.nextCursor !== '') !== (v.offset + v.rows.length < v.matchingCount) || v.nextCursor !== '' && v.nextCursor === query.cursor || new Set(v.rows.map(row => row.registrationId)).size !== v.rows.length) return false;
    const rows = v.rows as FullSoftwareRow[];
    if (!rows.every((row, i) => i === 0 || compareFullSoftwareRows(rows[i - 1], row, query.sort) < 0)) return false;
    if (v.search === '' && v.matchingCount !== v.complete.manifest.rowCount) return false;
    if (!v.latestAttempt || (v.latestAttempt as FullSoftwareAttempt).sequence < v.complete.manifest.sequence) return false;
    const attempt = v.latestAttempt as FullSoftwareAttempt;
    if (attempt.sequence === v.complete.manifest.sequence && (attempt.status !== 'complete' || attempt.attemptedAt !== v.complete.manifest.captureStartedAt)) return false;
    return true;
}
export function fullSoftwareVisible(page: FullSoftwarePage, elapsedMS: number): boolean {
    return page.status === 'ready' && page.complete !== null && page.authorityUntil !== null && page.cursorExpiresAt !== null && Number.isFinite(elapsedMS) && elapsedMS >= 0 && [page.complete.manifest.expiresAt, page.authorityUntil, page.cursorExpiresAt].every(expiry => inventoryAge(expiry, page.serverNow) > elapsedMS);
}
