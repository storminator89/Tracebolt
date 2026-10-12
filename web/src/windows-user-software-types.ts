import { inventoryAge } from './complete-packages-types';
import { sha256Bytes } from './sha256';
import { validWindowsDeviceId } from './windows-inventory-types';

/** Independently authorized operator-only generations. Never telemetry or alarm input. */
export const USER_SOFTWARE_PAGE_BYTES = 256 * 1024;
export const USER_SOFTWARE_PAGE_ROWS = 100;
export const userSoftwareSorts = ['name-asc', 'name-desc', 'version-asc', 'version-desc', 'publisher-asc', 'publisher-desc', 'source-asc', 'source-desc'] as const;
export type UserSoftwareSort = typeof userSoftwareSorts[number];
export interface UserSoftwareRow {
    registrationId: string; source: 'hkcu' | 'msix';
    name: string | null; nameQuality: 'observed' | 'unavailable';
    version: string | null; versionQuality: 'observed' | 'unavailable';
    publisher: string | null; publisherQuality: 'observed' | 'unavailable';
}
export interface UserSoftwareManifest {
    schemaVersion: 'tracebolt.windows-selected-user-software-manifest.v1'; scope: 'windows-selected-user-software-v1'; source: 'selected-account-hkcu-msix'; coverage: 'selected_account_complete' | 'selected_account_partial';
    accountContextId: string; accountLabel: string; captureNonce: string; hkcuStatus: UserSoftwareSourceStatus; msixStatus: UserSoftwareSourceStatus;
    deviceId: string; senderBinding: string; grantId: string; grantRevision: number; sequence: number; generationId: string;
    captureStartedAt: string; captureFinishedAt: string; expiresAt: string; rowCount: number; rowsBytes: number; rowsSha256: string; chunkCount: number;
}
export interface UserSoftwareComplete { manifest: UserSoftwareManifest; manifestSha256: string; receivedAt: string }
export const userSoftwareReasons = ['access_denied', 'unavailable', 'unsupported', 'source_changed', 'malformed_source', 'resource_limit', 'deadline', 'canceled'] as const;
export type UserSoftwareSourceStatus = 'complete' | typeof userSoftwareReasons[number];
export interface UserSoftwareAttempt { accountContextId: string; accountLabel: string; captureNonce: string; sequence: number; attemptedAt: string; status: 'pending' | 'complete' | 'source_failed' | 'expired'; reason: '' | typeof userSoftwareReasons[number] }
export interface UserSoftwareQuery { accountContextId: string; source: '' | 'hkcu' | 'msix'; search: string; sort: UserSoftwareSort; limit: number; cursor: string }
export interface UserSoftwarePage {
    accountContextId: string; source: '' | 'hkcu' | 'msix';
    schemaVersion: 'tracebolt.windows-selected-user-software-page.v1'; deviceId: string; serverNow: string;
    status: 'not_configured' | 'disabled' | 'awaiting' | 'ready' | 'unavailable'; authorityUntil: string | null; grantId: string | null; grantRevision: number | null;
    complete: UserSoftwareComplete | null; latestAttempt: UserSoftwareAttempt | null;
    search: string; sort: UserSoftwareSort; limit: number; offset: number; matchingCount: number; rows: UserSoftwareRow[]; nextCursor: string; cursorExpiresAt: string | null;
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
export const validUserSoftwareSearch = (v: unknown): v is string => text(v, 256);
export const validUserSoftwareSort = (v: unknown): v is UserSoftwareSort => member(v, userSoftwareSorts);
export const validUserSoftwareCursor = (v: unknown): v is string => typeof v === 'string' && v.length <= 4096 && (v === '' || /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/.test(v));
export function validUserSoftwareRow(v: unknown): v is UserSoftwareRow {
    if (!exact(v, ['registrationId', 'source', 'name', 'nameQuality', 'version', 'versionQuality', 'publisher', 'publisherQuality']) || !digest(v.registrationId) || !member(v.source, ['hkcu', 'msix'])) return false;
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
export function compareUserSoftwareRows(a: UserSoftwareRow, b: UserSoftwareRow, sort: UserSoftwareSort): number {
    const direction = sort.endsWith('desc') ? -1 : 1;
    const field = sort.startsWith('version') ? 'version' : sort.startsWith('publisher') ? 'publisher' : sort.startsWith('source') ? 'source' : 'name';
    const x = a[field], y = b[field], tie = rawCompare(a.registrationId, b.registrationId);
    if (x === null || y === null) return x === y ? tie : x === null ? 1 : -1;
    return rawCompare(x, y) * direction || tie;
}
const manifestKeys = ['accountContextId', 'accountLabel', 'captureNonce', 'hkcuStatus', 'msixStatus', 'schemaVersion', 'scope', 'source', 'coverage', 'deviceId', 'senderBinding', 'grantId', 'grantRevision', 'sequence', 'generationId', 'captureStartedAt', 'captureFinishedAt', 'expiresAt', 'rowCount', 'rowsBytes', 'rowsSha256', 'chunkCount'] as const;
export function userSoftwareManifestHash(manifest: UserSoftwareManifest): string {
    const ordered = Object.fromEntries(manifestKeys.map(key => [key, manifest[key]]));
    return sha256Bytes(new TextEncoder().encode(`tracebolt.windows-selected-user-software.manifest.v1\0${JSON.stringify(ordered)}`));
}
export function userSoftwareGenerationId(deviceId: string, grant: string, sequence: number): string {
    const prefix = new TextEncoder().encode(`tracebolt.windows-selected-user-software.generation.v1\0${deviceId}\0${grant}`);
    const bytes = new Uint8Array(prefix.length + 8); bytes.set(prefix); new DataView(bytes.buffer).setBigUint64(prefix.length, BigInt(sequence));
    return `sample_${sha256Bytes(bytes).slice(0, 32)}`;
}
export function validUserSoftwareComplete(v: unknown, deviceId: string, now: string): v is UserSoftwareComplete {
    if (!exact(v, ['manifest', 'manifestSha256', 'receivedAt']) || !digest(v.manifestSha256) || !timestamp(v.receivedAt) || inventoryAge(now, v.receivedAt) < 0 || !exact(v.manifest, manifestKeys)) return false;
    const m = v.manifest;
    if (m.schemaVersion !== 'tracebolt.windows-selected-user-software-manifest.v1' || m.scope !== 'windows-selected-user-software-v1' || m.source !== 'selected-account-hkcu-msix' || !member(m.coverage, ['selected_account_complete', 'selected_account_partial']) || !digest(m.accountContextId) || !text(m.accountLabel, 256) || m.accountLabel === '' || !digest(m.captureNonce) || !member(m.hkcuStatus, ['complete', ...userSoftwareReasons]) || !member(m.msixStatus, ['complete', ...userSoftwareReasons]) || (m.coverage === 'selected_account_complete') !== (m.hkcuStatus === 'complete' && m.msixStatus === 'complete') || m.deviceId !== deviceId || !digest(m.senderBinding) || !grantId(m.grantId) || !positive(m.grantRevision) || !positive(m.sequence) || !generationId(m.generationId) || !timestamp(m.captureStartedAt) || !timestamp(m.captureFinishedAt) || !timestamp(m.expiresAt) || !integer(m.rowCount, 4096) || !integer(m.rowsBytes, 4 << 20) || m.rowsBytes < 2 || !digest(m.rowsSha256) || !integer(m.chunkCount, 128) || m.chunkCount < 1) return false;
    if (userSoftwareManifestHash(m as unknown as UserSoftwareManifest) !== v.manifestSha256 || userSoftwareGenerationId(deviceId, m.grantId, m.sequence) !== m.generationId) return false;
    const duration = inventoryAge(m.captureFinishedAt, m.captureStartedAt);
    return duration >= 0 && duration <= 15000 && inventoryAge(v.receivedAt, m.captureFinishedAt) >= 0 && inventoryAge(m.expiresAt, m.captureStartedAt) === 86400000 && inventoryAge(m.expiresAt, now) > 0 && (m.rowCount === 0 ? m.chunkCount === 1 && m.rowsBytes === 2 && m.rowsSha256 === sha256Bytes(new TextEncoder().encode('tracebolt.windows-selected-user-software.rows.v1\0[]')) : m.chunkCount <= m.rowCount && m.rowCount <= m.chunkCount * 128 && m.rowsBytes > 0);
}
export function sameUserSoftwareComplete(a: UserSoftwareComplete, b: UserSoftwareComplete): boolean {
    return a.manifestSha256 === b.manifestSha256 && a.receivedAt === b.receivedAt && manifestKeys.every(k => a.manifest[k] === b.manifest[k]);
}
export function validUserSoftwarePage(v: unknown, deviceId: string, query: UserSoftwareQuery, expectedOffset: number): v is UserSoftwarePage {
    if (!exact(v, ['accountContextId', 'source', 'schemaVersion', 'deviceId', 'serverNow', 'status', 'authorityUntil', 'grantId', 'grantRevision', 'complete', 'latestAttempt', 'search', 'sort', 'limit', 'offset', 'matchingCount', 'rows', 'nextCursor', 'cursorExpiresAt']) || (query.accountContextId !== '' && v.accountContextId !== query.accountContextId) || v.source !== query.source || v.schemaVersion !== 'tracebolt.windows-selected-user-software-page.v1' || !validWindowsDeviceId(deviceId) || v.deviceId !== deviceId || !timestamp(v.serverNow) || !member(v.status, ['not_configured', 'disabled', 'awaiting', 'ready', 'unavailable']) || !validUserSoftwareSearch(v.search) || v.search !== query.search || !validUserSoftwareSort(v.sort) || v.sort !== query.sort || v.limit !== query.limit || !integer(v.limit, USER_SOFTWARE_PAGE_ROWS) || v.limit < 1 || !integer(v.offset, 4096) || !integer(v.matchingCount, 4096) || !Array.isArray(v.rows) || v.rows.length > query.limit || !v.rows.every(validUserSoftwareRow) || !validUserSoftwareCursor(v.nextCursor)) return false;
    const authority = timestamp(v.authorityUntil) && inventoryAge(v.authorityUntil, v.serverNow) > 0 && grantId(v.grantId) && positive(v.grantRevision);
    if (!authority && !(v.authorityUntil === null && v.grantId === null && v.grantRevision === null)) return false;
    if (v.latestAttempt !== null) {
        const a = v.latestAttempt;
        if (!exact(a, ['accountContextId', 'accountLabel', 'captureNonce', 'sequence', 'attemptedAt', 'status', 'reason']) || !digest(a.accountContextId) || !text(a.accountLabel, 256) || a.accountLabel === '' || !digest(a.captureNonce) || !positive(a.sequence) || !timestamp(a.attemptedAt) || (inventoryAge(v.serverNow, a.attemptedAt) < 0 || inventoryAge(v.serverNow, a.attemptedAt) >= 86400000) || !member(a.status, ['pending', 'complete', 'source_failed', 'expired']) || !(a.status === 'source_failed' ? member(a.reason, userSoftwareReasons) : a.reason === '')) return false;
    }
    if (v.status !== 'ready') return v.complete === null && v.rows.length === 0 && v.offset === 0 && v.matchingCount === 0 && v.nextCursor === '' && v.cursorExpiresAt === null && (v.status !== 'not_configured' || v.latestAttempt === null) && (v.status !== 'awaiting' && v.status !== 'disabled' || authority);
    if (!authority || !validUserSoftwareComplete(v.complete, deviceId, v.serverNow) || !timestamp(v.cursorExpiresAt) || inventoryAge(v.cursorExpiresAt, v.serverNow) <= 0 || inventoryAge(v.cursorExpiresAt, v.serverNow) > 900000 || inventoryAge(v.complete.manifest.expiresAt, v.cursorExpiresAt) < 0 || inventoryAge(v.authorityUntil as string, v.cursorExpiresAt) < 0 || v.complete.manifest.grantId !== v.grantId || v.complete.manifest.grantRevision !== v.grantRevision || v.offset !== expectedOffset || v.matchingCount > v.complete.manifest.rowCount || v.offset > v.matchingCount || v.rows.length > Math.min(query.limit, v.matchingCount - v.offset) || v.rows.length === 0 && v.offset < v.matchingCount || (v.nextCursor !== '') !== (v.offset + v.rows.length < v.matchingCount) || v.nextCursor !== '' && v.nextCursor === query.cursor || new Set(v.rows.map(row => row.registrationId)).size !== v.rows.length) return false;
    const rows = v.rows as UserSoftwareRow[], manifest = v.complete.manifest;
    if (v.accountContextId !== v.complete.manifest.accountContextId || query.accountContextId && query.accountContextId !== v.complete.manifest.accountContextId) return false;
    if (!rows.every(row => (query.source === '' || row.source === query.source) && (row.source === 'hkcu' ? manifest.hkcuStatus : manifest.msixStatus) === 'complete')) return false;
    if (!rows.every((row, i) => i === 0 || compareUserSoftwareRows(rows[i - 1], row, query.sort) < 0)) return false;
    if (v.search === '' && v.source === '' && v.matchingCount !== v.complete.manifest.rowCount) return false;
    if (!v.latestAttempt || (v.latestAttempt as UserSoftwareAttempt).sequence < v.complete.manifest.sequence) return false;
    const attempt = v.latestAttempt as UserSoftwareAttempt;
    if (attempt.sequence === v.complete.manifest.sequence && (attempt.accountContextId !== v.complete.manifest.accountContextId || attempt.accountLabel !== v.complete.manifest.accountLabel || attempt.captureNonce !== v.complete.manifest.captureNonce || attempt.status !== 'complete' || attempt.attemptedAt !== v.complete.manifest.captureStartedAt)) return false;
    return true;
}
/** All account metadata, including failed/pending attempts, retains its original
 * bounded lifetime. A background timer clears it without another manager read. */
export function userSoftwareMetadataVisible(page: UserSoftwarePage, elapsedMS: number): boolean {
    return Number.isFinite(elapsedMS) && elapsedMS >= 0 &&
        (page.authorityUntil === null || inventoryAge(page.authorityUntil, page.serverNow) > elapsedMS) &&
        (page.latestAttempt === null || inventoryAge(page.serverNow, page.latestAttempt.attemptedAt) >= 0 && inventoryAge(page.serverNow, page.latestAttempt.attemptedAt) + elapsedMS < 86400000);
}
export function userSoftwareVisible(page: UserSoftwarePage, elapsedMS: number): boolean {
    return userSoftwareMetadataVisible(page, elapsedMS) && page.status === 'ready' && page.complete !== null && page.authorityUntil !== null && page.cursorExpiresAt !== null && Number.isFinite(elapsedMS) && elapsedMS >= 0 && [page.complete.manifest.expiresAt, page.authorityUntil, page.cursorExpiresAt].every(expiry => inventoryAge(expiry, page.serverNow) > elapsedMS);
}
