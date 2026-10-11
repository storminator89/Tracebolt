import { inventoryAge } from './complete-packages-types';
import { numericWindowsAddress } from './windows-numeric-address';
import { sha256Bytes } from './sha256';
import { validWindowsDeviceId } from './windows-inventory-types';

/** Independently authorized operator-only generations. Never telemetry or alarm input. */
export const NETWORK_CONTEXT_PAGE_BYTES = 256 * 1024;
export const NETWORK_CONTEXT_PAGE_ROWS = 100;
export const networkContextSorts = ['source-asc', 'source-desc', 'interface-asc', 'interface-desc'] as const;
export type NetworkContextSort = typeof networkContextSorts[number];
export const networkContextKinds = ['all', 'route', 'interface'] as const;
export type NetworkContextKind = typeof networkContextKinds[number];
export interface NetworkContextRoute { destination: string; destinationScopeId: number; nextHop: string; metric: number; protocol: number; origin: number }
export interface NetworkContextCounters { alias: string | null; aliasQuality: 'observed' | 'unavailable'; inOctets: string; outOctets: string; inErrors: string; outErrors: string; inDiscards: string; outDiscards: string }
export type NetworkContextRow = { id: number; interfaceIndex: number } & ({ kind: 'route'; route: NetworkContextRoute } | { kind: 'interface'; counters: NetworkContextCounters });
export interface NetworkContextManifest {
    schemaVersion: 'tracebolt.windows-network-context-manifest.v1'; scope: 'windows-network-context-v1'; source: 'ip-helper-routes-and-raw-interface-counters'; coverage: 'caller_visible_tables_complete_nonatomic';
    deviceId: string; senderBinding: string; grantId: string; grantRevision: number; sequence: number; generationId: string;
    captureStartedAt: string; captureFinishedAt: string; expiresAt: string; rowCount: number; rowsBytes: number; rowsSha256: string; chunkCount: number;
}
export interface NetworkContextComplete { manifest: NetworkContextManifest; manifestSha256: string; receivedAt: string }
export const networkContextReasons = ['access_denied', 'unavailable', 'unsupported', 'source_changed', 'malformed_source', 'resource_limit', 'deadline', 'canceled'] as const;
export interface NetworkContextAttempt { sequence: number; attemptedAt: string; status: 'pending' | 'complete' | 'source_failed' | 'expired'; reason: '' | typeof networkContextReasons[number] }
export interface NetworkContextQuery { kind: NetworkContextKind; search: string; sort: NetworkContextSort; limit: number; cursor: string }
export interface NetworkContextPage {
    kind: NetworkContextKind; schemaVersion: 'tracebolt.windows-network-context-page.v1'; deviceId: string; serverNow: string;
    status: 'not_configured' | 'disabled' | 'awaiting' | 'ready' | 'unavailable'; authorityUntil: string | null; grantId: string | null; grantRevision: number | null;
    complete: NetworkContextComplete | null; latestAttempt: NetworkContextAttempt | null;
    search: string; sort: NetworkContextSort; limit: number; offset: number; matchingCount: number; rows: NetworkContextRow[]; nextCursor: string; cursorExpiresAt: string | null;
}
const exact = (v: unknown, keys: readonly string[]): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const integer = (v: unknown, max = Number.MAX_SAFE_INTEGER): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0) && v >= 0 && v <= max;
const positive = (v: unknown): v is number => integer(v) && v > 0;
const member = (v: unknown, set: readonly string[]): v is string => typeof v === 'string' && set.includes(v);
const text = (v: unknown, max: number): v is string => typeof v === 'string' && new TextEncoder().encode(v).byteLength <= max && !/[\u0000\uD800-\uDFFF]/u.test(v);
const digest = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const grantId = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{32}$/.test(v);
const generationId = (v: unknown): v is string => typeof v === 'string' && /^sample_[a-f0-9]{32}$/.test(v);
const timestamp = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number.isFinite(Date.parse(v)) && Number(v.slice(0, 4)) >= 2020 && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19);
export const validNetworkContextSearch = (v: unknown): v is string => text(v, 256);
export const validNetworkContextSort = (v: unknown): v is NetworkContextSort => member(v, networkContextSorts);
export const validNetworkContextCursor = (v: unknown): v is string => typeof v === 'string' && v.length <= 4096 && (v === '' || /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/.test(v));
export const validNetworkContextKind = (v: unknown): v is NetworkContextKind => member(v, networkContextKinds);
/** Counter strings are never rounded through Number, including zero and uint64 max. */
export const validNetworkContextCounter = (v: unknown): v is string => typeof v === 'string' && /^(?:0|[1-9][0-9]{0,19})$/.test(v) && (v.length < 20 || v <= '18446744073709551615');
function address(v: unknown, zoneAllowed: boolean): { bytes: number[]; family: 'ipv4' | 'ipv6' } | null {
    if (typeof v !== 'string' || v.length > 56) return null;
    const [raw, zone, extra] = v.split('%'), family = raw.includes(':') ? 'ipv6' : 'ipv4';
    if (extra !== undefined || zone !== undefined && (!zoneAllowed || family !== 'ipv6' || !/^[1-9][0-9]{0,9}$/.test(zone) || !integer(Number(zone), 0xffffffff))) return null;
    const bytes = numericWindowsAddress(raw, family);
    if (!bytes || family === 'ipv6' && bytes.slice(0, 10).every(n => n === 0) && bytes[10] === 255 && bytes[11] === 255) return null;
    return { bytes, family };
}
function route(v: unknown): v is NetworkContextRoute {
    if (!exact(v, ['destination', 'destinationScopeId', 'nextHop', 'metric', 'protocol', 'origin']) || typeof v.destination !== 'string' || !integer(v.destinationScopeId, 0xffffffff) || !integer(v.metric, 0xffffffff) || !integer(v.protocol, 0xffffffff) || !integer(v.origin, 0xffffffff)) return false;
    const parts = v.destination.split('/');
    if (parts.length !== 2 || !/^(?:0|[1-9][0-9]{0,2})$/.test(parts[1])) return false;
    const destination = address(parts[0], false), nextHop = address(v.nextHop, true), bits = Number(parts[1]);
    if (!destination || !nextHop || destination.family === 'ipv4' && v.destinationScopeId !== 0 || destination.family !== nextHop.family || bits > destination.bytes.length * 8) return false;
    return destination.bytes.every((byte, i) => (byte & (255 >>> Math.max(0, Math.min(8, bits - i * 8)))) === 0);
}
export function validNetworkContextRow(v: unknown): v is NetworkContextRow {
    if (!exact(v, ['id', 'kind', 'interfaceIndex', 'route']) && !exact(v, ['id', 'kind', 'interfaceIndex', 'counters'])) return false;
    if (!integer(v.id, 4352) || v.id < 1 || !integer(v.interfaceIndex, 0xffffffff) || v.interfaceIndex < 1) return false;
    if (v.kind === 'route') return route(v.route);
    if (v.kind !== 'interface' || !exact(v.counters, ['alias', 'aliasQuality', 'inOctets', 'outOctets', 'inErrors', 'outErrors', 'inDiscards', 'outDiscards'])) return false;
    const c = v.counters;
    if (!(c.aliasQuality === 'observed' ? text(c.alias, 1024) && c.alias.length > 0 && c.alias.length <= 256 : c.aliasQuality === 'unavailable' && c.alias === null)) return false;
    return [c.inOctets, c.outOctets, c.inErrors, c.outErrors, c.inDiscards, c.outDiscards].every(validNetworkContextCounter);
}
export function compareNetworkContextRows(a: NetworkContextRow, b: NetworkContextRow, sort: NetworkContextSort): number {
    const direction = sort.endsWith('desc') ? -1 : 1;
    const kind = a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0;
    return sort.startsWith('interface') ? (a.interfaceIndex - b.interfaceIndex) * direction || kind || a.id - b.id : kind * direction || a.id - b.id;
}
const manifestKeys = ['schemaVersion', 'scope', 'source', 'coverage', 'deviceId', 'senderBinding', 'grantId', 'grantRevision', 'sequence', 'generationId', 'captureStartedAt', 'captureFinishedAt', 'expiresAt', 'rowCount', 'rowsBytes', 'rowsSha256', 'chunkCount'] as const;
export function networkContextManifestHash(manifest: NetworkContextManifest): string {
    const ordered = Object.fromEntries(manifestKeys.map(key => [key, manifest[key]]));
    return sha256Bytes(new TextEncoder().encode(`tracebolt.windows-network-context.manifest.v1\0${JSON.stringify(ordered)}`));
}
export function networkContextGenerationId(deviceId: string, grant: string, sequence: number): string {
    const prefix = new TextEncoder().encode(`tracebolt.windows-network-context.generation.v1\0${deviceId}\0${grant}`);
    const bytes = new Uint8Array(prefix.length + 8); bytes.set(prefix); new DataView(bytes.buffer).setBigUint64(prefix.length, BigInt(sequence));
    return `sample_${sha256Bytes(bytes).slice(0, 32)}`;
}
export function validNetworkContextComplete(v: unknown, deviceId: string, now: string): v is NetworkContextComplete {
    if (!exact(v, ['manifest', 'manifestSha256', 'receivedAt']) || !digest(v.manifestSha256) || !timestamp(v.receivedAt) || inventoryAge(now, v.receivedAt) < 0 || !exact(v.manifest, manifestKeys)) return false;
    const m = v.manifest;
    if (m.schemaVersion !== 'tracebolt.windows-network-context-manifest.v1' || m.scope !== 'windows-network-context-v1' || m.source !== 'ip-helper-routes-and-raw-interface-counters' || m.coverage !== 'caller_visible_tables_complete_nonatomic' || m.deviceId !== deviceId || !digest(m.senderBinding) || !grantId(m.grantId) || !positive(m.grantRevision) || !positive(m.sequence) || !generationId(m.generationId) || !timestamp(m.captureStartedAt) || !timestamp(m.captureFinishedAt) || !timestamp(m.expiresAt) || !integer(m.rowCount, 4352) || !integer(m.rowsBytes, 2 << 20) || m.rowsBytes < 2 || !digest(m.rowsSha256) || !integer(m.chunkCount, 64) || m.chunkCount < 1) return false;
    if (networkContextManifestHash(m as unknown as NetworkContextManifest) !== v.manifestSha256 || networkContextGenerationId(deviceId, m.grantId, m.sequence) !== m.generationId) return false;
    const duration = inventoryAge(m.captureFinishedAt, m.captureStartedAt);
    return duration >= 0 && duration <= 5000 && inventoryAge(v.receivedAt, m.captureFinishedAt) >= 0 && inventoryAge(m.expiresAt, m.captureStartedAt) === 86400000 && inventoryAge(m.expiresAt, now) > 0 && (m.rowCount === 0 ? m.chunkCount === 1 && m.rowsBytes === 2 && m.rowsSha256 === sha256Bytes(new TextEncoder().encode('tracebolt.windows-network-context.rows.v1\0[]')) : m.chunkCount <= m.rowCount && m.rowCount <= m.chunkCount * 128 && m.rowsBytes > 0);
}
export function sameNetworkContextComplete(a: NetworkContextComplete, b: NetworkContextComplete): boolean {
    return a.manifestSha256 === b.manifestSha256 && a.receivedAt === b.receivedAt && manifestKeys.every(k => a.manifest[k] === b.manifest[k]);
}
export function validNetworkContextPage(v: unknown, deviceId: string, query: NetworkContextQuery, expectedOffset: number): v is NetworkContextPage {
    if (!exact(v, ['kind', 'schemaVersion', 'deviceId', 'serverNow', 'status', 'authorityUntil', 'grantId', 'grantRevision', 'complete', 'latestAttempt', 'search', 'sort', 'limit', 'offset', 'matchingCount', 'rows', 'nextCursor', 'cursorExpiresAt']) || !validNetworkContextKind(v.kind) || v.kind !== query.kind || v.schemaVersion !== 'tracebolt.windows-network-context-page.v1' || !validWindowsDeviceId(deviceId) || v.deviceId !== deviceId || !timestamp(v.serverNow) || !member(v.status, ['not_configured', 'disabled', 'awaiting', 'ready', 'unavailable']) || !validNetworkContextSearch(v.search) || v.search !== query.search || !validNetworkContextSort(v.sort) || v.sort !== query.sort || v.limit !== query.limit || !integer(v.limit, NETWORK_CONTEXT_PAGE_ROWS) || v.limit < 1 || !integer(v.offset, 4352) || !integer(v.matchingCount, 4352) || !Array.isArray(v.rows) || v.rows.length > query.limit || !v.rows.every(validNetworkContextRow) || !validNetworkContextCursor(v.nextCursor)) return false;
    const authority = timestamp(v.authorityUntil) && inventoryAge(v.authorityUntil, v.serverNow) > 0 && grantId(v.grantId) && positive(v.grantRevision);
    if (!authority && !(v.authorityUntil === null && v.grantId === null && v.grantRevision === null)) return false;
    if (v.latestAttempt !== null) {
        const a = v.latestAttempt;
        if (!exact(a, ['sequence', 'attemptedAt', 'status', 'reason']) || !positive(a.sequence) || !timestamp(a.attemptedAt) || inventoryAge(v.serverNow, a.attemptedAt) < 0 || !member(a.status, ['pending', 'complete', 'source_failed', 'expired']) || !(a.status === 'source_failed' ? member(a.reason, networkContextReasons) : a.reason === '')) return false;
    }
    if (v.status !== 'ready') return v.complete === null && v.rows.length === 0 && v.offset === 0 && v.matchingCount === 0 && v.nextCursor === '' && v.cursorExpiresAt === null && (v.status !== 'not_configured' || v.latestAttempt === null) && (v.status !== 'awaiting' && v.status !== 'disabled' || authority);
    if (!authority || !validNetworkContextComplete(v.complete, deviceId, v.serverNow) || !timestamp(v.cursorExpiresAt) || inventoryAge(v.cursorExpiresAt, v.serverNow) <= 0 || inventoryAge(v.cursorExpiresAt, v.serverNow) > 900000 || inventoryAge(v.complete.manifest.expiresAt, v.cursorExpiresAt) < 0 || inventoryAge(v.authorityUntil as string, v.cursorExpiresAt) < 0 || v.complete.manifest.grantId !== v.grantId || v.complete.manifest.grantRevision !== v.grantRevision || v.offset !== expectedOffset || v.matchingCount > v.complete.manifest.rowCount || v.offset > v.matchingCount || v.rows.length > Math.min(query.limit, v.matchingCount - v.offset) || v.rows.length === 0 && v.offset < v.matchingCount || (v.nextCursor !== '') !== (v.offset + v.rows.length < v.matchingCount) || v.nextCursor !== '' && v.nextCursor === query.cursor || new Set(v.rows.map(row => row.id)).size !== v.rows.length) return false;
    const rows = v.rows as NetworkContextRow[], rowCount = v.complete.manifest.rowCount;
    if (!rows.every((row, i) => i === 0 || compareNetworkContextRows(rows[i - 1], row, query.sort) < 0)) return false;
    if (!rows.every(row => row.id <= rowCount && (v.kind === 'all' || row.kind === v.kind)) || v.kind === 'route' && v.matchingCount > 4096 || v.kind === 'interface' && v.matchingCount > 256) return false;
    if (v.kind === 'all' && v.search === '' && v.matchingCount !== v.complete.manifest.rowCount) return false;
    if (!v.latestAttempt || (v.latestAttempt as NetworkContextAttempt).sequence < v.complete.manifest.sequence) return false;
    const attempt = v.latestAttempt as NetworkContextAttempt;
    if (attempt.sequence === v.complete.manifest.sequence && (attempt.status !== 'complete' || attempt.attemptedAt !== v.complete.manifest.captureStartedAt)) return false;
    return true;
}
export function networkContextVisible(page: NetworkContextPage, elapsedMS: number): boolean {
    return page.status === 'ready' && page.complete !== null && page.authorityUntil !== null && page.cursorExpiresAt !== null && Number.isFinite(elapsedMS) && elapsedMS >= 0 && [page.complete.manifest.expiresAt, page.authorityUntil, page.cursorExpiresAt].every(expiry => inventoryAge(expiry, page.serverNow) > elapsedMS);
}
