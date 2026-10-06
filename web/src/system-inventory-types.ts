import { inventoryAge, inventorySequence } from './complete-packages-types';

export type SystemSection = 'services' | 'sockets';
export const systemFilters = { services: ['all', 'active', 'failed', 'enabled'], sockets: ['all', 'tcp-listeners', 'udp', 'connections'] } as const;
export type SystemFilter = typeof systemFilters[SystemSection][number];
export const SYSTEM_STATUS_BYTES = 16384, SYSTEM_PAGE_BYTES = 262144;
// Keep the released protected response helper's byte ceiling unchanged.
export const systemPageSize = (section: SystemSection) => section === 'services' ? 100 : 25;
export const systemFailureReasons = ['source_missing', 'permission_denied', 'not_supported', 'timeout', 'invalid_source', 'read_failed', 'item_limit', 'byte_limit', 'collector_busy', 'not_collected'] as const;
export const attributionReasons = ['permission_denied', 'timeout', 'invalid_source', 'read_failed', 'no_match', 'process_gone', 'work_limit', 'owner_limit', 'not_collected', 'not_supported'] as const;
export type SystemReason = 'none' | typeof systemFailureReasons[number] | typeof attributionReasons[number];
export interface SectionMeta { generationId: string; observedAt: string; coverage: 'complete' | 'failed'; reason: SystemReason; observedCount: number | null; countExact: boolean }
export interface ServiceRow { name: string; runtime: null | { loadState: string; activeState: string; subState: string }; enablement: string | null; mainPid: null }
export interface SocketRow {
    protocol: 'tcp' | 'udp'; family: 'ipv4' | 'ipv6'; kind: 'listener' | 'bound' | 'connection' | 'unclassified'; local: { address: string; port: number }; remote: { address: string; port: number }; state: string;
    owners: { pid: number; processName: string | null; nameReason: SystemReason }[]; attribution: { coverage: 'observed' | 'partial' | 'unavailable'; reason: SystemReason };
}
export interface SocketOwnerProvenance {
    schemaVersion: 'tracebolt.socket-owner-source.v1'; scope: 'systemd-pid1-local-tcp-udp-socket-owners';
    grantEpoch: string; policyDigest: string; authorityRevision: string; contextId: string; startedAt: string; finishedAt: string;
}
export interface SystemSummary { sequence: string; meta: SectionMeta; status: 'fresh' | 'stale'; socketOwnerProvenance?: SocketOwnerProvenance }
export interface SystemView {
    schemaVersion: 'tracebolt.system-inventory-view.v1'; deviceId: string; collectionProfile: string; status: 'not_configured' | 'unknown' | 'awaiting' | 'fresh' | 'stale' | 'revoked' | 'expired'; serverNow: string; maxAgeSeconds: 120; sequence: string | null; receivedAt: string | null;
    latest: null | { generationId: string; collectedAt: string; durationMs: number; scope: 'agent-visible-linux-system'; services: SectionMeta; sockets: SectionMeta; socketOwnerProvenance?: SocketOwnerProvenance };
    lastComplete: { services: SystemSummary | null; sockets: SystemSummary | null };
}
export interface SystemPage {
    schemaVersion: 'tracebolt.system-inventory-page.v1'; deviceId: string; serverNow: string; collectionProfile: 'managed-operations-v3'; section: SystemSection; generationId: string; meta: SectionMeta; status: 'fresh' | 'stale'; totalRows: number; returnedCount: number; scannedCount: number; exhausted: boolean; nextCursor: string; cursorExpiresAt: string | null; services: ServiceRow[]; sockets: SocketRow[]; socketOwnerProvenance?: SocketOwnerProvenance;
}
const record = (v: unknown, keys: readonly string[]): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const sourceRecord = (v: unknown, keys: readonly string[]): v is Record<string, unknown> => record(v, keys) || record(v, [...keys, 'socketOwnerProvenance']);
const sourceKeys = ['schemaVersion', 'scope', 'grantEpoch', 'policyDigest', 'authorityRevision', 'contextId', 'startedAt', 'finishedAt'] as const;
// Preserve sub-millisecond source boundaries; Date.parse alone truncates them.
function timestampNanos(v: string): bigint { return BigInt(Date.parse(v.slice(0, 19) + 'Z')) * 1000000n + BigInt((v.slice(19, -1).slice(1) || '').padEnd(9, '0')); }
function validSocketSource(v: unknown, observedAt: string, now: string, durationMs?: number): v is SocketOwnerProvenance {
    if (!record(v, sourceKeys) || v.schemaVersion !== 'tracebolt.socket-owner-source.v1' || v.scope !== 'systemd-pid1-local-tcp-udp-socket-owners') return false;
    for (const key of ['grantEpoch', 'policyDigest', 'authorityRevision', 'contextId']) if (typeof v[key] !== 'string' || !/^[a-f0-9]{64}$/.test(v[key]) || /^0+$/.test(v[key])) return false;
    for (const key of ['startedAt', 'finishedAt']) if (!timestamp(v[key]) || /\.\d*0Z$/.test(v[key])) return false;
    const start = timestampNanos(v.startedAt as string), finish = timestampNanos(v.finishedAt as string), batch = timestampNanos(observedAt);
    return start >= batch && finish >= start && finish - start <= 5000000000n && finish <= timestampNanos(now) && (durationMs === undefined || finish - batch < (BigInt(durationMs) + 1n) * 1000000n);
}
function sameSocketSource(a: unknown, b: unknown): boolean {
    if (a === undefined || b === undefined) return a === b;
    return record(a, sourceKeys) && record(b, sourceKeys) && sourceKeys.every(key => a[key] === b[key]);
}
const integer = (v: unknown, max = Number.MAX_SAFE_INTEGER): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v <= max;
const member = (v: unknown, list: readonly string[]): boolean => typeof v === 'string' && list.includes(v);
const generation = (v: unknown): v is string => typeof v === 'string' && /^sample_[a-f0-9]{32}$/.test(v);
const stateCode = (v: unknown): v is string => typeof v === 'string' && /^[a-z][a-z0-9-]{0,63}$/.test(v);
function timestamp(v: unknown): v is string { return typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number.isFinite(Date.parse(v)) && Number(v.slice(0, 4)) >= 1970 && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19); }
const sectionLimit = (section: SystemSection) => section === 'services' ? 8192 : 16384;
export function systemAgeStatus(now: string, then: string, elapsed = 0): 'fresh' | 'stale' | 'expired' | 'unknown' {
    const age = inventoryAge(now, then) + elapsed;
    return !Number.isFinite(elapsed) || elapsed < 0 || age < 0 ? 'unknown' : age >= 86400000 ? 'expired' : age > 120000 ? 'stale' : 'fresh';
}
export function validSectionMeta(v: unknown, section: SystemSection): v is SectionMeta {
    return record(v, ['generationId', 'observedAt', 'coverage', 'reason', 'observedCount', 'countExact']) && generation(v.generationId) && timestamp(v.observedAt) && (v.coverage === 'complete' ? v.reason === 'none' && v.countExact === true && integer(v.observedCount, sectionLimit(section)) : v.coverage === 'failed' && member(v.reason, systemFailureReasons) && v.countExact === false && v.observedCount === null);
}
export function validServiceRow(v: unknown): v is ServiceRow {
    if (!record(v, ['name', 'runtime', 'enablement', 'mainPid']) || typeof v.name !== 'string' || v.name.length < 9 || v.name.length > 255 || !/^(?:[a-zA-Z0-9_.:@-]|\\x[a-f0-9]{2})+\.service$/.test(v.name) || v.mainPid !== null || v.runtime === null && v.enablement === null || !(v.enablement === null || stateCode(v.enablement))) return false;
    return v.runtime === null || record(v.runtime, ['loadState', 'activeState', 'subState']) && Object.values(v.runtime).every(stateCode);
}
function ipv4(value: string): number[] | null { const parts = value.split('.'); return parts.length === 4 && parts.every(p => /^(?:0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255) ? parts.map(Number) : null; }
/** Numeric addresses only, matching netip's canonical zero compression and
 * IPv4-mapped form. No URL interpretation, zone, DNS, or network operation. */
function validAddress(value: unknown, family: unknown): value is string {
    if (typeof value !== 'string' || value.length > 45) return false;
    if (family === 'ipv4') return ipv4(value) !== null;
    if (family !== 'ipv6' || !/^[a-f0-9:.]+$/.test(value)) return false;
    let expanded = value;
    if (expanded.includes('.')) { const last = expanded.lastIndexOf(':'), tail = ipv4(expanded.slice(last + 1)); if (!tail) return false; expanded = expanded.slice(0, last + 1) + ((tail[0] << 8) + tail[1]).toString(16) + ':' + ((tail[2] << 8) + tail[3]).toString(16); }
    const sides = expanded.split('::'); if (sides.length > 2) return false;
    const left = sides[0] ? sides[0].split(':') : [], right = sides.length === 2 && sides[1] ? sides[1].split(':') : [];
    if (![...left, ...right].every(p => /^[a-f0-9]{1,4}$/.test(p))) return false;
    const missing = 8 - left.length - right.length;
    if (sides.length === 1 ? missing !== 0 : missing < 1) return false;
    const numbers = [...left.map(p => parseInt(p, 16)), ...Array(sides.length === 2 ? missing : 0).fill(0), ...right.map(p => parseInt(p, 16))] as number[];
    if (numbers.slice(0, 5).every(n => n === 0) && numbers[5] === 65535) return value === `::ffff:${numbers[6] >> 8}.${numbers[6] & 255}.${numbers[7] >> 8}.${numbers[7] & 255}`;
    let start = -1, length = 1;
    for (let i = 0; i < 8;) { if (numbers[i] !== 0) { i++; continue; } let end = i; while (end < 8 && numbers[end] === 0) end++; if (end - i > length) { start = i; length = end - i; } i = end; }
    const hex = numbers.map(n => n.toString(16));
    return value === (start < 0 ? hex.join(':') : hex.slice(0, start).join(':') + '::' + hex.slice(start + length).join(':'));
}
const safeText = (v: unknown, max: number): v is string => typeof v === 'string' && v.length > 0 && new TextEncoder().encode(v).byteLength <= max && !/[\p{Cc}\p{Cf}\uFFFD\uD800-\uDFFF]/u.test(v);
const socketKinds: Record<string, string> = { listen: 'listener', 'bound-inactive': 'bound', closed: 'unclassified', established: 'connection', 'syn-sent': 'connection', 'syn-recv': 'connection', 'fin-wait-1': 'connection', 'fin-wait-2': 'connection', 'time-wait': 'connection', 'close-wait': 'connection', 'last-ack': 'connection', closing: 'connection', 'new-syn-recv': 'connection' };
export function validSocketRow(v: unknown): v is SocketRow {
    if (!record(v, ['protocol', 'family', 'kind', 'local', 'remote', 'state', 'owners', 'attribution']) || !member(v.protocol, ['tcp', 'udp']) || !member(v.family, ['ipv4', 'ipv6']) || typeof v.state !== 'string' || !Array.isArray(v.owners) || v.owners.length > 16) return false;
    for (const endpoint of [v.local, v.remote]) if (!record(endpoint, ['address', 'port']) || !validAddress(endpoint.address, v.family) || !integer(endpoint.port, 65535)) return false;
    const kind = v.protocol === 'tcp' ? socketKinds[v.state] : ({ bound: 'bound', connected: 'connection', unbound: 'unclassified' } as Record<string, string>)[v.state];
    if (!kind || kind !== v.kind || v.protocol === 'udp' && (v.state === 'unbound') !== ((v.local as { port: number }).port === 0 && (v.remote as { port: number }).port === 0)) return false;
    const a = v.attribution;
    if (!record(a, ['coverage', 'reason']) || (a.coverage === 'observed' ? a.reason !== 'none' || v.owners.length === 0 : a.coverage === 'partial' ? !member(a.reason, attributionReasons) : a.coverage !== 'unavailable' || !member(a.reason, attributionReasons) || v.owners.length !== 0)) return false;
    let pid = 0;
    for (const owner of v.owners) {
        if (!record(owner, ['pid', 'processName', 'nameReason']) || !integer(owner.pid, 2147483647) || owner.pid <= pid || (owner.processName === null ? !member(owner.nameReason, attributionReasons) || owner.nameReason === 'no_match' || a.coverage === 'observed' : !safeText(owner.processName, 64) || owner.nameReason !== 'none')) return false;
        pid = owner.pid;
    }
    return true;
}
export function validSystemView(v: unknown, deviceId: string): v is SystemView {
    if (!record(v, ['schemaVersion', 'deviceId', 'collectionProfile', 'status', 'serverNow', 'maxAgeSeconds', 'sequence', 'receivedAt', 'latest', 'lastComplete']) || v.schemaVersion !== 'tracebolt.system-inventory-view.v1' || v.deviceId !== deviceId || !/^agent_[A-Za-z0-9_-]{1,120}$/.test(deviceId) || !member(v.collectionProfile, ['', 'basic-readonly-v1', 'managed-operations-v1', 'managed-operations-v2', 'managed-operations-v3']) || !member(v.status, ['not_configured', 'unknown', 'awaiting', 'fresh', 'stale', 'revoked', 'expired']) || !timestamp(v.serverNow) || v.maxAgeSeconds !== 120 || !(v.sequence === null || inventorySequence(v.sequence)) || !(v.receivedAt === null || timestamp(v.receivedAt) && inventoryAge(v.serverNow, v.receivedAt) >= 0) || (v.sequence === null) !== (v.receivedAt === null) || !record(v.lastComplete, ['services', 'sockets'])) return false;
    const latest = v.latest;
    if (latest !== null) {
        if (!sourceRecord(latest, ['generationId', 'collectedAt', 'durationMs', 'scope', 'services', 'sockets']) || !generation(latest.generationId) || !timestamp(latest.collectedAt) || !integer(latest.durationMs) || latest.scope !== 'agent-visible-linux-system' || v.sequence === null || !timestamp(v.receivedAt) || inventoryAge(v.receivedAt, latest.collectedAt) < 0 || inventoryAge(v.receivedAt, latest.collectedAt) > 120000 || v.status !== systemAgeStatus(v.serverNow, latest.collectedAt)) return false;
        for (const section of ['services', 'sockets'] as const) if (!validSectionMeta(latest[section], section) || latest[section].generationId !== latest.generationId || latest[section].observedAt !== latest.collectedAt) return false;
        if (Object.hasOwn(latest, 'socketOwnerProvenance') && ((latest.sockets as SectionMeta).coverage !== 'complete' || !validSocketSource(latest.socketOwnerProvenance, latest.collectedAt, v.receivedAt, latest.durationMs))) return false;
    }
    for (const section of ['services', 'sockets'] as const) {
        const complete = v.lastComplete[section]; if (complete === null) { if (latest !== null && (latest[section] as SectionMeta).coverage === 'complete') return false; continue; }
        if (!sourceRecord(complete, ['sequence', 'meta', 'status']) || !inventorySequence(complete.sequence) || !validSectionMeta(complete.meta, section) || complete.meta.coverage !== 'complete' || !member(complete.status, ['fresh', 'stale']) || complete.status !== systemAgeStatus(v.serverNow, complete.meta.observedAt) || !inventorySequence(v.sequence) || BigInt(complete.sequence) > BigInt(v.sequence) || latest !== null && inventoryAge(latest.collectedAt as string, complete.meta.observedAt) < 0) return false;
        if (Object.hasOwn(complete, 'socketOwnerProvenance') && (section !== 'sockets' || !validSocketSource(complete.socketOwnerProvenance, complete.meta.observedAt, v.serverNow))) return false;
        if (section === 'sockets' && latest !== null && (latest.sockets as SectionMeta).coverage === 'complete' && !sameSocketSource(complete.socketOwnerProvenance, latest.socketOwnerProvenance)) return false;
        if (latest !== null && (latest[section] as SectionMeta).coverage === 'complete' && (complete.sequence !== v.sequence || !sameSectionMeta(complete.meta, latest[section] as SectionMeta))) return false;
    }
    if (v.collectionProfile !== 'managed-operations-v3') return member(v.status, ['not_configured', 'unknown']) && v.sequence === null && latest === null && v.lastComplete.services === null && v.lastComplete.sockets === null;
    if (member(v.status, ['not_configured', 'unknown', 'awaiting', 'revoked', 'expired'])) return latest === null && v.lastComplete.services === null && v.lastComplete.sockets === null;
    return latest !== null;
}
export function sameSectionMeta(a: SectionMeta, b: SectionMeta): boolean { return a.generationId === b.generationId && a.observedAt === b.observedAt && a.coverage === b.coverage && a.reason === b.reason && a.observedCount === b.observedCount && a.countExact === b.countExact; }
export function systemSectionVisible(v: SystemView, section: SystemSection, elapsed: number): boolean {
    const summary = v.lastComplete[section]; return !!summary && !['not_configured', 'revoked', 'expired', 'unknown', 'awaiting'].includes(v.status) && ['fresh', 'stale'].includes(systemAgeStatus(v.serverNow, summary.meta.observedAt, elapsed));
}
export function validSystemSearch(value: string): boolean { return new TextEncoder().encode(value).byteLength <= 128 && !/[\p{Cc}\p{Cf}\uFFFD\uD800-\uDFFF]/u.test(value); }
export function validSystemPage(v: unknown, deviceId: string, section: SystemSection, selected: SystemSummary, cursor: string, search = '', filter: SystemFilter = 'all'): v is SystemPage {
    if (!sourceRecord(v, ['schemaVersion', 'deviceId', 'serverNow', 'collectionProfile', 'section', 'generationId', 'meta', 'status', 'totalRows', 'returnedCount', 'scannedCount', 'exhausted', 'nextCursor', 'cursorExpiresAt', 'services', 'sockets']) || v.schemaVersion !== 'tracebolt.system-inventory-page.v1' || v.deviceId !== deviceId || v.collectionProfile !== 'managed-operations-v3' || v.section !== section || v.generationId !== selected.meta.generationId || !validSectionMeta(v.meta, section) || !sameSectionMeta(v.meta, selected.meta) || !timestamp(v.serverNow) || !member(v.status, ['fresh', 'stale']) || v.status !== systemAgeStatus(v.serverNow, v.meta.observedAt) || v.totalRows !== v.meta.observedCount || !integer(v.returnedCount, systemPageSize(section)) || !integer(v.scannedCount, Math.min(2048, v.totalRows as number)) || v.returnedCount > v.scannedCount || typeof v.exhausted !== 'boolean' || typeof v.nextCursor !== 'string' || new TextEncoder().encode(v.nextCursor).byteLength > 2048 || (v.exhausted ? v.nextCursor !== '' : v.nextCursor === '' || v.nextCursor === cursor || v.scannedCount === 0) || !(v.cursorExpiresAt === null ? v.exhausted : timestamp(v.cursorExpiresAt) && inventoryAge(v.cursorExpiresAt, v.serverNow) > 0 && inventoryAge(v.cursorExpiresAt, v.serverNow) <= 900000 && inventoryAge(v.cursorExpiresAt, v.meta.observedAt) <= 86400000) || !Array.isArray(v.services) || !Array.isArray(v.sockets) || (section === 'services' ? v.services : v.sockets).length !== v.returnedCount || (section === 'services' ? v.sockets : v.services).length !== 0) return false;
    if (Object.hasOwn(v, 'socketOwnerProvenance') && (section !== 'sockets' || !validSocketSource(v.socketOwnerProvenance, v.meta.observedAt, v.serverNow)) || !sameSocketSource(v.socketOwnerProvenance, selected.socketOwnerProvenance)) return false;
    if (!search.trim() && filter === 'all' && v.scannedCount !== v.returnedCount) return false;
    let previous = '';
    for (const row of v.services) { if (!validServiceRow(row) || row.name <= previous || filter === 'active' && row.runtime?.activeState !== 'active' || filter === 'failed' && row.runtime?.activeState !== 'failed' || filter === 'enabled' && row.enablement !== 'enabled' && row.enablement !== 'enabled-runtime') return false; previous = row.name; }
    return v.sockets.every(row => validSocketRow(row) && (filter !== 'tcp-listeners' || row.protocol === 'tcp' && row.kind === 'listener') && (filter !== 'udp' || row.protocol === 'udp') && (filter !== 'connections' || row.kind === 'connection'));
}
