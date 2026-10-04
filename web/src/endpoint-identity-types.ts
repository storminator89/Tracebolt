import { inventoryAge, inventorySequence } from './complete-packages-types';

/** Display-only observations. Never merge into Device, AI, a URL or a connection target. */
export const ENDPOINT_VIEW_BYTES = 16384, ENDPOINT_SNAPSHOT_BYTES = 8192;
export const endpointFailureReasons = ['source_missing', 'permission_denied', 'not_supported', 'timeout', 'invalid_source', 'read_failed', 'item_limit', 'byte_limit', 'collector_busy', 'not_collected'] as const;
export type EndpointReason = 'none' | 'address_unavailable' | typeof endpointFailureReasons[number];
export type EndpointStatus = 'not_collected' | 'fresh' | 'stale' | 'expired' | 'revoked' | 'unknown';
export interface EndpointMeta { coverage: 'complete' | 'partial' | 'failed'; reason: EndpointReason; observedCount: number | null; countExact: boolean }
export interface EndpointAddress { family: 'ipv4' | 'ipv6'; address: string; scope: 'unspecified' | 'loopback' | 'link-local' | 'multicast' | 'private' | 'other' }
export interface EndpointAddresses { meta: EndpointMeta; items: EndpointAddress[] }
export interface EndpointInterface { index: number; name: string; up: boolean; loopback: boolean; hardwareKind: 'unknown'; addresses: { ipv4: EndpointAddresses; ipv6: EndpointAddresses } }
export interface EndpointSnapshot {
    schemaVersion: 'tracebolt.endpoint-identity.v1'; generationId: string; collectedAt: string; durationMs: number; scope: 'agent-visible-linux-hostname-and-interface-addresses';
    reportedHostname: { coverage: 'complete' | 'failed'; reason: EndpointReason; value: string | null };
    interfaces: { meta: EndpointMeta; items: EndpointInterface[] };
}
export interface EndpointIdentityView {
    schemaVersion: 'tracebolt.endpoint-identity-view.v1'; deviceId: string; status: EndpointStatus; serverNow: string; maxAgeSeconds: 120;
    sequence: string | null; receivedAt: string | null; expiresAt: string | null; latest: EndpointSnapshot | null;
}
const record = (v: unknown, keys: readonly string[]): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const integer = (v: unknown, max = Number.MAX_SAFE_INTEGER): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v <= max;
const member = (v: unknown, list: readonly string[]): boolean => typeof v === 'string' && list.includes(v);
export const validEndpointDeviceId = (v: string): boolean => /^agent_[A-Za-z0-9_-]{1,120}$/.test(v);
const timestamp = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number.isFinite(Date.parse(v)) && Number(v.slice(0, 4)) >= 1970 && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19);
const text = (v: unknown, max: number): v is string => typeof v === 'string' && v.length > 0 && v.trim() === v && new TextEncoder().encode(v).byteLength <= max && !/[\p{Cc}\p{Cf}\uFFFD\uD800-\uDFFF\u2028\u2029]/u.test(v);
function meta(v: unknown, n: number, partial = false): v is EndpointMeta {
    if (!record(v, ['coverage', 'reason', 'observedCount', 'countExact'])) return false;
    if (v.coverage === 'complete') return v.reason === 'none' && v.countExact === true && v.observedCount === n;
    if (v.coverage === 'partial') return partial && n > 0 && v.reason === 'address_unavailable' && v.countExact === true && v.observedCount === n;
    return v.coverage === 'failed' && member(v.reason, endpointFailureReasons) && v.countExact === false && v.observedCount === null && n === 0;
}
function ipv4(v: string): number[] | null {
    const parts = v.split('.'); return parts.length === 4 && parts.every(p => /^(?:0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255) ? parts.map(Number) : null;
}
/** Canonical numeric netip spelling, parsed locally without URL/DNS interpretation. */
function numericAddress(v: unknown, family: 'ipv4' | 'ipv6'): number[] | null {
    if (typeof v !== 'string' || v.length > 45) return null;
    if (family === 'ipv4') return ipv4(v);
    if (!/^[a-f0-9:.]+$/.test(v)) return null;
    let expanded = v;
    if (expanded.includes('.')) {
        const last = expanded.lastIndexOf(':'), tail = ipv4(expanded.slice(last + 1)); if (!tail) return null;
        expanded = expanded.slice(0, last + 1) + ((tail[0] << 8) + tail[1]).toString(16) + ':' + ((tail[2] << 8) + tail[3]).toString(16);
    }
    const sides = expanded.split('::'); if (sides.length > 2) return null;
    const left = sides[0] ? sides[0].split(':') : [], right = sides.length === 2 && sides[1] ? sides[1].split(':') : [];
    if (![...left, ...right].every(p => /^[a-f0-9]{1,4}$/.test(p))) return null;
    const missing = 8 - left.length - right.length;
    if (sides.length === 1 ? missing !== 0 : missing < 1) return null;
    const words: number[] = [...left.map(p => parseInt(p, 16)), ...Array(sides.length === 2 ? missing : 0).fill(0), ...right.map(p => parseInt(p, 16))];
    if (words.slice(0, 5).every(n => n === 0) && words[5] === 65535) {
        if (v !== `::ffff:${words[6] >> 8}.${words[6] & 255}.${words[7] >> 8}.${words[7] & 255}`) return null;
    } else {
        let start = -1, length = 1;
        for (let i = 0; i < 8;) { if (words[i] !== 0) { i++; continue; } let end = i; while (end < 8 && words[end] === 0) end++; if (end - i > length) { start = i; length = end - i; } i = end; }
        const hex = words.map(n => n.toString(16));
        if (v !== (start < 0 ? hex.join(':') : hex.slice(0, start).join(':') + '::' + hex.slice(start + length).join(':'))) return null;
    }
    return words.flatMap(n => [n >> 8, n & 255]);
}
function addressScope(bytes: number[]): EndpointAddress['scope'] {
    // Go netip classifies mapped IPv6 using its embedded IPv4, except unspecified.
    if (bytes.every(n => n === 0)) return 'unspecified';
    let b = bytes;
    if (b.length === 16 && b.slice(0, 10).every(n => n === 0) && b[10] === 255 && b[11] === 255) b = b.slice(12);
    if (b.length === 4) {
        if (b[0] === 127) return 'loopback';
        if (b[0] === 169 && b[1] === 254) return 'link-local';
        if (b[0] >= 224 && b[0] <= 239) return 'multicast';
        if (b[0] === 10 || b[0] === 172 && b[1] >= 16 && b[1] <= 31 || b[0] === 192 && b[1] === 168) return 'private';
    } else {
        if (b.slice(0, 15).every(n => n === 0) && b[15] === 1) return 'loopback';
        if (b[0] === 254 && (b[1] & 192) === 128) return 'link-local';
        if (b[0] === 255) return 'multicast';
        if ((b[0] & 254) === 252) return 'private';
    }
    return 'other';
}
function addresses(v: unknown, family: 'ipv4' | 'ipv6'): v is EndpointAddresses {
    if (!record(v, ['meta', 'items']) || !Array.isArray(v.items) || v.items.length > 32 || !meta(v.meta, v.items.length)) return false;
    let previous: number[] | null = null;
    for (const row of v.items) {
        if (!record(row, ['family', 'address', 'scope']) || row.family !== family) return false;
        const bytes = numericAddress(row.address, family); if (!bytes || row.scope !== addressScope(bytes)) return false;
        if (previous) { const index = bytes.findIndex((n, i) => n !== previous![i]); if (index < 0 || bytes[index] < previous[index]) return false; }
        previous = bytes;
    }
    return true;
}
export function validEndpointSnapshot(v: unknown): v is EndpointSnapshot {
    if (!record(v, ['schemaVersion', 'generationId', 'collectedAt', 'durationMs', 'scope', 'reportedHostname', 'interfaces']) || v.schemaVersion !== 'tracebolt.endpoint-identity.v1' || v.scope !== 'agent-visible-linux-hostname-and-interface-addresses' || typeof v.generationId !== 'string' || !/^sample_[a-f0-9]{32}$/.test(v.generationId) || !timestamp(v.collectedAt) || !integer(v.durationMs)) return false;
    const h = v.reportedHostname, section = v.interfaces;
    if (!record(h, ['coverage', 'reason', 'value']) || (h.coverage === 'complete' ? h.reason !== 'none' || !text(h.value, 253) : h.coverage !== 'failed' || !member(h.reason, endpointFailureReasons) || h.value !== null)) return false;
    if (!record(section, ['meta', 'items']) || !Array.isArray(section.items) || section.items.length > 32 || !meta(section.meta, section.items.length, true)) return false;
    let previous = 0, count = 0, incomplete = false; const names = new Set<string>();
    for (const row of section.items) {
        if (!record(row, ['index', 'name', 'up', 'loopback', 'hardwareKind', 'addresses']) || !integer(row.index, 2147483647) || row.index <= previous || !text(row.name, 15) || row.name === '.' || row.name === '..' || /[\s/:\\]/u.test(row.name) || names.has(row.name) || typeof row.up !== 'boolean' || typeof row.loopback !== 'boolean' || row.hardwareKind !== 'unknown' || !record(row.addresses, ['ipv4', 'ipv6']) || !addresses(row.addresses.ipv4, 'ipv4') || !addresses(row.addresses.ipv6, 'ipv6')) return false;
        previous = row.index; names.add(row.name);
        const n = row.addresses.ipv4.items.length + row.addresses.ipv6.items.length; if (n > 32) return false; count += n;
        incomplete ||= row.addresses.ipv4.meta.coverage === 'failed' || row.addresses.ipv6.meta.coverage === 'failed';
    }
    if (count > 128 || (section.meta.coverage === 'partial') !== incomplete) return false;
    // Match Go's escaped JSON byte accounting as well as the transport ceiling.
    const encoded = JSON.stringify(v).replace(/[<>&\u2028\u2029]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
    return new TextEncoder().encode(encoded).byteLength <= ENDPOINT_SNAPSHOT_BYTES;
}
export function endpointAgeStatus(view: EndpointIdentityView, elapsed = 0): EndpointStatus {
    if (!Number.isFinite(elapsed) || elapsed < 0) return 'unknown';
    if (!view.latest || !['fresh', 'stale'].includes(view.status)) return view.status;
    const age = inventoryAge(view.serverNow, view.latest.collectedAt) + elapsed;
    return age < 0 ? 'unknown' : age >= 86400000 ? 'expired' : age > 120000 ? 'stale' : 'fresh';
}
export function endpointSnapshotVisible(view: EndpointIdentityView, elapsed: number): boolean { return view.latest !== null && ['fresh', 'stale'].includes(endpointAgeStatus(view, elapsed)); }
export function validEndpointView(v: unknown, deviceId: string): v is EndpointIdentityView {
    if (!record(v, ['schemaVersion', 'deviceId', 'status', 'serverNow', 'maxAgeSeconds', 'sequence', 'receivedAt', 'expiresAt', 'latest']) || v.schemaVersion !== 'tracebolt.endpoint-identity-view.v1' || !validEndpointDeviceId(deviceId) || v.deviceId !== deviceId || !member(v.status, ['not_collected', 'fresh', 'stale', 'expired', 'revoked', 'unknown']) || !timestamp(v.serverNow) || v.maxAgeSeconds !== 120) return false;
    const empty = v.sequence === null && v.receivedAt === null && v.expiresAt === null;
    if (!empty && (!inventorySequence(v.sequence) || !timestamp(v.receivedAt) || !timestamp(v.expiresAt) || inventoryAge(v.expiresAt, v.receivedAt) <= 0 || inventoryAge(v.expiresAt, v.receivedAt) > 86400000)) return false;
    if (v.status === 'not_collected' || v.status === 'revoked') return empty && v.latest === null;
    if (v.status === 'unknown') return empty && v.latest === null;
    if (v.status === 'expired') return v.latest === null && (empty || inventoryAge(v.serverNow, v.expiresAt as string) >= 0);
    if (empty || !validEndpointSnapshot(v.latest) || inventoryAge(v.receivedAt as string, v.latest.collectedAt) < 0 || inventoryAge(v.serverNow, v.receivedAt as string) < 0 || inventoryAge(v.expiresAt as string, v.latest.collectedAt) !== 86400000) return false;
    return endpointAgeStatus(v as unknown as EndpointIdentityView) === v.status;
}
