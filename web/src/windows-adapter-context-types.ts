import { inventoryAge } from './complete-packages-types';
import { numericWindowsAddress } from './windows-numeric-address';

export const WINDOWS_ADAPTER_CONTEXT_BYTES = 16 * 1024;
export const WINDOWS_ADAPTER_CONTEXT_ROWS = 32;
export const WINDOWS_ADAPTER_STATES = ['up', 'down', 'testing', 'unknown', 'dormant', 'not-present', 'lower-layer-down'] as const;
export interface WindowsAdapterAddresses { quality: 'observed' | 'partial' | 'unavailable'; addresses: string[] }
export interface WindowsAdapterContextRow {
    ifIndex: number; ipv6IfIndex: number; name: string; state: typeof WINDOWS_ADAPTER_STATES[number];
    txLinkBps: number | null; txQuality: 'observed' | 'unknown' | 'unavailable';
    rxLinkBps: number | null; rxQuality: 'observed' | 'unknown' | 'unavailable';
    dnsServers: WindowsAdapterAddresses; gateways: WindowsAdapterAddresses;
}
export interface WindowsAdapterContext {
    schemaVersion: 'tracebolt.windows-adapter-context.v1'; scope: 'windows-adapter-context-v1';
    grantId: string; generationId: string; collectedAt: string;
    quality: 'observed' | 'partial' | 'denied' | 'unavailable' | 'unsupported'; countExact: boolean; observedCount: number; truncated: boolean;
    rows: WindowsAdapterContextRow[];
}
const exact = (v: unknown, keys: readonly string[]): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const integer = (v: unknown, max = 4294967295): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0) && v >= 0 && v <= max;
const timestamp = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number(v.slice(0, 4)) >= 1970 && Number.isFinite(Date.parse(v)) && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19);
/** Numeric local parsing only: these observations are never URLs or DNS lookups. */
function address(v: unknown): v is string {
    if (typeof v !== 'string' || v.length > 56) return false;
    const parts = v.split('%'), family = parts[0].includes(':') ? 'ipv6' : 'ipv4';
    if (parts.length > 2 || parts.length === 2 && (family !== 'ipv6' || !/^[1-9]\d{0,9}$/.test(parts[1]) || !integer(Number(parts[1])))) return false;
    return numericWindowsAddress(parts[0], family) !== null;
}
function addresses(v: unknown): v is WindowsAdapterAddresses {
    return exact(v, ['quality', 'addresses']) && ['observed', 'partial', 'unavailable'].includes(v.quality as string) && Array.isArray(v.addresses) && v.addresses.length <= 8 && v.addresses.every(address) &&
        (v.quality !== 'unavailable' || v.addresses.length === 0) && v.addresses.every((value, i, all) => i === 0 || all[i - 1] < value);
}
function speed(value: unknown, quality: unknown): boolean {
    return quality === 'observed' ? integer(value, Number.MAX_SAFE_INTEGER) && value > 0 : (quality === 'unknown' || quality === 'unavailable') && value === null;
}
function row(v: unknown): v is WindowsAdapterContextRow {
    return exact(v, ['ifIndex', 'ipv6IfIndex', 'name', 'state', 'txLinkBps', 'txQuality', 'rxLinkBps', 'rxQuality', 'dnsServers', 'gateways']) && integer(v.ifIndex) && integer(v.ipv6IfIndex) && (v.ifIndex > 0 || v.ipv6IfIndex > 0) &&
        typeof v.name === 'string' && v.name.length > 0 && new TextEncoder().encode(v.name).byteLength <= 96 && !/^[\p{White_Space}]|[\p{White_Space}]$/u.test(v.name) && !/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069\uD800-\uDFFF]/u.test(v.name) &&
        WINDOWS_ADAPTER_STATES.includes(v.state as typeof WINDOWS_ADAPTER_STATES[number]) && speed(v.txLinkBps, v.txQuality) && speed(v.rxLinkBps, v.rxQuality) && addresses(v.dnsServers) && addresses(v.gateways);
}
function compare(a: WindowsAdapterContextRow, b: WindowsAdapterContextRow): number {
    return a.ifIndex - b.ifIndex || a.ipv6IfIndex - b.ipv6IfIndex || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
}
export function validWindowsAdapterContext(v: unknown, generation: string, serverNow: string): v is WindowsAdapterContext {
    if (!exact(v, ['schemaVersion', 'scope', 'grantId', 'generationId', 'collectedAt', 'quality', 'countExact', 'observedCount', 'truncated', 'rows']) || v.schemaVersion !== 'tracebolt.windows-adapter-context.v1' || v.scope !== 'windows-adapter-context-v1' || typeof v.grantId !== 'string' || !/^[a-f0-9]{32}$/.test(v.grantId) || typeof v.generationId !== 'string' || !/^sample_[a-f0-9]{32}$/.test(v.generationId) || v.generationId !== generation || !timestamp(v.collectedAt) || !timestamp(serverNow) || inventoryAge(v.collectedAt, serverNow) > 30000 || inventoryAge(serverNow, v.collectedAt) >= 86400000 || typeof v.countExact !== 'boolean' || !integer(v.observedCount, 128) || typeof v.truncated !== 'boolean' || !Array.isArray(v.rows) || v.rows.length > WINDOWS_ADAPTER_CONTEXT_ROWS || !v.rows.every(row) || v.observedCount < v.rows.length || v.truncated !== (v.observedCount > v.rows.length)) return false;
    const rows = v.rows as WindowsAdapterContextRow[];
    if (rows.some((value, i) => i > 0 && (compare(rows[i - 1], value) > 0 || rows[i - 1].ifIndex === value.ifIndex && rows[i - 1].ipv6IfIndex === value.ipv6IfIndex))) return false;
    if (v.quality === 'observed' ? !v.countExact : v.quality === 'partial' ? v.countExact : !['denied', 'unavailable', 'unsupported'].includes(v.quality as string) || v.countExact || v.observedCount !== 0 || rows.length !== 0) return false;
    // Match Go JSON's HTML escaping so names cannot evade the source byte cap.
    const encoded = JSON.stringify(v).replace(/[<>&\u2028\u2029]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
    return new TextEncoder().encode(encoded).byteLength <= WINDOWS_ADAPTER_CONTEXT_BYTES;
}
