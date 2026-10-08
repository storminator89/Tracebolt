import { inventoryAge } from './complete-packages-types';
import { numericWindowsAddress } from './windows-numeric-address';

export const WINDOWS_NETWORK_BYTES = 12 * 1024;
export const WINDOWS_NETWORK_STATES = ['closed', 'listen', 'syn-sent', 'syn-received', 'established', 'fin-wait-1', 'fin-wait-2', 'close-wait', 'closing', 'last-ack', 'time-wait', 'delete-tcb'] as const;
export interface WindowsNetworkEndpoint {
    protocol: 'tcp' | 'udp'; family: 'ipv4' | 'ipv6'; localAddress: string; localPort: number;
    remoteAddress: string | null; remotePort: number | null; state: typeof WINDOWS_NETWORK_STATES[number] | null; pid: number;
}
export interface WindowsNetwork {
    schemaVersion: 'tracebolt.windows-network-endpoints.v1'; scope: 'windows-network-endpoints-v1';
    grantId: string; generationId: string; collectedAt: string;
    quality: 'observed' | 'partial' | 'denied' | 'unavailable'; countExact: boolean; observedCount: number; truncated: boolean;
    rows: WindowsNetworkEndpoint[];
}
const exact = (v: unknown, keys: readonly string[]): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const integer = (v: unknown, max = 4294967295): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0) && v >= 0 && v <= max;
const timestamp = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number(v.slice(0, 4)) >= 1970 && Number.isFinite(Date.parse(v)) && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19);
/** Numeric-only local parsing: never invokes URL interpretation, DNS or a network request. */
function address(v: unknown, family: 'ipv4' | 'ipv6'): number[] | null {
    if (typeof v !== 'string' || v.length > 56) return null;
    const parts = v.split('%');
    if (parts.length > 2 || parts.length === 2 && (family !== 'ipv6' || !/^[1-9]\d{0,9}$/.test(parts[1]) || !integer(Number(parts[1])))) return null;
    const bytes = numericWindowsAddress(parts[0], family);
    return bytes ? [...bytes, parts.length === 2 ? Number(parts[1]) : 0] : null;
}
function endpoint(v: unknown): v is WindowsNetworkEndpoint {
    if (!exact(v, ['protocol', 'family', 'localAddress', 'localPort', 'remoteAddress', 'remotePort', 'state', 'pid']) || !['tcp', 'udp'].includes(v.protocol as string) || v.family !== 'ipv4' && v.family !== 'ipv6' || !address(v.localAddress, v.family) || !integer(v.localPort, 65535) || !integer(v.pid)) return false;
    if (v.protocol === 'udp') return v.remoteAddress === null && v.remotePort === null && v.state === null;
    if (typeof v.state !== 'string' || !WINDOWS_NETWORK_STATES.includes(v.state as typeof WINDOWS_NETWORK_STATES[number])) return false;
    // Windows leaves a LISTEN row's remote fields undefined; they are not a peer.
    if (v.state === 'listen') return v.remoteAddress === null && v.remotePort === null;
    return address(v.remoteAddress, v.family) !== null && integer(v.remotePort, 65535);
}
const compareText = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;
function compareAddress(a: string, b: string, family: WindowsNetworkEndpoint['family']): number {
    const left = address(a, family)!, right = address(b, family)!;
    for (let i = 0; i < left.length; i++) if (left[i] !== right[i]) return left[i] - right[i];
    return 0;
}
function compare(a: WindowsNetworkEndpoint, b: WindowsNetworkEndpoint): number {
    return compareText(a.protocol, b.protocol) || compareText(a.family, b.family) || compareAddress(a.localAddress, b.localAddress, a.family) || a.localPort - b.localPort ||
        (a.remoteAddress === null ? b.remoteAddress === null ? 0 : -1 : b.remoteAddress === null ? 1 : compareAddress(a.remoteAddress, b.remoteAddress, a.family)) || (a.remotePort ?? 0) - (b.remotePort ?? 0) || compareText(a.state ?? '', b.state ?? '') || a.pid - b.pid;
}
export function validWindowsNetwork(v: unknown, generation: string, serverNow: string): v is WindowsNetwork {
    if (!exact(v, ['schemaVersion', 'scope', 'grantId', 'generationId', 'collectedAt', 'quality', 'countExact', 'observedCount', 'truncated', 'rows']) || v.schemaVersion !== 'tracebolt.windows-network-endpoints.v1' || v.scope !== 'windows-network-endpoints-v1' || typeof v.grantId !== 'string' || !/^[a-f0-9]{32}$/.test(v.grantId) || typeof v.generationId !== 'string' || !/^sample_[a-f0-9]{32}$/.test(v.generationId) || v.generationId !== generation || !timestamp(v.collectedAt) || !timestamp(serverNow) || inventoryAge(v.collectedAt, serverNow) > 30000 || inventoryAge(serverNow, v.collectedAt) >= 86400000 || typeof v.countExact !== 'boolean' || !integer(v.observedCount, 16384) || typeof v.truncated !== 'boolean' || !Array.isArray(v.rows) || v.rows.length > 64 || !v.rows.every(endpoint) || v.observedCount < v.rows.length || v.truncated !== (v.observedCount > v.rows.length) || v.rows.some((row, i) => i > 0 && compare((v.rows as WindowsNetworkEndpoint[])[i - 1], row) > 0)) return false;
    if (v.quality === 'observed' ? !v.countExact : v.quality === 'partial' ? v.countExact : !['denied', 'unavailable'].includes(v.quality as string) || v.countExact || v.observedCount !== 0 || v.rows.length !== 0) return false;
    return new TextEncoder().encode(JSON.stringify(v)).byteLength <= WINDOWS_NETWORK_BYTES;
}
