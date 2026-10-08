import { numericWindowsAddress } from './windows-numeric-address';
import { validWindowsNetwork, type WindowsNetwork } from './windows-network-types';
import { validWindowsProcessMetrics, type WindowsProcessMetrics } from './windows-process-metrics-types';
import { validWindowsVolumes } from './windows-volumes-types';
import type { WindowsVolumes } from './windows-volumes-types';
import { validWindowsEvents } from './windows-events-types';
import type { WindowsEvents } from './windows-events-types';
import { inventoryAge } from './complete-packages-types';

/** Windows observations are display-only, never commands, connection targets or AI inputs. */
export const WINDOWS_INVENTORY_SNAPSHOT_BYTES = 48 * 1024;
export const WINDOWS_INVENTORY_VIEW_BYTES = 74 * 1024;
export type WindowsInventoryQuality = 'healthy' | 'partial' | 'denied' | 'unavailable';
export type WindowsInventoryStatus = 'not_configured' | 'awaiting' | 'fresh' | 'stale' | 'unavailable' | 'revoked';
export interface WindowsInventorySection<T> { source: string; scope: string; quality: WindowsInventoryQuality; observedCount: number; countExact: boolean; complete: boolean; truncated: boolean; rows: T[] }
export interface WindowsProcess { pid: number; parentPid: number; name: string; threads: number }
export interface WindowsService { name: string; displayName: string; state: 'stopped' | 'start_pending' | 'stop_pending' | 'running' | 'continue_pending' | 'pause_pending' | 'paused'; pid: number }
export interface WindowsSoftware { name: string; version: string; publisher: string; registryView: '32' | '64' }
export interface WindowsInterface { index: number; name: string; address: string; prefixLength: number }
export interface WindowsHostname { value: string }
export interface WindowsInventorySnapshot {
    schemaVersion: 'tracebolt.windows-inventory.v1'; collectionProfile: 'windows-inventory-v1'; generationId: string; collectedAt: string;
    hostname: WindowsInventorySection<WindowsHostname>; processes: WindowsInventorySection<WindowsProcess>; services: WindowsInventorySection<WindowsService>; software: WindowsInventorySection<WindowsSoftware>; network: WindowsInventorySection<WindowsInterface>;
}
export interface WindowsInventoryView {
    schemaVersion: 'tracebolt.windows-inventory-view.v1'; deviceId: string; collectionProfile: 'windows-inventory-v1'; serverNow: string; maxAgeSeconds: 120;
    events?: WindowsEvents;
    volumes?: WindowsVolumes;
    processMetrics?: WindowsProcessMetrics;
    network?: WindowsNetwork;
    status: WindowsInventoryStatus; sequence: number | null; receivedAt: string | null; snapshot: WindowsInventorySnapshot | null;
}
const exact = (value: unknown, keys: readonly string[]): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const integer = (value: unknown, max = 4294967295): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= max;
const text = (value: unknown, required = true, max = 256): value is string => typeof value === 'string' && (!required || value.trim().length > 0) && new TextEncoder().encode(value).byteLength <= max && !/[\p{Cc}\p{Cf}\uFFFD\uD800-\uDFFF\u2028\u2029]/u.test(value);
const timestamp = (value: unknown): value is string => typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value) && Number.isFinite(Date.parse(value)) && Number(value.slice(0, 4)) >= 1970 && new Date(Date.parse(value)).toISOString().slice(0, 19) === value.slice(0, 19);
export const validWindowsDeviceId = (value: string): boolean => /^agent_[a-f0-9]{32}$/.test(value);
function section<T>(value: unknown, cap: number, nativeCap: number, row: (value: unknown) => value is T): value is WindowsInventorySection<T> {
    if (!exact(value, ['source', 'scope', 'quality', 'observedCount', 'countExact', 'complete', 'truncated', 'rows']) || !text(value.source, true, 512) || !text(value.scope, true, 512) || !integer(value.observedCount, nativeCap) || typeof value.countExact !== 'boolean' || typeof value.complete !== 'boolean' || typeof value.truncated !== 'boolean' || !Array.isArray(value.rows) || value.rows.length > cap || value.observedCount < value.rows.length || !value.rows.every(row)) return false;
    if (value.observedCount > value.rows.length && !value.truncated) return false;
    if (value.quality === 'healthy') return value.complete && value.countExact && !value.truncated && value.observedCount === value.rows.length;
    if (value.quality === 'partial') return !value.complete && !(value.countExact && (!value.truncated || value.observedCount === value.rows.length));
    return (value.quality === 'denied' || value.quality === 'unavailable') && !value.complete && !value.countExact && value.observedCount === 0 && value.rows.length === 0;
}
function process(value: unknown): value is WindowsProcess { return exact(value, ['pid', 'parentPid', 'name', 'threads']) && integer(value.pid) && integer(value.parentPid) && integer(value.threads) && text(value.name) && !/[\\/]/.test(value.name); }
function service(value: unknown): value is WindowsService { return exact(value, ['name', 'displayName', 'state', 'pid']) && text(value.name) && text(value.displayName, false) && integer(value.pid) && typeof value.state === 'string' && ['stopped', 'start_pending', 'stop_pending', 'running', 'continue_pending', 'pause_pending', 'paused'].includes(value.state); }
function software(value: unknown): value is WindowsSoftware { return exact(value, ['name', 'version', 'publisher', 'registryView']) && text(value.name) && text(value.version, false) && text(value.publisher, false) && (value.registryView === '32' || value.registryView === '64'); }
function hostname(value: unknown): value is WindowsHostname { return exact(value, ['value']) && text(value.value); }
function network(value: unknown): value is WindowsInterface {
    if (!exact(value, ['index', 'name', 'address', 'prefixLength']) || !integer(value.index) || value.index < 1 || !text(value.name) || typeof value.address !== 'string') return false;
    const bytes = numericWindowsAddress(value.address, value.address.includes(':') ? 'ipv6' : 'ipv4');
    if (!bytes || !integer(value.prefixLength, bytes.length * 8) || bytes.every(n => n === 0)) return false;
    const mapped = bytes.length === 16 && bytes.slice(0, 10).every(n => n === 0) && bytes[10] === 255 && bytes[11] === 255;
    const b = mapped ? bytes.slice(12) : bytes;
    return b.length === 4 ? b[0] !== 127 && !(b[0] >= 224 && b[0] <= 239) : !(b.slice(0, 15).every(n => n === 0) && b[15] === 1) && b[0] !== 255;
}
export function validWindowsInventorySnapshot(value: unknown): value is WindowsInventorySnapshot {
    if (!exact(value, ['schemaVersion', 'collectionProfile', 'generationId', 'collectedAt', 'hostname', 'processes', 'services', 'software', 'network']) || value.schemaVersion !== 'tracebolt.windows-inventory.v1' || value.collectionProfile !== 'windows-inventory-v1' || typeof value.generationId !== 'string' || !/^sample_[a-f0-9]{32}$/.test(value.generationId) || !timestamp(value.collectedAt) || !section(value.hostname, 1, 1, hostname) || value.hostname.complete && value.hostname.rows.length !== 1 || !section(value.processes, 128, 2048, process) || !section(value.services, 128, 2048, service) || !section(value.software, 128, 2048, software) || !section(value.network, 64, 512, network)) return false;
    // Match Go JSON's HTML escaping in addition to the bounded HTTP reader.
    const encoded = JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
    return new TextEncoder().encode(encoded).byteLength <= WINDOWS_INVENTORY_SNAPSHOT_BYTES;
}
export function validWindowsInventoryView(value: unknown, deviceId: string): value is WindowsInventoryView {
    if (!exact(value, ['schemaVersion', 'deviceId', 'collectionProfile', 'serverNow', 'maxAgeSeconds', 'status', 'sequence', 'receivedAt', 'snapshot', ...(value !== null && typeof value === 'object' && Object.hasOwn(value, 'events') ? ['events'] : []), ...(value !== null && typeof value === 'object' && Object.hasOwn(value, 'volumes') ? ['volumes'] : []), ...(value !== null && typeof value === 'object' && Object.hasOwn(value, 'processMetrics') ? ['processMetrics'] : []), ...(value !== null && typeof value === 'object' && Object.hasOwn(value, 'network') ? ['network'] : [])]) || value.schemaVersion !== 'tracebolt.windows-inventory-view.v1' || value.collectionProfile !== 'windows-inventory-v1' || !validWindowsDeviceId(deviceId) || value.deviceId !== deviceId || !timestamp(value.serverNow) || value.maxAgeSeconds !== 120 || typeof value.status !== 'string' || !['not_configured', 'awaiting', 'fresh', 'stale', 'unavailable', 'revoked'].includes(value.status)) return false;
    const receipt = integer(value.sequence, Number.MAX_SAFE_INTEGER) && value.sequence > 0 && timestamp(value.receivedAt) && inventoryAge(value.serverNow, value.receivedAt) >= 0;
    if (!(value.sequence === null && value.receivedAt === null) && !receipt) return false;
    if (Object.hasOwn(value, 'events') && (!validWindowsInventorySnapshot(value.snapshot) || !validWindowsEvents(value.events, value.snapshot.generationId, value.serverNow))) return false;
    if (Object.hasOwn(value, 'volumes') && (!validWindowsInventorySnapshot(value.snapshot) || !validWindowsVolumes(value.volumes, value.snapshot.generationId, value.serverNow))) return false;
    if (Object.hasOwn(value, 'processMetrics') && (!validWindowsInventorySnapshot(value.snapshot) || !validWindowsProcessMetrics(value.processMetrics, value.snapshot.generationId, value.serverNow) || value.processMetrics.observedCount !== value.snapshot.processes.rows.length || new Set(value.snapshot.processes.rows.map(row => row.pid)).size !== value.snapshot.processes.rows.length || !value.processMetrics.rows.every(row => (value.snapshot as WindowsInventorySnapshot).processes.rows.some(process => process.pid === row.pid)))) return false;
    if (Object.hasOwn(value, 'network') && (!validWindowsInventorySnapshot(value.snapshot) || !validWindowsNetwork(value.network, value.snapshot.generationId, value.serverNow) || inventoryAge(value.network.collectedAt, value.snapshot.collectedAt) < 0)) return false;
    if (value.status !== 'fresh' && value.status !== 'stale') return !Object.hasOwn(value, 'events') && !Object.hasOwn(value, 'volumes') && !Object.hasOwn(value, 'processMetrics') && !Object.hasOwn(value, 'network') && value.snapshot === null && (!['not_configured', 'awaiting'].includes(value.status) || value.sequence === null);
    if (!receipt || !validWindowsInventorySnapshot(value.snapshot)) return false;
    if (value.processMetrics && inventoryAge((value.processMetrics as WindowsProcessMetrics).collectedAt, value.receivedAt as string) > 30000) return false;
    if (value.network && inventoryAge((value.network as WindowsNetwork).collectedAt, value.receivedAt as string) > 30000) return false;
    const age = inventoryAge(value.serverNow, value.snapshot.collectedAt);
    const receiptSkew = inventoryAge(value.snapshot.collectedAt, value.receivedAt as string);
    const receiptAge = inventoryAge(value.serverNow, value.receivedAt as string);
    return age >= -30000 && age < 86400000 && receiptSkew <= 30000 && (value.status === 'fresh' ? age >= 0 && age <= 120000 && receiptAge <= 120000 : age < 0 || age > 120000 || receiptAge > 120000);
}
export function windowsInventoryStatus(view: WindowsInventoryView, elapsed: number): WindowsInventoryStatus {
    if (!Number.isFinite(elapsed) || elapsed < 0) return 'unavailable';
    if (!view.snapshot || !['fresh', 'stale'].includes(view.status)) return view.status;
    const age = inventoryAge(view.serverNow, view.snapshot.collectedAt) + elapsed;
    if (age >= 86400000) return 'unavailable';
    const receiptAge = view.receivedAt ? inventoryAge(view.serverNow, view.receivedAt) + elapsed : Infinity;
    return view.status === 'fresh' && (age > 120000 || receiptAge > 120000) ? 'stale' : view.status;
}
