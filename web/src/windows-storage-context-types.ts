import { inventoryAge } from './complete-packages-types';
import type { WindowsInventorySnapshot } from './windows-inventory-types';

export const WINDOWS_STORAGE_CONTEXT_BYTES = 16 * 1024;
export const WINDOWS_STORAGE_CONTEXT_REASONS = ['', 'windows_storage_context_access_denied', 'windows_storage_context_unavailable', 'windows_storage_context_unsupported_platform', 'windows_storage_context_invalid_metadata', 'windows_storage_context_bounds', 'windows_storage_context_partial_result', 'windows_storage_context_budget_exhausted'] as const;
export interface WindowsStorageField { value: string | null; quality: 'observed' | 'empty' | 'denied' | 'unavailable' }
export interface WindowsStorageDrive { letter: string; driveType: 'fixed' | 'removable' | 'cdrom' | 'ramdisk' | 'unknown'; volumeGuid: string | null; quality: 'observed' | 'denied' | 'unavailable'; reason: typeof WINDOWS_STORAGE_CONTEXT_REASONS[number] }
/** DeviceId is provider-local text, never an OS disk number or a volume join key. */
export interface WindowsStorageDisk { index: number; deviceId: WindowsStorageField; friendlyName: WindowsStorageField; healthStatus: number | null; operationalStatus: number[]; busType: number | null; mediaType: number | null; sizeBytes: string | null }
export interface WindowsStorageGroup<T> { quality: 'observed' | 'partial' | 'denied' | 'unavailable'; reason: typeof WINDOWS_STORAGE_CONTEXT_REASONS[number]; rows: T[]; observedCount: number; countExact: boolean; complete: boolean; truncated: boolean }
export interface WindowsStorageContext {
    schemaVersion: 'tracebolt.windows-storage-context.v1'; scope: 'windows-storage-context-v1'; grantId: string; generationId: string; collectedAt: string;
    drives: WindowsStorageGroup<WindowsStorageDrive>; disks: WindowsStorageGroup<WindowsStorageDisk>;
}
const exact = (v: unknown, keys: readonly string[]): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const integer = (v: unknown, max: number): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0) && v >= 0 && v <= max;
const timestamp = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number(v.slice(0, 4)) >= 1970 && Number.isFinite(Date.parse(v)) && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19);
const reason = (v: unknown): boolean => WINDOWS_STORAGE_CONTEXT_REASONS.includes(v as WindowsStorageDrive['reason']);
const label = (v: unknown, units: number): v is string => typeof v === 'string' && v.length > 0 && v.length <= units && !/[\p{Cc}\uFFFD\uD800-\uDFFF]/u.test(v);
const field = (v: unknown, units: number): v is WindowsStorageField => exact(v, ['value', 'quality']) && (v.quality === 'observed' ? label(v.value, units) : v.value === null && ['empty', 'denied', 'unavailable'].includes(v.quality as string));
const guid = (v: unknown): v is string => typeof v === 'string' && /^\\\\\?\\Volume\{[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\}\\$/.test(v);
function coverage(v: unknown, maxRows: number, maxCount: number): v is WindowsStorageGroup<unknown> {
    if (!exact(v, ['quality', 'reason', 'rows', 'observedCount', 'countExact', 'complete', 'truncated']) || !reason(v.reason) || !Array.isArray(v.rows) || v.rows.length > maxRows || !integer(v.observedCount, maxCount) || v.observedCount < v.rows.length || typeof v.countExact !== 'boolean' || typeof v.complete !== 'boolean' || typeof v.truncated !== 'boolean' || v.truncated && v.complete || v.complete && (!v.countExact || v.rows.length !== v.observedCount)) return false;
    if (v.quality === 'observed') return v.reason === '' && v.complete && !v.truncated;
    if (v.quality === 'partial') return v.reason !== '' && (!v.complete || v.rows.length > 0) && v.complete === (v.countExact && v.rows.length === v.observedCount) && v.truncated === (v.observedCount > v.rows.length || !v.countExact);
    return (v.quality === 'denied' || v.quality === 'unavailable') && v.reason !== '' && (v.quality === 'denied') === (v.reason === 'windows_storage_context_access_denied') && v.rows.length === 0 && v.observedCount === 0 && !v.countExact && !v.complete && !v.truncated;
}
function drive(v: unknown): v is WindowsStorageDrive {
    if (!exact(v, ['letter', 'driveType', 'volumeGuid', 'quality', 'reason']) || typeof v.letter !== 'string' || !/^[A-Z]:$/.test(v.letter) || !['fixed', 'removable', 'cdrom', 'ramdisk', 'unknown'].includes(v.driveType as string) || !reason(v.reason)) return false;
    if (v.quality === 'observed') return guid(v.volumeGuid) && v.reason === '' && v.driveType !== 'unknown';
    return (v.quality === 'denied' || v.quality === 'unavailable') && v.volumeGuid === null && v.reason !== '' && (v.quality === 'denied') === (v.reason === 'windows_storage_context_access_denied');
}
function disk(v: unknown, index: number): v is WindowsStorageDisk {
    return exact(v, ['index', 'deviceId', 'friendlyName', 'healthStatus', 'operationalStatus', 'busType', 'mediaType', 'sizeBytes']) && integer(v.index, 31) && v.index === index && field(v.deviceId, 64) && field(v.friendlyName, 128) && [v.healthStatus, v.busType, v.mediaType].every(n => n === null || integer(n, 65535)) && Array.isArray(v.operationalStatus) && v.operationalStatus.length <= 16 && v.operationalStatus.every(n => integer(n, 65535)) && new Set(v.operationalStatus).size === v.operationalStatus.length && (v.sizeBytes === null || typeof v.sizeBytes === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(v.sizeBytes) && BigInt(v.sizeBytes) <= 18446744073709551615n);
}
export function validWindowsStorageContext(v: unknown, snapshot: WindowsInventorySnapshot, serverNow: string): v is WindowsStorageContext {
    if (!exact(v, ['schemaVersion', 'scope', 'grantId', 'generationId', 'collectedAt', 'drives', 'disks']) || v.schemaVersion !== 'tracebolt.windows-storage-context.v1' || v.scope !== 'windows-storage-context-v1' || typeof v.grantId !== 'string' || !/^[a-f0-9]{32}$/.test(v.grantId) || typeof v.generationId !== 'string' || !/^sample_[a-f0-9]{32}$/.test(v.generationId) || v.generationId !== snapshot.generationId || !timestamp(v.collectedAt) || !timestamp(snapshot.collectedAt) || !timestamp(serverNow) || inventoryAge(v.collectedAt, snapshot.collectedAt) !== 0 || inventoryAge(v.collectedAt, serverNow) > 30000 || inventoryAge(serverNow, v.collectedAt) >= 86400000 || !coverage(v.drives, 26, 26) || !v.drives.rows.every(drive) || v.drives.quality === 'observed' && !v.drives.rows.every(row => (row as WindowsStorageDrive).quality === 'observed') || !v.drives.rows.every((row, i, rows) => i === 0 || (row as WindowsStorageDrive).letter > (rows[i - 1] as WindowsStorageDrive).letter) || !coverage(v.disks, 32, 64) || !v.disks.rows.every(disk) || v.disks.quality === 'observed' && !v.disks.rows.every(row => { const r = row as WindowsStorageDisk; return ![r.deviceId.quality, r.friendlyName.quality].some(q => q === 'denied' || q === 'unavailable') && [r.healthStatus, r.busType, r.mediaType, r.sizeBytes].every(value => value !== null); })) return false;
    const encoded = JSON.stringify(v).replace(/[<>&\u2028\u2029]/g, ch => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`);
    return new TextEncoder().encode(encoded).byteLength <= WINDOWS_STORAGE_CONTEXT_BYTES;
}
/** Unknown, Other, reserved and future classifications remain displayable, but
 * cannot by themselves replace a previously useful original-age capture. */
export function usefulWindowsStorageContext(v: WindowsStorageContext): boolean {
    return [v.drives, v.disks].some(group => group.quality === 'observed' && group.complete && group.rows.length === 0) || v.drives.rows.some(row => row.volumeGuid !== null) || v.disks.rows.some(row =>
        row.deviceId.value !== null || row.friendlyName.value !== null || row.sizeBytes !== null ||
        row.healthStatus !== null && [0, 1, 2].includes(row.healthStatus) ||
        row.busType !== null && (row.busType >= 1 && row.busType <= 13 || row.busType >= 15 && row.busType <= 17) ||
        row.mediaType !== null && [3, 4, 5].includes(row.mediaType) ||
        row.operationalStatus.some(status => status >= 2 && status <= 18));
}
