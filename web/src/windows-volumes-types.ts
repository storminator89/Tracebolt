import { inventoryAge } from './complete-packages-types';
/** Read-only, separately consented local volumes. Keep uint64 byte values as strings. */
export const WINDOWS_VOLUMES_BYTES = 12 * 1024;
export interface WindowsVolumeCapacity { totalBytes: string; freeBytes: string; availableBytes: string }
export interface WindowsVolume { volumeId: string; driveType: 'fixed' | 'removable' | 'cdrom' | 'ramdisk' | 'unknown'; quality: 'observed' | 'denied' | 'unavailable'; reason: string; capacity: WindowsVolumeCapacity | null }
export interface WindowsVolumes { schemaVersion: 'tracebolt.windows-volumes.v1'; scope: 'windows-visible-volumes-v1'; grantId: string; generationId: string; collectedAt: string; quality: 'observed' | 'bounded' | 'partial' | 'denied' | 'unavailable'; reason: string; complete: boolean; truncated: boolean; countExact: boolean; observedCount: number; rows: WindowsVolume[] }
const exact = (v: unknown, keys: string[]): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const reasons = ['', 'windows_volumes_access_denied', 'windows_volumes_source_unavailable', 'windows_volumes_unsupported_platform', 'windows_volumes_invalid_metadata', 'windows_volumes_unsupported_drive_type', 'context canceled', 'context deadline exceeded'];
const uint64 = (v: unknown): v is string => typeof v === 'string' && /^(?:0|[1-9]\d{0,19})$/.test(v) && BigInt(v) <= 18446744073709551615n;
function capacity(v: unknown): v is WindowsVolumeCapacity {
    return exact(v, ['totalBytes', 'freeBytes', 'availableBytes']) && uint64(v.totalBytes) && uint64(v.freeBytes) && uint64(v.availableBytes) && BigInt(v.availableBytes) <= BigInt(v.totalBytes) && BigInt(v.availableBytes) <= BigInt(v.freeBytes);
}
function row(v: unknown): v is WindowsVolume {
    if (!exact(v, ['volumeId', 'driveType', 'quality', 'reason', 'capacity']) || typeof v.volumeId !== 'string' || !/^\\\\\?\\Volume\{[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\}\\$/.test(v.volumeId) || typeof v.driveType !== 'string' || !['fixed', 'removable', 'cdrom', 'ramdisk', 'unknown'].includes(v.driveType) || typeof v.reason !== 'string' || !reasons.includes(v.reason)) return false;
    if (v.reason === 'windows_volumes_unsupported_drive_type' && v.driveType !== 'unknown') return false;
    if (v.quality === 'observed') return v.driveType !== 'unknown' && v.reason === '' && capacity(v.capacity);
    return (v.quality === 'denied' || v.quality === 'unavailable') && v.capacity === null && v.reason !== '' && (v.quality === 'denied') === (v.reason === 'windows_volumes_access_denied');
}
export function validWindowsVolumes(v: unknown, generation: string, serverNow: string): v is WindowsVolumes {
    if (!exact(v, ['schemaVersion', 'scope', 'grantId', 'generationId', 'collectedAt', 'quality', 'reason', 'complete', 'truncated', 'countExact', 'observedCount', 'rows']) || v.schemaVersion !== 'tracebolt.windows-volumes.v1' || v.scope !== 'windows-visible-volumes-v1' || typeof v.grantId !== 'string' || !/^[a-f0-9]{32}$/.test(v.grantId) || typeof v.generationId !== 'string' || !/^sample_[a-f0-9]{32}$/.test(v.generationId) || v.generationId !== generation || typeof v.collectedAt !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v.collectedAt) || Number(v.collectedAt.slice(0,4)) < 1970 || !Number.isFinite(Date.parse(v.collectedAt)) || new Date(Date.parse(v.collectedAt)).toISOString().slice(0,19) !== v.collectedAt.slice(0,19) || !Number.isFinite(Date.parse(serverNow)) || inventoryAge(v.collectedAt, serverNow) > 30000 || inventoryAge(serverNow, v.collectedAt) >= 86400000 || typeof v.reason !== 'string' || !reasons.includes(v.reason) || typeof v.complete !== 'boolean' || typeof v.truncated !== 'boolean' || typeof v.countExact !== 'boolean' || typeof v.observedCount !== 'number' || !Number.isInteger(v.observedCount) || v.observedCount < 0 || v.observedCount > 128 || !Array.isArray(v.rows) || v.rows.length > 64 || !v.rows.every(row) || new Set(v.rows.map(r => r.volumeId)).size !== v.rows.length || v.observedCount < v.rows.length || v.observedCount > v.rows.length && !v.truncated) return false;
    let valid = false;
    if (v.quality === 'observed') valid = v.complete && v.countExact && !v.truncated && !v.reason && v.observedCount === v.rows.length;
    else if (v.quality === 'bounded') valid = !v.complete && v.truncated && !v.reason && (v.countExact ? v.observedCount > v.rows.length : v.observedCount === 128);
    else if (v.quality === 'partial') valid = !v.complete && !v.countExact && Boolean(v.reason) && v.observedCount > 0;
    else if (v.quality === 'denied' || v.quality === 'unavailable') valid = !v.complete && !v.truncated && !v.countExact && v.observedCount === 0 && v.rows.length === 0 && Boolean(v.reason) && (v.quality === 'denied') === (v.reason === 'windows_volumes_access_denied');
    return valid && new TextEncoder().encode(JSON.stringify(v).replace(/[<>&\u2028\u2029]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`)).length <= WINDOWS_VOLUMES_BYTES;
}
