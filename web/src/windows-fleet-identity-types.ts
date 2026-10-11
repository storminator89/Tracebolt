import { inventoryAge, inventorySequence } from './complete-packages-types';
import { validWindowsDeviceId, validWindowsIdentitySections } from './windows-inventory-types';
import type { WindowsHostname, WindowsInterface, WindowsInventorySection } from './windows-inventory-types';

export interface WindowsFleetSnapshot {
    schemaVersion: 'tracebolt.windows-fleet-identity.v1'; collectionProfile: 'windows-inventory-v1'; generationId: string; collectedAt: string;
    hostname: WindowsInventorySection<WindowsHostname>; network: WindowsInventorySection<WindowsInterface>;
}
export interface WindowsFleetIdentityView {
    schemaVersion: 'tracebolt.windows-fleet-identity-view.v1'; deviceId: string; collectionProfile: 'windows-inventory-v1'; serverNow: string; maxAgeSeconds: 120;
    status: 'fresh' | 'stale' | 'expired' | 'revoked' | 'awaiting'; sequence: string | null; receivedAt: string | null; expiresAt: string | null; latest: WindowsFleetSnapshot | null;
}
const exact = (v: unknown, keys: string[]): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const timestamp = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number.isFinite(Date.parse(v)) && Number(v.slice(0, 4)) >= 1970 && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19);
export function validWindowsFleetIdentity(value: unknown): value is WindowsFleetIdentityView {
    if (!exact(value, ['schemaVersion', 'deviceId', 'collectionProfile', 'serverNow', 'maxAgeSeconds', 'status', 'sequence', 'receivedAt', 'expiresAt', 'latest']) || value.schemaVersion !== 'tracebolt.windows-fleet-identity-view.v1' || value.collectionProfile !== 'windows-inventory-v1' || typeof value.deviceId !== 'string' || !validWindowsDeviceId(value.deviceId) || !timestamp(value.serverNow) || value.maxAgeSeconds !== 120 || !['fresh', 'stale', 'expired', 'revoked', 'awaiting'].includes(value.status as string)) return false;
    const receipt = inventorySequence(value.sequence) && Number(value.sequence) <= Number.MAX_SAFE_INTEGER && timestamp(value.receivedAt) && inventoryAge(value.serverNow, value.receivedAt) >= 0 && timestamp(value.expiresAt);
    if (!receipt && !(value.sequence === null && value.receivedAt === null && value.expiresAt === null)) return false;
    if (value.status === 'revoked' || value.status === 'awaiting') return value.latest === null && value.sequence === null;
    if (value.status === 'expired') return value.latest === null && (!receipt || inventoryAge(value.serverNow, value.expiresAt as string) >= 0);
    const s = value.latest;
    if (!receipt || !exact(s, ['schemaVersion', 'collectionProfile', 'generationId', 'collectedAt', 'hostname', 'network']) || s.schemaVersion !== 'tracebolt.windows-fleet-identity.v1' || s.collectionProfile !== 'windows-inventory-v1' || typeof s.generationId !== 'string' || !/^sample_[a-f0-9]{32}$/.test(s.generationId) || !timestamp(s.collectedAt) || !validWindowsIdentitySections(s.hostname, s.network)) return false;
    const age = inventoryAge(value.serverNow, s.collectedAt), receiptAge = inventoryAge(value.serverNow, value.receivedAt as string), lifetime = inventoryAge(value.expiresAt as string, s.collectedAt);
    return age >= -30000 && age < 86400000 && inventoryAge(s.collectedAt, value.receivedAt as string) <= 30000 && inventoryAge(value.expiresAt as string, value.serverNow) > 0 && lifetime > 0 && lifetime <= 86400000 && (value.status === 'fresh' ? age >= 0 && age <= 120000 && receiptAge <= 120000 : age < 0 || age > 120000 || receiptAge > 120000);
}
export function windowsFleetStatus(v: WindowsFleetIdentityView, elapsed: number): WindowsFleetIdentityView['status'] {
    if (v.status === 'revoked' || v.status === 'expired') return v.status;
    if (!Number.isFinite(elapsed) || elapsed < 0 || v.expiresAt && inventoryAge(v.expiresAt, v.serverNow) <= elapsed) return 'expired';
    if (!v.latest) return v.status;
    return v.status === 'fresh' && (inventoryAge(v.serverNow, v.latest.collectedAt) + elapsed > 120000 || inventoryAge(v.serverNow, v.receivedAt!) + elapsed > 120000) ? 'stale' : v.status;
}
