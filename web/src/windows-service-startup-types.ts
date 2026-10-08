import { inventoryAge } from './complete-packages-types';
import { sha256Bytes } from './sha256';
import type { WindowsInventorySnapshot, WindowsService } from './windows-inventory-types';

export const WINDOWS_SERVICE_STARTUP_BYTES = 16 * 1024;
export interface WindowsServiceStartupRow {
    serviceIndex: number; startupMode: 'automatic' | 'manual' | 'disabled' | null;
    startupQuality: 'observed' | 'denied' | 'unavailable' | 'unknown';
    delayedAutoStart: boolean | null; delayedAutoQuality: 'observed' | 'not-applicable' | 'denied' | 'unavailable' | 'unknown';
}
export interface WindowsServiceStartup {
    schemaVersion: 'tracebolt.windows-service-startup.v1'; scope: 'windows-service-startup-v1';
    grantId: string; generationId: string; servicesSHA256: string; collectedAt: string;
    requestedCount: number; truncated: boolean; rows: WindowsServiceStartupRow[];
}
const exact = (v: unknown, keys: readonly string[]): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const integer = (v: unknown, max: number): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0) && v >= 0 && v <= max;
const timestamp = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number(v.slice(0, 4)) >= 1970 && Number.isFinite(Date.parse(v)) && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19);
/** Match encoding/json over the exact final base row order, including HTML escaping.
 * Never bind by a service name, PID, sorted UI position or another generation. */
export function windowsServicesCanonicalJSON(rows: readonly WindowsService[]): string {
    return JSON.stringify(rows.map(({ name, displayName, state, pid }) => ({ name, displayName, state, pid }))).replace(/[<>&\u2028\u2029]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}
export function windowsServicesDigest(rows: readonly WindowsService[]): string {
    return sha256Bytes(new TextEncoder().encode(windowsServicesCanonicalJSON(rows)));
}
function validRow(v: unknown): v is WindowsServiceStartupRow {
    if (!exact(v, ['serviceIndex', 'startupMode', 'startupQuality', 'delayedAutoStart', 'delayedAutoQuality']) || !integer(v.serviceIndex, 127)) return false;
    if (v.startupQuality !== 'observed') return ['denied', 'unavailable', 'unknown'].includes(v.startupQuality as string) && v.startupMode === null && v.delayedAutoStart === null && v.delayedAutoQuality === v.startupQuality;
    if (v.startupMode === 'manual' || v.startupMode === 'disabled') return v.delayedAutoStart === null && v.delayedAutoQuality === 'not-applicable';
    if (v.startupMode !== 'automatic') return false;
    return v.delayedAutoQuality === 'observed' ? typeof v.delayedAutoStart === 'boolean' : ['denied', 'unavailable', 'unknown'].includes(v.delayedAutoQuality as string) && v.delayedAutoStart === null;
}
/** Display-only defensive validation. Authorization remains the manager's job. */
export function validWindowsServiceStartup(v: unknown, snapshot: WindowsInventorySnapshot, serverNow: string): v is WindowsServiceStartup {
    if (!exact(v, ['schemaVersion', 'scope', 'grantId', 'generationId', 'servicesSHA256', 'collectedAt', 'requestedCount', 'truncated', 'rows']) || v.schemaVersion !== 'tracebolt.windows-service-startup.v1' || v.scope !== 'windows-service-startup-v1' || typeof v.grantId !== 'string' || !/^[a-f0-9]{32}$/.test(v.grantId) || typeof v.generationId !== 'string' || !/^sample_[a-f0-9]{32}$/.test(v.generationId) || v.generationId !== snapshot.generationId || typeof v.servicesSHA256 !== 'string' || !/^[a-f0-9]{64}$/.test(v.servicesSHA256) || !timestamp(v.collectedAt) || !timestamp(serverNow) || inventoryAge(v.collectedAt, snapshot.collectedAt) < 0 || inventoryAge(v.collectedAt, serverNow) > 30000 || inventoryAge(serverNow, v.collectedAt) >= 86400000 || !integer(v.requestedCount, 128) || v.requestedCount !== snapshot.services.rows.length || typeof v.truncated !== 'boolean' || !Array.isArray(v.rows) || v.rows.length > v.requestedCount || !v.rows.every(validRow) || v.truncated !== (v.requestedCount > v.rows.length)) return false;
    if (v.rows.some((row, i) => row.serviceIndex >= snapshot.services.rows.length || i > 0 && row.serviceIndex <= (v.rows as WindowsServiceStartupRow[])[i - 1].serviceIndex)) return false;
    return new TextEncoder().encode(JSON.stringify(v)).byteLength <= WINDOWS_SERVICE_STARTUP_BYTES && v.servicesSHA256 === windowsServicesDigest(snapshot.services.rows);
}
