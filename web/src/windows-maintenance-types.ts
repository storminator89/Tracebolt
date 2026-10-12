import { inventoryAge } from './complete-packages-types';
import { validWindowsCapacityDeviceId, validWindowsCapacityTimestamp } from './windows-capacity-types';

export const WINDOWS_MAINTENANCE_BYTES = 256 * 1024;
export const WINDOWS_MAINTENANCE_DOMAINS = ['all', 'contact', 'cpu', 'disk', 'memory', 'service'] as const;
export type WindowsMaintenanceDomain = typeof WINDOWS_MAINTENANCE_DOMAINS[number];
export type WindowsMaintenanceIntent = 'planned-work' | 'investigation' | 'other';
export interface WindowsMaintenanceWindow { id: number; startedAt: string; endsAt: string; endedAt: string | null; intent: WindowsMaintenanceIntent }
export interface WindowsMaintenanceTarget { key: string; deviceId: string; domain: WindowsMaintenanceDomain; revision: number; changedAt: string | null; windows: WindowsMaintenanceWindow[] }
export interface WindowsMaintenanceView { schemaVersion: 'tracebolt.windows-maintenance.v1'; serverNow: string; authorityExpiresAt: string; targets: WindowsMaintenanceTarget[] }
export type WindowsMaintenanceStart = { key: string; revision: number; endsAt: string; intent: WindowsMaintenanceIntent };
export type WindowsMaintenanceEnd = { key: string; revision: number; windowId: number };
const exact = (value: unknown, keys: readonly string[]): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const integer = (value: unknown, minimum = 0): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum;
export const validWindowsMaintenanceKey = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
export const validWindowsMaintenanceIntent = (value: unknown): value is WindowsMaintenanceIntent => ['planned-work', 'investigation', 'other'].includes(value as string);
/** Exact RFC3339Nano UTC spelling, including sub-millisecond source precision. */
export const validWindowsMaintenanceTime = (value: unknown): value is string => validWindowsCapacityTimestamp(value) && !/\.\d*0Z$/.test(value);
const atOrBefore = (value: unknown, now: string): value is string => validWindowsMaintenanceTime(value) && inventoryAge(now, value) >= 0;

function validWindow(value: unknown, now: string): value is WindowsMaintenanceWindow {
    if (!exact(value, ['id', 'startedAt', 'endsAt', 'endedAt', 'intent']) || !integer(value.id, 1) || !atOrBefore(value.startedAt, now) || !validWindowsMaintenanceTime(value.endsAt) || !validWindowsMaintenanceIntent(value.intent)) return false;
    const duration = inventoryAge(value.endsAt, value.startedAt);
    return duration >= 60000 && duration <= 86400000 && (value.endedAt === null || atOrBefore(value.endedAt, now) && inventoryAge(value.endedAt, value.startedAt) >= 0 && inventoryAge(value.endsAt, value.endedAt) > 0);
}
function validTarget(value: unknown, now: string): value is WindowsMaintenanceTarget {
    if (!exact(value, ['key', 'deviceId', 'domain', 'revision', 'changedAt', 'windows']) || !validWindowsMaintenanceKey(value.key) || typeof value.deviceId !== 'string' || !validWindowsCapacityDeviceId(value.deviceId) || !(WINDOWS_MAINTENANCE_DOMAINS as readonly unknown[]).includes(value.domain) || !integer(value.revision) || !Array.isArray(value.windows) || value.windows.length > 4 || !value.windows.every(window => validWindow(window, now))) return false;
    if (value.revision === 0) return value.changedAt === null && value.windows.length === 0;
    if (!atOrBefore(value.changedAt, now) || value.windows.length === 0) return false;
    const windows = value.windows as WindowsMaintenanceWindow[], latest = windows[0];
    if (value.changedAt !== (latest.endedAt ?? latest.startedAt) || value.revision !== latest.id + (latest.endedAt === null ? 0 : 1)) return false;
    for (let index = 1; index < windows.length; index++) {
        const newer = windows[index - 1], older = windows[index];
        if (newer.id !== older.id + (older.endedAt === null ? 1 : 2) || inventoryAge(newer.startedAt, older.endedAt ?? older.endsAt) < 0) return false;
    }
    return true;
}

/** Closed metadata-only projection. It has no incident, health, notification or host fields. */
export function validWindowsMaintenanceView(value: unknown): value is WindowsMaintenanceView {
    if (!exact(value, ['schemaVersion', 'serverNow', 'authorityExpiresAt', 'targets']) || value.schemaVersion !== 'tracebolt.windows-maintenance.v1' || !validWindowsMaintenanceTime(value.serverNow) || !validWindowsMaintenanceTime(value.authorityExpiresAt) || inventoryAge(value.authorityExpiresAt, value.serverNow) <= 0 || !Array.isArray(value.targets) || value.targets.length > 150 || value.targets.length % 6 !== 0 || !value.targets.every(target => validTarget(target, value.serverNow as string))) return false;
    const targets = value.targets as WindowsMaintenanceTarget[];
    if (new Set(targets.map(target => target.key)).size !== targets.length) return false;
    for (let index = 0; index < targets.length; index += 6) {
        const group = targets.slice(index, index + 6), deviceId = group[0].deviceId;
        if (index > 0 && targets[index - 6].deviceId >= deviceId || group.some((target, domain) => target.deviceId !== deviceId || target.domain !== WINDOWS_MAINTENANCE_DOMAINS[domain])) return false;
        const active = group.filter(target => target.windows[0] && windowsMaintenanceState(target.windows[0], value.serverNow as string, 0) === 'active');
        if (active.some(target => target.domain === 'all') && active.length > 1) return false;
    }
    return new TextEncoder().encode(JSON.stringify(value)).byteLength <= WINDOWS_MAINTENANCE_BYTES;
}

/** Aging can only expire an active label; an explicit early end stays ended. */
export function windowsMaintenanceState(window: WindowsMaintenanceWindow, serverNow: string, elapsed: number): 'active' | 'ended' | 'expired' | 'unknown' {
    if (!Number.isFinite(elapsed) || elapsed < 0) return 'unknown';
    return window.endedAt !== null ? 'ended' : inventoryAge(window.endsAt, serverNow) > elapsed ? 'active' : 'expired';
}
export function windowsMaintenanceCanStart(view: WindowsMaintenanceView, target: WindowsMaintenanceTarget, elapsed: number): boolean {
    if (!Number.isFinite(elapsed) || elapsed < 0 || target.revision >= Number.MAX_SAFE_INTEGER) return false;
    return !view.targets.some(candidate => candidate.deviceId === target.deviceId && (target.domain === 'all' || candidate.domain === 'all' || candidate.key === target.key) && candidate.windows[0] && windowsMaintenanceState(candidate.windows[0], view.serverNow, elapsed) === 'active');
}
/** A duration is only a proposal; the visible absolute end is frozen by review. */
export function windowsMaintenanceEndTime(serverNow: string, elapsed: number, minutes: number): string | null {
    if (!validWindowsMaintenanceTime(serverNow) || !Number.isFinite(elapsed) || elapsed < 0 || elapsed >= 120000 || ![15, 30, 60, 120, 240, 480, 1440].includes(minutes)) return null;
    // The conservative request age may run slightly ahead of the manager. The
    // maximum preset therefore uses the original manager instant as its ceiling.
    return new Date(Date.parse(serverNow) + (minutes === 1440 ? 0 : Math.floor(elapsed)) + minutes * 60000).toISOString().replace(/\.000Z$/, 'Z').replace(/(\.\d*?[1-9])0+Z$/, '$1Z');
}
