import { inventoryAge } from './complete-packages-types';
import { validAlarmStatus } from './alarm-status-types';
import type { AlarmStatus } from './alarm-status-types';
import { validWindowsCapacityDeviceId } from './windows-capacity-types';
import { validWindowsMaintenanceKey, validWindowsMaintenanceTime } from './windows-maintenance-types';
export const WINDOWS_NOTIFICATIONS_BYTES = 256 * 1024;
export const WINDOWS_NOTIFICATION_DOMAINS = ['contact', 'cpu', 'disk', 'memory', 'service'] as const;
export type WindowsNotificationDomain = typeof WINDOWS_NOTIFICATION_DOMAINS[number];
export interface WindowsNotificationTarget { key: string; deviceId: string; domain: WindowsNotificationDomain; revision: number; enabled: boolean; effective: boolean; maintenanceUntil: string | null; changedAt: string | null }
export interface WindowsNotificationView { schemaVersion: 'tracebolt.windows-notifications.v1'; serverNow: string; authorityExpiresAt: string; destinationHost: string; destinationBinding: string; deliveryEnabled: boolean; targets: WindowsNotificationTarget[]; counts: AlarmStatus }
export type WindowsNotificationChange = { key: string; revision: number; enabled: boolean; destinationBinding: string; payloadAcknowledged: boolean };
const exact = (v: unknown, keys: string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const integer = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
function validTarget(v: unknown, now: string, delivery: boolean): v is WindowsNotificationTarget {
    if (!exact(v, ['key', 'deviceId', 'domain', 'revision', 'enabled', 'effective', 'maintenanceUntil', 'changedAt']) || !validWindowsMaintenanceKey(v.key) || typeof v.deviceId !== 'string' || !validWindowsCapacityDeviceId(v.deviceId) || !(WINDOWS_NOTIFICATION_DOMAINS as readonly unknown[]).includes(v.domain) || !integer(v.revision) || typeof v.enabled !== 'boolean' || typeof v.effective !== 'boolean' || v.effective && (!v.enabled || !delivery)) return false;
    if (v.maintenanceUntil !== null && (!validWindowsMaintenanceTime(v.maintenanceUntil) || inventoryAge(v.maintenanceUntil, now) <= 0 || inventoryAge(v.maintenanceUntil, now) > 86400000)) return false;
    return v.revision === 0 ? v.changedAt === null && !v.enabled && !v.effective : validWindowsMaintenanceTime(v.changedAt) && inventoryAge(now, v.changedAt) >= 0;
}
export function validWindowsNotificationView(v: unknown): v is WindowsNotificationView {
    if (!exact(v, ['schemaVersion', 'serverNow', 'authorityExpiresAt', 'destinationHost', 'destinationBinding', 'deliveryEnabled', 'targets', 'counts']) || v.schemaVersion !== 'tracebolt.windows-notifications.v1' || !validWindowsMaintenanceTime(v.serverNow) || !validWindowsMaintenanceTime(v.authorityExpiresAt) || inventoryAge(v.authorityExpiresAt, v.serverNow) <= 0 || inventoryAge(v.authorityExpiresAt, v.serverNow) > 120000 || typeof v.deliveryEnabled !== 'boolean' || !validAlarmStatus(v.counts) || v.counts.enabled !== v.deliveryEnabled || typeof v.destinationHost !== 'string' || v.destinationHost.length > 253 || typeof v.destinationBinding !== 'string') return false;
    if (v.destinationBinding === '' ? v.destinationHost !== '' || v.deliveryEnabled : !validWindowsMaintenanceKey(v.destinationBinding) || !/^[a-zA-Z0-9.:[\]-]+$/.test(v.destinationHost) || v.destinationHost.length === 0) return false;
    if (!Array.isArray(v.targets) || v.targets.length > 125 || v.targets.length % 5 !== 0 || !v.targets.every(t => validTarget(t, v.serverNow as string, v.deliveryEnabled as boolean))) return false;
    const targets = v.targets as WindowsNotificationTarget[];
    if (new Set(targets.map(t => t.key)).size !== targets.length) return false;
    for (let i = 0; i < targets.length; i += 5) if (i > 0 && targets[i - 5].deviceId >= targets[i].deviceId || targets.slice(i, i + 5).some((t, j) => t.deviceId !== targets[i].deviceId || t.domain !== WINDOWS_NOTIFICATION_DOMAINS[j])) return false;
    return new TextEncoder().encode(JSON.stringify(v)).byteLength <= WINDOWS_NOTIFICATIONS_BYTES;
}
