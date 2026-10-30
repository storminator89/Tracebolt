import { inventoryAge } from './complete-packages-types';
import { validAlarmStatus } from './alarm-status-types';
import type { AlarmStatus } from './alarm-status-types';
import { validWindowsCapacityDeviceId } from './windows-capacity-types';
import { validWindowsMaintenanceKey, validWindowsMaintenanceTime } from './windows-maintenance-types';
import { validWindowsServiceHealthCompleteSelection } from './windows-service-health-complete-types';
import type { WindowsNotificationChange } from './windows-notifications-types';

export const WINDOWS_COMPLETE_NOTIFICATIONS_BYTES = 256 * 1024;
export interface WindowsCompleteNotificationTarget {
    key: string; deviceId: string; domain: 'service-complete'; revision: number; enabled: boolean; effective: boolean;
    maintenanceUntil: string | null; changedAt: string | null; healthPolicyRevision: number; grantId: string; grantRevision: number; services: string[]; actionable: boolean;
}
export interface WindowsCompleteNotificationView {
    schemaVersion: 'tracebolt.windows-complete-notifications.v1'; serverNow: string; authorityExpiresAt: string;
    destinationHost: string; destinationBinding: string; deliveryEnabled: boolean; targets: WindowsCompleteNotificationTarget[]; counts: AlarmStatus;
}
export type WindowsCompleteNotificationChange = WindowsNotificationChange;
const exact = (value: unknown, keys: string[]): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const integer = (value: unknown, minimum = 0): value is number => typeof value === 'number' && Number.isSafeInteger(value) && !Object.is(value, -0) && value >= minimum;
function validTarget(value: unknown, now: string, delivery: boolean): value is WindowsCompleteNotificationTarget {
    if (!exact(value, ['key', 'deviceId', 'domain', 'revision', 'enabled', 'effective', 'maintenanceUntil', 'changedAt', 'healthPolicyRevision', 'grantId', 'grantRevision', 'services', 'actionable']) || !validWindowsMaintenanceKey(value.key) || typeof value.deviceId !== 'string' || !validWindowsCapacityDeviceId(value.deviceId) || value.domain !== 'service-complete' || !integer(value.revision) || typeof value.enabled !== 'boolean' || typeof value.effective !== 'boolean' || typeof value.actionable !== 'boolean' || value.effective && (!value.enabled || !delivery || !value.actionable) || !integer(value.healthPolicyRevision, 1) || typeof value.grantId !== 'string' || !/^[a-f0-9]{32}$/.test(value.grantId) || !integer(value.grantRevision, 1) || !validWindowsServiceHealthCompleteSelection(value.services, value.actionable)) return false;
    if (value.maintenanceUntil !== null && (!validWindowsMaintenanceTime(value.maintenanceUntil) || inventoryAge(value.maintenanceUntil, now) <= 0 || inventoryAge(value.maintenanceUntil, now) > 86400000)) return false;
    return value.revision === 0 ? value.changedAt === null && !value.enabled && !value.effective : validWindowsMaintenanceTime(value.changedAt) && inventoryAge(now, value.changedAt) >= 0;
}
/** Separate, closed complete-source contract. V1 preview envelopes never qualify. */
export function validWindowsCompleteNotificationView(value: unknown): value is WindowsCompleteNotificationView {
    if (!exact(value, ['schemaVersion', 'serverNow', 'authorityExpiresAt', 'destinationHost', 'destinationBinding', 'deliveryEnabled', 'targets', 'counts']) || value.schemaVersion !== 'tracebolt.windows-complete-notifications.v1' || !validWindowsMaintenanceTime(value.serverNow) || !validWindowsMaintenanceTime(value.authorityExpiresAt) || inventoryAge(value.authorityExpiresAt, value.serverNow) <= 0 || inventoryAge(value.authorityExpiresAt, value.serverNow) > 120000 || typeof value.deliveryEnabled !== 'boolean' || !validAlarmStatus(value.counts) || value.counts.enabled !== value.deliveryEnabled || typeof value.destinationHost !== 'string' || value.destinationHost.length > 253 || typeof value.destinationBinding !== 'string') return false;
    if (value.destinationBinding === '' ? value.destinationHost !== '' || value.deliveryEnabled : !validWindowsMaintenanceKey(value.destinationBinding) || !/^[a-zA-Z0-9.:[\]-]+$/.test(value.destinationHost) || value.destinationHost.length === 0) return false;
    if (!Array.isArray(value.targets) || value.targets.length > 25 || !value.targets.every(target => validTarget(target, value.serverNow as string, value.deliveryEnabled as boolean))) return false;
    const targets = value.targets as WindowsCompleteNotificationTarget[];
    if (new Set(targets.map(target => target.key)).size !== targets.length || targets.some((target, index) => index > 0 && targets[index - 1].deviceId >= target.deviceId)) return false;
    return new TextEncoder().encode(JSON.stringify(value)).byteLength <= WINDOWS_COMPLETE_NOTIFICATIONS_BYTES;
}
