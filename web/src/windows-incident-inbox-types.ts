import { inventoryAge } from './complete-packages-types';
import { validWindowsCapacityDeviceId, validWindowsCapacityTimestamp as timestamp } from './windows-capacity-types';
import { validWindowsServiceHealthName } from './windows-service-health-types';

export const WINDOWS_INCIDENT_INBOX_BYTES = 256 * 1024;
export const WINDOWS_INCIDENT_ACK_BYTES = 1024;
export const WINDOWS_INCIDENT_PAGE_SIZE = 25;
export type WindowsIncidentScope = 'active' | 'recent' | 'resolved' | 'all';
export type WindowsIncidentAckFilter = 'all' | 'acknowledged' | 'unacknowledged';
export type WindowsIncidentDomain = 'contact' | 'disk' | 'cpu' | 'memory' | 'service';
export interface WindowsIncidentItem {
    key: string; deviceId: string; domain: WindowsIncidentDomain; incidentId: string; serviceName: string;
    openedAt: string; lastConfirmedAt: string; collectedAt: string | null; receivedAt: string;
    resolvedAt: string | null; recoveryCollectedAt: string | null; recoveryReceivedAt: string | null;
    closedReason: '' | 'reports-resumed' | 'within-policy' | 'running' | 'policy-changed';
    status: 'disabled' | 'unknown' | 'pending' | 'overdue' | 'recent' | 'pressure' | 'within-policy' | 'attention' | 'running';
    evaluatedAt: string | null; statusValidUntil: string | null; acknowledgedAt: string | null;
}
export interface WindowsIncidentInboxView {
    schemaVersion: 'tracebolt.windows-incident-inbox.v1'; serverNow: string; authorityExpiresAt: string;
    scope: WindowsIncidentScope; ack: WindowsIncidentAckFilter; offset: number; limit: number; total: number; nextOffset: number | null;
    counts: { active: number; resolved: number; acknowledged: number; unacknowledged: number; total: number };
    coverage: { devices: number; unavailableDevices: number; unknownChecks: number; disabledChecks: number };
    items: WindowsIncidentItem[];
}
export interface WindowsIncidentAcknowledgement { schemaVersion: 'tracebolt.windows-incident-ack.v1'; serverNow: string; key: string; acknowledgedAt: string }
const exact = (value: unknown, keys: readonly string[]): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const integer = (value: unknown, min = 0, max = Number.MAX_SAFE_INTEGER): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= min && value <= max;
const keyValid = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const atOrBefore = (value: unknown, now: string): value is string => timestamp(value) && inventoryAge(now, value) >= 0;
const optionalTime = (value: unknown, now: string): value is string | null => value === null || atOrBefore(value, now);
export function validWindowsIncidentQuery(scope: unknown, ack: unknown, offset: unknown, limit: unknown): boolean {
    return ['active', 'recent', 'resolved', 'all'].includes(scope as string) && ['all', 'acknowledged', 'unacknowledged'].includes(ack as string) && integer(offset, 0, 12500) && integer(limit, 1, 50);
}
function validItem(value: unknown, now: string): value is WindowsIncidentItem {
    if (!exact(value, ['key', 'deviceId', 'domain', 'incidentId', 'serviceName', 'openedAt', 'lastConfirmedAt', 'collectedAt', 'receivedAt', 'resolvedAt', 'recoveryCollectedAt', 'recoveryReceivedAt', 'closedReason', 'status', 'evaluatedAt', 'statusValidUntil', 'acknowledgedAt']) || !keyValid(value.key) || typeof value.deviceId !== 'string' || !validWindowsCapacityDeviceId(value.deviceId) || !['contact', 'disk', 'cpu', 'memory', 'service'].includes(value.domain as string)) return false;
    const prefix = value.domain === 'contact' ? 'wcontact_' : value.domain === 'service' ? 'wservice_' : 'wcapacity_';
    if (typeof value.incidentId !== 'string' || !new RegExp(`^${prefix}[a-f0-9]{16}$`).test(value.incidentId) || BigInt(`0x${value.incidentId.slice(prefix.length)}`) < 1n || BigInt(`0x${value.incidentId.slice(prefix.length)}`) > BigInt(Number.MAX_SAFE_INTEGER)) return false;
    if (value.domain === 'service' ? !validWindowsServiceHealthName(value.serviceName) : value.serviceName !== '') return false;
    const statuses = value.domain === 'contact' ? ['unknown', 'pending', 'overdue', 'recent'] : value.domain === 'service' ? ['disabled', 'unknown', 'pending', 'attention', 'running'] : ['disabled', 'unknown', 'pending', 'pressure', 'within-policy'];
    if (!statuses.includes(value.status as string) || !atOrBefore(value.openedAt, now) || !atOrBefore(value.lastConfirmedAt, now) || inventoryAge(value.lastConfirmedAt, value.openedAt) < 0 || !atOrBefore(value.receivedAt, value.lastConfirmedAt) || !optionalTime(value.evaluatedAt, now) || !optionalTime(value.acknowledgedAt, now) || value.acknowledgedAt !== null && inventoryAge(value.acknowledgedAt, value.openedAt) < 0) return false;
    if (value.status === 'unknown' || value.status === 'disabled' ? value.statusValidUntil !== null : !timestamp(value.statusValidUntil) || inventoryAge(value.statusValidUntil, now) < 0 || !timestamp(value.evaluatedAt) || inventoryAge(value.statusValidUntil, value.evaluatedAt) > 120000) return false;
    if (value.domain === 'contact' ? value.collectedAt !== null : !atOrBefore(value.collectedAt, value.lastConfirmedAt)) return false;
    if (value.resolvedAt === null) return value.closedReason === '' && value.recoveryCollectedAt === null && value.recoveryReceivedAt === null;
    if (!atOrBefore(value.resolvedAt, now) || inventoryAge(value.resolvedAt, value.lastConfirmedAt) < 0) return false;
    if (value.closedReason === 'policy-changed') return value.domain !== 'contact' && value.recoveryCollectedAt === null && value.recoveryReceivedAt === null;
    const reason = value.domain === 'contact' ? 'reports-resumed' : value.domain === 'service' ? 'running' : 'within-policy';
    return value.closedReason === reason && atOrBefore(value.recoveryReceivedAt, value.resolvedAt) && (value.domain === 'contact' ? value.recoveryCollectedAt === null : atOrBefore(value.recoveryCollectedAt, value.resolvedAt));
}
/** A closed, bounded projection: acknowledgement is independent of incident closure. */
export function validWindowsIncidentInboxView(value: unknown, scope: WindowsIncidentScope, ack: WindowsIncidentAckFilter, offset: number, limit = WINDOWS_INCIDENT_PAGE_SIZE): value is WindowsIncidentInboxView {
    if (!validWindowsIncidentQuery(scope, ack, offset, limit) || !exact(value, ['schemaVersion', 'serverNow', 'authorityExpiresAt', 'scope', 'ack', 'offset', 'limit', 'total', 'nextOffset', 'counts', 'coverage', 'items']) || value.schemaVersion !== 'tracebolt.windows-incident-inbox.v1' || !timestamp(value.serverNow) || !timestamp(value.authorityExpiresAt) || inventoryAge(value.authorityExpiresAt, value.serverNow) <= 0 || value.scope !== scope || value.ack !== ack || value.offset !== offset || value.limit !== limit || !integer(value.total)) return false;
    if (!exact(value.counts, ['active', 'resolved', 'acknowledged', 'unacknowledged', 'total']) || !Object.values(value.counts).every(n => integer(n)) || !exact(value.coverage, ['devices', 'unavailableDevices', 'unknownChecks', 'disabledChecks']) || !Object.values(value.coverage).every(n => integer(n))) return false;
    const counts = value.counts as unknown as WindowsIncidentInboxView['counts'];
    if (counts.active + counts.resolved !== counts.total || counts.acknowledged + counts.unacknowledged !== counts.total || value.total > counts.total || scope === 'active' && value.total > counts.active || scope === 'resolved' && value.total > counts.resolved || ack !== 'all' && value.total > counts[ack]) return false;
    if (!Array.isArray(value.items) || value.items.length !== Math.min(limit, Math.max(0, value.total - offset)) || !value.items.every(item => validItem(item, value.serverNow as string)) || new Set(value.items.map(item => item.key)).size !== value.items.length) return false;
    const items = value.items as WindowsIncidentItem[];
    if (items.some(item => item.statusValidUntil !== null && inventoryAge(value.authorityExpiresAt as string, item.statusValidUntil) < 0)) return false;
    if (items.some(item => scope === 'active' && item.resolvedAt !== null || scope === 'resolved' && item.resolvedAt === null || scope === 'recent' && inventoryAge(value.serverNow as string, item.openedAt) > 7 * 86400000 && (!item.resolvedAt || inventoryAge(value.serverNow as string, item.resolvedAt) > 7 * 86400000) || ack === 'acknowledged' && item.acknowledgedAt === null || ack === 'unacknowledged' && item.acknowledgedAt !== null)) return false;
    const next = offset + items.length < value.total ? offset + items.length : null;
    if (value.nextOffset !== next || next !== null && !integer(next, 1, 12500)) return false;
    return new TextEncoder().encode(JSON.stringify(value)).byteLength <= WINDOWS_INCIDENT_INBOX_BYTES;
}
export function validWindowsIncidentAcknowledgement(value: unknown, key: string): value is WindowsIncidentAcknowledgement {
    return exact(value, ['schemaVersion', 'serverNow', 'key', 'acknowledgedAt']) && value.schemaVersion === 'tracebolt.windows-incident-ack.v1' && keyValid(key) && value.key === key && timestamp(value.serverNow) && atOrBefore(value.acknowledgedAt, value.serverNow) && new TextEncoder().encode(JSON.stringify(value)).byteLength <= WINDOWS_INCIDENT_ACK_BYTES;
}

/** Local elapsed time can withhold a source status; receipt never refreshes evidence. */
export function windowsIncidentSourceStatus(item: WindowsIncidentItem, serverNow: string, elapsed: number): WindowsIncidentItem['status'] {
    if (item.status === 'disabled') return 'disabled';
    return Number.isFinite(elapsed) && elapsed >= 0 && item.statusValidUntil && inventoryAge(item.statusValidUntil, serverNow) > elapsed ? item.status : 'unknown';
}
