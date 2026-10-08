import { inventoryAge } from './complete-packages-types';
import type { Device } from './types';
import { validWindowsDeviceId } from './windows-inventory-types';

export const WINDOWS_CONTACT_VIEW_BYTES = 64 * 1024;
export type WindowsContactStatus = 'unknown' | 'recent' | 'pending' | 'overdue';
export interface WindowsContactIncident {
    id: string; kind: 'overdue-report'; openedAt: string; lastConfirmedAt: string; lastAcceptedAt: string; sequence: number;
    resolvedAt: string | null; recoveryAcceptedAt: string | null; recoverySequence: number; closedReason?: 'reports-resumed';
}
export interface WindowsContactView {
    schemaVersion: 'tracebolt.windows-contact-view.v1'; deviceId: string; serverNow: string; status: WindowsContactStatus;
    lastAcceptedAt: string | null; sequence: number; evaluatedAt: string | null; certificateExpiresAt: string;
    incidents: WindowsContactIncident[];
}
const exact = (value: unknown, keys: readonly string[]): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
export const validWindowsContactTimestamp = (value: unknown): value is string => typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value) && Number.isFinite(Date.parse(value)) && Number(value.slice(0, 4)) >= 1970 && new Date(Date.parse(value)).toISOString().slice(0, 19) === value.slice(0, 19);
export const validWindowsContactDeviceId = (value: string): boolean => validWindowsDeviceId(value) && value !== `agent_${'0'.repeat(32)}`;
const sequence = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
function incident(value: unknown, serverNow: string): value is WindowsContactIncident {
    const closed = value !== null && typeof value === 'object' && Object.hasOwn(value, 'closedReason');
    if (!exact(value, ['id', 'kind', 'openedAt', 'lastConfirmedAt', 'lastAcceptedAt', 'sequence', 'resolvedAt', 'recoveryAcceptedAt', 'recoverySequence', ...(closed ? ['closedReason'] : [])]) || typeof value.id !== 'string' || !/^wcontact_[a-f0-9]{16}$/.test(value.id) || (BigInt('0x' + value.id.slice(9)) === 0n || BigInt('0x' + value.id.slice(9)) > BigInt(Number.MAX_SAFE_INTEGER)) || value.kind !== 'overdue-report' || !validWindowsContactTimestamp(value.openedAt) || !validWindowsContactTimestamp(value.lastConfirmedAt) || !validWindowsContactTimestamp(value.lastAcceptedAt) || !sequence(value.sequence) || value.sequence === 0 || !sequence(value.recoverySequence)) return false;
    if (inventoryAge(serverNow, value.openedAt) < 0 || inventoryAge(serverNow, value.lastConfirmedAt) < 0 || inventoryAge(value.lastConfirmedAt, value.openedAt) < 0 || inventoryAge(value.openedAt, value.lastAcceptedAt) <= 120000) return false;
    if (value.resolvedAt === null) return value.recoveryAcceptedAt === null && value.recoverySequence === 0 && !closed;
    return validWindowsContactTimestamp(value.resolvedAt) && validWindowsContactTimestamp(value.recoveryAcceptedAt) && value.closedReason === 'reports-resumed' && inventoryAge(serverNow, value.resolvedAt) >= 0 && inventoryAge(value.resolvedAt, value.lastConfirmedAt) >= 0 && inventoryAge(value.resolvedAt, value.recoveryAcceptedAt) >= 0 && inventoryAge(value.recoveryAcceptedAt, value.lastConfirmedAt) >= 0 && inventoryAge(value.resolvedAt, value.recoveryAcceptedAt) <= 120000 && value.recoverySequence > value.sequence;
}
/** Closed operator display schema. No host rows, free-form detail or provider data. */
export function validWindowsContactView(value: unknown, deviceId: string): value is WindowsContactView {
    if (!exact(value, ['schemaVersion', 'deviceId', 'serverNow', 'status', 'lastAcceptedAt', 'sequence', 'evaluatedAt', 'certificateExpiresAt', 'incidents']) || value.schemaVersion !== 'tracebolt.windows-contact-view.v1' || !validWindowsContactDeviceId(deviceId) || value.deviceId !== deviceId || !validWindowsContactTimestamp(value.serverNow) || !validWindowsContactTimestamp(value.certificateExpiresAt) || inventoryAge(value.certificateExpiresAt, value.serverNow) <= 0 || typeof value.status !== 'string' || !['unknown', 'recent', 'pending', 'overdue'].includes(value.status) || !sequence(value.sequence) || !Array.isArray(value.incidents) || value.incidents.length > 100 || !value.incidents.every(row => incident(row, value.serverNow as string)) || new Set(value.incidents.map(row => row.id)).size !== value.incidents.length) return false;
    if (value.lastAcceptedAt === null ? value.sequence !== 0 : !validWindowsContactTimestamp(value.lastAcceptedAt) || value.sequence === 0 || inventoryAge(value.serverNow, value.lastAcceptedAt) < 0) return false;
    if (value.evaluatedAt !== null && (!validWindowsContactTimestamp(value.evaluatedAt) || inventoryAge(value.serverNow, value.evaluatedAt) < 0)) return false;
    if (value.incidents.some(row => !value.evaluatedAt || inventoryAge(value.evaluatedAt as string, row.lastConfirmedAt) < 0 || row.resolvedAt !== null && inventoryAge(value.evaluatedAt as string, row.resolvedAt) < 0)) return false;
    for (let i = 1; i < value.incidents.length; i++) {
        const newer = value.incidents[i - 1], older = value.incidents[i];
        if (BigInt('0x' + older.id.slice(9)) >= BigInt('0x' + newer.id.slice(9)) || older.resolvedAt === null || inventoryAge(newer.openedAt, older.resolvedAt) < 0) return false;
    }
    const open = value.incidents.filter(row => row.resolvedAt === null);
    if (open.length > 1 || value.status !== 'unknown' && (!value.evaluatedAt || !value.lastAcceptedAt) || value.status === 'overdue' && open.length !== 1 || value.status === 'pending' && open.length !== 0 || value.status === 'recent' && open.length !== 0) return false;
    return new TextEncoder().encode(JSON.stringify(value)).byteLength <= WINDOWS_CONTACT_VIEW_BYTES;
}
export function windowsContactDeviceEligible(device: Device | undefined, id: string): boolean {
    const identities = device?.capabilities?.filter(item => item.id === 'agent_identity') ?? [];
    return Boolean(device && validWindowsContactDeviceId(id) && device.id === id && device.platform === 'windows' && device.source === 'lan' && !device.synthetic && identities.length === 1 && identities[0].status === 'supported' && device.agentCertificate?.source === 'guided-enrollment' && validWindowsContactTimestamp(device.agentCertificate.checkedAt) && validWindowsContactTimestamp(device.agentCertificate.expiresAt));
}
/** Local time can withhold a decision, never create or resolve an incident. */
export function windowsContactStatus(view: WindowsContactView, elapsedMS: number): WindowsContactStatus {
    if (!Number.isFinite(elapsedMS) || elapsedMS < 0 || !view.evaluatedAt || inventoryAge(view.serverNow, view.evaluatedAt) + elapsedMS > 120000) return 'unknown';
    if (view.status === 'recent' && (!view.lastAcceptedAt || inventoryAge(view.serverNow, view.lastAcceptedAt) + elapsedMS > 120000)) return 'unknown';
    return view.status;
}
