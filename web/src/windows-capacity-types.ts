import { inventoryAge } from './complete-packages-types';
import type { Device } from './types';
import { validWindowsDeviceId } from './windows-inventory-types';

export const WINDOWS_CAPACITY_VIEW_BYTES = 128 * 1024;
export type WindowsCapacityStatus = 'disabled' | 'unknown' | 'within-policy' | 'pending' | 'pressure';
export interface WindowsCapacityPolicy { enabled: boolean; thresholdPercent: number; revision: number }
export interface WindowsCapacityObservation { value: number; collectedAt: string; receivedAt: string; sequence: number }
export interface WindowsCapacityIncident {
    id: string; policyRevision: number; thresholdPercent: number; openedAt: string; lastConfirmedAt: string;
    openingObservation: WindowsCapacityObservation; lastHighObservation: WindowsCapacityObservation;
    resolvedAt: string | null; recoveryObservation: WindowsCapacityObservation | null; closedReason: '' | 'within-policy' | 'policy-changed';
}
export type WindowsResourceMetric = 'cpu' | 'memory';
export type WindowsPercentageMetric = 'disk' | WindowsResourceMetric;
interface WindowsPercentageFields {
    deviceId: string; serverNow: string; certificateExpiresAt: string;
    policy: WindowsCapacityPolicy; status: WindowsCapacityStatus; evaluatedAt: string | null;
    observation: WindowsCapacityObservation | null; incidents: WindowsCapacityIncident[];
}
export interface WindowsCapacityView extends WindowsPercentageFields { schemaVersion: 'tracebolt.windows-capacity-view.v1' }
export interface WindowsResourceView extends WindowsPercentageFields { schemaVersion: 'tracebolt.windows-resource-view.v1'; readonly metric: WindowsResourceMetric }
export type WindowsPercentageView = WindowsCapacityView | WindowsResourceView;
const exact = (value: unknown, keys: readonly string[]): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
export const validWindowsCapacityTimestamp = (value: unknown): value is string => typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value) && Number.isFinite(Date.parse(value)) && Number(value.slice(0, 4)) >= 1970 && new Date(Date.parse(value)).toISOString().slice(0, 19) === value.slice(0, 19);
export const validWindowsCapacityDeviceId = (value: string): boolean => validWindowsDeviceId(value) && value !== `agent_${'0'.repeat(32)}`;
const integer = (value: unknown, minimum: number): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum;
export const validWindowsCapacityThreshold = (value: unknown): value is number => integer(value, 50) && value <= 99;
function observation(value: unknown, at: string): value is WindowsCapacityObservation {
    return exact(value, ['value', 'collectedAt', 'receivedAt', 'sequence']) && typeof value.value === 'number' && Number.isFinite(value.value) && value.value >= 0 && value.value <= 100 && validWindowsCapacityTimestamp(value.collectedAt) && validWindowsCapacityTimestamp(value.receivedAt) && integer(value.sequence, 1) && inventoryAge(at, value.collectedAt) >= 0 && inventoryAge(at, value.receivedAt) >= 0;
}
const fresh = (value: WindowsCapacityObservation, at: string, elapsed = 0) => inventoryAge(at, value.collectedAt) + elapsed <= 120000 && inventoryAge(at, value.receivedAt) + elapsed <= 120000;
function incident(value: unknown, serverNow: string): value is WindowsCapacityIncident {
    if (!exact(value, ['id', 'policyRevision', 'thresholdPercent', 'openedAt', 'lastConfirmedAt', 'openingObservation', 'lastHighObservation', 'resolvedAt', 'recoveryObservation', 'closedReason']) || typeof value.id !== 'string' || !/^wcapacity_[a-f0-9]{16}$/.test(value.id) || BigInt('0x' + value.id.slice(10)) === 0n || BigInt('0x' + value.id.slice(10)) > BigInt(Number.MAX_SAFE_INTEGER) || !integer(value.policyRevision, 1) || !validWindowsCapacityThreshold(value.thresholdPercent) || !validWindowsCapacityTimestamp(value.openedAt) || !validWindowsCapacityTimestamp(value.lastConfirmedAt) || inventoryAge(serverNow, value.lastConfirmedAt) < 0 || inventoryAge(value.lastConfirmedAt, value.openedAt) < 0 || !observation(value.openingObservation, value.openedAt) || !observation(value.lastHighObservation, value.lastConfirmedAt) || value.openingObservation.value < value.thresholdPercent || value.lastHighObservation.value < value.thresholdPercent || !fresh(value.openingObservation, value.openedAt) || !fresh(value.lastHighObservation, value.lastConfirmedAt) || value.lastHighObservation.sequence < value.openingObservation.sequence || inventoryAge(value.lastHighObservation.collectedAt, value.openingObservation.collectedAt) < 0) return false;
    if (value.resolvedAt === null) return value.closedReason === '' && value.recoveryObservation === null;
    if (!validWindowsCapacityTimestamp(value.resolvedAt) || inventoryAge(serverNow, value.resolvedAt) < 0 || inventoryAge(value.resolvedAt, value.lastConfirmedAt) < 0) return false;
    if (value.closedReason === 'policy-changed') return value.recoveryObservation === null;
    return value.closedReason === 'within-policy' && observation(value.recoveryObservation, value.resolvedAt) && fresh(value.recoveryObservation, value.resolvedAt) && value.recoveryObservation.value <= value.thresholdPercent - 5 && value.recoveryObservation.sequence > value.lastHighObservation.sequence && inventoryAge(value.recoveryObservation.collectedAt, value.lastHighObservation.collectedAt) >= 0;
}
/** Exact bounded operator-only schema. Never accept host rows or free-form detail. */
export function validWindowsPercentageView(value: unknown, deviceId: string, metric: WindowsPercentageMetric): value is WindowsPercentageView {
    if (!['disk', 'cpu', 'memory'].includes(metric)) return false;
    const keys = ['schemaVersion', 'deviceId', 'serverNow', 'certificateExpiresAt', 'policy', 'status', 'evaluatedAt', 'observation', 'incidents'];
    if (metric !== 'disk') keys.push('metric');
    if (!exact(value, keys) || (metric === 'disk' ? value.schemaVersion !== 'tracebolt.windows-capacity-view.v1' : value.schemaVersion !== 'tracebolt.windows-resource-view.v1' || value.metric !== metric) || !validWindowsCapacityDeviceId(deviceId) || value.deviceId !== deviceId || !validWindowsCapacityTimestamp(value.serverNow) || !validWindowsCapacityTimestamp(value.certificateExpiresAt) || inventoryAge(value.certificateExpiresAt, value.serverNow) <= 0 || !exact(value.policy, ['enabled', 'thresholdPercent', 'revision']) || typeof value.policy.enabled !== 'boolean' || !validWindowsCapacityThreshold(value.policy.thresholdPercent) || !integer(value.policy.revision, 0) || value.policy.enabled && value.policy.revision === 0 || typeof value.status !== 'string' || !['disabled', 'unknown', 'within-policy', 'pending', 'pressure'].includes(value.status) || (value.status === 'disabled') === value.policy.enabled || !Array.isArray(value.incidents) || value.incidents.length > 100 || !value.incidents.every(row => incident(row, value.serverNow as string)) || new Set(value.incidents.map(row => row.id)).size !== value.incidents.length) return false;
    if (value.evaluatedAt !== null && (!validWindowsCapacityTimestamp(value.evaluatedAt) || inventoryAge(value.serverNow, value.evaluatedAt) < 0)) return false;
    if (value.observation !== null && (!observation(value.observation, value.serverNow) || ['unknown', 'disabled'].includes(value.status))) return false;
    if (value.evaluatedAt !== null && (value.observation !== null && !observation(value.observation, value.evaluatedAt as string) || value.incidents.some(row => inventoryAge(value.evaluatedAt as string, row.lastConfirmedAt) < 0 || row.resolvedAt !== null && inventoryAge(value.evaluatedAt as string, row.resolvedAt) < 0))) return false;
    const policy = value.policy as unknown as WindowsCapacityPolicy;
    if (value.incidents.some(row => row.policyRevision > policy.revision || row.closedReason === 'policy-changed' && row.policyRevision >= policy.revision || row.resolvedAt === null && (!policy.enabled || row.policyRevision !== policy.revision || row.thresholdPercent !== policy.thresholdPercent))) return false;
    for (let i = 1; i < value.incidents.length; i++) {
        const newer = value.incidents[i - 1], older = value.incidents[i];
        if (BigInt('0x' + older.id.slice(10)) >= BigInt('0x' + newer.id.slice(10)) || older.resolvedAt === null || inventoryAge(newer.openedAt, older.resolvedAt) < 0) return false;
    }
    const open = value.incidents.filter(row => row.resolvedAt === null);
    if (value.observation !== null && open.some(row => (value.observation as WindowsCapacityObservation).sequence < row.lastHighObservation.sequence || inventoryAge((value.observation as WindowsCapacityObservation).collectedAt, row.lastHighObservation.collectedAt) < 0)) return false;
    if (open.length > 1 || value.status === 'pressure' && open.length !== 1 || ['within-policy', 'pending', 'disabled'].includes(value.status) && open.length !== 0) return false;
    if (!['unknown', 'disabled'].includes(value.status) && (!value.evaluatedAt || !value.observation || !fresh(value.observation as WindowsCapacityObservation, value.serverNow) || inventoryAge(value.serverNow, value.evaluatedAt as string) > 120000)) return false;
    if (value.status === 'pending' && (value.observation as WindowsCapacityObservation).value < policy.thresholdPercent || value.status === 'within-policy' && (value.observation as WindowsCapacityObservation).value >= policy.thresholdPercent) return false;
    return new TextEncoder().encode(JSON.stringify(value)).byteLength <= WINDOWS_CAPACITY_VIEW_BYTES;
}
// Disk remains a closed, unchanged v1 contract. A resource response must match its
// requested metric; neither a disk response nor another resource can be adopted.
export function validWindowsCapacityView(value: unknown, deviceId: string): value is WindowsCapacityView { return validWindowsPercentageView(value, deviceId, 'disk'); }
export function validWindowsResourceView(value: unknown, deviceId: string, metric: WindowsResourceMetric): value is WindowsResourceView { return (metric === 'cpu' || metric === 'memory') && validWindowsPercentageView(value, deviceId, metric); }
export function windowsCapacityDeviceEligible(device: Device | undefined, id: string): boolean {
    const identities = device?.capabilities?.filter(item => item.id === 'agent_identity') ?? [];
    return Boolean(device && validWindowsCapacityDeviceId(id) && device.id === id && device.platform === 'windows' && device.source === 'lan' && !device.synthetic && identities.length === 1 && identities[0].status === 'supported' && device.agentCertificate?.source === 'guided-enrollment' && validWindowsCapacityTimestamp(device.agentCertificate.checkedAt) && validWindowsCapacityTimestamp(device.agentCertificate.expiresAt));
}
/** Time only withholds assessments; it never opens or resolves incidents. */
export function windowsCapacityStatus(view: WindowsPercentageView, elapsedMS: number): WindowsCapacityStatus {
    if (!Number.isFinite(elapsedMS) || elapsedMS < 0) return 'unknown';
    if (!view.policy.enabled) return 'disabled';
    if (!view.evaluatedAt || inventoryAge(view.serverNow, view.evaluatedAt) + elapsedMS > 120000 || !view.observation || !fresh(view.observation, view.serverNow, elapsedMS)) return 'unknown';
    return view.status;
}
