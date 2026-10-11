import { inventoryAge } from './complete-packages-types';
import { validWindowsCapacityDeviceId, validWindowsCapacityTimestamp } from './windows-capacity-types';
import type { WindowsService } from './windows-inventory-types';

export const WINDOWS_SERVICE_HEALTH_VIEW_BYTES = 512 * 1024;
export type WindowsServiceHealthStatus = 'disabled' | 'unknown' | 'running' | 'pending' | 'attention';
export interface WindowsServiceHealthPolicy { enabled: boolean; services: string[]; revision: number }
export interface WindowsServiceHealthObservation { state: 'running' | 'stopped' | 'paused'; collectedAt: string; receivedAt: string; sequence: number }
export interface WindowsServiceHealthCheck { name: string; status: Exclude<WindowsServiceHealthStatus, 'disabled'>; observation: WindowsServiceHealthObservation | null }
export interface WindowsServiceHealthIncident {
    id: string; name: string; policyRevision: number; openedAt: string; lastConfirmedAt: string;
    openingObservation: WindowsServiceHealthObservation; lastBadObservation: WindowsServiceHealthObservation;
    resolvedAt: string | null; recoveryObservation: WindowsServiceHealthObservation | null; closedReason: '' | 'policy-changed' | 'running';
}
export interface WindowsServiceHealthInventory {
    collectedAt: string; receivedAt: string; sequence: number; quality: 'healthy' | 'partial'; complete: boolean; truncated: boolean; countExact: boolean; observedCount: number;
    services: { name: string; displayName: string; state: WindowsService['state'] }[];
}
export interface WindowsServiceHealthView {
    schemaVersion: 'tracebolt.windows-service-view.v1'; deviceId: string; serverNow: string; certificateExpiresAt: string;
    policy: WindowsServiceHealthPolicy; status: WindowsServiceHealthStatus; evaluatedAt: string | null;
    checks: WindowsServiceHealthCheck[]; incidents: WindowsServiceHealthIncident[]; inventory: WindowsServiceHealthInventory | null;
}
const exact = (value: unknown, keys: readonly string[]): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const integer = (value: unknown, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): value is number => typeof value === 'number' && Number.isSafeInteger(value) && !Object.is(value, -0) && value >= minimum && value <= maximum;
const text = (value: unknown, required = true): value is string => typeof value === 'string' && (!required || value.trim().length > 0) && new TextEncoder().encode(value).byteLength <= 256 && !/[\p{Cc}\p{Cf}\uFFFD\uD800-\uDFFF\u2028\u2029]/u.test(value);
export const validWindowsServiceHealthName = (value: unknown): value is string => text(value);
/** Go sorts opaque UTF-8 names by bytes. JS's default UTF-16 sort is not equivalent. */
export function compareWindowsServiceNames(a: string, b: string): number {
    const left = new TextEncoder().encode(a), right = new TextEncoder().encode(b);
    for (let i = 0; i < Math.min(left.length, right.length); i++) if (left[i] !== right[i]) return left[i] - right[i];
    return left.length - right.length;
}
export function validWindowsServiceHealthSelection(value: unknown, enabled: boolean): value is string[] {
    return Array.isArray(value) && value.length <= 8 && (!enabled || value.length > 0) && value.every(validWindowsServiceHealthName) && value.every((name, i) => i === 0 || compareWindowsServiceNames(value[i - 1], name) < 0);
}
export const sameWindowsServiceNames = (left: readonly string[], right: readonly string[]): boolean => left.length === right.length && left.every((name, i) => name === right[i]);
const timestamp = validWindowsCapacityTimestamp;
const fresh = (value: { collectedAt: string; receivedAt: string }, at: string, elapsed = 0) => inventoryAge(at, value.collectedAt) + elapsed <= 120000 && inventoryAge(at, value.receivedAt) + elapsed <= 120000;
const bad = (value: WindowsServiceHealthObservation) => value.state === 'stopped' || value.state === 'paused';
function observation(value: unknown, at: string): value is WindowsServiceHealthObservation {
    return exact(value, ['state', 'collectedAt', 'receivedAt', 'sequence']) && ['running', 'stopped', 'paused'].includes(value.state as string) && timestamp(value.collectedAt) && timestamp(value.receivedAt) && integer(value.sequence, 1) && inventoryAge(at, value.collectedAt) >= 0 && inventoryAge(at, value.receivedAt) >= 0;
}
function incident(value: unknown, at: string): value is WindowsServiceHealthIncident {
    if (!exact(value, ['id', 'name', 'policyRevision', 'openedAt', 'lastConfirmedAt', 'openingObservation', 'lastBadObservation', 'resolvedAt', 'recoveryObservation', 'closedReason']) || typeof value.id !== 'string' || !/^wservice_[a-f0-9]{16}$/.test(value.id) || BigInt('0x' + value.id.slice(9)) === 0n || BigInt('0x' + value.id.slice(9)) > BigInt(Number.MAX_SAFE_INTEGER) || !validWindowsServiceHealthName(value.name) || !integer(value.policyRevision, 1) || !timestamp(value.openedAt) || !timestamp(value.lastConfirmedAt) || inventoryAge(at, value.lastConfirmedAt) < 0 || inventoryAge(value.lastConfirmedAt, value.openedAt) < 0 || !observation(value.openingObservation, value.openedAt) || !observation(value.lastBadObservation, value.lastConfirmedAt) || !bad(value.openingObservation) || !bad(value.lastBadObservation) || !fresh(value.openingObservation, value.openedAt) || !fresh(value.lastBadObservation, value.lastConfirmedAt) || value.lastBadObservation.sequence < value.openingObservation.sequence || inventoryAge(value.lastBadObservation.collectedAt, value.openingObservation.collectedAt) < 0) return false;
    if (value.resolvedAt === null) return value.closedReason === '' && value.recoveryObservation === null;
    if (!timestamp(value.resolvedAt) || inventoryAge(at, value.resolvedAt) < 0 || inventoryAge(value.resolvedAt, value.lastConfirmedAt) < 0) return false;
    if (value.closedReason === 'policy-changed') return value.recoveryObservation === null;
    return value.closedReason === 'running' && observation(value.recoveryObservation, value.resolvedAt) && value.recoveryObservation.state === 'running' && fresh(value.recoveryObservation, value.resolvedAt) && value.recoveryObservation.sequence > value.lastBadObservation.sequence && inventoryAge(value.recoveryObservation.collectedAt, value.lastBadObservation.collectedAt) > 0;
}
function inventory(value: unknown, at: string): value is WindowsServiceHealthInventory {
    if (!exact(value, ['collectedAt', 'receivedAt', 'sequence', 'quality', 'complete', 'truncated', 'countExact', 'observedCount', 'services']) || !timestamp(value.collectedAt) || !timestamp(value.receivedAt) || inventoryAge(at, value.collectedAt) < 0 || inventoryAge(at, value.receivedAt) < 0 || !fresh(value as unknown as WindowsServiceHealthInventory, at) || !integer(value.sequence, 1) || !['healthy', 'partial'].includes(value.quality as string) || typeof value.complete !== 'boolean' || typeof value.truncated !== 'boolean' || typeof value.countExact !== 'boolean' || !integer(value.observedCount, 0, 2048) || !Array.isArray(value.services) || value.services.length > 128 || value.observedCount < value.services.length) return false;
    if (value.quality === 'healthy' ? !value.complete || !value.countExact || value.truncated : value.complete || value.countExact && (!value.truncated || value.observedCount <= value.services.length)) return false;
    return value.services.every(row => exact(row, ['name', 'displayName', 'state']) && validWindowsServiceHealthName(row.name) && text(row.displayName, false) && ['running', 'stopped', 'paused', 'start_pending', 'stop_pending', 'continue_pending', 'pause_pending'].includes(row.state as string)) && value.services.every((row, i) => i === 0 || compareWindowsServiceNames((value.services as { name: string }[])[i - 1].name, row.name) < 0);
}
/** Closed operator contract. Unexpected host metadata and cross-scope envelopes fail closed. */
export function validWindowsServiceHealthView(value: unknown, deviceId: string): value is WindowsServiceHealthView {
    if (!exact(value, ['schemaVersion', 'deviceId', 'serverNow', 'certificateExpiresAt', 'policy', 'status', 'evaluatedAt', 'checks', 'incidents', 'inventory']) || value.schemaVersion !== 'tracebolt.windows-service-view.v1' || !validWindowsCapacityDeviceId(deviceId) || value.deviceId !== deviceId || !timestamp(value.serverNow) || !timestamp(value.certificateExpiresAt) || inventoryAge(value.certificateExpiresAt, value.serverNow) <= 0 || !exact(value.policy, ['enabled', 'services', 'revision']) || typeof value.policy.enabled !== 'boolean' || !validWindowsServiceHealthSelection(value.policy.services, value.policy.enabled) || !integer(value.policy.revision) || value.policy.enabled && value.policy.revision === 0 || !['disabled', 'unknown', 'running', 'pending', 'attention'].includes(value.status as string) || (value.status === 'disabled') === value.policy.enabled || !Array.isArray(value.checks) || value.checks.length > 8 || !Array.isArray(value.incidents) || value.incidents.length > 100 || !value.incidents.every(row => incident(row, value.serverNow as string))) return false;
    const policy = value.policy as unknown as WindowsServiceHealthPolicy, checks = value.checks as unknown as WindowsServiceHealthCheck[], incidents = value.incidents as unknown as WindowsServiceHealthIncident[];
    if (value.evaluatedAt !== null && (!timestamp(value.evaluatedAt) || inventoryAge(value.serverNow, value.evaluatedAt) < 0)) return false;
    if (value.inventory !== null && !inventory(value.inventory, value.serverNow)) return false;
    if (checks.some(row => !exact(row, ['name', 'status', 'observation']) || !validWindowsServiceHealthName(row.name) || !['unknown', 'running', 'pending', 'attention'].includes(row.status) || (row.status === 'unknown' ? row.observation !== null : row.observation === null || !observation(row.observation, value.serverNow as string)))) return false;
    if (!sameWindowsServiceNames(checks.map(row => row.name), policy.services)) return false;
    for (const row of checks) {
        if (!policy.enabled && row.status !== 'unknown') return false;
        if (row.observation) {
            const source = value.inventory as WindowsServiceHealthInventory | null, choice = source?.services.find(item => item.name === row.name);
            if (!source || !choice || choice.state !== row.observation.state || source.collectedAt !== row.observation.collectedAt || source.receivedAt !== row.observation.receivedAt || source.sequence !== row.observation.sequence) return false;
        }
        if (row.status !== 'unknown' && (!value.evaluatedAt || !row.observation || !observation(row.observation, value.evaluatedAt as string) || !fresh(row.observation, value.serverNow) || inventoryAge(value.serverNow, value.evaluatedAt as string) > 120000)) return false;
        if (row.status === 'running' && row.observation?.state !== 'running' || row.status === 'pending' && (!row.observation || !bad(row.observation))) return false;
        const open = incidents.filter(item => item.name === row.name && item.resolvedAt === null);
        if (open.length > 1 || row.status === 'attention' && open.length !== 1 || ['running', 'pending'].includes(row.status) && open.length !== 0) return false;
        if (row.observation && open.some(item => row.observation!.sequence < item.lastBadObservation.sequence || inventoryAge(row.observation!.collectedAt, item.lastBadObservation.collectedAt) < 0)) return false;
    }
    if (incidents.some((row, i) => row.policyRevision > policy.revision || row.closedReason === 'policy-changed' && row.policyRevision >= policy.revision || row.resolvedAt === null && (!policy.enabled || row.policyRevision !== policy.revision || !policy.services.includes(row.name)) || i > 0 && BigInt('0x' + incidents[i - 1].id.slice(9)) <= BigInt('0x' + row.id.slice(9)))) return false;
    const derived = !policy.enabled ? 'disabled' : checks.some(row => row.status === 'attention') ? 'attention' : checks.some(row => row.status === 'pending') ? 'pending' : checks.some(row => row.status === 'unknown') ? 'unknown' : 'running';
    if (value.status !== derived) return false;
    return new TextEncoder().encode(JSON.stringify(value)).byteLength <= WINDOWS_SERVICE_HEALTH_VIEW_BYTES;
}
/** Time only withholds a current assessment. It never opens or resolves an episode. */
export function windowsServiceHealthCheckStatus(view: WindowsServiceHealthView, check: WindowsServiceHealthCheck, elapsed: number): WindowsServiceHealthCheck['status'] {
    return !Number.isFinite(elapsed) || elapsed < 0 || !view.evaluatedAt || inventoryAge(view.serverNow, view.evaluatedAt) + elapsed > 120000 || !check.observation || !fresh(check.observation, view.serverNow, elapsed) ? 'unknown' : check.status;
}
export function windowsServiceHealthStatus(view: WindowsServiceHealthView, elapsed: number): WindowsServiceHealthStatus {
    if (!Number.isFinite(elapsed) || elapsed < 0) return 'unknown';
    if (!view.policy.enabled) return 'disabled';
    const states = view.checks.map(check => windowsServiceHealthCheckStatus(view, check, elapsed));
    return states.includes('attention') ? 'attention' : states.includes('pending') ? 'pending' : states.includes('unknown') ? 'unknown' : 'running';
}
export function windowsServiceHealthChoices(view: WindowsServiceHealthView, elapsed: number) {
    return view.inventory && Number.isFinite(elapsed) && elapsed >= 0 && fresh(view.inventory, view.serverNow, elapsed) ? view.inventory.services : [];
}
