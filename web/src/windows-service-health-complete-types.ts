import { inventoryAge } from './complete-packages-types';
import { validWindowsCapacityDeviceId, validWindowsCapacityTimestamp } from './windows-capacity-types';
import { fullServicesGenerationId, validFullServiceRow } from './windows-full-services-types';
import type { FullServicesComplete, FullServiceState } from './windows-full-services-types';
import { compareWindowsServiceNames, sameWindowsServiceNames } from './windows-service-health-types';

export const WINDOWS_SERVICE_HEALTH_COMPLETE_VIEW_BYTES = 512 * 1024;
export type WindowsServiceHealthCompleteStatus = 'disabled' | 'unknown' | 'running' | 'pending' | 'attention';
export interface WindowsServiceHealthCompletePolicy { enabled: boolean; services: string[]; revision: number; source?: WindowsServiceHealthSourceBinding }
export interface WindowsServiceHealthCompleteObservation { state: 'running' | 'stopped' | 'paused'; collectedAt: string; receivedAt: string; sequence: number; source: WindowsServiceHealthSource }
export interface WindowsServiceHealthCompleteCheck { name: string; status: Exclude<WindowsServiceHealthCompleteStatus, 'disabled'>; observation: WindowsServiceHealthCompleteObservation | null }
export interface WindowsServiceHealthCompleteIncident {
    id: string; name: string; policyRevision: number; openedAt: string; lastConfirmedAt: string;
    openingObservation: WindowsServiceHealthCompleteObservation; lastBadObservation: WindowsServiceHealthCompleteObservation;
    resolvedAt: string | null; recoveryObservation: WindowsServiceHealthCompleteObservation | null; closedReason: '' | 'policy-changed' | 'running';
}
export interface WindowsServiceHealthCompleteInventory {
    collectedAt: string; receivedAt: string; sequence: number; quality: 'healthy' | 'partial'; complete: boolean; truncated: boolean; countExact: boolean; observedCount: number;
    services: { name: string; displayName: string; state: FullServiceState | 'unknown' }[]; source: WindowsServiceHealthSource;
}
export interface WindowsServiceHealthCompleteView {
    schemaVersion: 'tracebolt.windows-service-view.v2'; deviceId: string; serverNow: string; certificateExpiresAt: string;
    policy: WindowsServiceHealthCompletePolicy; status: WindowsServiceHealthCompleteStatus; evaluatedAt: string | null;
    checks: WindowsServiceHealthCompleteCheck[]; incidents: WindowsServiceHealthCompleteIncident[]; inventory: WindowsServiceHealthCompleteInventory | null;
}
const exact = (value: unknown, keys: readonly string[]): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const integer = (value: unknown, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): value is number => typeof value === 'number' && Number.isSafeInteger(value) && !Object.is(value, -0) && value >= minimum && value <= maximum;
const text = (value: unknown, required = true): value is string => typeof value === 'string' && (!required || value.length > 0) && value.length <= 256 && new TextEncoder().encode(value).byteLength <= 1024 && !/[\u0000\uD800-\uDFFF]/u.test(value);
export const validWindowsServiceHealthCompleteName = (value: unknown): value is string => text(value) && validFullServiceRow({ name: value, displayName: null, displayNameQuality: 'unavailable', state: null, stateQuality: 'unavailable', pid: null, pidQuality: 'unavailable' });
export function validWindowsServiceHealthCompleteSelection(value: unknown, enabled: boolean): value is string[] {
    return Array.isArray(value) && value.length <= 8 && (!enabled || value.length > 0) && value.every(validWindowsServiceHealthCompleteName) && value.every((name, i) => i === 0 || compareWindowsServiceNames(value[i - 1], name) < 0);
}
const timestamp = validWindowsCapacityTimestamp;
const fresh = (value: { source: WindowsServiceHealthSource }, at: string, elapsed = 0) => windowsServiceHealthSourceFresh(value.source, at, elapsed);
const bad = (value: WindowsServiceHealthCompleteObservation) => value.state === 'stopped' || value.state === 'paused';
function observation(value: unknown, at: string): value is WindowsServiceHealthCompleteObservation {
    return exact(value, ['state', 'collectedAt', 'receivedAt', 'sequence', 'source']) && ['running', 'stopped', 'paused'].includes(value.state as string) && timestamp(value.collectedAt) && timestamp(value.receivedAt) && integer(value.sequence, 1) && inventoryAge(at, value.collectedAt) >= 0 && inventoryAge(at, value.receivedAt) >= 0 && validWindowsServiceHealthSource(value.source) && value.sequence === value.source.sequence && value.collectedAt === value.source.capturedAt && value.receivedAt === value.source.receivedAt;
}
function incident(value: unknown, at: string): value is WindowsServiceHealthCompleteIncident {
    if (!exact(value, ['id', 'name', 'policyRevision', 'openedAt', 'lastConfirmedAt', 'openingObservation', 'lastBadObservation', 'resolvedAt', 'recoveryObservation', 'closedReason']) || typeof value.id !== 'string' || !/^wservice_[a-f0-9]{16}$/.test(value.id) || BigInt('0x' + value.id.slice(9)) === 0n || BigInt('0x' + value.id.slice(9)) > BigInt(Number.MAX_SAFE_INTEGER) || !validWindowsServiceHealthCompleteName(value.name) || !integer(value.policyRevision, 1) || !timestamp(value.openedAt) || !timestamp(value.lastConfirmedAt) || inventoryAge(at, value.lastConfirmedAt) < 0 || inventoryAge(value.lastConfirmedAt, value.openedAt) < 0 || !observation(value.openingObservation, value.openedAt) || !observation(value.lastBadObservation, value.lastConfirmedAt) || !bad(value.openingObservation) || !bad(value.lastBadObservation) || !fresh(value.openingObservation, value.openedAt) || !fresh(value.lastBadObservation, value.lastConfirmedAt) || value.lastBadObservation.sequence < value.openingObservation.sequence || inventoryAge(value.lastBadObservation.collectedAt, value.openingObservation.collectedAt) < 0) return false;
    if (value.resolvedAt === null) return value.closedReason === '' && value.recoveryObservation === null;
    if (!timestamp(value.resolvedAt) || inventoryAge(at, value.resolvedAt) < 0 || inventoryAge(value.resolvedAt, value.lastConfirmedAt) < 0) return false;
    if (value.closedReason === 'policy-changed') return value.recoveryObservation === null;
    return value.closedReason === 'running' && observation(value.recoveryObservation, value.resolvedAt) && value.recoveryObservation.state === 'running' && fresh(value.recoveryObservation, value.resolvedAt) && value.recoveryObservation.sequence > value.lastBadObservation.sequence && inventoryAge(value.recoveryObservation.collectedAt, value.lastBadObservation.collectedAt) > 0;
}
export function validWindowsServiceHealthCompletePolicy(value: unknown): value is WindowsServiceHealthCompletePolicy {
    return exact(value, ['enabled', 'services', 'revision', ...(value && typeof value === 'object' && Object.hasOwn(value, 'source') ? ['source'] : [])]) && typeof value.enabled === 'boolean' && validWindowsServiceHealthCompleteSelection(value.services, value.enabled) && integer(value.revision) && (!value.enabled || value.revision > 0) && (!(value.enabled || value.revision > 0 && value.services.length > 0) || validWindowsServiceHealthSourceBinding(value.source)) && (value.source === undefined || validWindowsServiceHealthSourceBinding(value.source));
}
export function validWindowsServiceHealthCompleteInventory(value: unknown, at: string): value is WindowsServiceHealthCompleteInventory {
    if (!exact(value, ['collectedAt', 'receivedAt', 'sequence', 'quality', 'complete', 'truncated', 'countExact', 'observedCount', 'services', 'source']) || !validWindowsServiceHealthSource(value.source) || !windowsServiceHealthSourceFresh(value.source, at) || value.collectedAt !== value.source.capturedAt || value.receivedAt !== value.source.receivedAt || value.sequence !== value.source.sequence || value.quality !== 'healthy' || value.complete !== true || value.truncated !== false || value.countExact !== true || value.observedCount !== value.source.rowCount || !Array.isArray(value.services) || value.services.length > 8 || value.services.length > value.source.rowCount) return false;
    return value.services.every(row => exact(row, ['name', 'displayName', 'state']) && validWindowsServiceHealthCompleteName(row.name) && text(row.displayName, false) && ['unknown', 'running', 'stopped', 'paused', 'start_pending', 'stop_pending', 'continue_pending', 'pause_pending'].includes(row.state as string)) && value.services.every((row, i) => i === 0 || compareWindowsServiceNames((value.services as { name: string }[])[i - 1].name, row.name) < 0);
}
/** Closed operator contract. Unexpected host metadata and cross-scope envelopes fail closed. */
export function validWindowsServiceHealthCompleteView(value: unknown, deviceId: string): value is WindowsServiceHealthCompleteView {
    if (!exact(value, ['schemaVersion', 'deviceId', 'serverNow', 'certificateExpiresAt', 'policy', 'status', 'evaluatedAt', 'checks', 'incidents', 'inventory']) || value.schemaVersion !== 'tracebolt.windows-service-view.v2' || !validWindowsCapacityDeviceId(deviceId) || value.deviceId !== deviceId || !timestamp(value.serverNow) || !timestamp(value.certificateExpiresAt) || inventoryAge(value.certificateExpiresAt, value.serverNow) <= 0 || !validWindowsServiceHealthCompletePolicy(value.policy) || !['disabled', 'unknown', 'running', 'pending', 'attention'].includes(value.status as string) || (value.status === 'disabled') === value.policy.enabled || !Array.isArray(value.checks) || value.checks.length > 8 || !Array.isArray(value.incidents) || value.incidents.length > 100 || !value.incidents.every(row => incident(row, value.serverNow as string))) return false;
    const policy = value.policy as unknown as WindowsServiceHealthCompletePolicy, checks = value.checks as unknown as WindowsServiceHealthCompleteCheck[], incidents = value.incidents as unknown as WindowsServiceHealthCompleteIncident[];
    if (value.evaluatedAt !== null && (!timestamp(value.evaluatedAt) || inventoryAge(value.serverNow, value.evaluatedAt) < 0)) return false;
    if (value.inventory !== null && (!validWindowsServiceHealthCompleteInventory(value.inventory, value.serverNow) || !validSourceDevice(value.inventory.source, deviceId) || value.inventory.services.some(row => !policy.services.includes(row.name)))) return false;
    if (incidents.some(row => ![row.openingObservation, row.lastBadObservation, row.recoveryObservation].every(o => o === null || validSourceDevice(o.source, deviceId)))) return false;
    if (checks.some(row => !exact(row, ['name', 'status', 'observation']) || !validWindowsServiceHealthCompleteName(row.name) || !['unknown', 'running', 'pending', 'attention'].includes(row.status) || (row.status === 'unknown' ? row.observation !== null : row.observation === null || !observation(row.observation, value.serverNow as string)))) return false;
    if (!sameWindowsServiceNames(checks.map(row => row.name), policy.services)) return false;
    for (const row of checks) {
        if (!policy.enabled && row.status !== 'unknown') return false;
        if (row.observation) {
            const source = value.inventory as WindowsServiceHealthCompleteInventory | null, choice = source?.services.find(item => item.name === row.name);
            if (!source || !choice || choice.state !== row.observation.state || source.collectedAt !== row.observation.collectedAt || source.receivedAt !== row.observation.receivedAt || source.sequence !== row.observation.sequence || !sameWindowsServiceHealthSource(source.source, row.observation.source) || !sourceBindingMatches(policy.source, row.observation.source)) return false;
        }
        if (row.status !== 'unknown' && (!value.evaluatedAt || !row.observation || !observation(row.observation, value.evaluatedAt as string) || !fresh(row.observation, value.serverNow) || inventoryAge(value.serverNow, value.evaluatedAt as string) > 120000)) return false;
        if (row.status === 'running' && row.observation?.state !== 'running' || row.status === 'pending' && (!row.observation || !bad(row.observation))) return false;
        const open = incidents.filter(item => item.name === row.name && item.resolvedAt === null);
        if (open.length > 1 || row.status === 'attention' && open.length !== 1 || ['running', 'pending'].includes(row.status) && open.length !== 0) return false;
        if (row.observation && !validSourceDevice(row.observation.source, deviceId)) return false;
        if (row.observation && open.some(item => row.observation!.sequence < item.lastBadObservation.sequence || inventoryAge(row.observation!.collectedAt, item.lastBadObservation.collectedAt) < 0)) return false;
    }
    if (incidents.some((row, i) => row.policyRevision > policy.revision || row.closedReason === 'policy-changed' && row.policyRevision >= policy.revision || row.resolvedAt === null && (!policy.enabled || row.policyRevision !== policy.revision || !policy.services.includes(row.name)) || i > 0 && BigInt('0x' + incidents[i - 1].id.slice(9)) <= BigInt('0x' + row.id.slice(9)))) return false;
    const derived = !policy.enabled ? 'disabled' : checks.some(row => row.status === 'attention') ? 'attention' : checks.some(row => row.status === 'pending') ? 'pending' : checks.some(row => row.status === 'unknown') ? 'unknown' : 'running';
    if (value.status !== derived) return false;
    return new TextEncoder().encode(JSON.stringify(value)).byteLength <= WINDOWS_SERVICE_HEALTH_COMPLETE_VIEW_BYTES;
}
/** Time only withholds a current assessment. It never opens or resolves an episode. */
export function windowsServiceHealthCompleteCheckStatus(view: WindowsServiceHealthCompleteView, check: WindowsServiceHealthCompleteCheck, elapsed: number): WindowsServiceHealthCompleteCheck['status'] {
    return !Number.isFinite(elapsed) || elapsed < 0 || !view.evaluatedAt || inventoryAge(view.serverNow, view.evaluatedAt) + elapsed > 120000 || !check.observation || !fresh(check.observation, view.serverNow, elapsed) ? 'unknown' : check.status;
}
export function windowsServiceHealthCompleteStatus(view: WindowsServiceHealthCompleteView, elapsed: number): WindowsServiceHealthCompleteStatus {
    if (!Number.isFinite(elapsed) || elapsed < 0) return 'unknown';
    if (!view.policy.enabled) return 'disabled';
    const states = view.checks.map(check => windowsServiceHealthCompleteCheckStatus(view, check, elapsed));
    return states.includes('attention') ? 'attention' : states.includes('pending') ? 'pending' : states.includes('unknown') ? 'unknown' : 'running';
}
export function windowsServiceHealthCompleteChoices(view: WindowsServiceHealthCompleteView, elapsed: number) {
    return view.inventory && Number.isFinite(elapsed) && elapsed >= 0 && fresh(view.inventory, view.serverNow, elapsed) ? view.inventory.services : [];
}

export interface WindowsServiceHealthSourceBinding { kind: 'windows_full_services'; grantId: string; grantRevision: number }
export interface WindowsServiceHealthSource extends WindowsServiceHealthSourceBinding {
    generationId: string; manifestSha256: string; sequence: number; capturedAt: string; captureFinishedAt: string; receivedAt: string; expiresAt: string; rowCount: number;
}
const sourceKeys = ['kind', 'grantId', 'grantRevision', 'generationId', 'manifestSha256', 'sequence', 'capturedAt', 'captureFinishedAt', 'receivedAt', 'expiresAt', 'rowCount'] as const;
export function validWindowsServiceHealthSourceBinding(value: unknown): value is WindowsServiceHealthSourceBinding {
    return exact(value, ['kind', 'grantId', 'grantRevision']) && value.kind === 'windows_full_services' && typeof value.grantId === 'string' && /^[a-f0-9]{32}$/.test(value.grantId) && integer(value.grantRevision, 1);
}
export function validWindowsServiceHealthSource(value: unknown): value is WindowsServiceHealthSource {
    if (!exact(value, sourceKeys) || !validWindowsServiceHealthSourceBinding({ kind: value.kind, grantId: value.grantId, grantRevision: value.grantRevision }) || typeof value.generationId !== 'string' || !/^sample_[a-f0-9]{32}$/.test(value.generationId) || typeof value.manifestSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(value.manifestSha256) || !integer(value.sequence, 1) || !timestamp(value.capturedAt) || !timestamp(value.captureFinishedAt) || !timestamp(value.receivedAt) || !timestamp(value.expiresAt) || !integer(value.rowCount, 0, 8192)) return false;
    return inventoryAge(value.captureFinishedAt, value.capturedAt) >= 0 && inventoryAge(value.captureFinishedAt, value.capturedAt) <= 15000 && inventoryAge(value.receivedAt, value.captureFinishedAt) >= 0 && inventoryAge(value.expiresAt, value.capturedAt) === 86400000;
}
export function windowsServiceHealthSourceFresh(value: WindowsServiceHealthSource, at: string, elapsed = 0) {
    return validWindowsServiceHealthSource(value) && timestamp(at) && Number.isFinite(elapsed) && elapsed >= 0 && [value.capturedAt, value.receivedAt].every(t => inventoryAge(at, t) >= 0 && inventoryAge(at, t) + elapsed <= 300000) && inventoryAge(value.expiresAt, at) > elapsed;
}
export const sourceBindingMatches = (binding: WindowsServiceHealthSourceBinding | undefined, source: WindowsServiceHealthSourceBinding | undefined) => !!binding && !!source && binding.kind === source.kind && binding.grantId === source.grantId && binding.grantRevision === source.grantRevision;
export const sameWindowsServiceHealthSource = (a: WindowsServiceHealthSource | null, b: WindowsServiceHealthSource | null) => a === b || !!a && !!b && sourceKeys.every(key => a[key] === b[key]);
const validSourceDevice = (source: WindowsServiceHealthSource, deviceId: string) => fullServicesGenerationId(deviceId, source.grantId, source.sequence) === source.generationId;
export function completeServiceHealthSource(complete: FullServicesComplete): WindowsServiceHealthSource {
    const m = complete.manifest;
    return { kind: 'windows_full_services', grantId: m.grantId, grantRevision: m.grantRevision, generationId: m.generationId, manifestSha256: complete.manifestSha256, sequence: m.sequence, capturedAt: m.captureStartedAt, captureFinishedAt: m.captureFinishedAt, receivedAt: complete.receivedAt, expiresAt: m.expiresAt, rowCount: m.rowCount };
}
