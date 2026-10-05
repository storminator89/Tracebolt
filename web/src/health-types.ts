/** Selected manager-side checks only; never an overall device-health assessment. */
export type HealthKind = 'offline' | 'filesystem' | 'service';
export interface HealthCheck {
    key: string; kind: HealthKind; target: string;
    state: 'ok' | 'pending' | 'open' | 'unknown'; observedAt: string | null; value: number | null;
}
export interface HealthIncident {
    id: string; key: string; kind: HealthKind; target: string;
    openedAt: string; lastObservedAt: string; resolvedAt: string | null; acknowledgedAt: string | null;
    closedReason?: 'recovered' | 'monitoring_stopped';
}
export interface HealthView {
    schemaVersion: 'tracebolt.health-view.v1'; deviceId: string; serverNow: string; evaluatedAt: string | null;
    status: 'attention' | 'clear' | 'unknown' | 'maintenance'; maintenanceUntil: string | null;
    monitoredServices: string[]; checks: HealthCheck[]; incidents: HealthIncident[];
}
export const HEALTH_VIEW_BYTES = 131072;
export const validHealthDeviceId = (v: string): boolean => /^agent_[A-Za-z0-9_-]{1,120}$/.test(v);
export const validHealthService = (v: string): boolean => /^[a-zA-Z0-9][a-zA-Z0-9_.@:-]{0,118}\.service$/.test(v);
export function parseHealthServices(input: string): string[] | null {
    const names = input.trim() ? input.trim().split(/[\s,]+/) : [];
    if (names.length > 8 || !names.every(validHealthService) || new Set(names).size !== names.length) return null;
    return names.sort();
}
const record = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const fields = (v: Record<string, unknown>, required: string[], optional: string[] = []): boolean => required.every(k => Object.hasOwn(v, k)) && Object.keys(v).every(k => required.includes(k) || optional.includes(k));
const member = (v: unknown, list: string[]): boolean => typeof v === 'string' && list.includes(v);
const timestamp = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number.isFinite(Date.parse(v)) && Number(v.slice(0, 4)) >= 1970 && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19);
const optionalTime = (v: unknown, now: string): boolean => v === null || timestamp(v) && Date.parse(v) <= Date.parse(now);
function target(v: Record<string, unknown>): boolean {
    return v.kind === 'offline' ? v.key === 'offline:contact' && v.target === 'agent'
        : v.kind === 'filesystem' ? v.key === 'filesystem:root' && v.target === '/'
        : v.kind === 'service' && typeof v.target === 'string' && validHealthService(v.target) && v.key === `service:${v.target}`;
}
export function validHealthView(v: unknown, id: string): v is HealthView {
    if (!record(v) || !fields(v, ['schemaVersion', 'deviceId', 'serverNow', 'evaluatedAt', 'status', 'maintenanceUntil', 'monitoredServices', 'checks', 'incidents']) || v.schemaVersion !== 'tracebolt.health-view.v1' || v.deviceId !== id || !validHealthDeviceId(id) || !timestamp(v.serverNow)) return false;
    if (!member(v.status, ['attention', 'clear', 'unknown', 'maintenance']) || !optionalTime(v.evaluatedAt, v.serverNow) || !(v.maintenanceUntil === null || timestamp(v.maintenanceUntil))) return false;
    if (!Array.isArray(v.monitoredServices) || v.monitoredServices.length > 8 || !v.monitoredServices.every(x => typeof x === 'string' && validHealthService(x)) || new Set(v.monitoredServices).size !== v.monitoredServices.length) return false;
    if (!Array.isArray(v.checks) || v.checks.length !== v.monitoredServices.length + 2 || !Array.isArray(v.incidents) || v.incidents.length > 100) return false;
    const keys = new Set<string>(), ids = new Set<string>();
    for (const c of v.checks) {
        if (!record(c) || !fields(c, ['key', 'kind', 'target', 'state', 'observedAt', 'value']) || !target(c) || typeof c.key !== 'string' || keys.has(c.key) || !member(c.state, ['ok', 'pending', 'open', 'unknown']) || !optionalTime(c.observedAt, v.serverNow)) return false;
        if (c.state !== 'unknown' && (c.observedAt === null || v.evaluatedAt === null || Date.parse(v.serverNow) - Date.parse(v.evaluatedAt as string) > 120000)) return false;
        if (c.state !== 'unknown' && c.kind !== 'offline' && Date.parse(v.serverNow) - Date.parse(c.observedAt as string) > 120000) return false;
        if (c.kind === 'filesystem' && c.state !== 'unknown' && c.value === null) return false;
        if (c.kind === 'service' && !v.monitoredServices.includes(c.target)) return false;
        if (!(c.value === null || typeof c.value === 'number' && Number.isFinite(c.value) && c.value >= 0)) return false;
        if (c.kind === 'filesystem' && typeof c.value === 'number' && c.value > 100) return false;
        keys.add(c.key);
    }
    if (v.status === 'clear' && v.checks.some(c => c.state !== 'ok')) return false;
    if (!keys.has('offline:contact') || !keys.has('filesystem:root')) return false;
    for (const i of v.incidents) {
        if (!record(i) || !fields(i, ['id', 'key', 'kind', 'target', 'openedAt', 'lastObservedAt', 'resolvedAt', 'acknowledgedAt'], ['closedReason']) || !target(i) || typeof i.id !== 'string' || !/^[a-zA-Z0-9_-]{1,128}$/.test(i.id) || ids.has(i.id)) return false;
        if (!timestamp(i.openedAt) || !timestamp(i.lastObservedAt) || !optionalTime(i.openedAt, v.serverNow) || !optionalTime(i.lastObservedAt, v.serverNow) || !optionalTime(i.resolvedAt, v.serverNow) || !optionalTime(i.acknowledgedAt, v.serverNow)) return false;
        if (typeof i.resolvedAt === 'string' && Date.parse(i.resolvedAt) < Date.parse(i.openedAt) || typeof i.acknowledgedAt === 'string' && Date.parse(i.acknowledgedAt) < Date.parse(i.openedAt)) return false;
        if (i.closedReason !== undefined && (!member(i.closedReason, ['recovered', 'monitoring_stopped']) || i.resolvedAt === null)) return false;
        ids.add(i.id);
    }
    return true;
}
