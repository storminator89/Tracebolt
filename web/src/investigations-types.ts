import { validHealthView } from './health-types';
import type { HealthIncident, HealthView } from './health-types';
export type InvestigationScope = 'open' | 'recovered' | 'closed' | 'all';
export interface InvestigationItem { deviceId: string; incident: HealthIncident }
export interface InvestigationsView {
    schemaVersion: 'tracebolt.investigations.v1'; serverNow: string; scope: InvestigationScope; offset: number; total: number;
    counts: Record<InvestigationScope, number>; devices: HealthView[]; items: InvestigationItem[];
}
export const INVESTIGATIONS_BYTES = 262144;
export const INVESTIGATIONS_PAGE_SIZE = 50;
export function incidentScope(incident: HealthIncident): Exclude<InvestigationScope, 'all'> { return !incident.resolvedAt ? 'open' : incident.closedReason === 'recovered' ? 'recovered' : 'closed'; }
const record = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const fields = (v: Record<string, unknown>, keys: string[]) => Object.keys(v).length === keys.length && keys.every(key => Object.hasOwn(v, key));
const count = (v: unknown): v is number => Number.isSafeInteger(v) && Number(v) >= 0 && Number(v) <= 2500;
export function validInvestigationsView(v: unknown, scope: InvestigationScope, offset: number): v is InvestigationsView {
    if (!record(v) || !fields(v, ['schemaVersion', 'serverNow', 'scope', 'offset', 'total', 'counts', 'devices', 'items']) || v.schemaVersion !== 'tracebolt.investigations.v1' || v.scope !== scope || v.offset !== offset || !count(v.total)) return false;
    if (typeof v.serverNow !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v.serverNow) || !Number.isFinite(Date.parse(v.serverNow)) || Number(v.serverNow.slice(0, 4)) < 1970 || new Date(Date.parse(v.serverNow)).toISOString().slice(0, 19) !== v.serverNow.slice(0, 19)) return false;
    if (!record(v.counts) || !fields(v.counts, ['open', 'recovered', 'closed', 'all']) || !Object.values(v.counts).every(count) || Number(v.counts.open) + Number(v.counts.recovered) + Number(v.counts.closed) !== v.counts.all || v.total !== v.counts[scope]) return false;
    if (!Array.isArray(v.devices) || v.devices.length > 25 || !Array.isArray(v.items) || v.items.length !== Math.min(50, Math.max(0, v.total - offset))) return false;
    const devices = new Map<string, HealthView>(), seen = new Set<string>(), openKeys = new Set<string>();
    if (Number(v.counts.all) > v.devices.length * 100) return false;
    for (const device of v.devices) {
        if (!record(device) || typeof device.deviceId !== 'string' || !/^agent_[a-f0-9]{32}$/.test(device.deviceId) || !validHealthView(device, device.deviceId) || device.serverNow !== v.serverNow || device.incidents.length !== 0 || devices.has(device.deviceId)) return false;
        devices.set(device.deviceId, device);
    }
    if (Number(v.counts.open) > [...devices.values()].reduce((sum, device) => sum + device.checks.length, 0)) return false;
    for (const item of v.items) {
        if (!record(item) || !fields(item, ['deviceId', 'incident']) || typeof item.deviceId !== 'string' || !record(item.incident)) return false;
        const device = devices.get(item.deviceId);
        if (!device || !validHealthView({ ...device, incidents: [item.incident] }, item.deviceId) || typeof item.incident.id !== 'string' || !/^health_[a-f0-9]{16}$/.test(item.incident.id)) return false;
        const incident = item.incident as unknown as HealthIncident, key = `${item.deviceId}:${incident.id}`;
        if (seen.has(key) || incident.resolvedAt !== null && !incident.closedReason || scope !== 'all' && incidentScope(incident) !== scope) return false;
        if (!incident.resolvedAt && !device.checks.some(check => check.key === incident.key)) return false;
        const openKey = `${item.deviceId}:${incident.key}`;
        if (!incident.resolvedAt && openKeys.has(openKey)) return false;
        if (!incident.resolvedAt) openKeys.add(openKey);
        seen.add(key);
    }
    return true;
}
/** Age the original evaluation and source timestamps, never the refresh time. */
export function ageInvestigations(view: InvestigationsView, elapsed: number): InvestigationsView {
    const now = Date.parse(view.serverNow) + elapsed;
    return { ...view, devices: view.devices.map(device => ({ ...device, maintenanceUntil: device.maintenanceUntil && Date.parse(device.maintenanceUntil) > now ? device.maintenanceUntil : null, checks: device.checks.map(check => {
        const expired = device.evaluatedAt === null || now - Date.parse(device.evaluatedAt) > 120000 || (check.kind !== 'offline' || check.state === 'ok') && check.observedAt !== null && now - Date.parse(check.observedAt) > 120000;
        return expired ? { ...check, state: 'unknown', value: null } : check;
    }) })) };
}
