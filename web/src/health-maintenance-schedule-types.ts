import { validHealthDeviceId } from './health-types';

export const HEALTH_MAINTENANCE_SCHEDULE_BYTES = 8192;
export type MaintenanceAction = 'schedule' | 'cancel' | 'end';
export interface MaintenanceWindow {
    id: string; createdAt: string; startsAt: string; endsAt: string;
    state: 'pending' | 'active' | 'canceled' | 'ended' | 'expired'; closedAt: string | null;
}
export interface MaintenanceRequest {
    requestId: string; expectedRevision: string; action: MaintenanceAction;
    windowId: string; startsAt: string | null; endsAt: string | null;
}
export interface MaintenanceScheduleView {
    schemaVersion: 'tracebolt.linux-maintenance-schedule-view.v1'; deviceId: string; serverNow: string;
    revision: string; canManage: boolean; remainingSlots: number; legacyMaintenanceUntil: string | null;
    window: MaintenanceWindow | null;
    lastRequest: { requestId: string; action: MaintenanceAction; windowId: string } | null;
}
const exact = (v: unknown, keys: readonly string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
export const maintenanceId = (v: unknown): v is string => typeof v === 'string' && /^maintenance_[0-9a-f]{32}$/.test(v) && v !== `maintenance_${'0'.repeat(32)}`;
const revision = (v: unknown): v is string => typeof v === 'string' && /^(?:0|[1-9][0-9]{0,19})$/.test(v) && BigInt(v) <= 18446744073709551615n;
export const maintenanceTime = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number(v.slice(0, 4)) >= 1970 && Number.isFinite(Date.parse(v)) && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19);
const action = (v: unknown): v is MaintenanceAction => v === 'schedule' || v === 'cancel' || v === 'end';
const duration = (start: string, end: string): boolean => [15, 60, 240].includes((Date.parse(end) - Date.parse(start)) / 60000);
const wholeTime = (v: unknown): v is string => maintenanceTime(v) && !v.includes('.');

/** Separate closed metadata contract. Old Health v1 bytes remain unchanged. */
export function validMaintenanceSchedule(v: unknown, deviceId: string): v is MaintenanceScheduleView {
    if (!validHealthDeviceId(deviceId) || !exact(v, ['schemaVersion', 'deviceId', 'serverNow', 'revision', 'canManage', 'remainingSlots', 'legacyMaintenanceUntil', 'window', 'lastRequest']) || v.schemaVersion !== 'tracebolt.linux-maintenance-schedule-view.v1' || v.deviceId !== deviceId || !maintenanceTime(v.serverNow) || !revision(v.revision) || typeof v.canManage !== 'boolean' || typeof v.remainingSlots !== 'number' || !Number.isInteger(v.remainingSlots) || v.remainingSlots < 0 || v.remainingSlots > 64 || !(v.legacyMaintenanceUntil === null || maintenanceTime(v.legacyMaintenanceUntil))) return false;
    const now = Date.parse(v.serverNow);
    if (v.legacyMaintenanceUntil !== null && Date.parse(v.legacyMaintenanceUntil) <= now) return false;
    if (v.window !== null) {
        const w = v.window;
        if (!exact(w, ['id', 'createdAt', 'startsAt', 'endsAt', 'state', 'closedAt']) || !maintenanceId(w.id) || !maintenanceTime(w.createdAt) || Date.parse(w.createdAt) > now || !wholeTime(w.startsAt) || !wholeTime(w.endsAt) || !duration(w.startsAt, w.endsAt) || Date.parse(w.startsAt) < Date.parse(w.createdAt) + 60000 || Date.parse(w.startsAt) > Date.parse(w.createdAt) + 7 * 86400000 || !['pending', 'active', 'canceled', 'ended', 'expired'].includes(w.state as string) || !(w.closedAt === null || maintenanceTime(w.closedAt) && Date.parse(w.closedAt) <= now)) return false;
        if ((w.state === 'pending' || w.state === 'active') && w.closedAt !== null) return false;
        if (w.state === 'pending' && Date.parse(w.startsAt) <= now || w.state === 'active' && (Date.parse(w.startsAt) > now || Date.parse(w.endsAt) <= now) || w.state === 'expired' && Date.parse(w.endsAt) > now) return false;
        if ((w.state === 'canceled' || w.state === 'ended') && (w.closedAt === null || Date.parse(w.closedAt) < Date.parse(w.createdAt))) return false;
        if (w.state === 'expired' && w.closedAt !== w.endsAt || w.state === 'canceled' && Date.parse(w.closedAt as string) >= Date.parse(w.startsAt) || w.state === 'ended' && (Date.parse(w.closedAt as string) < Date.parse(w.startsAt) || Date.parse(w.closedAt as string) >= Date.parse(w.endsAt))) return false;
    }
    const window = v.window as MaintenanceWindow | null;
    if (v.lastRequest !== null && (!exact(v.lastRequest, ['requestId', 'action', 'windowId']) || !maintenanceId(v.lastRequest.requestId) || !action(v.lastRequest.action) || !maintenanceId(v.lastRequest.windowId) || window === null || v.lastRequest.windowId !== window.id)) return false;
    if (v.window === null ? v.revision !== '0' || v.lastRequest !== null || v.remainingSlots !== 64 : v.revision === '0' || v.lastRequest === null || v.remainingSlots === 64) return false;
    return new TextEncoder().encode(JSON.stringify(v)).byteLength <= HEALTH_MAINTENANCE_SCHEDULE_BYTES;
}

/** datetime-local is deliberately interpreted as UTC, never browser local time. */
export function maintenanceUTC(input: string): string | null {
    if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d$/.test(input)) return null;
    const value = `${input}:00Z`;
    return wholeTime(value) ? value : null;
}
export function maintenanceDraft(start: string, minutes: number, now: number): { startsAt: string; endsAt: string } | null {
    const startsAt = maintenanceUTC(start), at = startsAt ? Date.parse(startsAt) : NaN;
    if (!startsAt || ![15, 60, 240].includes(minutes) || !Number.isFinite(now) || at < now + 60000 || at > now + 7 * 86400000) return null;
    return { startsAt, endsAt: new Date(at + minutes * 60000).toISOString().replace('.000Z', 'Z') };
}
export function maintenanceConfirmed(view: MaintenanceScheduleView, body: MaintenanceRequest): boolean {
    const last = view.lastRequest, w = view.window;
    if (!last || !w) return false;
    // A creation's unique ID and immutable bounds remain proof of that creation
    // even when a different operator has since canceled or ended the window.
    if (body.action === 'schedule' && w?.id === body.requestId && w.id === body.windowId && w.startsAt === body.startsAt && w.endsAt === body.endsAt && BigInt(view.revision) > BigInt(body.expectedRevision)) return true;
    if (last.requestId !== body.requestId || last.windowId !== body.windowId || last.action !== body.action || view.revision !== (BigInt(body.expectedRevision) + 1n).toString()) return false;
    return body.action === 'schedule' ? w.id === body.requestId && w.startsAt === body.startsAt && w.endsAt === body.endsAt : w.id === body.windowId && w.state === (body.action === 'cancel' ? 'canceled' : 'ended');
}
export function newMaintenanceId(): string {
    return `maintenance_${[...crypto.getRandomValues(new Uint8Array(16))].map(v => v.toString(16).padStart(2, '0')).join('')}`;
}
