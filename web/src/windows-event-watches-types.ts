import { inventoryAge } from './complete-packages-types';
export type EventWatchSelector = { channel: 'Application' | 'System'; provider: string; eventId: number; level: number };
export type EventWatchIncident = { id: string; selector: EventWatchSelector; firstObservedAt: string; lastObservedAt: string; firstReceivedAt: string; lastReceivedAt: string; countLowerBound: number; reviewedAt: string | null };
export type EventWatchesView = {
    schemaVersion: 'tracebolt.windows-event-watches.v1'; deviceId: string; serverNow: string; validUntil: string; revision: number; canManage: boolean;
    source: { token: string; available: boolean; collectedAt: string | null; receivedAt: string | null; reason: 'none' | 'unavailable' | 'stale'; choices: EventWatchSelector[] };
    policy: { enabled: boolean; selectors: EventWatchSelector[]; enabledAt: string | null; retentionAcknowledged: boolean };
    status: 'disabled' | 'unknown' | 'baselining' | 'watching' | 'matched' | 'continuity-unknown' | 'history-full'; incidents: EventWatchIncident[];
    retentionDays: 7; maxSelectors: 4; maxIncidents: 100;
    lastRequest: { requestId: string; operation: 'policy' | 'review'; incidentId: string | null } | null;
};
type Common = { requestId: string; expectedRevision: number; sourceToken: string };
export type EventWatchRequest = { operation: 'policy'; body: Common & { enabled: boolean; selectors: EventWatchSelector[]; retentionAcknowledged: boolean } } | { operation: 'review'; body: Common & { incidentId: string } };
export const EVENT_WATCH_BYTES = 131072;
export const eventWatchDeviceId = (value: string) => /^agent_[a-f0-9]{32}$/.test(value);
const object = (v: unknown): v is Record<string, unknown> => Boolean(v && typeof v === 'object' && !Array.isArray(v));
const exact = (v: Record<string, unknown>, keys: string) => Object.keys(v).sort().join(',') === keys.split(' ').sort().join(',');
const integer = (v: unknown, max: number) => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v <= max;
const text = (v: unknown, max: number): v is string => typeof v === 'string' && v.length > 0 && v.length <= max && !/[\p{Cc}\p{Cf}\p{Cs}\u2028\u2029\ufffd]/u.test(v);
export function eventWatchTime(v: unknown): number | null { return typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number.isFinite(Date.parse(v)) && Number(v.slice(0, 4)) >= 1970 && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19) ? Date.parse(v) : null; }
const nullableTime = (v: unknown) => v === null || eventWatchTime(v) !== null;
export const selectorKey = (v: EventWatchSelector) => JSON.stringify([v.channel, v.provider, v.eventId, v.level]);
export function validEventWatchSelector(v: unknown): v is EventWatchSelector {
    return object(v) && exact(v, 'channel provider eventId level') && ['Application', 'System'].includes(String(v.channel)) && text(v.provider, 256) && v.provider.trim() === v.provider && integer(v.eventId, 65535) && integer(v.level, 255);
}
function selectors(v: unknown, max: number): v is EventWatchSelector[] { return Array.isArray(v) && v.length <= max && v.every(validEventWatchSelector) && new Set(v.map(selectorKey)).size === v.length; }
export function validEventWatches(v: unknown, deviceId: string): v is EventWatchesView {
    if (!object(v) || !exact(v, 'schemaVersion deviceId serverNow validUntil revision canManage source policy status incidents retentionDays maxSelectors maxIncidents lastRequest') || v.schemaVersion !== 'tracebolt.windows-event-watches.v1' || !eventWatchDeviceId(deviceId) || v.deviceId !== deviceId || !integer(v.revision, Number.MAX_SAFE_INTEGER) || typeof v.canManage !== 'boolean') return false;
    const now = eventWatchTime(v.serverNow), until = eventWatchTime(v.validUntil);
    if (now === null || until === null || inventoryAge(v.validUntil as string, v.serverNow as string) <= 0 || inventoryAge(v.validUntil as string, v.serverNow as string) > 30000 || v.retentionDays !== 7 || v.maxSelectors !== 4 || v.maxIncidents !== 100) return false;
    const s = v.source, p = v.policy;
    if (!object(s) || !exact(s, 'token available collectedAt receivedAt reason choices') || typeof s.token !== 'string' || !/^eventsource_[a-f0-9]{32}$/.test(s.token) || typeof s.available !== 'boolean' || !['none', 'unavailable', 'stale'].includes(String(s.reason)) || !nullableTime(s.collectedAt) || !nullableTime(s.receivedAt) || !selectors(s.choices, 32)) return false;
    if (s.available ? s.reason !== 'none' || s.collectedAt === null || s.receivedAt === null || [s.collectedAt, s.receivedAt].some(t => inventoryAge(v.serverNow as string, t as string) < 0 || inventoryAge(v.serverNow as string, t as string) >= 120000) : s.reason === 'none' || s.choices.length !== 0 || s.collectedAt !== null || s.receivedAt !== null) return false;
    if (s.available && (inventoryAge(s.receivedAt as string, s.collectedAt as string) < 0 || [s.collectedAt, s.receivedAt].some(t => inventoryAge(v.validUntil as string, t as string) > 120000))) return false;
    if (!object(p) || !exact(p, 'enabled selectors enabledAt retentionAcknowledged') || typeof p.enabled !== 'boolean' || typeof p.retentionAcknowledged !== 'boolean' || !selectors(p.selectors, 4) || !nullableTime(p.enabledAt)) return false;
    if (p.enabled ? !p.retentionAcknowledged || !p.selectors.length || p.enabledAt === null : p.retentionAcknowledged || p.selectors.length !== 0 || p.enabledAt !== null) return false;
    if (p.enabledAt !== null && inventoryAge(v.serverNow as string, p.enabledAt as string) < 0) return false;
    if (!['disabled', 'unknown', 'baselining', 'watching', 'matched', 'continuity-unknown', 'history-full'].includes(String(v.status)) || (p.enabled ? v.status === 'disabled' : v.status !== 'disabled' && !(v.status === 'unknown' && (!v.canManage || !s.available) && Array.isArray(v.incidents) && v.incidents.length === 0 && v.lastRequest === null))) return false;
    if (!Array.isArray(v.incidents) || v.incidents.length > 100 || !v.incidents.every(i => {
        if (!object(i) || !exact(i, 'id selector firstObservedAt lastObservedAt firstReceivedAt lastReceivedAt countLowerBound reviewedAt') || typeof i.id !== 'string' || !/^wevent_[a-f0-9]{16}$/.test(i.id) || i.id === 'wevent_0000000000000000' || !validEventWatchSelector(i.selector) || !integer(i.countLowerBound, Number.MAX_SAFE_INTEGER) || i.countLowerBound === 0 || !nullableTime(i.reviewedAt)) return false;
        const times = [i.firstObservedAt, i.lastObservedAt, i.firstReceivedAt, i.lastReceivedAt];
        return times.every(t => eventWatchTime(t) !== null && inventoryAge(v.serverNow as string, t as string) >= 0) && inventoryAge(i.lastObservedAt as string, i.firstObservedAt as string) >= 0 && inventoryAge(i.lastReceivedAt as string, i.firstReceivedAt as string) >= 0 && inventoryAge(i.firstReceivedAt as string, i.firstObservedAt as string) >= 0 && inventoryAge(i.lastReceivedAt as string, i.lastObservedAt as string) >= 0 && inventoryAge(v.serverNow as string, i.lastReceivedAt as string) < 7 * 86400000 && (i.reviewedAt === null || inventoryAge(v.serverNow as string, i.reviewedAt as string) >= 0 && inventoryAge(i.reviewedAt as string, i.lastReceivedAt as string) >= 0);
    }) || new Set(v.incidents.map(i => i.id)).size !== v.incidents.length) return false;
    if (v.status === 'matched' && !v.incidents.some(i => i.reviewedAt === null)) return false;
    const r = v.lastRequest;
    return r === null || object(r) && exact(r, 'requestId operation incidentId') && typeof r.requestId === 'string' && /^eventrequest_[a-f0-9]{32}$/.test(r.requestId) && (r.operation === 'policy' ? r.incidentId === null : r.operation === 'review' && typeof r.incidentId === 'string' && /^wevent_[a-f0-9]{16}$/.test(r.incidentId) && r.incidentId !== 'wevent_0000000000000000');
}
export function eventWatchConfirmed(view: EventWatchesView, change: EventWatchRequest): boolean {
    if (view.source.token !== change.body.sourceToken || view.revision !== change.body.expectedRevision + 1 || view.lastRequest?.requestId !== change.body.requestId || view.lastRequest.operation !== change.operation || view.lastRequest.incidentId !== (change.operation === 'review' ? change.body.incidentId : null)) return false;
    if (change.operation === 'review') return view.incidents.some(i => i.id === change.body.incidentId && i.reviewedAt !== null);
    return view.policy.enabled === change.body.enabled && view.policy.retentionAcknowledged === change.body.retentionAcknowledged && view.policy.selectors.length === change.body.selectors.length && view.policy.selectors.every(s => change.body.selectors.some(expected => selectorKey(expected) === selectorKey(s)));
}
export function eventWatchRequestId(): string { return 'eventrequest_' + Array.from(crypto.getRandomValues(new Uint8Array(16)), n => n.toString(16).padStart(2, '0')).join(''); }
