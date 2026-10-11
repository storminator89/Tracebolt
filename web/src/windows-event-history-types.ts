import type { WindowsEvent } from './windows-events-types';
import { validWindowsDeviceId } from './windows-inventory-types';

export const EVENT_HISTORY_VIEW_BYTES = 64 * 1024;
export const EVENT_HISTORY_RESULT_BYTES = 512 * 1024;
export const EVENT_HISTORY_WARNING = 'Application/System event history and selected messages are operator-only. Messages may contain credentials, personal data and other secrets; do not send to AI providers or export. Complete means only that this bounded query was exhausted, not that retained history is complete or immutable.';
export interface HistorySearch { channel: 'Application' | 'System'; start: string; end: string; level?: number; eventId?: number }
export type SelectedEvent = WindowsEvent & { channel: 'Application' | 'System' };
export interface EventHistoryIdentity { id: string; sequence: string; queryDigest: string }
export interface EventHistoryReceipt { identity: EventHistoryIdentity; policyDigest: string; resultDigest: string; acceptedAt: string; expiresAt: string }
export interface EventHistoryDescription {
    schemaVersion: 'tracebolt.windows-event-history-request.v1'; identity: EventHistoryIdentity; deviceId: string; certificateHash: string; grantId: string;
    headerGenerationId: string; headerCollectedAt: string; headerSnapshotDigest: string; query: { events: SelectedEvent[]; search?: HistorySearch }; sourceSearch?: HistorySearch; searchReceipt?: EventHistoryReceipt;
    budgets: { maxSearchEvents: 100; maxSearchBytes: 262144; maxRangeHours: 168; maxLookbackHours: 720; maxSelectedEvents: 16; maxMessageBytes: 16384; maxTotalMessageBytes: 65536; timeoutMs: 5000 }; createdAt: string; expiresAt: string;
}
export interface EventHistoryRecord { description: EventHistoryDescription; state: 'pending' | 'claimed' | 'accepted' | 'canceled' | 'expired'; policyDigest: string; claimedAt: string | null; receipt: EventHistoryReceipt | null; canceledAt: string | null; expiredAt: string | null }
export interface EventHistoryView {
    schemaVersion: 'tracebolt.windows-event-history-view.v1'; deviceId: string; serverNow: string; sessionBinding: string; sessionExpiresAt: string; configured: boolean; expectedFloor: string;
    localStatus: 'unavailable' | 'enabled' | 'disabled' | 'stale'; contentStatus: 'unavailable' | 'pending' | 'claimed' | 'available' | 'expired' | 'canceled' | 'result_lost';
    endpointStatus?: '' | 'checking' | 'disabled' | 'denied' | 'reader_unavailable' | 'budget_exhausted' | 'result_lost' | 'expired' | 'canceled';
    capability?: { enabled: boolean; grantId: string; reportedAt: string; expiresAt: string };
    headers?: { generationId: string; snapshotDigest: string; collectedAt: string; expiresAt: string }; request: EventHistoryRecord | null;
}
export interface EventHistoryRow { event: SelectedEvent; message: string; quality: 'observed' | 'bounded' | 'unavailable'; complete: boolean; truncated: boolean; reason?: string }
export interface EventHistoryReport { source: 'windows-event-log-bounded-history'; warning: typeof EVENT_HISTORY_WARNING; quality: 'observed' | 'bounded' | 'partial' | 'unavailable'; collectedAt: string; complete: boolean; truncated: boolean; events: EventHistoryRow[]; search?: HistorySearch; reason?: string }
export interface EventHistoryResult { identity: EventHistoryIdentity; receipt: EventHistoryReceipt; report: EventHistoryReport; expiresAt: string }
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const shape = (v: unknown, required: string[], optional: string[] = []): v is Record<string, unknown> => object(v) && required.every(k => Object.hasOwn(v, k)) && Object.keys(v).every(k => required.includes(k) || optional.includes(k));
const hex = (v: unknown, length: number): v is string => typeof v === 'string' && new RegExp(`^[a-f0-9]{${length}}$`).test(v);
const digest = (v: unknown): v is string => typeof v === 'string' && /^sha256:[a-f0-9]{64}$/.test(v);
const uint = (v: unknown, zero = false): v is string => typeof v === 'string' && (zero ? /^(?:0|[1-9]\d{0,19})$/ : /^[1-9]\d{0,19}$/).test(v) && BigInt(v) <= 18446744073709551615n;
const integer = (v: unknown, max: number): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= max;
export function eventHistoryTime(v: unknown, year = 1970): v is string { return typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number(v.slice(0, 4)) >= year && Number.isFinite(Date.parse(v)) && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19); }
// Compare full RFC3339Nano identities, never round a native event to milliseconds.
export function eventHistoryNanos(v: string): bigint { return BigInt(Date.parse(v.slice(0, 19) + 'Z')) * 1000000n + BigInt((v.split('.')[1]?.slice(0, -1) ?? '').padEnd(9, '0')); }
export const eventHistoryAge = (later: string, earlier: string) => Number(eventHistoryNanos(later) - eventHistoryNanos(earlier)) / 1e6;
export const sameHistoryIdentity = (a: EventHistoryIdentity, b: EventHistoryIdentity) => a.id === b.id && a.sequence === b.sequence && a.queryDigest === b.queryDigest;
export const sameSelectedEvent = (a: SelectedEvent, b: SelectedEvent) => a.channel === b.channel && a.recordId === b.recordId && a.eventId === b.eventId && a.level === b.level && a.provider === b.provider && a.timestamp === b.timestamp;
export function validSelectedEvent(v: unknown): v is SelectedEvent {
    return shape(v, ['recordId', 'eventId', 'level', 'provider', 'timestamp', 'channel']) && uint(v.recordId) && integer(v.eventId, 65535) && integer(v.level, 255) && (v.channel === 'Application' || v.channel === 'System') && typeof v.provider === 'string' && v.provider.length > 0 && v.provider.length <= 256 && v.provider.trim() === v.provider && !/[\p{Cc}\p{Cf}\uFFFD\uD800-\uDFFF\u2028\u2029]/u.test(v.provider) && eventHistoryTime(v.timestamp, 1601) && eventHistoryNanos(v.timestamp) % 100n === 0n;
}
export function validSelectedEvents(v: unknown): v is SelectedEvent[] { return Array.isArray(v) && v.length > 0 && v.length <= 16 && v.every(validSelectedEvent) && new Set(v.map(e => `${e.channel}:${e.recordId}`)).size === v.length; }
const identity = (v: unknown): v is EventHistoryIdentity => shape(v, ['id', 'sequence', 'queryDigest']) && typeof v.id === 'string' && /^winhistory_[a-f0-9]{32}$/.test(v.id) && uint(v.sequence) && digest(v.queryDigest);
export function encodedContentBytes(v: unknown): number { return new TextEncoder().encode(JSON.stringify(v).replace(/[<>&\u2028\u2029]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`)).length; }
function receipt(v: unknown, d: EventHistoryDescription, policy: string): v is EventHistoryReceipt { return shape(v, ['identity', 'policyDigest', 'resultDigest', 'acceptedAt', 'expiresAt']) && identity(v.identity) && sameHistoryIdentity(v.identity, d.identity) && v.policyDigest === policy && digest(v.resultDigest) && eventHistoryTime(v.acceptedAt) && eventHistoryAge(v.acceptedAt, d.createdAt) >= 0 && eventHistoryAge(d.expiresAt, v.acceptedAt) > 0 && v.expiresAt === d.expiresAt; }
export const sameSearch = (a?: HistorySearch, b?: HistorySearch) => !!a && !!b && a.channel === b.channel && a.start === b.start && a.end === b.end && a.level === b.level && a.eventId === b.eventId;
export function validHistorySearch(v: unknown, now?: string): v is HistorySearch {
 if (!shape(v,['channel','start','end'],['level','eventId']) || !['Application','System'].includes(String(v.channel)) || !eventHistoryTime(v.start) || !eventHistoryTime(v.end) || eventHistoryAge(v.end,v.start)<=0 || eventHistoryAge(v.end,v.start)>604800000 || v.level!==undefined && !integer(v.level,255) || v.eventId!==undefined && !integer(v.eventId,65535)) return false;
 return !now || eventHistoryAge(now,v.end)>=0 && eventHistoryAge(now,v.start)<=2592000000;
}
function description(v: unknown, deviceId: string): v is EventHistoryDescription {
 if (!shape(v, ['schemaVersion','identity','deviceId','certificateHash','grantId','headerGenerationId','headerCollectedAt','headerSnapshotDigest','query','budgets','createdAt','expiresAt'],['sourceSearch','searchReceipt']) || v.schemaVersion!=='tracebolt.windows-event-history-request.v1' || !identity(v.identity) || v.deviceId!==deviceId || !hex(v.certificateHash,64) || !hex(v.grantId,32) || typeof v.headerGenerationId!=='string' || !/^sample_[a-f0-9]{32}$/.test(v.headerGenerationId) || !digest(v.headerSnapshotDigest) || !eventHistoryTime(v.headerCollectedAt) || !eventHistoryTime(v.createdAt) || !eventHistoryTime(v.expiresAt) || v.headerCollectedAt!==v.createdAt || eventHistoryAge(v.expiresAt,v.createdAt)!==900000 || !shape(v.query,['events'],['search']) || !Array.isArray(v.query.events) || !shape(v.budgets,['maxSearchEvents','maxSearchBytes','maxRangeHours','maxLookbackHours','maxSelectedEvents','maxMessageBytes','maxTotalMessageBytes','timeoutMs'])) return false;
 const b=v.budgets;
 if (b.maxSearchEvents!==100 || b.maxSearchBytes!==262144 || b.maxRangeHours!==168 || b.maxLookbackHours!==720 || b.maxSelectedEvents!==16 || b.maxMessageBytes!==16384 || b.maxTotalMessageBytes!==65536 || b.timeoutMs!==5000) return false;
 if (v.query.search!==undefined) return v.query.events.length===0 && validHistorySearch(v.query.search,v.createdAt) && v.sourceSearch===undefined && v.searchReceipt===undefined;
 if (!validSelectedEvents(v.query.events) || !validHistorySearch(v.sourceSearch,v.createdAt) || !shape(v.searchReceipt,['identity','policyDigest','resultDigest','acceptedAt','expiresAt']) || !identity(v.searchReceipt.identity) || !digest(v.searchReceipt.policyDigest) || !digest(v.searchReceipt.resultDigest) || v.searchReceipt.expiresAt!==v.expiresAt || !eventHistoryTime(v.searchReceipt.acceptedAt) || eventHistoryAge(v.searchReceipt.acceptedAt,v.createdAt)<0 || eventHistoryAge(v.expiresAt,v.searchReceipt.acceptedAt)<=0 || BigInt(v.searchReceipt.identity.sequence)>=BigInt(v.identity.sequence)) return false;
 const s=v.sourceSearch;
 return v.query.events.every(e=>e.channel===s.channel && eventHistoryAge(e.timestamp,s.start)>=0 && eventHistoryAge(s.end,e.timestamp)>0 && (s.level===undefined || e.level===s.level) && (s.eventId===undefined || e.eventId===s.eventId));
}
function record(v: unknown, deviceId: string, serverNow: string): v is EventHistoryRecord {
    if (!shape(v, ['description', 'state', 'policyDigest', 'claimedAt', 'receipt', 'canceledAt', 'expiredAt']) || !description(v.description, deviceId) || !['pending', 'claimed', 'accepted', 'canceled', 'expired'].includes(String(v.state))) return false;
    const d = v.description; let last = d.searchReceipt?.acceptedAt ?? d.createdAt;
    if (eventHistoryAge(serverNow, last) < 0 || (v.claimedAt === null) !== (v.policyDigest === '')) return false;
    if (v.claimedAt !== null) { if (!digest(v.policyDigest) || !eventHistoryTime(v.claimedAt) || eventHistoryAge(v.claimedAt, last) < 0 || eventHistoryAge(d.expiresAt, v.claimedAt) <= 0) return false; last = v.claimedAt; }
    if (v.receipt !== null) { if (v.claimedAt === null || !receipt(v.receipt, d, String(v.policyDigest)) || eventHistoryAge(v.receipt.acceptedAt, last) < 0) return false; last = v.receipt.acceptedAt; }
    if (v.canceledAt !== null) { if (!eventHistoryTime(v.canceledAt) || eventHistoryAge(v.canceledAt, last) < 0 || eventHistoryAge(d.expiresAt, v.canceledAt) <= 0) return false; last = v.canceledAt; }
    if (v.expiredAt !== null) { if (!eventHistoryTime(v.expiredAt) || eventHistoryAge(v.expiredAt, last) < 0 || eventHistoryAge(v.expiredAt, d.expiresAt) < 0) return false; last = v.expiredAt; }
    if (eventHistoryAge(serverNow, last) < 0) return false;
    if (v.state === 'pending' && (v.claimedAt !== null || v.receipt !== null || v.canceledAt !== null || v.expiredAt !== null)) return false;
    if (v.state === 'claimed' && (v.claimedAt === null || v.receipt !== null || v.canceledAt !== null || v.expiredAt !== null)) return false;
    if (v.state === 'accepted' && (v.receipt === null || v.canceledAt !== null || v.expiredAt !== null)) return false;
    if (v.state === 'canceled' && (v.canceledAt === null || v.expiredAt !== null)) return false;
    return !(v.state === 'expired' && v.expiredAt === null) && encodedContentBytes(v) <= 32768;
}
export function validEventHistoryView(v: unknown, deviceId: string, sessionKey: string | null): v is EventHistoryView {
    if (!validWindowsDeviceId(deviceId) || !shape(v, ['schemaVersion', 'deviceId', 'serverNow', 'sessionBinding', 'sessionExpiresAt', 'configured', 'expectedFloor', 'localStatus', 'contentStatus', 'request'], ['capability', 'headers', 'endpointStatus']) || v.schemaVersion !== 'tracebolt.windows-event-history-view.v1' || v.deviceId !== deviceId || !eventHistoryTime(v.serverNow) || !eventHistoryTime(v.sessionExpiresAt) || sessionKey !== null && v.sessionExpiresAt !== sessionKey || eventHistoryAge(v.sessionExpiresAt, v.serverNow) <= 0 || !hex(v.sessionBinding, 64) || typeof v.configured !== 'boolean' || !uint(v.expectedFloor, true) || !['unavailable', 'enabled', 'disabled', 'stale'].includes(String(v.localStatus)) || !['unavailable', 'pending', 'claimed', 'available', 'expired', 'canceled', 'result_lost'].includes(String(v.contentStatus))) return false;
    if (v.endpointStatus !== undefined && !['', 'checking', 'disabled', 'denied', 'reader_unavailable', 'budget_exhausted', 'result_lost', 'expired', 'canceled'].includes(String(v.endpointStatus))) return false;
    if (v.capability !== undefined && (!shape(v.capability, ['enabled', 'grantId', 'reportedAt', 'expiresAt']) || typeof v.capability.enabled !== 'boolean' || !hex(v.capability.grantId, 32) || !eventHistoryTime(v.capability.reportedAt) || !eventHistoryTime(v.capability.expiresAt) || eventHistoryAge(v.capability.expiresAt, v.capability.reportedAt) !== 300000 || eventHistoryAge(v.serverNow, v.capability.reportedAt) < 0)) return false;
    if (v.headers !== undefined && (!shape(v.headers, ['generationId', 'snapshotDigest', 'collectedAt', 'expiresAt']) || typeof v.headers.generationId !== 'string' || !/^sample_[a-f0-9]{32}$/.test(v.headers.generationId) || !digest(v.headers.snapshotDigest) || !eventHistoryTime(v.headers.collectedAt) || !eventHistoryTime(v.headers.expiresAt) || eventHistoryAge(v.headers.expiresAt, v.headers.collectedAt) !== 86400000 || eventHistoryAge(v.serverNow, v.headers.collectedAt) < 0 || eventHistoryAge(v.headers.expiresAt, v.serverNow) <= 0)) return false;
    if (v.request !== null && (!record(v.request, deviceId, v.serverNow) || BigInt(v.request.description.identity.sequence) > BigInt(v.expectedFloor))) return false;
    const r = v.request as EventHistoryRecord | null;
    if (v.contentStatus === 'available' && (r?.state !== 'accepted' || !r.receipt) || v.contentStatus === 'result_lost' && r?.state !== 'accepted' || ['pending', 'claimed', 'expired', 'canceled'].includes(String(v.contentStatus)) && r?.state !== v.contentStatus) return false;
    return encodedContentBytes(v) <= EVENT_HISTORY_VIEW_BYTES;
}
export const historyUnavailableReasons = ['context canceled', 'context deadline exceeded', 'windows_event_content_unsupported_platform', 'windows_event_content_access_denied', 'windows_event_content_source_unavailable', 'windows_event_content_read_failed', 'windows_event_content_invalid_data', 'windows_event_content_native_buffer_limit', 'windows_event_content_record_not_found', 'windows_event_content_identity_mismatch', 'windows_event_content_publisher_unavailable', 'windows_event_content_message_unavailable'];
export function validEventHistoryResult(v: unknown, r: EventHistoryRecord, sessionExpiresAt?: string): v is EventHistoryResult {
    if (!r.receipt || !shape(v, ['identity', 'receipt', 'report', 'expiresAt']) || !identity(v.identity) || !sameHistoryIdentity(v.identity, r.description.identity) || !receipt(v.receipt, r.description, r.policyDigest) || v.receipt.resultDigest !== r.receipt.resultDigest || v.receipt.acceptedAt !== r.receipt.acceptedAt || !eventHistoryTime(v.expiresAt) || eventHistoryAge(v.expiresAt, r.receipt.acceptedAt) <= 0 || eventHistoryAge(r.description.expiresAt, v.expiresAt) < 0 || eventHistoryAge(v.expiresAt, r.description.headerCollectedAt) > 86400000 || sessionExpiresAt !== undefined && eventHistoryAge(sessionExpiresAt, v.expiresAt) < 0 || !shape(v.report, ['source', 'warning', 'quality', 'collectedAt', 'complete', 'truncated', 'events'],['search','reason'])) return false;
    const p = v.report;
    if (p.source !== 'windows-event-log-bounded-history' || p.warning !== EVENT_HISTORY_WARNING || !eventHistoryTime(p.collectedAt) || !r.claimedAt || eventHistoryAge(p.collectedAt, r.claimedAt) < 0 || eventHistoryAge(r.receipt.acceptedAt, p.collectedAt) < 0 || !Array.isArray(p.events)) return false;
    if (r.description.query.search) {
        const s=r.description.query.search;
        if (!validHistorySearch(p.search,r.description.createdAt) || !sameSearch(p.search,s) || p.events.length>100 || typeof p.complete!=='boolean' || typeof p.truncated!=='boolean') return false;
        for (let i=0;i<p.events.length;i++) {
            const row:unknown=p.events[i];
            if (!shape(row,['event','message','quality','complete','truncated']) || !validSelectedEvent(row.event) || row.message!=='' || row.quality!=='observed' || row.complete!==true || row.truncated!==false || row.event.channel!==s.channel || eventHistoryAge(row.event.timestamp,s.start)<0 || eventHistoryAge(s.end,row.event.timestamp)<=0 || s.level!==undefined && row.event.level!==s.level || s.eventId!==undefined && row.event.eventId!==s.eventId || i>0 && BigInt(row.event.recordId)>=BigInt(p.events[i-1].event.recordId)) return false;
        }
        const reasons=['context canceled','context deadline exceeded','windows_event_history_unsupported_platform','windows_event_history_access_denied','windows_event_history_source_unavailable','windows_event_history_read_failed','windows_event_history_invalid_metadata','windows_event_history_metadata_buffer_limit'];
        const valid=p.quality==='observed' ? p.complete && !p.truncated && p.reason===undefined : p.quality==='bounded' ? p.events.length>0 && !p.complete && p.truncated && p.reason==='windows_event_history_result_limit' : p.quality==='partial' ? !p.complete && p.events.length>0 && reasons.includes(String(p.reason)) : p.quality==='unavailable' && !p.complete && !p.truncated && p.events.length===0 && reasons.includes(String(p.reason));
        return Boolean(valid) && encodedContentBytes(p)<=262144 && encodedContentBytes(v)<=EVENT_HISTORY_RESULT_BYTES;
    }
    if (p.search!==undefined || p.reason!==undefined || p.events.length!==r.description.query.events.length) return false;
    let total = 0, complete = true, truncated = false, observed = false, failed = false;
    for (let i = 0; i < p.events.length; i++) {
        const row: unknown = p.events[i];
        if (!shape(row, ['event', 'message', 'quality', 'complete', 'truncated'], ['reason']) || !validSelectedEvent(row.event) || !sameSelectedEvent(row.event, r.description.query.events[i]) || typeof row.message !== 'string' || /[\u0000\uD800-\uDFFF]/u.test(row.message) || typeof row.complete !== 'boolean' || typeof row.truncated !== 'boolean') return false;
        const bytes = new TextEncoder().encode(row.message).length, remaining = 65536 - total, limit = Math.min(16384, remaining);
        if (bytes > limit || remaining === 0 && (row.quality !== 'bounded' || row.message !== '' || row.reason !== 'windows_event_content_total_limit')) return false;
        if (row.quality === 'observed') { if (!row.complete || row.truncated || row.reason !== undefined) return false; observed = true; }
        else if (row.quality === 'bounded') { if (row.complete || !row.truncated || row.reason !== (remaining < 16384 ? 'windows_event_content_total_limit' : 'windows_event_content_message_limit') || bytes < Math.max(0, limit - 3)) return false; observed ||= bytes > 0; }
        else if (row.quality === 'unavailable') { if (row.complete || row.truncated || bytes !== 0 || typeof row.reason !== 'string' || !historyUnavailableReasons.includes(row.reason)) return false; failed = true; }
        else return false;
        total += bytes; complete &&= row.complete; truncated ||= row.truncated;
    }
    const quality = failed ? observed ? 'partial' : 'unavailable' : truncated ? 'bounded' : 'observed';
    return p.quality === quality && p.complete === complete && p.truncated === truncated && encodedContentBytes(v) <= EVENT_HISTORY_RESULT_BYTES;
}
