import type { WindowsEvent } from './windows-events-types';
import { validWindowsDeviceId } from './windows-inventory-types';

export const EVENT_CONTENT_VIEW_BYTES = 64 * 1024;
export const EVENT_CONTENT_RESULT_BYTES = 512 * 1024;
export const EVENT_CONTENT_WARNING = 'Event messages may contain credentials, personal data and other secrets. Authorized operator-only content; do not send to AI providers or export.';
export type SelectedEvent = WindowsEvent & { channel: 'Application' | 'System' };
export interface EventContentIdentity { id: string; sequence: string; queryDigest: string }
export interface EventContentReceipt { identity: EventContentIdentity; policyDigest: string; resultDigest: string; acceptedAt: string; expiresAt: string }
export interface EventContentDescription {
    schemaVersion: 'tracebolt.windows-event-content-request.v1'; identity: EventContentIdentity; deviceId: string; certificateHash: string; grantId: string;
    headerGenerationId: string; headerCollectedAt: string; headerSnapshotDigest: string; query: { events: SelectedEvent[] };
    budgets: { maxSelectedEvents: 16; maxMessageBytes: 16384; maxTotalMessageBytes: 65536; timeoutMs: 5000 }; createdAt: string; expiresAt: string;
}
export interface EventContentRecord { description: EventContentDescription; state: 'pending' | 'claimed' | 'accepted' | 'canceled' | 'expired'; policyDigest: string; claimedAt: string | null; receipt: EventContentReceipt | null; canceledAt: string | null; expiredAt: string | null }
export interface EventContentView {
    schemaVersion: 'tracebolt.windows-event-content-view.v1'; deviceId: string; serverNow: string; sessionBinding: string; sessionExpiresAt: string; configured: boolean; expectedFloor: string;
    localStatus: 'unavailable' | 'enabled' | 'disabled' | 'stale'; contentStatus: 'unavailable' | 'pending' | 'claimed' | 'available' | 'expired' | 'canceled' | 'result_lost';
    endpointStatus?: '' | 'checking' | 'disabled' | 'denied' | 'reader_unavailable' | 'result_lost' | 'expired' | 'canceled';
    capability?: { enabled: boolean; grantId: string; reportedAt: string; expiresAt: string };
    headers?: { generationId: string; snapshotDigest: string; collectedAt: string; expiresAt: string }; request: EventContentRecord | null;
}
export interface EventContentRow { event: SelectedEvent; message: string; quality: 'observed' | 'bounded' | 'unavailable'; complete: boolean; truncated: boolean; reason?: string }
export interface EventContentReport { source: 'windows-event-log-message-content'; warning: typeof EVENT_CONTENT_WARNING; quality: 'observed' | 'bounded' | 'partial' | 'unavailable'; collectedAt: string; complete: boolean; truncated: boolean; events: EventContentRow[] }
export interface EventContentResult { identity: EventContentIdentity; receipt: EventContentReceipt; report: EventContentReport; expiresAt: string }
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const shape = (v: unknown, required: string[], optional: string[] = []): v is Record<string, unknown> => object(v) && required.every(k => Object.hasOwn(v, k)) && Object.keys(v).every(k => required.includes(k) || optional.includes(k));
const hex = (v: unknown, length: number): v is string => typeof v === 'string' && new RegExp(`^[a-f0-9]{${length}}$`).test(v);
const digest = (v: unknown): v is string => typeof v === 'string' && /^sha256:[a-f0-9]{64}$/.test(v);
const uint = (v: unknown, zero = false): v is string => typeof v === 'string' && (zero ? /^(?:0|[1-9]\d{0,19})$/ : /^[1-9]\d{0,19}$/).test(v) && BigInt(v) <= 18446744073709551615n;
const integer = (v: unknown, max: number): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= max;
export function eventContentTime(v: unknown, year = 1970): v is string { return typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number(v.slice(0, 4)) >= year && Number.isFinite(Date.parse(v)) && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19); }
// Compare full RFC3339Nano identities, never round a native event to milliseconds.
export function eventContentNanos(v: string): bigint { return BigInt(Date.parse(v.slice(0, 19) + 'Z')) * 1000000n + BigInt((v.split('.')[1]?.slice(0, -1) ?? '').padEnd(9, '0')); }
export const eventContentAge = (later: string, earlier: string) => Number(eventContentNanos(later) - eventContentNanos(earlier)) / 1e6;
export const sameContentIdentity = (a: EventContentIdentity, b: EventContentIdentity) => a.id === b.id && a.sequence === b.sequence && a.queryDigest === b.queryDigest;
export const sameSelectedEvent = (a: SelectedEvent, b: SelectedEvent) => a.channel === b.channel && a.recordId === b.recordId && a.eventId === b.eventId && a.level === b.level && a.provider === b.provider && a.timestamp === b.timestamp;
export function validSelectedEvent(v: unknown): v is SelectedEvent {
    return shape(v, ['recordId', 'eventId', 'level', 'provider', 'timestamp', 'channel']) && uint(v.recordId) && integer(v.eventId, 65535) && integer(v.level, 255) && (v.channel === 'Application' || v.channel === 'System') && typeof v.provider === 'string' && v.provider.length > 0 && v.provider.length <= 256 && v.provider.trim() === v.provider && !/[\p{Cc}\p{Cf}\uFFFD\uD800-\uDFFF\u2028\u2029]/u.test(v.provider) && eventContentTime(v.timestamp, 1601) && eventContentNanos(v.timestamp) % 100n === 0n;
}
export function validSelectedEvents(v: unknown): v is SelectedEvent[] { return Array.isArray(v) && v.length > 0 && v.length <= 16 && v.every(validSelectedEvent) && new Set(v.map(e => `${e.channel}:${e.recordId}`)).size === v.length; }
const identity = (v: unknown): v is EventContentIdentity => shape(v, ['id', 'sequence', 'queryDigest']) && typeof v.id === 'string' && /^winevent_[a-f0-9]{32}$/.test(v.id) && uint(v.sequence) && digest(v.queryDigest);
export function encodedContentBytes(v: unknown): number { return new TextEncoder().encode(JSON.stringify(v).replace(/[<>&\u2028\u2029]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`)).length; }
function receipt(v: unknown, d: EventContentDescription, policy: string): v is EventContentReceipt { return shape(v, ['identity', 'policyDigest', 'resultDigest', 'acceptedAt', 'expiresAt']) && identity(v.identity) && sameContentIdentity(v.identity, d.identity) && v.policyDigest === policy && digest(v.resultDigest) && eventContentTime(v.acceptedAt) && eventContentAge(v.acceptedAt, d.createdAt) >= 0 && eventContentAge(d.expiresAt, v.acceptedAt) > 0 && v.expiresAt === d.expiresAt; }
function description(v: unknown, deviceId: string): v is EventContentDescription {
    return shape(v, ['schemaVersion', 'identity', 'deviceId', 'certificateHash', 'grantId', 'headerGenerationId', 'headerCollectedAt', 'headerSnapshotDigest', 'query', 'budgets', 'createdAt', 'expiresAt']) && v.schemaVersion === 'tracebolt.windows-event-content-request.v1' && identity(v.identity) && v.deviceId === deviceId && hex(v.certificateHash, 64) && hex(v.grantId, 32) && typeof v.headerGenerationId === 'string' && /^sample_[a-f0-9]{32}$/.test(v.headerGenerationId) && digest(v.headerSnapshotDigest) && eventContentTime(v.headerCollectedAt) && eventContentTime(v.createdAt) && eventContentTime(v.expiresAt) && eventContentAge(v.expiresAt, v.createdAt) === 900000 && eventContentAge(v.createdAt, v.headerCollectedAt) >= 0 && eventContentAge(v.createdAt, v.headerCollectedAt) < 86400000 && shape(v.query, ['events']) && validSelectedEvents(v.query.events) && shape(v.budgets, ['maxSelectedEvents', 'maxMessageBytes', 'maxTotalMessageBytes', 'timeoutMs']) && v.budgets.maxSelectedEvents === 16 && v.budgets.maxMessageBytes === 16384 && v.budgets.maxTotalMessageBytes === 65536 && v.budgets.timeoutMs === 5000;
}
function record(v: unknown, deviceId: string, serverNow: string): v is EventContentRecord {
    if (!shape(v, ['description', 'state', 'policyDigest', 'claimedAt', 'receipt', 'canceledAt', 'expiredAt']) || !description(v.description, deviceId) || !['pending', 'claimed', 'accepted', 'canceled', 'expired'].includes(String(v.state))) return false;
    const d = v.description; let last = d.createdAt;
    if (eventContentAge(serverNow, last) < 0 || (v.claimedAt === null) !== (v.policyDigest === '')) return false;
    if (v.claimedAt !== null) { if (!digest(v.policyDigest) || !eventContentTime(v.claimedAt) || eventContentAge(v.claimedAt, last) < 0 || eventContentAge(d.expiresAt, v.claimedAt) <= 0) return false; last = v.claimedAt; }
    if (v.receipt !== null) { if (v.claimedAt === null || !receipt(v.receipt, d, String(v.policyDigest)) || eventContentAge(v.receipt.acceptedAt, last) < 0) return false; last = v.receipt.acceptedAt; }
    if (v.canceledAt !== null) { if (!eventContentTime(v.canceledAt) || eventContentAge(v.canceledAt, last) < 0 || eventContentAge(d.expiresAt, v.canceledAt) <= 0) return false; last = v.canceledAt; }
    if (v.expiredAt !== null) { if (!eventContentTime(v.expiredAt) || eventContentAge(v.expiredAt, last) < 0 || eventContentAge(v.expiredAt, d.expiresAt) < 0) return false; last = v.expiredAt; }
    if (eventContentAge(serverNow, last) < 0) return false;
    if (v.state === 'pending' && (v.claimedAt !== null || v.receipt !== null || v.canceledAt !== null || v.expiredAt !== null)) return false;
    if (v.state === 'claimed' && (v.claimedAt === null || v.receipt !== null || v.canceledAt !== null || v.expiredAt !== null)) return false;
    if (v.state === 'accepted' && (v.receipt === null || v.canceledAt !== null || v.expiredAt !== null)) return false;
    if (v.state === 'canceled' && (v.canceledAt === null || v.expiredAt !== null)) return false;
    return !(v.state === 'expired' && v.expiredAt === null) && encodedContentBytes(v) <= 32768;
}
export function validEventContentView(v: unknown, deviceId: string, sessionKey: string | null): v is EventContentView {
    if (!validWindowsDeviceId(deviceId) || !shape(v, ['schemaVersion', 'deviceId', 'serverNow', 'sessionBinding', 'sessionExpiresAt', 'configured', 'expectedFloor', 'localStatus', 'contentStatus', 'request'], ['capability', 'headers', 'endpointStatus']) || v.schemaVersion !== 'tracebolt.windows-event-content-view.v1' || v.deviceId !== deviceId || !eventContentTime(v.serverNow) || !eventContentTime(v.sessionExpiresAt) || sessionKey !== null && v.sessionExpiresAt !== sessionKey || eventContentAge(v.sessionExpiresAt, v.serverNow) <= 0 || !hex(v.sessionBinding, 64) || typeof v.configured !== 'boolean' || !uint(v.expectedFloor, true) || !['unavailable', 'enabled', 'disabled', 'stale'].includes(String(v.localStatus)) || !['unavailable', 'pending', 'claimed', 'available', 'expired', 'canceled', 'result_lost'].includes(String(v.contentStatus))) return false;
    if (v.endpointStatus !== undefined && !['', 'checking', 'disabled', 'denied', 'reader_unavailable', 'result_lost', 'expired', 'canceled'].includes(String(v.endpointStatus))) return false;
    if (v.capability !== undefined && (!shape(v.capability, ['enabled', 'grantId', 'reportedAt', 'expiresAt']) || typeof v.capability.enabled !== 'boolean' || !hex(v.capability.grantId, 32) || !eventContentTime(v.capability.reportedAt) || !eventContentTime(v.capability.expiresAt) || eventContentAge(v.capability.expiresAt, v.capability.reportedAt) !== 300000 || eventContentAge(v.serverNow, v.capability.reportedAt) < 0)) return false;
    if (v.headers !== undefined && (!shape(v.headers, ['generationId', 'snapshotDigest', 'collectedAt', 'expiresAt']) || typeof v.headers.generationId !== 'string' || !/^sample_[a-f0-9]{32}$/.test(v.headers.generationId) || !digest(v.headers.snapshotDigest) || !eventContentTime(v.headers.collectedAt) || !eventContentTime(v.headers.expiresAt) || eventContentAge(v.headers.expiresAt, v.headers.collectedAt) !== 86400000 || eventContentAge(v.serverNow, v.headers.collectedAt) < 0 || eventContentAge(v.headers.expiresAt, v.serverNow) <= 0)) return false;
    if (v.request !== null && (!record(v.request, deviceId, v.serverNow) || BigInt(v.request.description.identity.sequence) > BigInt(v.expectedFloor))) return false;
    const r = v.request as EventContentRecord | null;
    if (v.contentStatus === 'available' && (r?.state !== 'accepted' || !r.receipt) || v.contentStatus === 'result_lost' && r?.state !== 'accepted' || ['pending', 'claimed', 'expired', 'canceled'].includes(String(v.contentStatus)) && r?.state !== v.contentStatus) return false;
    return encodedContentBytes(v) <= EVENT_CONTENT_VIEW_BYTES;
}
export const contentUnavailableReasons = ['context canceled', 'context deadline exceeded', 'windows_event_content_unsupported_platform', 'windows_event_content_access_denied', 'windows_event_content_source_unavailable', 'windows_event_content_read_failed', 'windows_event_content_invalid_data', 'windows_event_content_native_buffer_limit', 'windows_event_content_record_not_found', 'windows_event_content_identity_mismatch', 'windows_event_content_publisher_unavailable', 'windows_event_content_message_unavailable'];
export function validEventContentResult(v: unknown, r: EventContentRecord, sessionExpiresAt?: string): v is EventContentResult {
    if (!r.receipt || !shape(v, ['identity', 'receipt', 'report', 'expiresAt']) || !identity(v.identity) || !sameContentIdentity(v.identity, r.description.identity) || !receipt(v.receipt, r.description, r.policyDigest) || v.receipt.resultDigest !== r.receipt.resultDigest || v.receipt.acceptedAt !== r.receipt.acceptedAt || !eventContentTime(v.expiresAt) || eventContentAge(v.expiresAt, r.receipt.acceptedAt) <= 0 || eventContentAge(r.description.expiresAt, v.expiresAt) < 0 || eventContentAge(v.expiresAt, r.description.headerCollectedAt) > 86400000 || sessionExpiresAt !== undefined && eventContentAge(sessionExpiresAt, v.expiresAt) < 0 || !shape(v.report, ['source', 'warning', 'quality', 'collectedAt', 'complete', 'truncated', 'events'])) return false;
    const p = v.report;
    if (p.source !== 'windows-event-log-message-content' || p.warning !== EVENT_CONTENT_WARNING || !eventContentTime(p.collectedAt) || !r.claimedAt || eventContentAge(p.collectedAt, r.claimedAt) < 0 || eventContentAge(r.receipt.acceptedAt, p.collectedAt) < 0 || !Array.isArray(p.events) || p.events.length !== r.description.query.events.length) return false;
    let total = 0, complete = true, truncated = false, observed = false, failed = false;
    for (let i = 0; i < p.events.length; i++) {
        const row: unknown = p.events[i];
        if (!shape(row, ['event', 'message', 'quality', 'complete', 'truncated'], ['reason']) || !validSelectedEvent(row.event) || !sameSelectedEvent(row.event, r.description.query.events[i]) || typeof row.message !== 'string' || /[\u0000\uD800-\uDFFF]/u.test(row.message) || typeof row.complete !== 'boolean' || typeof row.truncated !== 'boolean') return false;
        const bytes = new TextEncoder().encode(row.message).length, remaining = 65536 - total, limit = Math.min(16384, remaining);
        if (bytes > limit || remaining === 0 && (row.quality !== 'bounded' || row.message !== '' || row.reason !== 'windows_event_content_total_limit')) return false;
        if (row.quality === 'observed') { if (!row.complete || row.truncated || row.reason !== undefined) return false; observed = true; }
        else if (row.quality === 'bounded') { if (row.complete || !row.truncated || row.reason !== (remaining < 16384 ? 'windows_event_content_total_limit' : 'windows_event_content_message_limit') || bytes < Math.max(0, limit - 3)) return false; observed ||= bytes > 0; }
        else if (row.quality === 'unavailable') { if (row.complete || row.truncated || bytes !== 0 || typeof row.reason !== 'string' || !contentUnavailableReasons.includes(row.reason)) return false; failed = true; }
        else return false;
        total += bytes; complete &&= row.complete; truncated ||= row.truncated;
    }
    const quality = failed ? observed ? 'partial' : 'unavailable' : truncated ? 'bounded' : 'observed';
    return p.quality === quality && p.complete === complete && p.truncated === truncated && encodedContentBytes(v) <= EVENT_CONTENT_RESULT_BYTES;
}
