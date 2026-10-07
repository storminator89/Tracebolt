export const WINDOWS_EVENTS_BYTES = 6 * 1024;
export interface WindowsEvent { recordId: string; eventId: number; level: number; provider: string; timestamp: string }
export interface WindowsEventChannel { channel: 'Application' | 'System'; quality: 'observed' | 'bounded' | 'partial' | 'denied' | 'unavailable'; reason: string; complete: boolean; truncated: boolean; observedCount: number; rows: WindowsEvent[] }
export interface WindowsEvents { schemaVersion: 'tracebolt.windows-event-metadata.v1'; scope: 'windows-application-system-event-headers-v1'; grantId: string; generationId: string; collectedAt: string; channels: WindowsEventChannel[] }
const exact = (v: unknown, keys: string[]): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v,k));
const integer = (v: unknown, max: number): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= max;
const text = (v: unknown): v is string => typeof v === 'string' && v.length > 0 && v.length <= 256 && v.trim() === v && new TextEncoder().encode(v).length <= 1024 && !/[\p{Cc}\p{Cf}\uFFFD\uD800-\uDFFF\u2028\u2029]/u.test(v);
const stamp = (v: unknown, minYear: number): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number(v.slice(0,4)) >= minYear && Number.isFinite(Date.parse(v)) && new Date(Date.parse(v)).toISOString().slice(0,19) === v.slice(0,19);
const reasons = ['', 'windows_events_access_denied', 'windows_events_unsupported_platform', 'windows_events_source_unavailable', 'windows_events_invalid_metadata', 'windows_events_metadata_buffer_limit', 'windows_events_read_failed', 'context canceled', 'context deadline exceeded'];
function row(v: unknown): v is WindowsEvent { return exact(v,['recordId','eventId','level','provider','timestamp']) && typeof v.recordId === 'string' && /^[1-9]\d{0,19}$/.test(v.recordId) && BigInt(v.recordId) <= 18446744073709551615n && integer(v.eventId,65535) && integer(v.level,255) && text(v.provider) && stamp(v.timestamp,1601); }
function channel(v: unknown, i: number): v is WindowsEventChannel {
    if (!exact(v,['channel','quality','reason','complete','truncated','observedCount','rows']) || v.channel !== ['Application','System'][i] || typeof v.complete !== 'boolean' || typeof v.truncated !== 'boolean' || typeof v.reason !== 'string' || !reasons.includes(v.reason) || !integer(v.observedCount,16) || !Array.isArray(v.rows) || v.rows.length > 16 || !v.rows.every(row) || new Set(v.rows.map(r=>r.recordId)).size !== v.rows.length || v.observedCount < v.rows.length || v.observedCount > v.rows.length && !v.truncated) return false;
    if ((v.quality === 'denied') !== (v.reason === 'windows_events_access_denied' && v.rows.length === 0)) return false;
    if (v.quality === 'observed') return v.complete && !v.truncated && !v.reason && v.observedCount === v.rows.length;
    if (v.quality === 'bounded') return !v.complete && v.truncated && !v.reason;
    if (v.quality === 'partial') return !v.complete && Boolean(v.reason);
    return (v.quality === 'denied' || v.quality === 'unavailable') && !v.complete && !v.truncated && v.rows.length === 0 && v.observedCount === 0 && Boolean(v.reason);
}
export function validWindowsEvents(v: unknown, generation: string, serverNow: string): v is WindowsEvents {
    if (!exact(v,['schemaVersion','scope','grantId','generationId','collectedAt','channels']) || v.schemaVersion !== 'tracebolt.windows-event-metadata.v1' || v.scope !== 'windows-application-system-event-headers-v1' || typeof v.grantId !== 'string' || !/^[a-f0-9]{32}$/.test(v.grantId) || v.generationId !== generation || !stamp(v.collectedAt,1970) || Date.parse(v.collectedAt) - Date.parse(serverNow) > 30000 || Date.parse(serverNow)-Date.parse(v.collectedAt) >= 86400000 || !Array.isArray(v.channels) || v.channels.length !== 2 || !v.channels.every(channel)) return false;
    return new TextEncoder().encode(JSON.stringify(v).replace(/[<>&\u2028\u2029]/g,c=>`\\u${c.charCodeAt(0).toString(16).padStart(4,'0')}`)).length <= WINDOWS_EVENTS_BYTES;
}
