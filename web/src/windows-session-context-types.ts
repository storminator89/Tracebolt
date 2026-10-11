import { inventoryAge } from './complete-packages-types';
import type { WindowsInventorySnapshot } from './windows-inventory-types';

/** Personal, operator-only local metadata. Never an account inventory or action target. */
export const WINDOWS_SESSION_CONTEXT_BYTES = 24 * 1024;
export const WINDOWS_SESSION_CONTEXT_REASONS = ['', 'windows_session_context_access_denied', 'windows_session_context_unavailable', 'windows_session_context_unsupported_platform', 'windows_session_context_invalid_metadata', 'windows_session_context_bounds', 'windows_session_context_partial_result', 'windows_session_context_budget_exhausted'] as const;
export const WINDOWS_SESSION_STATES = ['active', 'connected', 'connect-query', 'shadow', 'disconnected', 'idle', 'listen', 'reset', 'down', 'init', 'unknown'] as const;
export type WindowsSessionFieldQuality = 'observed' | 'empty' | 'denied' | 'unavailable';
interface WindowsSessionSource { quality: 'observed' | 'partial' | 'denied' | 'unavailable'; reason: typeof WINDOWS_SESSION_CONTEXT_REASONS[number] }
export interface WindowsSessionRow { sessionId: number; userName: string | null; userQuality: WindowsSessionFieldQuality; domainName: string | null; domainQuality: WindowsSessionFieldQuality; state: typeof WINDOWS_SESSION_STATES[number]; protocol: 'console' | 'rdp' | 'unknown' }
export interface WindowsSessionContext {
    schemaVersion: 'tracebolt.windows-session-context.v1'; scope: 'windows-session-context-v1'; grantId: string; generationId: string; collectedAt: string;
    sessions: WindowsSessionSource & { observedCount: number | null; retainedCount: number; truncatedCount: number | null; rows: WindowsSessionRow[] };
    join: WindowsSessionSource & { status: 'unjoined' | 'domain' | 'workgroup' | 'unknown'; name: string | null };
}
const exact = (v: unknown, keys: readonly string[]): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const integer = (v: unknown, max = 4294967295): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0) && v >= 0 && v <= max;
const timestamp = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number(v.slice(0, 4)) >= 1970 && Number.isFinite(Date.parse(v)) && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19);
// String.length measures UTF-16 units; reject malformed surrogate sequences as Go rejects invalid UTF-8.
const label = (v: unknown, units: number): v is string => typeof v === 'string' && v.length > 0 && v.length <= units && !/[\p{Cc}\uFFFD\uD800-\uDFFF]/u.test(v);
const field = (v: unknown, quality: unknown): boolean => quality === 'observed' ? label(v, 64) : v === null && ['empty', 'denied', 'unavailable'].includes(quality as string);
const reason = (v: unknown): boolean => WINDOWS_SESSION_CONTEXT_REASONS.includes(v as WindowsSessionSource['reason']);
const unavailable = (v: Record<string, unknown>): boolean => (v.quality === 'denied' || v.quality === 'unavailable') && v.reason !== '' && (v.quality === 'denied') === (v.reason === 'windows_session_context_access_denied');
function sessions(v: unknown): boolean {
    if (!exact(v, ['quality', 'reason', 'observedCount', 'retainedCount', 'truncatedCount', 'rows']) || !reason(v.reason) || !Array.isArray(v.rows) || v.rows.length > 32 || !integer(v.retainedCount, 32) || v.retainedCount !== v.rows.length) return false;
    if (v.quality === 'denied' || v.quality === 'unavailable') return unavailable(v) && v.rows.length === 0 && v.observedCount === null && v.truncatedCount === null;
    if (!integer(v.observedCount, 4096) || !integer(v.truncatedCount, 4096) || v.retainedCount > v.observedCount || v.truncatedCount !== v.observedCount - v.retainedCount) return false;
    let partial = v.truncatedCount > 0, previous = -1;
    for (const row of v.rows) {
        if (!exact(row, ['sessionId', 'userName', 'userQuality', 'domainName', 'domainQuality', 'state', 'protocol']) || !integer(row.sessionId) || row.sessionId <= previous || !field(row.userName, row.userQuality) || !field(row.domainName, row.domainQuality) || !WINDOWS_SESSION_STATES.includes(row.state as WindowsSessionRow['state']) || !['console', 'rdp', 'unknown'].includes(row.protocol as string)) return false;
        previous = row.sessionId;
        partial ||= ['denied', 'unavailable'].includes(row.userQuality as string) || ['denied', 'unavailable'].includes(row.domainQuality as string) || row.state === 'unknown' || row.protocol === 'unknown';
    }
    return v.quality === 'observed' && !partial && v.reason === '' || v.quality === 'partial' && partial && v.reason !== '';
}
function join(v: unknown): boolean {
    if (!exact(v, ['quality', 'reason', 'status', 'name']) || !reason(v.reason)) return false;
    if (v.quality === 'observed') return v.reason === '' && (v.status === 'unjoined' && v.name === null || (v.status === 'domain' || v.status === 'workgroup') && label(v.name, 256));
    if (v.quality === 'partial') return v.reason !== '' && (v.status === 'domain' || v.status === 'workgroup') && v.name === null;
    return unavailable(v) && v.status === 'unknown' && v.name === null;
}
export function validWindowsSessionContext(v: unknown, snapshot: WindowsInventorySnapshot, serverNow: string): v is WindowsSessionContext {
    if (!exact(v, ['schemaVersion', 'scope', 'grantId', 'generationId', 'collectedAt', 'sessions', 'join']) || v.schemaVersion !== 'tracebolt.windows-session-context.v1' || v.scope !== 'windows-session-context-v1' || typeof v.grantId !== 'string' || !/^[a-f0-9]{32}$/.test(v.grantId) || typeof v.generationId !== 'string' || !/^sample_[a-f0-9]{32}$/.test(v.generationId) || v.generationId !== snapshot.generationId || !timestamp(v.collectedAt) || !timestamp(snapshot.collectedAt) || !timestamp(serverNow) || inventoryAge(v.collectedAt, snapshot.collectedAt) !== 0 || inventoryAge(v.collectedAt, serverNow) > 30000 || inventoryAge(serverNow, v.collectedAt) >= 86400000 || !sessions(v.sessions) || !join(v.join)) return false;
    // Mirror encoding/json's HTML-safe bytes, including U+2028/U+2029, for its exact budget.
    const encoded = JSON.stringify(v).replace(/[<>&\u2028\u2029]/g, ch => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`);
    return new TextEncoder().encode(encoded).byteLength <= WINDOWS_SESSION_CONTEXT_BYTES;
}
