/** Retained manager-side observations only. No destination or request controls. */
export const APPLICATION_CHECKS_BYTES = 16384;
export type ApplicationState = 'ok' | 'http_error' | 'network_error' | 'tls_error' | 'unknown';
export type ApplicationReason = 'http_2xx' | 'http_status' | 'redirect_blocked' | 'dns_failed' | 'timeout' | 'request_failed' | 'tls_verification_failed' | 'tls_handshake_failed' | 'not_checked' | 'invalid_configuration' | 'cancelled' | 'destination_blocked' | 'stale';
export type ApplicationTLSState = 'valid' | 'expiring' | 'expired' | 'unknown' | 'not_applicable';
export interface ApplicationCheck {
    id: string; targetScheme: 'http' | 'https'; state: ApplicationState; reason: ApplicationReason;
    observedAt: string | null; httpStatus: number | null; tls: { state: ApplicationTLSState; expiresAt: string | null };
}
export interface ApplicationChecksView {
    schemaVersion: 'tracebolt.application-checks.v1'; enabled: boolean; vantage: 'management_server'; serverNow: string;
    intervalSeconds: number; maxAgeSeconds: number; items: ApplicationCheck[];
}
const record = (value: unknown, keys: readonly string[]): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const integer = (value: unknown, min: number, max: number): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= min && value <= max;
const member = (value: unknown, values: readonly string[]) => typeof value === 'string' && values.includes(value);
/** Preserve Go's nanosecond ordering, including just-future and freshness edges. */
function timestamp(value: unknown): bigint | null {
    if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value) || Number(value.slice(0, 4)) < 1970) return null;
    const seconds = value.slice(0, 19), ms = Date.parse(`${seconds}Z`);
    if (!Number.isFinite(ms) || new Date(ms).toISOString().slice(0, 19) !== seconds) return null;
    return BigInt(ms) * 1000000n + BigInt((value.includes('.') ? value.slice(20, -1) : '').padEnd(9, '0'));
}
const days30 = 30n * 24n * 60n * 60n * 1000000000n;
function certificateState(expiry: bigint, now: bigint): ApplicationTLSState { return expiry <= now ? 'expired' : expiry - now <= days30 ? 'expiring' : 'valid'; }
function validRow(value: unknown, now: bigint): value is ApplicationCheck {
    if (!record(value, ['id', 'targetScheme', 'state', 'reason', 'observedAt', 'httpStatus', 'tls']) || typeof value.id !== 'string' || !/^[a-z0-9_-]{1,48}$/.test(value.id) || !member(value.targetScheme, ['http', 'https'])) return false;
    const observed = timestamp(value.observedAt), tls = value.tls;
    if (value.observedAt !== null && observed === null || !record(tls, ['state', 'expiresAt'])) return false;
    if (value.targetScheme === 'http') {
        if (tls.state !== 'not_applicable' || tls.expiresAt !== null || value.state === 'tls_error') return false;
    } else if (tls.state === 'unknown') {
        if (tls.expiresAt !== null) return false;
    } else {
        const expires = timestamp(tls.expiresAt);
        if (expires === null || observed === null || expires <= observed || tls.state !== certificateState(expires, now)) return false;
    }
    if (value.state === 'ok' || value.state === 'http_error') {
        if (observed === null || !integer(value.httpStatus, 100, 999) || value.targetScheme === 'https' && tls.state === 'unknown') return false;
        const ok = value.httpStatus >= 200 && value.httpStatus < 300;
        return value.state === (ok ? 'ok' : 'http_error') && value.reason === (ok ? 'http_2xx' : value.httpStatus >= 300 && value.httpStatus < 400 ? 'redirect_blocked' : 'http_status');
    }
    if (value.httpStatus !== null) return false;
    if (value.state === 'network_error') return observed !== null && member(value.reason, ['dns_failed', 'timeout', 'request_failed']) && (value.reason !== 'dns_failed' || value.targetScheme === 'http' || tls.state === 'unknown');
    if (value.state === 'tls_error') return observed !== null && tls.state === 'unknown' && member(value.reason, ['tls_verification_failed', 'tls_handshake_failed']);
    return value.state === 'unknown' && (tls.state === 'unknown' || tls.state === 'not_applicable') && member(value.reason, ['not_checked', 'invalid_configuration', 'cancelled', 'destination_blocked', 'stale']) && (value.reason === 'not_checked' ? observed === null : observed !== null);
}
export function validApplicationChecksView(value: unknown): value is ApplicationChecksView {
    if (!record(value, ['schemaVersion', 'enabled', 'vantage', 'serverNow', 'intervalSeconds', 'maxAgeSeconds', 'items']) || value.schemaVersion !== 'tracebolt.application-checks.v1' || typeof value.enabled !== 'boolean' || value.vantage !== 'management_server' || !Array.isArray(value.items) || value.items.length > 8) return false;
    const now = timestamp(value.serverNow); if (now === null) return false;
    if (!value.enabled) return value.intervalSeconds === 0 && value.maxAgeSeconds === 0 && value.items.length === 0;
    if (value.items.length === 0 || !integer(value.intervalSeconds, 60, 3600) || value.maxAgeSeconds !== value.intervalSeconds + (value.items.length + 1) * 5) return false;
    const ids = new Set<string>();
    for (const row of value.items) { if (!validRow(row, now) || ids.has(row.id)) return false; ids.add(row.id); }
    return true;
}
export function applicationObservationAge(view: ApplicationChecksView, row: ApplicationCheck, elapsedMs: number): number | null {
    const now = timestamp(view.serverNow), observed = timestamp(row.observedAt);
    // A future observation must not turn green just because the browser waited.
    if (now === null || observed === null || observed > now || !Number.isFinite(elapsedMs) || elapsedMs < 0) return null;
    return Number(now - observed) / 1000000 + elapsedMs;
}
/** Never refresh observation time on GET; age HTTP and verified TLS together. */
export function projectApplicationCheck(view: ApplicationChecksView, row: ApplicationCheck, elapsedMs: number): ApplicationCheck {
    const age = applicationObservationAge(view, row, elapsedMs);
    if (age === null || age > view.maxAgeSeconds * 1000) return { ...row, state: 'unknown', reason: row.observedAt === null ? 'not_checked' : 'stale', httpStatus: null, tls: { state: row.targetScheme === 'http' ? 'not_applicable' : 'unknown', expiresAt: null } };
    const expiry = timestamp(row.tls.expiresAt), now = timestamp(view.serverNow);
    if (expiry !== null && now !== null) return { ...row, tls: { ...row.tls, state: certificateState(expiry, now + BigInt(Math.ceil(elapsedMs * 1000000))) } };
    return row;
}
