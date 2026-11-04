/** A separate historical representation. Never pass these rows to live status or AI. */
export const APPLICATION_HISTORY_MEDIA = 'application/vnd.tracebolt.application-check-history.v1+json';
export const APPLICATION_HISTORY_BYTES = 131072;
export interface ApplicationHistorySample {
    observedAt: string; completedAt: string; state: 'ok' | 'http_error' | 'network_error' | 'tls_error' | 'unknown';
    reason: string; httpStatus: number | null; gapBefore: boolean;
}
export interface ApplicationHistoryTarget {
    id: string; kind: 'http' | 'dns' | 'tcp'; targetScheme: '' | 'http' | 'https'; earlierOmitted: boolean; samples: ApplicationHistorySample[];
}
export interface ApplicationHistory {
    schemaVersion: 'tracebolt.application-check-history.v1'; enabled: boolean; vantage: 'management_server'; serverNow: string;
    retentionSeconds: 86400; perTargetLimit: 32; clockReliable: boolean; items: ApplicationHistoryTarget[];
}
const record = (v: unknown, keys: string[]): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
function timestamp(v: unknown): bigint | null {
    if (typeof v !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) || Number(v.slice(0, 4)) < 1970) return null;
    const base = v.slice(0, 19), ms = Date.parse(`${base}Z`);
    if (!Number.isFinite(ms) || new Date(ms).toISOString().slice(0, 19) !== base) return null;
    return BigInt(ms) * 1000000n + BigInt((v.includes('.') ? v.slice(20, -1) : '').padEnd(9, '0'));
}
function outcome(v: Record<string, unknown>, kind: string, scheme: unknown): boolean {
    const state = v.state, reason = v.reason, status = v.httpStatus;
    if (state === 'unknown') return status === null && ['invalid_configuration', 'destination_blocked'].includes(String(reason));
    if (kind !== 'http') return status === null && (state === 'ok' && reason === (kind === 'dns' ? 'dns_resolved' : 'tcp_connected') || state === 'network_error' && ['dns_failed', 'timeout', ...(kind === 'tcp' ? ['tcp_failed'] : [])].includes(String(reason)));
    if (state === 'network_error') return status === null && ['dns_failed', 'timeout', 'request_failed'].includes(String(reason));
    if (state === 'tls_error') return scheme === 'https' && status === null && ['tls_verification_failed', 'tls_handshake_failed'].includes(String(reason));
    if (typeof status !== 'number' || !Number.isSafeInteger(status) || status < 100 || status > 999) return false;
    return status >= 200 && status < 300 ? state === 'ok' && reason === 'http_2xx' : state === 'http_error' && reason === (status >= 300 && status < 400 ? 'redirect_blocked' : 'http_status');
}
export function validApplicationHistory(v: unknown): v is ApplicationHistory {
    if (!record(v, ['schemaVersion', 'enabled', 'vantage', 'serverNow', 'retentionSeconds', 'perTargetLimit', 'clockReliable', 'items']) || v.schemaVersion !== 'tracebolt.application-check-history.v1' || v.vantage !== 'management_server' || typeof v.enabled !== 'boolean' || typeof v.clockReliable !== 'boolean' || v.retentionSeconds !== 86400 || v.perTargetLimit !== 32 || !Array.isArray(v.items) || v.items.length > 8) return false;
    const now = timestamp(v.serverNow); if (now === null) return false;
    if (!v.enabled) return v.items.length === 0 && v.clockReliable;
    if (v.items.length === 0) return false;
    const ids = new Set<string>();
    for (const target of v.items) {
        if (!record(target, ['id', 'kind', 'targetScheme', 'earlierOmitted', 'samples']) || typeof target.id !== 'string' || !/^[a-z0-9_-]{1,48}$/.test(target.id) || ids.has(target.id) || !['http', 'dns', 'tcp'].includes(String(target.kind)) || typeof target.earlierOmitted !== 'boolean' || !Array.isArray(target.samples) || target.samples.length > 32 || (target.kind === 'http' ? !['http', 'https'].includes(String(target.targetScheme)) : target.targetScheme !== '')) return false;
        ids.add(target.id); let previous: bigint | null = null;
        if (!v.clockReliable && (target.samples.length !== 0 || !target.earlierOmitted)) return false;
        for (const sample of target.samples) {
            if (!record(sample, ['observedAt', 'completedAt', 'state', 'reason', 'httpStatus', 'gapBefore']) || typeof sample.gapBefore !== 'boolean') return false;
            const start = timestamp(sample.observedAt), end = timestamp(sample.completedAt);
            if (start === null || end === null || start > end || end > now || now - start > 86400n * 1000000000n || previous !== null && start <= previous || !outcome(sample, String(target.kind), target.targetScheme)) return false;
            previous = end;
        }
    }
    return true;
}
