export const APPLICATION_INCIDENT_BYTES = 196608;
export type ApplicationIncidentKind = 'http' | 'dns' | 'tcp';
export type IncidentOperation = 'enable' | 'disable' | 'acknowledge';
export interface IncidentTarget { id: string; kind: ApplicationIncidentKind; targetScheme: 'http' | 'https' | null }
export interface IncidentCheck extends IncidentTarget {
    condition: 'ok' | 'pending' | 'incident' | 'unknown'; observedAt: string | null; completedAt: string | null;
    reason: string | null; httpStatus: number | null; failureCount: number; successCount: number;
}
export interface ApplicationIncident {
    id: string; targetId: string; kind: ApplicationIncidentKind; targetScheme: 'http' | 'https' | null;
    state: 'open' | 'recovered' | 'monitoring_stopped'; sourceCurrent: boolean;
    opening: { firstObservedAt: string; observedAt: string; completedAt: string; reason: string; httpStatus: number | null; samples: 2 | 3 };
    lastObservedAt: string; lastCompletedAt: string; closedAt: string | null; acknowledgedAt: string | null;
    recovery: { firstObservedAt: string; observedAt: string; completedAt: string; samples: 2 } | null;
}
export interface ApplicationIncidentsView {
    schemaVersion: 'tracebolt.application-incidents.v1'; serverNow: string; revision: string; canManage: boolean; clockReliable: boolean;
    retentionDays: 30; maxIncidents: 128; earlierOmitted: boolean;
    currentSource: { token: string; mode: 'managed' | 'external'; checksEnabled: boolean; intervalSeconds: number; maxAgeSeconds: number; targets: IncidentTarget[] };
    policy: { enabled: boolean; sourceMatches: boolean; targetIds: string[]; consecutiveFailures: 2 | 3; enabledAt: string | null };
    checks: IncidentCheck[]; incidents: ApplicationIncident[];
    lastRequest: { requestId: string; operation: IncidentOperation; sourceToken: string; incidentId: string | null } | null;
}
export interface IncidentRequest {
    requestId: string; expectedRevision: string; operation: IncidentOperation; sourceToken: string;
    targetIds: string[]; consecutiveFailures: number; incidentId: string | null; retentionAcknowledged: boolean;
}
const exact = (v: unknown, fields: readonly string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === fields.length && fields.every(k => Object.hasOwn(v, k));
const integer = (v: unknown, min: number, max: number): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= min && v <= max;
const id = (v: unknown): v is string => typeof v === 'string' && /^[a-z0-9_-]{1,48}$/.test(v);
export const incidentSourceToken = (v: unknown): v is string => typeof v === 'string' && /^appsource_[0-9a-f]{32}$/.test(v);
const requestId = (v: unknown): v is string => typeof v === 'string' && /^apprequest_[0-9a-f]{32}$/.test(v);
const incidentId = (v: unknown): v is string => typeof v === 'string' && /^appincident_[0-9a-f]{16}$/.test(v) && v !== 'appincident_0000000000000000';
const revision = (v: unknown): v is string => typeof v === 'string' && /^(?:0|[1-9][0-9]{0,19})$/.test(v) && BigInt(v) <= 18446744073709551615n;
export function incidentTime(v: unknown): bigint | null {
    if (typeof v !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) || Number(v.slice(0, 4)) < 1970) return null;
    const base = v.slice(0, 19), ms = Date.parse(`${base}Z`);
    return Number.isFinite(ms) && new Date(ms).toISOString().slice(0, 19) === base ? BigInt(ms) * 1000000n + BigInt((v.includes('.') ? v.slice(20, -1) : '').padEnd(9, '0')) : null;
}
function target(v: Record<string, unknown>, key = 'id'): boolean {
    return id(v[key]) && (v.kind === 'http' ? v.targetScheme === 'http' || v.targetScheme === 'https' : (v.kind === 'dns' || v.kind === 'tcp') && v.targetScheme === null);
}
function outcome(reason: unknown, status: unknown, kind: unknown, scheme: unknown): boolean {
    if (reason === null) return status === null;
    if (typeof reason !== 'string') return false;
    if (['not_checked', 'invalid_configuration', 'cancelled', 'destination_blocked', 'stale'].includes(reason)) return status === null;
    if (kind !== 'http') return status === null && ['dns_failed', 'timeout', ...(kind === 'dns' ? ['dns_resolved'] : ['tcp_failed', 'tcp_connected'])].includes(reason);
    if (reason === 'http_2xx') return integer(status, 200, 299);
    if (reason === 'redirect_blocked') return integer(status, 300, 399);
    if (reason === 'http_status') return integer(status, 100, 999) && (status < 200 || status >= 400);
    return status === null && ['dns_failed', 'timeout', 'request_failed', ...(scheme === 'https' ? ['tls_verification_failed', 'tls_handshake_failed'] : [])].includes(reason);
}
const successReason = (reason: unknown) => ['http_2xx', 'dns_resolved', 'tcp_connected'].includes(reason as string);
const failureReason = (reason: unknown) => ['http_status', 'redirect_blocked', 'dns_failed', 'timeout', 'request_failed', 'tls_verification_failed', 'tls_handshake_failed', 'tcp_failed'].includes(reason as string);
function times(v: Record<string, unknown>, keys: string[]): boolean {
    const values = keys.map(k => incidentTime(v[k]));
    return values.every(v => v !== null) && values.every((v, i) => i === 0 || v! >= values[i - 1]!);
}
const uniqueIds = (v: unknown): v is string[] => Array.isArray(v) && v.length <= 8 && v.every(id) && new Set(v).size === v.length;
export function validApplicationIncidents(v: unknown): v is ApplicationIncidentsView {
    if (!exact(v, ['schemaVersion', 'serverNow', 'revision', 'canManage', 'clockReliable', 'retentionDays', 'maxIncidents', 'earlierOmitted', 'currentSource', 'policy', 'checks', 'incidents', 'lastRequest']) || v.schemaVersion !== 'tracebolt.application-incidents.v1' || incidentTime(v.serverNow) === null || !revision(v.revision) || typeof v.canManage !== 'boolean' || typeof v.clockReliable !== 'boolean' || v.retentionDays !== 30 || v.maxIncidents !== 128 || typeof v.earlierOmitted !== 'boolean') return false;
    const s = v.currentSource, p = v.policy;
    if (!exact(s, ['token', 'mode', 'checksEnabled', 'intervalSeconds', 'maxAgeSeconds', 'targets']) || !incidentSourceToken(s.token) || !['managed', 'external'].includes(s.mode as string) || typeof s.checksEnabled !== 'boolean' || !Array.isArray(s.targets) || s.targets.length > 8 || !s.targets.every(t => exact(t, ['id', 'kind', 'targetScheme']) && target(t)) || new Set(s.targets.map(t => t.id)).size !== s.targets.length) return false;
    if (s.checksEnabled ? s.targets.length === 0 || !integer(s.intervalSeconds, 60, 3600) || !integer(s.maxAgeSeconds, 65, 3645) : s.targets.length !== 0 || s.intervalSeconds !== 0 || s.maxAgeSeconds !== 0) return false;
    if (s.checksEnabled && s.maxAgeSeconds !== (s.intervalSeconds as number) + (s.targets.length + 1) * 5) return false;
    const currentTargets = s.targets;
    if (!exact(p, ['enabled', 'sourceMatches', 'targetIds', 'consecutiveFailures', 'enabledAt']) || typeof p.enabled !== 'boolean' || typeof p.sourceMatches !== 'boolean' || !uniqueIds(p.targetIds) || !integer(p.consecutiveFailures, 2, 3) || !(p.enabledAt === null || incidentTime(p.enabledAt) !== null) || p.enabled && (p.targetIds.length === 0 || p.enabledAt === null)) return false;
    if (!p.enabled && (p.targetIds.length !== 0 || p.enabledAt !== null || p.consecutiveFailures !== 2)) return false;
    if (!Array.isArray(v.checks) || v.checks.length > 8 || (!p.enabled || !p.sourceMatches) && v.checks.length !== 0 || !Array.isArray(v.incidents) || v.incidents.length > 128) return false;
    if (p.enabled && p.sourceMatches && (!s.checksEnabled || p.targetIds.some(id => !currentTargets.some(t => t.id === id)) || v.checks.length !== p.targetIds.length)) return false;
    const checkIds = new Set<string>(), incidentIds = new Set<string>();
    for (const c of v.checks) {
        if (!exact(c, ['id', 'kind', 'targetScheme', 'condition', 'observedAt', 'completedAt', 'reason', 'httpStatus', 'failureCount', 'successCount']) || !target(c) || !p.targetIds.includes(c.id as string) || !s.targets.some(t => t.id === c.id && t.kind === c.kind && t.targetScheme === c.targetScheme) || checkIds.has(c.id as string) || !['ok', 'pending', 'incident', 'unknown'].includes(c.condition as string) || !v.clockReliable && c.condition !== 'unknown' || !integer(c.failureCount, 0, 3) || !integer(c.successCount, 0, 2) || !outcome(c.reason, c.httpStatus, c.kind, c.targetScheme)) return false;
        if (c.observedAt === null ? c.completedAt !== null : !times(c, ['observedAt', 'completedAt'])) return false;
        if (c.condition !== 'unknown' && (c.observedAt === null || incidentTime(c.completedAt)! > incidentTime(v.serverNow)!)) return false;
        if (c.failureCount * c.successCount !== 0 || c.condition === 'ok' && (!successReason(c.reason) || c.successCount < 1 || c.failureCount !== 0) || c.condition === 'pending' && (!failureReason(c.reason) || c.failureCount < 1 || c.failureCount >= p.consecutiveFailures || c.successCount !== 0) || c.condition === 'incident' && (c.failureCount + c.successCount < 1 || c.successCount > 1) || c.condition === 'unknown' && c.failureCount + c.successCount !== 0 || c.failureCount > 0 && !failureReason(c.reason) || c.successCount > 0 && !successReason(c.reason)) return false;
        if (!v.clockReliable && (c.observedAt !== null || c.completedAt !== null || c.reason !== null || c.httpStatus !== null)) return false;
        checkIds.add(c.id as string);
    }
    for (const i of v.incidents) {
        if (!exact(i, ['id', 'targetId', 'kind', 'targetScheme', 'state', 'sourceCurrent', 'opening', 'lastObservedAt', 'lastCompletedAt', 'closedAt', 'acknowledgedAt', 'recovery']) || !incidentId(i.id) || incidentIds.has(i.id) || typeof i.sourceCurrent !== 'boolean' || !target(i, 'targetId') || !['open', 'recovered', 'monitoring_stopped'].includes(i.state as string) || !exact(i.opening, ['firstObservedAt', 'observedAt', 'completedAt', 'reason', 'httpStatus', 'samples']) || !times(i.opening, ['firstObservedAt', 'observedAt', 'completedAt']) || ![2, 3].includes(i.opening.samples as number) || typeof i.opening.reason !== 'string' || !outcome(i.opening.reason, i.opening.httpStatus, i.kind, i.targetScheme) || !times(i, ['lastObservedAt', 'lastCompletedAt']) || incidentTime(i.lastObservedAt)! < incidentTime(i.opening.observedAt)! || incidentTime(i.lastCompletedAt)! < incidentTime(i.opening.completedAt)!) return false;
        if (!(i.closedAt === null || incidentTime(i.closedAt) !== null) || !(i.acknowledgedAt === null || incidentTime(i.acknowledgedAt) !== null)) return false;
        if (!failureReason(i.opening.reason) || incidentTime(i.opening.firstObservedAt)! >= incidentTime(i.opening.observedAt)! || i.closedAt !== null && incidentTime(i.closedAt)! < incidentTime(i.lastCompletedAt)! || i.acknowledgedAt !== null && incidentTime(i.acknowledgedAt)! < incidentTime(i.opening.completedAt)!) return false;
        if (i.state === 'open' && (i.closedAt !== null || i.recovery !== null) || i.state === 'monitoring_stopped' && i.recovery !== null) return false;
        if (i.state === 'recovered') {
            const recovery = i.recovery;
            if (!exact(recovery, ['firstObservedAt', 'observedAt', 'completedAt', 'samples']) || recovery.samples !== 2 || !times(recovery, ['firstObservedAt', 'observedAt', 'completedAt']) || i.closedAt !== recovery.completedAt || incidentTime(recovery.firstObservedAt)! <= incidentTime(i.opening.completedAt)! || incidentTime(recovery.firstObservedAt)! >= incidentTime(recovery.observedAt)! || recovery.observedAt !== i.lastObservedAt || recovery.completedAt !== i.lastCompletedAt) return false;
        }
        incidentIds.add(i.id);
    }
    if (v.lastRequest !== null && (!exact(v.lastRequest, ['requestId', 'operation', 'sourceToken', 'incidentId']) || !requestId(v.lastRequest.requestId) || !['enable', 'disable', 'acknowledge'].includes(v.lastRequest.operation as string) || !incidentSourceToken(v.lastRequest.sourceToken) || (v.lastRequest.operation === 'acknowledge' ? !incidentId(v.lastRequest.incidentId) : v.lastRequest.incidentId !== null))) return false;
    return new TextEncoder().encode(JSON.stringify(v)).byteLength <= APPLICATION_INCIDENT_BYTES;
}
export function incidentRequestId(): string { return `apprequest_${[...crypto.getRandomValues(new Uint8Array(16))].map(v => v.toString(16).padStart(2, '0')).join('')}`; }
export function incidentRequestConfirmed(view: ApplicationIncidentsView, body: IncidentRequest): boolean {
    const last = view.lastRequest;
    if (!last || last.requestId !== body.requestId || last.operation !== body.operation || last.sourceToken !== body.sourceToken || last.incidentId !== body.incidentId || BigInt(view.revision) !== BigInt(body.expectedRevision) + 1n) return false;
    return body.operation === 'acknowledge' ? view.incidents.some(i => i.id === body.incidentId && i.acknowledgedAt !== null) : body.operation === 'disable' ? !view.policy.enabled : view.policy.enabled && view.policy.sourceMatches && view.currentSource.token === body.sourceToken && view.policy.consecutiveFailures === body.consecutiveFailures && [...view.policy.targetIds].sort().join(',') === [...body.targetIds].sort().join(',');
}
