export const PROCESS_WATCH_BYTES = 262144;
export const PROCESS_WATCH_MAX_REVISION = 9223372036854775807n;
export interface ProcessGeneration {
    sequence: string; generationId: string; manifestHash: string;
    captureStartedAt: string; captureFinishedAt: string; receivedAt: string;
    totalRows: number; unidentifiedRows: number;
}
export interface ProcessObservation { generation: ProcessGeneration; activeCount: number; nonRunningCount: number }
export interface ProcessProof { first: ProcessObservation; last: ProcessObservation; samples: 2 | 3 }
export interface ProcessWatchCheck { name: string; condition: 'present' | 'pending' | 'incident' | 'unknown'; activeCount: number | null; nonRunningCount: number | null; failureCount: number; successCount: number }
export interface ProcessWatchIncident {
    id: string; name: string; state: 'open' | 'recovered' | 'monitoring_stopped'; sourceCurrent: boolean;
    openedAt: string; lastObservedAt: string; closedAt: string | null; acknowledgedAt: string | null;
    opening: ProcessProof; recovery: ProcessProof | null;
}
export interface ProcessWatchesView {
    schemaVersion: 'tracebolt.linux-process-watches.v1'; deviceId: string; serverNow: string; validUntil: string;
    revision: string; canManage: boolean; clockReliable: boolean; maxRules: 8; maxIncidents: 128; retentionDays: 30; earlierOmitted: number;
    source: { token: string; scope: 'agent-visible-linux-namespaces'; status: 'available' | 'unknown'; reason: 'none' | 'not_configured' | 'no_generation' | 'newer_attempt' | 'stale' | 'unavailable'; generation: ProcessGeneration | null };
    policy: { enabled: boolean; names: string[]; consecutiveFailures: 2 | 3; enabledAt: string | null; sourceMatches: boolean };
    checks: ProcessWatchCheck[]; incidents: ProcessWatchIncident[];
    lastRequest: { requestId: string; operation: 'policy' | 'acknowledge'; sourceToken: string; incidentId: string | null } | null;
}
export interface ProcessPolicyRequest { requestId: string; expectedRevision: string; sourceToken: string; enabled: boolean; names: string[]; consecutiveFailures: number; retentionAcknowledged: boolean }
export interface ProcessAcknowledgeRequest { requestId: string; expectedRevision: string; sourceToken: string; incidentId: string }
export type ProcessWatchRequest = { operation: 'policy'; body: ProcessPolicyRequest } | { operation: 'acknowledge'; body: ProcessAcknowledgeRequest };
export const processWatchDeviceId = (v: unknown): v is string => typeof v === 'string' && /^agent_[0-9a-f]{32}$/.test(v);
const exact = (v: unknown, fields: readonly string[]): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === fields.length && fields.every(k => Object.hasOwn(v, k));
const integer = (v: unknown, max: number): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v <= max;
const decimal = (v: unknown, positive = false): v is string => typeof v === 'string' && /^(?:0|[1-9][0-9]{0,18})$/.test(v) && BigInt(v) <= PROCESS_WATCH_MAX_REVISION && (!positive || v !== '0');
const token = (v: unknown): v is string => typeof v === 'string' && /^processsource_[0-9a-f]{32}$/.test(v) && v !== `processsource_${'0'.repeat(32)}`;
const requestId = (v: unknown): v is string => typeof v === 'string' && /^processrequest_[0-9a-f]{32}$/.test(v) && v !== `processrequest_${'0'.repeat(32)}`;
const incidentId = (v: unknown): v is string => typeof v === 'string' && /^processincident_[0-9a-f]{16}$/.test(v) && v !== 'processincident_0000000000000000';
export function processWatchTime(v: unknown): bigint | null {
    if (typeof v !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) || Number(v.slice(0, 4)) < 1970) return null;
    const seconds = v.slice(0, 19), ms = Date.parse(`${seconds}Z`);
    if (!Number.isFinite(ms) || new Date(ms).toISOString().slice(0, 19) !== seconds) return null;
    return BigInt(ms) * 1000000n + BigInt((v.includes('.') ? v.slice(20, -1) : '').padEnd(9, '0'));
}
export function validProcessWatchName(v: unknown): v is string {
    return typeof v === 'string' && v.length > 0 && new TextEncoder().encode(v).length <= 64 && !/[\p{Cc}\p{Cf}\u2028\u2029\ufffd]/u.test(v) && !Array.from(v).some(c => c.codePointAt(0)! >= 0xd800 && c.codePointAt(0)! <= 0xdfff);
}
export function processNameOrder(a: string, b: string): number { const x = new TextEncoder().encode(a), y = new TextEncoder().encode(b); for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i]; return x.length - y.length; }
export const processWatchNames = (v: unknown): v is string[] => Array.isArray(v) && v.length <= 8 && v.every(validProcessWatchName) && v.every((x, i) => i === 0 || processNameOrder(v[i - 1], x) < 0);
const time = (v: unknown): v is string => processWatchTime(v) !== null;
function generation(v: unknown, now: string, reliable: boolean): v is ProcessGeneration {
    return exact(v, ['sequence', 'generationId', 'manifestHash', 'captureStartedAt', 'captureFinishedAt', 'receivedAt', 'totalRows', 'unidentifiedRows']) && decimal(v.sequence, true) && typeof v.generationId === 'string' && /^sample_[0-9a-f]{32}$/.test(v.generationId) && typeof v.manifestHash === 'string' && /^[0-9a-f]{64}$/.test(v.manifestHash) && time(v.captureStartedAt) && time(v.captureFinishedAt) && time(v.receivedAt) && processWatchTime(v.captureStartedAt)! <= processWatchTime(v.captureFinishedAt)! && processWatchTime(v.captureFinishedAt)! <= processWatchTime(v.receivedAt)! && (!reliable || processWatchTime(v.receivedAt)! <= processWatchTime(now)!) && integer(v.totalRows, 32768) && integer(v.unidentifiedRows, v.totalRows);
}
function observation(v: unknown, now: string, reliable: boolean): v is ProcessObservation {
    return exact(v, ['generation', 'activeCount', 'nonRunningCount']) && generation(v.generation, now, reliable) && integer(v.activeCount, 32768) && integer(v.nonRunningCount, 32768) && v.activeCount + v.nonRunningCount <= v.generation.totalRows - v.generation.unidentifiedRows;
}
function proof(v: unknown, now: string, reliable: boolean, recovery: boolean): v is ProcessProof {
    if (!exact(v, ['first', 'last', 'samples']) || !(v.samples === 2 || !recovery && v.samples === 3) || !observation(v.first, now, reliable) || !observation(v.last, now, reliable)) return false;
    const first = v.first, last = v.last;
    return BigInt(last.generation.sequence) - BigInt(first.generation.sequence) === BigInt(v.samples - 1) && first.generation.generationId !== last.generation.generationId && processWatchTime(first.generation.captureStartedAt)! < processWatchTime(last.generation.captureStartedAt)! && processWatchTime(first.generation.receivedAt)! <= processWatchTime(last.generation.receivedAt)! && (recovery ? first.activeCount > 0 && last.activeCount > 0 : first.activeCount === 0 && last.activeCount === 0 && first.generation.unidentifiedRows === 0 && last.generation.unidentifiedRows === 0);
}
export function validProcessWatches(v: unknown, deviceId: string): v is ProcessWatchesView {
    if (!processWatchDeviceId(deviceId) || !exact(v, ['schemaVersion', 'deviceId', 'serverNow', 'validUntil', 'revision', 'canManage', 'clockReliable', 'maxRules', 'maxIncidents', 'retentionDays', 'earlierOmitted', 'source', 'policy', 'checks', 'incidents', 'lastRequest']) || v.schemaVersion !== 'tracebolt.linux-process-watches.v1' || v.deviceId !== deviceId || !time(v.serverNow) || !time(v.validUntil) || processWatchTime(v.validUntil)! <= processWatchTime(v.serverNow)! || processWatchTime(v.validUntil)! - processWatchTime(v.serverNow)! > 30000000000n || !decimal(v.revision) || typeof v.canManage !== 'boolean' || typeof v.clockReliable !== 'boolean' || v.maxRules !== 8 || v.maxIncidents !== 128 || v.retentionDays !== 30 || !integer(v.earlierOmitted, Number.MAX_SAFE_INTEGER)) return false;
    const s = v.source, p = v.policy;
    if (!exact(s, ['token', 'scope', 'status', 'reason', 'generation']) || !token(s.token) || s.scope !== 'agent-visible-linux-namespaces' || !['available', 'unknown'].includes(s.status as string) || !['none', 'not_configured', 'no_generation', 'newer_attempt', 'stale', 'unavailable'].includes(s.reason as string)) return false;
    if (s.status === 'available' ? !v.clockReliable || s.reason !== 'none' || !generation(s.generation, v.serverNow, true) || processWatchTime(v.serverNow)! - processWatchTime(s.generation.captureStartedAt)! >= 120000000000n || processWatchTime(v.serverNow)! - processWatchTime(s.generation.receivedAt)! >= 120000000000n || processWatchTime(v.validUntil)! > processWatchTime(s.generation.captureStartedAt)! + 120000000000n || processWatchTime(v.validUntil)! > processWatchTime(s.generation.receivedAt)! + 120000000000n : s.generation !== null || s.reason === 'none') return false;
    if (!exact(p, ['enabled', 'names', 'consecutiveFailures', 'enabledAt', 'sourceMatches']) || typeof p.enabled !== 'boolean' || !processWatchNames(p.names) || p.consecutiveFailures !== 2 && p.consecutiveFailures !== 3 || !(p.enabledAt === null || time(p.enabledAt)) || typeof p.sourceMatches !== 'boolean' || p.enabled && (p.names.length === 0 || p.enabledAt === null) || !p.enabled && (p.names.length !== 0 || p.enabledAt !== null || p.consecutiveFailures !== 2)) return false;
    if (!Array.isArray(v.checks) || v.checks.length !== p.names.length || !Array.isArray(v.incidents) || v.incidents.length > 128) return false;
    const ids = new Set<string>();
    for (const i of v.incidents) {
        if (!exact(i, ['id', 'name', 'state', 'sourceCurrent', 'openedAt', 'lastObservedAt', 'closedAt', 'acknowledgedAt', 'opening', 'recovery']) || !incidentId(i.id) || ids.has(i.id) || !validProcessWatchName(i.name) || !['open', 'recovered', 'monitoring_stopped'].includes(i.state as string) || typeof i.sourceCurrent !== 'boolean' || !time(i.openedAt) || !time(i.lastObservedAt) || !(i.closedAt === null || time(i.closedAt)) || !(i.acknowledgedAt === null || time(i.acknowledgedAt)) || !proof(i.opening, v.serverNow, v.clockReliable, false)) return false;
        if (processWatchTime(i.openedAt)! < processWatchTime(i.opening.last.generation.receivedAt)! || processWatchTime(i.lastObservedAt)! < processWatchTime(i.opening.last.generation.captureFinishedAt)!) return false;
        if (i.closedAt !== null && (processWatchTime(i.closedAt)! < processWatchTime(i.lastObservedAt)! || processWatchTime(i.closedAt)! < processWatchTime(i.openedAt)!) || i.acknowledgedAt !== null && processWatchTime(i.acknowledgedAt)! < processWatchTime(i.openedAt)!) return false;
        if (v.clockReliable && [i.openedAt, i.lastObservedAt, i.closedAt, i.acknowledgedAt].some(t => t !== null && processWatchTime(t)! > processWatchTime(v.serverNow)!)) return false;
        // GET is pure: an old identity's open record may remain retained until
        // the next evaluator pass. It is history, never current source evidence.
        if (i.state === 'open' && (i.closedAt !== null || i.recovery !== null || !p.enabled || i.sourceCurrent !== p.sourceMatches || !p.names.includes(i.name)) || i.state === 'monitoring_stopped' && i.recovery !== null || i.state === 'recovered' && (!proof(i.recovery, v.serverNow, v.clockReliable, true) || i.closedAt === null || processWatchTime(i.recovery.first.generation.captureStartedAt)! <= processWatchTime(i.opening.last.generation.captureStartedAt)!)) return false;
        if (i.state === 'recovered') {
            if (!proof(i.recovery, v.serverNow, v.clockReliable, true) || processWatchTime(i.closedAt)! < processWatchTime(i.recovery.last.generation.receivedAt)! || i.lastObservedAt !== i.recovery.last.generation.captureFinishedAt || BigInt(i.recovery.first.generation.sequence) <= BigInt(i.opening.last.generation.sequence)) return false;
        }
        ids.add(i.id);
    }
    for (let n = 0; n < v.checks.length; n++) {
        const c = v.checks[n];
        if (!exact(c, ['name', 'condition', 'activeCount', 'nonRunningCount', 'failureCount', 'successCount']) || c.name !== p.names[n] || !['present', 'pending', 'incident', 'unknown'].includes(c.condition as string) || !integer(c.failureCount, 3) || !integer(c.successCount, 2) || c.failureCount * c.successCount !== 0) return false;
        if (c.condition === 'unknown') { if (c.activeCount !== null || c.nonRunningCount !== null || c.failureCount + c.successCount !== 0) return false; continue; }
        if (!v.clockReliable || !p.enabled || !p.sourceMatches || s.status !== 'available' || !generation(s.generation, v.serverNow, true) || !integer(c.activeCount, 32768) || !integer(c.nonRunningCount, 32768) || c.activeCount + c.nonRunningCount > s.generation.totalRows - s.generation.unidentifiedRows || c.activeCount === 0 && s.generation.unidentifiedRows !== 0) return false;
        const open = v.incidents.filter(i => i.name === c.name && i.state === 'open' && i.sourceCurrent);
        if (c.condition === 'incident' && open.some(i => i.lastObservedAt !== (s.generation as unknown as ProcessGeneration).captureFinishedAt)) return false;
        // The evaluator resets an opening failure sequence when the incident is
        // created, and tracks successes only while an open incident is recovering.
        if (open.length > 1 || c.condition === 'present' && (c.activeCount === 0 || open.length !== 0 || c.failureCount !== 0 || c.successCount !== 0) || c.condition === 'pending' && (c.activeCount !== 0 || c.failureCount < 1 || c.failureCount >= p.consecutiveFailures || c.successCount !== 0 || open.length !== 0) || c.condition === 'incident' && (open.length !== 1 || c.failureCount !== 0 || c.successCount !== (c.activeCount > 0 ? 1 : 0))) return false;
    }
    if (v.lastRequest !== null && (!exact(v.lastRequest, ['requestId', 'operation', 'sourceToken', 'incidentId']) || !requestId(v.lastRequest.requestId) || !['policy', 'acknowledge'].includes(v.lastRequest.operation as string) || !token(v.lastRequest.sourceToken) || (v.lastRequest.operation === 'policy' ? v.lastRequest.incidentId !== null : !incidentId(v.lastRequest.incidentId)))) return false;
    return new TextEncoder().encode(JSON.stringify(v)).length <= PROCESS_WATCH_BYTES;
}
export function processWatchRequestId(): string { return `processrequest_${[...crypto.getRandomValues(new Uint8Array(16))].map(v => v.toString(16).padStart(2, '0')).join('')}`; }
export function processWatchConfirmed(v: ProcessWatchesView, request: ProcessWatchRequest): boolean {
    const b = request.body, last = v.lastRequest;
    if (BigInt(v.revision) !== BigInt(b.expectedRevision) + 1n || last?.requestId !== b.requestId || last.operation !== request.operation || last.sourceToken !== b.sourceToken || last.incidentId !== (request.operation === 'acknowledge' ? request.body.incidentId : null)) return false;
    if (request.operation === 'acknowledge') return v.incidents.some(i => i.id === request.body.incidentId && i.acknowledgedAt !== null);
    return v.policy.enabled === request.body.enabled && (!request.body.enabled || v.policy.sourceMatches && v.source.token === b.sourceToken && v.policy.consecutiveFailures === request.body.consecutiveFailures && JSON.stringify(v.policy.names) === JSON.stringify(request.body.names));
}
export function processWatchCondition(v: ProcessWatchesView, c: ProcessWatchCheck, elapsedMs: number): ProcessWatchCheck['condition'] {
    const g = v.source.generation;
    if (!v.clockReliable || !Number.isFinite(elapsedMs) || elapsedMs < 0 || v.source.status !== 'available' || g === null || Number(processWatchTime(v.serverNow)! - processWatchTime(g.captureStartedAt)!) / 1000000 + elapsedMs >= 120000 || Number(processWatchTime(v.serverNow)! - processWatchTime(g.receivedAt)!) / 1000000 + elapsedMs >= 120000) return 'unknown';
    return c.condition;
}
