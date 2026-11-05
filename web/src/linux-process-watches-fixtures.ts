import type { ProcessGeneration, ProcessObservation, ProcessWatchIncident, ProcessWatchRequest, ProcessWatchesView } from './linux-process-watches-types';
export const processDevice = `agent_${'a'.repeat(32)}`, processNow = '2026-11-04T12:00:00Z', processToken = `processsource_${'b'.repeat(32)}`;
export function processGeneration(sequence = 3, minute = '59'): ProcessGeneration {
    return { sequence: String(sequence), generationId: `sample_${sequence.toString(16).padStart(32, '0')}`, manifestHash: 'c'.repeat(64), captureStartedAt: `2026-11-04T11:${minute}:40Z`, captureFinishedAt: `2026-11-04T11:${minute}:41Z`, receivedAt: `2026-11-04T11:${minute}:42Z`, totalRows: 10, unidentifiedRows: 0 };
}
export function processObservation(sequence = 3, minute = '59', active = 0): ProcessObservation { return { generation: processGeneration(sequence, minute), activeCount: active, nonRunningCount: 0 }; }
export function processIncident(): ProcessWatchIncident {
    return { id: 'processincident_0000000000000001', name: 'worker', state: 'open', sourceCurrent: true, openedAt: '2026-11-04T11:59:43Z', lastObservedAt: '2026-11-04T11:59:41Z', closedAt: null, acknowledgedAt: null, opening: { first: processObservation(2, '58'), last: processObservation(), samples: 2 }, recovery: null };
}
export function processView(): ProcessWatchesView {
    return { schemaVersion: 'tracebolt.linux-process-watches.v1', deviceId: processDevice, serverNow: processNow, validUntil: '2026-11-04T12:00:30Z', revision: '0', canManage: true, clockReliable: true, maxRules: 8, maxIncidents: 128, retentionDays: 30, earlierOmitted: 0,
        source: { token: processToken, scope: 'agent-visible-linux-namespaces', status: 'available', reason: 'none', generation: processGeneration() }, policy: { enabled: false, names: [], consecutiveFailures: 2, enabledAt: null, sourceMatches: false }, checks: [], incidents: [], lastRequest: null };
}
export function processEnabled(): ProcessWatchesView {
    const v = processView(); v.revision = '1'; v.policy = { enabled: true, names: ['worker'], consecutiveFailures: 2, enabledAt: '2026-11-04T11:55:00Z', sourceMatches: true };
    v.checks = [{ name: 'worker', condition: 'incident', activeCount: 0, nonRunningCount: 0, failureCount: 0, successCount: 0 }]; v.incidents = [processIncident()]; return v;
}
export function processCommand(v = processView()): ProcessWatchRequest {
    return { operation: 'policy', body: { requestId: `processrequest_${'d'.repeat(32)}`, expectedRevision: v.revision, sourceToken: v.source.token, enabled: true, names: ['worker'], consecutiveFailures: 2, retentionAcknowledged: true } };
}
export function processConfirmed(v: ProcessWatchesView, request: ProcessWatchRequest): ProcessWatchesView {
    const next = structuredClone(v), b = request.body; next.revision = String(BigInt(b.expectedRevision) + 1n);
    next.lastRequest = { requestId: b.requestId, operation: request.operation, sourceToken: b.sourceToken, incidentId: request.operation === 'acknowledge' ? request.body.incidentId : null };
    if (request.operation === 'policy') {
        next.policy = { enabled: request.body.enabled, names: request.body.names, consecutiveFailures: request.body.enabled ? request.body.consecutiveFailures as 2 | 3 : 2, enabledAt: request.body.enabled ? processNow : null, sourceMatches: true };
        next.checks = request.body.names.map(name => ({ name, condition: 'unknown', activeCount: null, nonRunningCount: null, failureCount: 0, successCount: 0 }));
        next.incidents = next.incidents.map(i => i.state === 'open' ? { ...i, state: 'monitoring_stopped', closedAt: processNow } : i);
    } else next.incidents = next.incidents.map(i => i.id === request.body.incidentId ? { ...i, acknowledgedAt: processNow } : i);
    return next;
}
