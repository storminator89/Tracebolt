import type { ServiceActionJob, ServiceActionPreview, ServiceActionView } from './service-action-types';
import type { OperatorSession } from './auth';
export const actionDevice = `agent_${'a'.repeat(32)}`, actionActor = `operator_${'b'.repeat(32)}`, actionID = `action_${'c'.repeat(32)}`;
export const actionNow = '2026-10-05T12:00:00Z', actionExpiry = '2026-10-05T12:01:00Z', actionSessionExpiry = '2026-10-05T13:00:00Z';
export const actionDigest = `sha256:${'d'.repeat(64)}`;
export const actionAccess = { actorId: actionActor, sessionKey: actionSessionExpiry, insecureTestMode: false };
export const actionSession: OperatorSession = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'synthetic-csrf', serverNow: actionNow, expiresAt: actionSessionExpiry, expiresInSeconds: 3600, loginMode: 'named', actorId: actionActor, capabilities: ['read', 'restart_service'] };
export function actionPreview(unit = 'fixture.service'): ServiceActionPreview {
    return { version: 'tracebolt.service-action-preview.v1', id: actionID, deviceId: actionDevice, actorId: actionActor, sequence: '9007199254740993', plan: { version: 'tracebolt.action-plan.v1', action: 'service.try-restart', unit, unitPolicyDigest: actionDigest }, planDigest: actionDigest, rootPolicyDigest: actionDigest, keyId: actionDigest, incarnationDigest: actionDigest, transportProfile: 'production-tls', createdAt: actionNow, expiresAt: actionExpiry, digest: actionDigest };
}
export function actionJob(state: ServiceActionJob['state'] = 'approved'): ServiceActionJob {
    const result: ServiceActionJob['result'] = state === 'operation_completed' ? { phase: state, outcome: 'completed', observedState: 'active' } : state === 'not_started' ? { phase: state, reason: 'inactive' } : state === 'needs_intervention' ? { phase: state, outcome: 'unknown', observedState: 'unknown' } : null;
    return { id: actionID, unit: 'fixture.service', actorId: actionActor, approvedAt: actionNow, startDeadline: actionExpiry, state, envelopeDigest: actionDigest, result };
}
export function actionView(): ServiceActionView {
    return { schemaVersion: 'tracebolt.service-action-view.v1', deviceId: actionDevice, serverNow: actionNow, configured: true, available: true, reason: 'ready', services: [{ unit: 'fixture.service', unitPolicyDigest: actionDigest }, { unit: 'other.service', unitPolicyDigest: actionDigest }], preview: null, job: null };
}
export function actionJobView(state: ServiceActionJob['state'] = 'approved'): ServiceActionView {
    const blocked = ['approved', 'claimed', 'needs_intervention'].includes(state);
    return { ...actionView(), available: !blocked, reason: state === 'needs_intervention' ? 'needs_intervention' : blocked ? 'action_in_progress' : 'ready', job: actionJob(state) };
}
