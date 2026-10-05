import { journalAge, journalTime } from './journal-types';

export const SERVICE_ACTION_VIEW_BYTES = 32768;
export const serviceActionReasons = ['not_configured', 'operator_capability_required', 'helper_unavailable', 'helper_stale', 'helper_disabled', 'action_in_progress', 'needs_intervention', 'capacity', 'ready'] as const;
export type ServiceActionReason = typeof serviceActionReasons[number];
export type ServiceActionState = 'approved' | 'claimed' | 'expired' | 'operation_completed' | 'not_started' | 'needs_intervention';
export interface ServiceActionPreview {
    version: 'tracebolt.service-action-preview.v1'; id: string; deviceId: string; actorId: string; sequence: string;
    plan: { version: 'tracebolt.action-plan.v1'; action: 'service.try-restart'; unit: string; unitPolicyDigest: string };
    planDigest: string; rootPolicyDigest: string; keyId: string; incarnationDigest: string;
    transportProfile: 'production-tls' | 'disposable-http-test'; createdAt: string; expiresAt: string; digest: string;
}
export interface ServiceActionResult {
    phase: 'admitted' | 'dispatching' | 'expired' | 'operation_completed' | 'not_started' | 'needs_intervention';
    reason?: 'canceled' | 'expired' | 'policy_changed' | 'preflight' | 'inactive';
    outcome?: 'completed' | 'unknown'; observedState?: 'active' | 'inactive' | 'failed' | 'unknown';
}
export interface ServiceActionJob {
    id: string; unit: string; actorId: string; approvedAt: string; startDeadline: string;
    state: ServiceActionState; envelopeDigest: string; result: ServiceActionResult | null;
}
export interface ServiceActionView {
    schemaVersion: 'tracebolt.service-action-view.v1'; deviceId: string; serverNow: string;
    configured: boolean; available: boolean; reason: ServiceActionReason;
    services: { unit: string; unitPolicyDigest: string }[];
    preview: ServiceActionPreview | null; job: ServiceActionJob | null;
}
const record = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const exact = (v: unknown, required: string[], optional: string[] = []): v is Record<string, unknown> => record(v) && required.every(k => Object.hasOwn(v, k)) && Object.keys(v).every(k => required.includes(k) || optional.includes(k));
const digest = (v: unknown): v is string => typeof v === 'string' && /^sha256:[a-f0-9]{64}$/.test(v) && v !== `sha256:${'0'.repeat(64)}`;
const member = (v: unknown, values: readonly string[]) => typeof v === 'string' && values.includes(v);
export const validActionID = (v: unknown, prefix: 'action_' | 'agent_' | 'operator_'): v is string => typeof v === 'string' && new RegExp(`^${prefix}[a-f0-9]{32}$`).test(v) && v !== `${prefix}${'0'.repeat(32)}`;
export const validServiceActionUnit = (v: unknown): v is string => typeof v === 'string' && v.length <= 128 && /^[A-Za-z0-9][A-Za-z0-9_.-]*\.service$/.test(v);
const sequence = (v: unknown): v is string => typeof v === 'string' && /^[1-9][0-9]{0,19}$/.test(v) && BigInt(v) <= 18446744073709551615n;
export const serviceActionBlocksNew = (job: ServiceActionJob | null) => !!job && ['approved', 'claimed', 'needs_intervention'].includes(job.state);
export const serviceActionPending = (job: ServiceActionJob | null) => !!job && (job.state === 'approved' || job.state === 'claimed');
function validResult(v: unknown, state: ServiceActionState): v is ServiceActionResult | null {
    if (v === null) return ['approved', 'claimed', 'expired'].includes(state);
    if (!exact(v, ['phase'], ['reason', 'outcome', 'observedState'])) return false;
    const observed = member(v.observedState, ['active', 'inactive', 'failed', 'unknown']);
    const empty = v.reason === undefined && v.outcome === undefined && v.observedState === undefined;
    if (state === 'claimed') return member(v.phase, ['admitted', 'dispatching']) && empty;
    if (state === 'expired') return v.phase === state && empty;
    if (v.phase !== state) return false;
    if (state === 'not_started') return member(v.reason, ['canceled', 'expired', 'policy_changed', 'preflight', 'inactive']) && v.outcome === undefined && v.observedState === undefined;
    if (state === 'operation_completed') return v.reason === undefined && v.outcome === 'completed' && observed;
    if (state === 'needs_intervention') return empty || v.reason === undefined && v.outcome === 'unknown' && observed;
    return false;
}
function validJob(v: unknown, now: string): v is ServiceActionJob {
    return exact(v, ['id', 'unit', 'actorId', 'approvedAt', 'startDeadline', 'state', 'envelopeDigest', 'result']) && validActionID(v.id, 'action_') && validServiceActionUnit(v.unit) && validActionID(v.actorId, 'operator_') && journalTime(v.approvedAt) && journalTime(v.startDeadline) && journalAge(v.startDeadline, v.approvedAt) > 0 && journalAge(v.startDeadline, v.approvedAt) <= 120000 && journalAge(now, v.approvedAt) >= 0 && member(v.state, ['approved', 'claimed', 'expired', 'operation_completed', 'not_started', 'needs_intervention']) && digest(v.envelopeDigest) && validResult(v.result, v.state as ServiceActionState);
}
function validPreview(v: unknown, deviceId: string, actorId: string, insecure: boolean, now: string): v is ServiceActionPreview {
    if (!exact(v, ['version', 'id', 'deviceId', 'actorId', 'sequence', 'plan', 'planDigest', 'rootPolicyDigest', 'keyId', 'incarnationDigest', 'transportProfile', 'createdAt', 'expiresAt', 'digest'])) return false;
    return v.version === 'tracebolt.service-action-preview.v1' && validActionID(v.id, 'action_') && v.deviceId === deviceId && v.actorId === actorId && sequence(v.sequence) && exact(v.plan, ['version', 'action', 'unit', 'unitPolicyDigest']) && v.plan.version === 'tracebolt.action-plan.v1' && v.plan.action === 'service.try-restart' && validServiceActionUnit(v.plan.unit) && digest(v.plan.unitPolicyDigest) && [v.planDigest, v.rootPolicyDigest, v.keyId, v.incarnationDigest, v.digest].every(digest) && v.transportProfile === (insecure ? 'disposable-http-test' : 'production-tls') && journalTime(v.createdAt) && journalTime(v.expiresAt) && journalAge(now, v.createdAt) >= 0 && journalAge(v.expiresAt, v.createdAt) === 60000;
}
/** Fail closed on unknown fields/states. Display metadata is not host authorization. */
export function validServiceActionView(v: unknown, deviceId: string, actorId: string, insecure: boolean): v is ServiceActionView {
    if (!validActionID(deviceId, 'agent_') || !validActionID(actorId, 'operator_') || !exact(v, ['schemaVersion', 'deviceId', 'serverNow', 'configured', 'available', 'reason', 'services', 'preview', 'job']) || v.schemaVersion !== 'tracebolt.service-action-view.v1' || v.deviceId !== deviceId || !journalTime(v.serverNow) || typeof v.configured !== 'boolean' || typeof v.available !== 'boolean' || !member(v.reason, serviceActionReasons) || v.available !== (v.reason === 'ready') || v.available && !v.configured || !Array.isArray(v.services) || v.services.length > 16) return false;
    const seen = new Set<string>();
    for (const service of v.services) {
        if (!exact(service, ['unit', 'unitPolicyDigest']) || !validServiceActionUnit(service.unit) || !digest(service.unitPolicyDigest) || seen.has(service.unit)) return false;
        seen.add(service.unit);
    }
    if (v.job !== null && !validJob(v.job, v.serverNow)) return false;
    if (v.available && (v.services.length === 0 || serviceActionBlocksNew(v.job as ServiceActionJob | null))) return false;
    if (v.preview !== null) {
        if (!validPreview(v.preview, deviceId, actorId, insecure, v.serverNow) || serviceActionBlocksNew(v.job as ServiceActionJob | null) || (v.job as ServiceActionJob | null)?.id === v.preview.id) return false;
        if (!v.services.some(service => service.unit === (v.preview as ServiceActionPreview).plan.unit && service.unitPolicyDigest === (v.preview as ServiceActionPreview).plan.unitPolicyDigest)) return false;
    }
    return true;
}
