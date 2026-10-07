import { affectedServicesDigest } from './service-action-impact';
import { journalAge, journalTime } from './journal-types';

export const SERVICE_ACTION_VIEW_BYTES = 32768;
export const SERVICE_ACTION_V2_VIEW_BYTES = 256 * 1024;
export const serviceActionScope = 'control-existing-root-trusted-system-services';
export const serviceActionReviewNotice = 'This action trusts the existing root-controlled systemd service configuration and its host authority. It may interrupt dependent services, management connectivity, or your current session. Existing root-run programs may indirectly affect Tracebolt; this grant is not a sandbox.';
const exclusionReasons = ['generated_transient_or_user_authority', 'generated_or_transient_unit', 'generated_transient_or_masked_unit', 'loaded_configuration_stale', 'alternate_execution_root', 'unsupported_stop_policy', 'unit_transitioning', 'ambiguous_execution_path', 'unsupported_or_ambiguous_relationship', 'unsupported_configuration_or_graph', 'unit_authority_untrusted', 'canonical_unit_required', 'unsupported_automatic_relationship', 'graph_bound_exceeded', 'configuration_changed', 'control_plane_protected', 'inspection_unavailable'];
export const serviceActionReasons = ['not_configured', 'operator_capability_required', 'helper_unavailable', 'helper_stale', 'helper_disabled', 'action_in_progress', 'needs_intervention', 'capacity', 'ready'] as const;
export type ServiceActionReason = typeof serviceActionReasons[number];
export type ServiceActionState = 'approved' | 'claimed' | 'expired' | 'operation_completed' | 'not_started' | 'needs_intervention';
export interface ServiceActionPreview {
    version: 'tracebolt.service-action-preview.v1' | 'tracebolt.service-action-preview.v2';
    scope?: typeof serviceActionScope; reviewNotice?: typeof serviceActionReviewNotice; affectedServices?: string[]; id: string; deviceId: string; actorId: string; sequence: string;
    plan: { version: 'tracebolt.action-plan.v1' | 'tracebolt.action-plan.v2'; affectedServicesDigest?: string; action: 'service.try-restart'; unit: string; unitPolicyDigest: string };
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
    schemaVersion: 'tracebolt.service-action-view.v1' | 'tracebolt.service-action-view.v2';
    scope?: typeof serviceActionScope; reviewNotice?: typeof serviceActionReviewNotice; excludedServices?: { unit: string; reason: string }[]; deviceId: string; serverNow: string;
    configured: boolean; available: boolean; reason: ServiceActionReason;
    services: { unit: string; unitPolicyDigest: string; affectedServices?: string[] }[];
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
function validImpact(v: unknown, unit: string): v is string[] {
    return Array.isArray(v) && v.length >= 1 && v.length <= 64 && v.includes(unit) && v.every((name, i) => validServiceActionUnit(name) && (i === 0 || v[i - 1] < name));
}
function fullScope(v: Record<string, unknown>) { return v.scope === serviceActionScope && v.reviewNotice === serviceActionReviewNotice; }
export function validServiceActionPreview(v: unknown, deviceId: string, actorId: string, insecure: boolean, now: string): v is ServiceActionPreview {
    const v2 = record(v) && v.version === 'tracebolt.service-action-preview.v2';
    if (!exact(v, ['version', 'id', 'deviceId', 'actorId', 'sequence', 'plan', 'planDigest', 'rootPolicyDigest', 'keyId', 'incarnationDigest', 'transportProfile', 'createdAt', 'expiresAt', 'digest', ...(v2 ? ['scope', 'reviewNotice', 'affectedServices'] : [])])) return false;
    if (v2 && (!fullScope(v) || !record(v.plan) || typeof v.plan.unit !== 'string' || !validImpact(v.affectedServices, v.plan.unit) || v.plan.affectedServicesDigest !== affectedServicesDigest(v.affectedServices))) return false;
    return (v2 || v.version === 'tracebolt.service-action-preview.v1') && validActionID(v.id, 'action_') && v.deviceId === deviceId && v.actorId === actorId && sequence(v.sequence) && exact(v.plan, ['version', 'action', 'unit', 'unitPolicyDigest', ...(v2 ? ['affectedServicesDigest'] : [])]) && v.plan.version === (v2 ? 'tracebolt.action-plan.v2' : 'tracebolt.action-plan.v1') && v.plan.action === 'service.try-restart' && validServiceActionUnit(v.plan.unit) && digest(v.plan.unitPolicyDigest) && [v.planDigest, v.rootPolicyDigest, v.keyId, v.incarnationDigest, v.digest].every(digest) && v.transportProfile === (insecure ? 'disposable-http-test' : 'production-tls') && journalTime(v.createdAt) && journalTime(v.expiresAt) && journalAge(now, v.createdAt) >= 0 && journalAge(v.expiresAt, v.createdAt) === 60000;
}
/** Fail closed on unknown fields/states. Display metadata is not host authorization. */
export function validServiceActionView(v: unknown, deviceId: string, actorId: string, insecure: boolean): v is ServiceActionView {
    const v2 = record(v) && v.schemaVersion === 'tracebolt.service-action-view.v2';
    if (!validActionID(deviceId, 'agent_') || !validActionID(actorId, 'operator_') || !exact(v, ['schemaVersion', 'deviceId', 'serverNow', 'configured', 'available', 'reason', 'services', 'preview', 'job', ...(v2 ? ['scope', 'reviewNotice'] : [])], v2 ? ['excludedServices'] : []) || (!v2 && v.schemaVersion !== 'tracebolt.service-action-view.v1') || (v2 && !fullScope(v)) || v.deviceId !== deviceId || !journalTime(v.serverNow) || typeof v.configured !== 'boolean' || typeof v.available !== 'boolean' || !member(v.reason, serviceActionReasons) || v.available !== (v.reason === 'ready') || v.available && !v.configured || !Array.isArray(v.services) || v.services.length > (v2 ? 256 : 16)) return false;
    const seen = new Set<string>();
    let lastService = '';
    for (const service of v.services) {
        if (!exact(service, ['unit', 'unitPolicyDigest', ...(v2 ? ['affectedServices'] : [])]) || !validServiceActionUnit(service.unit) || !digest(service.unitPolicyDigest) || seen.has(service.unit) || (v2 && (!validImpact(service.affectedServices, service.unit) || lastService >= service.unit))) return false;
        seen.add(service.unit); lastService = service.unit;
    }
    if (v2 && v.excludedServices !== undefined) {
        if (!Array.isArray(v.excludedServices) || v.services.length + v.excludedServices.length > 256) return false;
        let last = '';
        for (const excluded of v.excludedServices) {
            if (!exact(excluded, ['unit', 'reason']) || typeof excluded.unit !== 'string' || excluded.unit.length < 9 || excluded.unit.length > 255 || !/^[!-~]+\.service$/.test(excluded.unit) || excluded.unit.includes('/') || excluded.unit <= last || seen.has(excluded.unit) || !member(excluded.reason, exclusionReasons)) return false;
            last = excluded.unit;
        }
    }
    if (v.job !== null && !validJob(v.job, v.serverNow)) return false;
    if (v.available && (!v2 && v.services.length === 0 || serviceActionBlocksNew(v.job as ServiceActionJob | null))) return false;
    if (v.preview !== null) {
        if (!record(v.preview) || v.preview.version !== (v2 ? 'tracebolt.service-action-preview.v2' : 'tracebolt.service-action-preview.v1') || !validServiceActionPreview(v.preview, deviceId, actorId, insecure, v.serverNow) || serviceActionBlocksNew(v.job as ServiceActionJob | null) || (v.job as ServiceActionJob | null)?.id === v.preview.id) return false;
        if (!v.services.some(service => service.unit === (v.preview as ServiceActionPreview).plan.unit && service.unitPolicyDigest === (v.preview as ServiceActionPreview).plan.unitPolicyDigest && (!v2 || JSON.stringify(service.affectedServices) === JSON.stringify((v.preview as ServiceActionPreview).affectedServices)))) return false;
    }
    return true;
}
