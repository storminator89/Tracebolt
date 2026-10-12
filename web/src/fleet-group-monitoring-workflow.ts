import { APIError } from './api';
import { groupMonitoringKey, groupMonitoringMetrics } from './fleet-group-monitoring-types';
import type { GroupMonitoringIO, GroupMonitoringTarget, GroupMonitoringView, GroupMonitoringWrite } from './fleet-group-monitoring-types';
import type { GroupHealthSetting } from './fleet-groups-workflow';

export type GroupMonitoringReview = { view: GroupMonitoringView; body: GroupMonitoringWrite; targets: GroupMonitoringTarget[]; stopping: boolean };
export function reviewGroupMonitoring(view: GroupMonitoringView, definitions: GroupHealthSetting[], ids: string[], consent: boolean, stop?: GroupMonitoringTarget): GroupMonitoringReview {
    const frozen = structuredClone(view);
    if (stop) {
        const target = frozen.targets.find(t => groupMonitoringKey(t) === groupMonitoringKey(stop));
        if (!target || target.assignmentRevision !== stop.assignmentRevision || target.policy.revision !== stop.policy.revision || !target.owned || !['pending', 'inherited'].includes(target.status)) throw new Error('Inheritance changed.');
        return { view: frozen, targets: [target], stopping: true, body: { expectedGroupRevision: frozen.groupRevision, expectedRevision: frozen.revision, consent: false, definitions: [], assignments: [{ deviceId: target.deviceId, metric: target.metric, expectedRevision: target.assignmentRevision, expectedPolicyRevision: target.policy.revision, inherit: false }] } };
    }
    if (!consent || definitions.length < 1 || definitions.length > 3 || new Set(definitions.map(d => d.metric)).size !== definitions.length || definitions.some(d => !groupMonitoringMetrics.includes(d.metric) || typeof d.enabled !== 'boolean' || !Number.isSafeInteger(d.thresholdPercent) || d.thresholdPercent < 50 || d.thresholdPercent > 99) || ids.length > 25 || new Set(ids).size !== ids.length || ids.some(id => !frozen.targets.some(t => t.deviceId === id))) throw new Error('Invalid inheritance review.');
    const targets = frozen.targets.filter(t => definitions.some(d => d.metric === t.metric) && (ids.includes(t.deviceId) || t.owned && ['pending', 'inherited'].includes(t.status)));
    const unavailableExisting = frozen.unavailableAssignments > 0 && definitions.every(d => frozen.definitions.some(current => current.metric === d.metric));
    if (!targets.length && !unavailableExisting || targets.some(t => t.status === 'conflict')) throw new Error('No eligible exact assignment.');
    return { view: frozen, targets, stopping: false, body: { expectedGroupRevision: frozen.groupRevision, expectedRevision: frozen.revision, consent: true, definitions: structuredClone(definitions), assignments: targets.map(t => ({ deviceId: t.deviceId, metric: t.metric, expectedRevision: t.assignmentRevision, expectedPolicyRevision: t.policy.revision, inherit: true })) } };
}
export type GroupMonitoringResult = { status: 'saved' | 'conflict' | 'unconfirmed'; view: GroupMonitoringView | null };
const attempted = new WeakSet<GroupMonitoringReview>();
/** One write per frozen review. Readback describes current state, never proof of our uncertain write. */
export async function saveGroupMonitoring(review: GroupMonitoringReview, io: GroupMonitoringIO): Promise<GroupMonitoringResult> {
    if (attempted.has(review)) throw new Error('A fresh review is required.');
    attempted.add(review);
    if (!io.active()) return { status: 'conflict', view: null };
    try {
        const view = await io.post(structuredClone(review.body));
        if (!io.active() || view.groupId !== review.view.groupId || view.groupRevision !== review.body.expectedGroupRevision || view.revision !== review.body.expectedRevision + (review.body.definitions.length ? 1 : 0) || review.body.assignments.some(a => !view.targets.some(t => t.deviceId === a.deviceId && t.metric === a.metric && t.assignmentRevision > a.expectedRevision))) throw new Error('Unconfirmed response.');
        return { status: 'saved', view };
    } catch (error) {
        const status = error instanceof APIError && [400, 401, 403, 404, 409].includes(error.status ?? 0) ? 'conflict' : 'unconfirmed';
        let view: GroupMonitoringView | null = null;
        if (io.active()) { try { view = await io.get(); } catch { /* Preserve the write outcome; never retry. */ } }
        return { status, view };
    }
}
