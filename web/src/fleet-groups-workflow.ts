import { APIError } from './api';
import type { FleetGroup, FleetGroupDevice, FleetGroupsView } from './fleet-groups-types';
import { validFleetGroupsView } from './fleet-groups-types';
import { validWindowsPercentageView } from './windows-capacity-types';
import type { WindowsCapacityPolicy, WindowsPercentageMetric, WindowsPercentageView } from './windows-capacity-types';
export type GroupHealthSetting = { metric: WindowsPercentageMetric; enabled: boolean; thresholdPercent: number };
export type ReviewedMember = FleetGroupDevice & { policy: WindowsCapacityPolicy };
export type GroupHealthReview = { group: FleetGroup; setting: GroupHealthSetting; members: ReviewedMember[] };
export type GroupHealthStatus = 'changed' | 'currently-matching' | 'conflict' | 'not-attempted' | 'unconfirmed';
export type GroupHealthResult = ReviewedMember & { status: GroupHealthStatus; matchingAfterUnconfirmed?: boolean };
export type GroupHealthIO = { get: (path: string) => Promise<unknown>; post: (path: string, body: unknown) => Promise<unknown>; active: () => boolean; accept: (view: WindowsPercentageView) => boolean };
export const percentagePath = (id: string, metric: WindowsPercentageMetric): string => `/devices/${id}/${metric === 'disk' ? 'windows-capacity' : `windows-resource/${metric}`}`;
const matches = (policy: WindowsCapacityPolicy, setting: GroupHealthSetting) => policy.enabled === setting.enabled && policy.thresholdPercent === setting.thresholdPercent;
const sameGroup = (a: FleetGroup, b: FleetGroup) => a.id === b.id && a.name === b.name && a.revision === b.revision && a.unavailableMembers === b.unavailableMembers && [...a.memberIds].sort().join(',') === [...b.memberIds].sort().join(',');
function requireActive(io: GroupHealthIO) { if (!io.active()) throw new Error('Group review is no longer active.'); }
async function currentPolicy(io: GroupHealthIO, member: FleetGroupDevice, metric: WindowsPercentageMetric) {
    requireActive(io);
    const view = await io.get(percentagePath(member.id, metric));
    requireActive(io);
    if (!validWindowsPercentageView(view, member.id, metric) || !io.accept(view)) throw new Error('Policy authority is unavailable.');
    return view.policy;
}
export async function reviewGroupHealth(group: FleetGroup, view: FleetGroupsView, selectedIds: string[], setting: GroupHealthSetting, io: GroupHealthIO): Promise<GroupHealthReview> {
    if (!validFleetGroupsView(view) || !view.groups.some(g => sameGroup(g, group)) || selectedIds.length < 1 || selectedIds.length > 25 || new Set(selectedIds).size !== selectedIds.length || !['disk', 'cpu', 'memory'].includes(setting.metric) || typeof setting.enabled !== 'boolean' || !Number.isSafeInteger(setting.thresholdPercent) || setting.thresholdPercent < 50 || setting.thresholdPercent > 99) throw new Error('Invalid group review.');
    const members: ReviewedMember[] = [];
    for (const id of selectedIds) {
        const member = view.devices.find(d => d.id === id && d.platform === 'windows' && group.memberIds.includes(id));
        if (!member) throw new Error('Member is no longer eligible.');
        members.push({ ...member, policy: { ...await currentPolicy(io, member, setting.metric) } });
    }
    return { group: { ...group, memberIds: [...group.memberIds] }, setting: { ...setting }, members };
}
// Deliberately not a durable bulk job. One frozen reviewed set, one metric, one
// sequential POST at a time. No dynamic membership, retry or rollback.
export async function applyGroupHealth(review: GroupHealthReview, io: GroupHealthIO, update: (rows: GroupHealthResult[]) => void): Promise<GroupHealthResult[]> {
    const result: GroupHealthResult[] = review.members.map(m => ({ ...m, policy: { ...m.policy }, status: 'not-attempted' }));
    const publish = () => update(result.map(r => ({ ...r })));
    publish();
    try {
        requireActive(io);
        const current = await io.get(`/fleet/groups/${review.group.id}`);
        requireActive(io);
        if (!validFleetGroupsView(current) || current.groups.length !== 1 || !sameGroup(current.groups[0], review.group) || review.members.some(m => !current.devices.some(d => d.id === m.id && d.name === m.name && d.platform === 'windows'))) throw new Error('Group changed.');
    } catch { if (io.active() && result[0]) result[0].status = 'conflict'; publish(); return result; }
    for (const row of result) {
        if (!io.active()) break;
        let policy: WindowsCapacityPolicy;
        try {
            policy = await currentPolicy(io, row, review.setting.metric);
            if (policy.revision !== row.policy.revision || policy.enabled !== row.policy.enabled || policy.thresholdPercent !== row.policy.thresholdPercent) throw new Error('Policy changed.');
        } catch { if (io.active()) row.status = 'conflict'; publish(); break; }
        if (matches(policy, review.setting)) { row.status = 'currently-matching'; publish(); continue; }
        try {
            requireActive(io);
            const value = await io.post(`${percentagePath(row.id, review.setting.metric)}/policy`, { enabled: review.setting.enabled, thresholdPercent: review.setting.thresholdPercent, expectedRevision: policy.revision });
            requireActive(io);
            if (!validWindowsPercentageView(value, row.id, review.setting.metric) || !io.accept(value) || !matches(value.policy, review.setting) || value.policy.revision !== policy.revision + 1) throw new Error('Write result is unconfirmed.');
            row.status = 'changed'; publish();
        } catch (error) {
            row.status = error instanceof APIError && [400, 401, 403, 404, 409].includes(error.status ?? 0) ? 'conflict' : 'unconfirmed';
            publish();
            if (row.status === 'unconfirmed' && io.active()) {
                // Matching after an uncertain POST cannot prove who wrote it.
                try { row.matchingAfterUnconfirmed = matches(await currentPolicy(io, row, review.setting.metric), review.setting); } catch { /* Preserve uncertainty. */ }
                publish();
            }
            break;
        }
    }
    publish(); return result;
}
