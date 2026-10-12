import { APIError } from './api';
import type { FleetGroup, FleetGroupDevice, FleetGroupsView } from './fleet-groups-types';
import { validFleetGroupsView } from './fleet-groups-types';
import { validWindowsPercentageView } from './windows-capacity-types';
import type { WindowsCapacityPolicy, WindowsPercentageMetric, WindowsPercentageView } from './windows-capacity-types';
export type GroupHealthSetting = { metric: WindowsPercentageMetric; enabled: boolean; thresholdPercent: number };
export type ReviewedMember = FleetGroupDevice & { metric: WindowsPercentageMetric; policy: WindowsCapacityPolicy };
export type GroupHealthReview = { group: FleetGroup | null; settings: GroupHealthSetting[]; members: ReviewedMember[] };
export type GroupHealthStatus = 'changed' | 'currently-matching' | 'conflict' | 'not-attempted' | 'unconfirmed';
export type GroupHealthResult = ReviewedMember & { status: GroupHealthStatus; matchingAfterUnconfirmed?: boolean };
export type GroupHealthIO = { get: (path: string) => Promise<unknown>; post: (path: string, body: unknown) => Promise<unknown>; active: () => boolean; accept: (view: WindowsPercentageView) => boolean };
export const percentagePath = (id: string, metric: WindowsPercentageMetric): string => `/devices/${id}/${metric === 'disk' ? 'windows-capacity' : `windows-resource/${metric}`}`;
const matches = (policy: WindowsCapacityPolicy, setting: GroupHealthSetting) => policy.enabled === setting.enabled && policy.thresholdPercent === setting.thresholdPercent;
const sameGroup = (a: FleetGroup, b: FleetGroup) => a.id === b.id && a.name === b.name && a.revision === b.revision && a.unavailableMembers === b.unavailableMembers && [...a.memberIds].sort().join(',') === [...b.memberIds].sort().join(',');
function requireActive(io: GroupHealthIO) { if (!io.active()) throw new Error('Policy review is no longer active.'); }
async function currentPolicy(io: GroupHealthIO, member: FleetGroupDevice, metric: WindowsPercentageMetric) {
    requireActive(io);
    const view = await io.get(percentagePath(member.id, metric));
    requireActive(io);
    if (!validWindowsPercentageView(view, member.id, metric) || !io.accept(view)) throw new Error('Policy authority is unavailable.');
    return view.policy;
}
export async function reviewGroupHealth(group: FleetGroup | null, view: FleetGroupsView, selectedIds: string[], settings: GroupHealthSetting[], io: GroupHealthIO): Promise<GroupHealthReview> {
    if (!validFleetGroupsView(view) || group !== null && !view.groups.some(g => sameGroup(g, group)) || selectedIds.length < 1 || selectedIds.length > 25 || new Set(selectedIds).size !== selectedIds.length || settings.length < 1 || settings.length > 3 || new Set(settings.map(s => s.metric)).size !== settings.length || settings.some(s => !['disk', 'cpu', 'memory'].includes(s.metric) || typeof s.enabled !== 'boolean' || !Number.isSafeInteger(s.thresholdPercent) || s.thresholdPercent < 50 || s.thresholdPercent > 99)) throw new Error('Invalid policy review.');
    // Freeze all inputs before network reads. Groups are optional selection
    // filters, never policy authority or an inheritance relationship.
    const frozenGroup = group ? { ...group, memberIds: [...group.memberIds] } : null;
    const frozenSettings = settings.map(s => ({ ...s }));
    const selected = selectedIds.map(id => {
        const member = view.devices.find(d => d.id === id && d.platform === 'windows' && (!frozenGroup || frozenGroup.memberIds.includes(id)));
        if (!member) throw new Error('Member is no longer eligible.');
        return { ...member };
    });
    const members: ReviewedMember[] = [];
    for (const member of selected) for (const setting of frozenSettings) {
        members.push({ ...member, metric: setting.metric, policy: { ...await currentPolicy(io, member, setting.metric) } });
    }
    requireActive(io);
    return { group: frozenGroup, settings: frozenSettings, members };
}
const attempted = new WeakSet<GroupHealthReview>();
// A temporary reviewed selection, not a bulk authority or durable job. Device
// order and per-device policy order are frozen. Stop the entire remainder after
// any conflict or uncertainty; retain earlier outcomes without rollback/retry.
export async function applyGroupHealth(review: GroupHealthReview, io: GroupHealthIO, update: (rows: GroupHealthResult[]) => void): Promise<GroupHealthResult[]> {
    if (attempted.has(review)) throw new Error('A new review is required.');
    attempted.add(review);
    const result: GroupHealthResult[] = review.members.map(m => ({ ...m, policy: { ...m.policy }, status: 'not-attempted' }));
    const publish = () => update(result.map(r => ({ ...r, policy: { ...r.policy } })));
    publish();
    try {
        requireActive(io);
        const current = await io.get(review.group ? `/fleet/groups/${review.group.id}` : '/fleet/groups');
        requireActive(io);
        if (!validFleetGroupsView(current) || review.group && (current.groups.length !== 1 || !sameGroup(current.groups[0], review.group)) || review.members.some(m => !current.devices.some(d => d.id === m.id && d.name === m.name && d.platform === 'windows'))) throw new Error('Selection changed.');
    } catch { if (io.active() && result[0]) result[0].status = 'conflict'; publish(); return result; }
    for (const row of result) {
        if (!io.active()) break;
        const setting = review.settings.find(s => s.metric === row.metric)!;
        let policy: WindowsCapacityPolicy;
        try {
            policy = await currentPolicy(io, row, row.metric);
            if (policy.revision !== row.policy.revision || policy.enabled !== row.policy.enabled || policy.thresholdPercent !== row.policy.thresholdPercent) throw new Error('Policy changed.');
        } catch { if (io.active()) row.status = 'conflict'; publish(); break; }
        if (matches(policy, setting)) { row.status = 'currently-matching'; publish(); continue; }
        try {
            requireActive(io);
            const value = await io.post(`${percentagePath(row.id, row.metric)}/policy`, { enabled: setting.enabled, thresholdPercent: setting.thresholdPercent, expectedRevision: policy.revision });
            requireActive(io);
            if (!validWindowsPercentageView(value, row.id, row.metric) || !io.accept(value) || !matches(value.policy, setting) || value.policy.revision !== policy.revision + 1) throw new Error('Write result is unconfirmed.');
            row.status = 'changed'; publish();
        } catch (error) {
            row.status = error instanceof APIError && [400, 401, 403, 404, 409].includes(error.status ?? 0) ? 'conflict' : 'unconfirmed';
            publish();
            if (row.status === 'unconfirmed' && io.active()) {
                // Matching after an uncertain POST cannot prove who wrote it.
                try { row.matchingAfterUnconfirmed = matches(await currentPolicy(io, row, row.metric), setting); } catch { /* Preserve uncertainty. */ }
                publish();
            }
            break;
        }
    }
    publish(); return result;
}
