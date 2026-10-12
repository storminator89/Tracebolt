import { APIError } from './api';
import { inventoryAge } from './complete-packages-types';
import { validFleetGroupName } from './fleet-groups-types';
import { validWindowsCapacityDeviceId } from './windows-capacity-types';
import { validWindowsMaintenanceIntent, validWindowsMaintenanceView, windowsMaintenanceCanStart, windowsMaintenanceEndTime } from './windows-maintenance-types';
import type { WindowsMaintenanceDomain, WindowsMaintenanceIntent, WindowsMaintenanceStart, WindowsMaintenanceTarget, WindowsMaintenanceView } from './windows-maintenance-types';

export type GroupMaintenanceMember = { deviceId: string; name: string; targets: WindowsMaintenanceTarget[] };
export type GroupMaintenanceView = { schemaVersion: 'tracebolt.fleet-group-maintenance.v1'; serverNow: string; authorityExpiresAt: string; groupId: string; groupName: string; groupRevision: number; excludedLinuxMembers: number; unavailableMembers: number; members: GroupMaintenanceMember[] };
export type GroupMaintenanceStart = WindowsMaintenanceStart & { groupRevision: number };
export type GroupMaintenanceIO = { active: () => boolean; get: () => Promise<GroupMaintenanceView>; post: (body: GroupMaintenanceStart) => Promise<GroupMaintenanceView> };
export type ReviewedMaintenanceMember = { deviceId: string; name: string; target: WindowsMaintenanceTarget };
export type GroupMaintenanceReview = { groupId: string; groupName: string; groupRevision: number; authorityExpiresAt: string; domain: WindowsMaintenanceDomain; intent: WindowsMaintenanceIntent; endsAt: string; members: ReviewedMaintenanceMember[] };
export type GroupMaintenanceResult = ReviewedMaintenanceMember & { status: 'started' | 'conflict' | 'unconfirmed' | 'not-attempted'; matchingAfterUnconfirmed?: boolean };
const exact = (v: unknown, keys: string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const integer = (v: unknown, minimum = 0): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= minimum;
export const groupMaintenanceMetadata = (view: GroupMaintenanceView): WindowsMaintenanceView => ({ schemaVersion: 'tracebolt.windows-maintenance.v1', serverNow: view.serverNow, authorityExpiresAt: view.authorityExpiresAt, targets: view.members.flatMap(m => m.targets) });
/** One server-owned original-identity projection; never join independent rosters by ID. */
export function validGroupMaintenanceView(v: unknown, groupId: string): v is GroupMaintenanceView {
    if (!exact(v, ['schemaVersion', 'serverNow', 'authorityExpiresAt', 'groupId', 'groupName', 'groupRevision', 'excludedLinuxMembers', 'unavailableMembers', 'members']) || v.schemaVersion !== 'tracebolt.fleet-group-maintenance.v1' || v.groupId !== groupId || !/^group_[a-f0-9]{32}$/.test(groupId) || groupId === `group_${'0'.repeat(32)}` || !validFleetGroupName(v.groupName) || !integer(v.groupRevision, 1) || !integer(v.excludedLinuxMembers) || !integer(v.unavailableMembers) || !Array.isArray(v.members) || v.members.length > 25 || v.members.length + v.excludedLinuxMembers + v.unavailableMembers > 50) return false;
    if (!v.members.every(m => exact(m, ['deviceId', 'name', 'targets']) && typeof m.deviceId === 'string' && validWindowsCapacityDeviceId(m.deviceId) && typeof m.name === 'string' && m.name.length > 0 && new TextEncoder().encode(m.name).length <= 256 && Array.isArray(m.targets) && m.targets.length === 6 && m.targets.every(t => !!t && typeof t === 'object' && t.deviceId === m.deviceId))) return false;
    const value = v as GroupMaintenanceView;
    return validWindowsMaintenanceView(groupMaintenanceMetadata(value)) && inventoryAge(value.authorityExpiresAt, value.serverNow) <= 120000 && new Set(value.members.map(m => m.deviceId)).size === value.members.length && new TextEncoder().encode(JSON.stringify(value)).byteLength <= 262144;
}
const cloneTarget = (t: WindowsMaintenanceTarget): WindowsMaintenanceTarget => ({ ...t, windows: t.windows.map(w => ({ ...w })) });
const sameTarget = (a: WindowsMaintenanceTarget, b: WindowsMaintenanceTarget) => JSON.stringify(a) === JSON.stringify(b);
const approved = new WeakMap<GroupMaintenanceReview, GroupMaintenanceReview>();
const attempted = new WeakSet<GroupMaintenanceReview>();
export function reviewGroupMaintenance(original: GroupMaintenanceView, current: GroupMaintenanceView, ids: string[], domain: WindowsMaintenanceDomain, intent: WindowsMaintenanceIntent, minutes: number, age: number): GroupMaintenanceReview {
    if (!validGroupMaintenanceView(original, original.groupId) || !validGroupMaintenanceView(current, original.groupId) || original.groupRevision !== current.groupRevision || original.groupName !== current.groupName || !validWindowsMaintenanceIntent(intent) || !Number.isFinite(age) || age < 0 || inventoryAge(original.authorityExpiresAt, current.serverNow) <= age || ids.length < 1 || ids.length > 25 || new Set(ids).size !== ids.length) throw new Error('Invalid maintenance review');
    const endsAt = windowsMaintenanceEndTime(current.serverNow, age, minutes);
    if (!endsAt) throw new Error('Invalid maintenance end');
    const members = ids.map(id => {
        const previous = original.members.find(m => m.deviceId === id), member = current.members.find(m => m.deviceId === id);
        const before = previous?.targets.find(t => t.domain === domain), target = member?.targets.find(t => t.domain === domain);
        if (!member || !previous || member.name !== previous.name || !before || !target || !sameTarget(before, target) || !windowsMaintenanceCanStart(groupMaintenanceMetadata(current), target, age)) throw new Error('Exact membership or maintenance changed');
        return { deviceId: member.deviceId, name: member.name, target: cloneTarget(target) };
    });
    const review = { groupId: current.groupId, groupName: current.groupName, groupRevision: current.groupRevision, authorityExpiresAt: inventoryAge(original.authorityExpiresAt, current.authorityExpiresAt) < 0 ? original.authorityExpiresAt : current.authorityExpiresAt, domain, intent, endsAt, members };
    // Hold a private copy so external mutation of a rendered review cannot expand it.
    approved.set(review, { ...review, members: members.map(m => ({ ...m, target: cloneTarget(m.target) })) });
    return review;
}
const matchesStart = (view: GroupMaintenanceView, row: ReviewedMaintenanceMember, review: GroupMaintenanceReview) => {
    const target = view.members.find(m => m.deviceId === row.deviceId)?.targets.find(t => t.key === row.target.key), window = target?.windows[0];
    return target?.revision === row.target.revision + 1 && window?.id === target.revision && window.endsAt === review.endsAt && window.intent === review.intent && window.endedAt === null;
};
/** One-use foreground sequence. Every POST has the same reviewed absolute end.
 * Group revision/original membership is also checked by the single-target commit.
 * This is neither an atomic group operation nor an ongoing membership rule. */
export async function applyGroupMaintenance(review: GroupMaintenanceReview, io: GroupMaintenanceIO, update: (rows: GroupMaintenanceResult[]) => void): Promise<GroupMaintenanceResult[]> {
    const frozen = approved.get(review);
    if (!frozen || attempted.has(review)) throw new Error('A fresh review is required');
    attempted.add(review);
    const rows: GroupMaintenanceResult[] = frozen.members.map(m => ({ ...m, target: cloneTarget(m.target), status: 'not-attempted' }));
    const publish = () => update(rows.map(r => ({ ...r, target: cloneTarget(r.target) })));
    publish();
    for (const row of rows) {
        if (!io.active()) break;
        try {
            const current = await io.get();
            if (!io.active()) break;
            const member = current.members.find(m => m.deviceId === row.deviceId), target = member?.targets.find(t => t.key === row.target.key);
            if (!validGroupMaintenanceView(current, frozen.groupId) || current.groupRevision !== frozen.groupRevision || current.groupName !== frozen.groupName || member?.name !== row.name || !target || !sameTarget(target, row.target) || inventoryAge(frozen.authorityExpiresAt, current.serverNow) <= 0 || inventoryAge(frozen.endsAt, current.serverNow) < 60000 || !windowsMaintenanceCanStart(groupMaintenanceMetadata(current), target, 0)) throw new Error('Maintenance review changed');
        } catch { if (io.active()) row.status = 'conflict'; publish(); break; }
        if (!io.active()) break;
        try {
            const result = await io.post({ groupRevision: frozen.groupRevision, key: row.target.key, revision: row.target.revision, endsAt: frozen.endsAt, intent: frozen.intent });
            if (!io.active() || !validGroupMaintenanceView(result, frozen.groupId) || result.groupRevision !== frozen.groupRevision || !matchesStart(result, row, frozen)) throw new Error('Start is unconfirmed');
            row.status = 'started'; publish();
        } catch (error) {
            // Even a conflict can be reported by the final response guard after
            // commit. Keep that possibility explicit, and never retry the write.
            row.status = error instanceof APIError && [400, 403, 404, 409].includes(error.status ?? 0) ? 'conflict' : 'unconfirmed';
            publish();
            if (io.active()) {
                try { const current = await io.get(); if (validGroupMaintenanceView(current, frozen.groupId)) row.matchingAfterUnconfirmed = matchesStart(current, row, frozen); } catch { /* Readback cannot remove uncertainty. */ }
                publish();
            }
            break;
        }
    }
    publish(); return rows;
}
