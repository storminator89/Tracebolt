import { APIError } from './api';
import { inventoryAge } from './complete-packages-types';
import { validGroupMaintenanceView } from './fleet-group-maintenance-workflow';
import type { GroupMaintenanceView, ReviewedMaintenanceMember } from './fleet-group-maintenance-workflow';
import { windowsMaintenanceState } from './windows-maintenance-types';
import type { WindowsMaintenanceEnd, WindowsMaintenanceTarget } from './windows-maintenance-types';

export type GroupMaintenanceEnd = WindowsMaintenanceEnd & { groupRevision: number };
export type GroupMaintenanceEndIO = { active: () => boolean; get: () => Promise<GroupMaintenanceView>; end: (body: GroupMaintenanceEnd) => Promise<GroupMaintenanceView> };
export type GroupMaintenanceEndReview = { groupId: string; groupName: string; groupRevision: number; authorityExpiresAt: string; members: ReviewedMaintenanceMember[] };
export type GroupMaintenanceEndResult = ReviewedMaintenanceMember & { status: 'ended' | 'conflict' | 'unconfirmed' | 'not-attempted'; matchingAfterUnconfirmed?: boolean };
const cloneTarget = (target: WindowsMaintenanceTarget): WindowsMaintenanceTarget => ({ ...target, windows: target.windows.map(window => ({ ...window })) });
const sameTarget = (a: WindowsMaintenanceTarget, b: WindowsMaintenanceTarget) => JSON.stringify(a) === JSON.stringify(b);
const approved = new WeakMap<GroupMaintenanceEndReview, GroupMaintenanceEndReview>();
const attempted = new WeakSet<GroupMaintenanceEndReview>();
const activeWindow = (target: WindowsMaintenanceTarget, now: string, age: number) => target.revision < Number.MAX_SAFE_INTEGER && !!target.windows[0] && windowsMaintenanceState(target.windows[0], now, age) === 'active';

/** Selection is by exact original-identity/domain key, never by a mutable ID alone. */
export function reviewGroupMaintenanceEnd(original: GroupMaintenanceView, current: GroupMaintenanceView, keys: string[], age: number): GroupMaintenanceEndReview {
    if (!validGroupMaintenanceView(original, original.groupId) || !validGroupMaintenanceView(current, original.groupId) || original.groupRevision !== current.groupRevision || original.groupName !== current.groupName || !Number.isFinite(age) || age < 0 || inventoryAge(original.authorityExpiresAt, current.serverNow) <= age || inventoryAge(current.authorityExpiresAt, current.serverNow) <= age || keys.length < 1 || keys.length > 25 || new Set(keys).size !== keys.length) throw new Error('Invalid early-end review');
    const members = keys.map(key => {
        const previous = original.members.find(member => member.targets.some(target => target.key === key));
        const member = current.members.find(candidate => candidate.deviceId === previous?.deviceId);
        const before = previous?.targets.find(target => target.key === key), target = member?.targets.find(target => target.key === key);
        if (!member || !previous || member.name !== previous.name || !before || !target || !sameTarget(before, target) || !activeWindow(target, current.serverNow, age)) throw new Error('Exact active maintenance changed');
        return { deviceId: member.deviceId, name: member.name, target: cloneTarget(target) };
    });
    const review = { groupId: current.groupId, groupName: current.groupName, groupRevision: current.groupRevision, authorityExpiresAt: inventoryAge(original.authorityExpiresAt, current.authorityExpiresAt) < 0 ? original.authorityExpiresAt : current.authorityExpiresAt, members };
    approved.set(review, { ...review, members: members.map(member => ({ ...member, target: cloneTarget(member.target) })) });
    return review;
}
const matchesEnd = (view: GroupMaintenanceView, row: ReviewedMaintenanceMember, review: GroupMaintenanceEndReview) => {
    const member = view.members.find(candidate => candidate.deviceId === row.deviceId), target = member?.targets.find(candidate => candidate.key === row.target.key);
    const window = target?.windows[0], original = row.target.windows[0];
    return view.groupRevision === review.groupRevision && view.groupName === review.groupName && member?.name === row.name && target?.revision === row.target.revision + 1 && window?.id === original.id && window.startedAt === original.startedAt && window.endsAt === original.endsAt && window.intent === original.intent && window.endedAt !== null;
};

/** One-use foreground sequence. Stop affects unsent work; an in-flight end can commit.
 * Matching readback never confirms this attempt and never authorizes another POST. */
export async function applyGroupMaintenanceEnd(review: GroupMaintenanceEndReview, io: GroupMaintenanceEndIO, update: (rows: GroupMaintenanceEndResult[]) => void): Promise<GroupMaintenanceEndResult[]> {
    const frozen = approved.get(review);
    if (!frozen || attempted.has(review)) throw new Error('A fresh early-end review is required');
    attempted.add(review);
    const rows: GroupMaintenanceEndResult[] = frozen.members.map(member => ({ ...member, target: cloneTarget(member.target), status: 'not-attempted' }));
    const publish = () => update(rows.map(row => ({ ...row, target: cloneTarget(row.target) })));
    publish();
    for (const row of rows) {
        if (!io.active()) break;
        try {
            const current = await io.get();
            if (!io.active()) break;
            if (!validGroupMaintenanceView(current, frozen.groupId)) throw new Error('Invalid maintenance projection');
            const member = current.members.find(candidate => candidate.deviceId === row.deviceId), target = member?.targets.find(candidate => candidate.key === row.target.key);
            if (current.groupRevision !== frozen.groupRevision || current.groupName !== frozen.groupName || member?.name !== row.name || !target || !sameTarget(target, row.target) || inventoryAge(frozen.authorityExpiresAt, current.serverNow) <= 0 || !activeWindow(target, current.serverNow, 0)) throw new Error('Early-end review changed');
        } catch { if (io.active()) row.status = 'conflict'; publish(); break; }
        if (!io.active()) break;
        try {
            const result = await io.end({ groupRevision: frozen.groupRevision, key: row.target.key, revision: row.target.revision, windowId: row.target.windows[0].id });
            if (!io.active() || !validGroupMaintenanceView(result, frozen.groupId) || !matchesEnd(result, row, frozen)) throw new Error('End is unconfirmed');
            row.status = 'ended'; publish();
        } catch (error) {
            // A final response guard can reject after commit, including with 409.
            row.status = error instanceof APIError && [400, 403, 404, 409].includes(error.status ?? 0) ? 'conflict' : 'unconfirmed';
            publish();
            if (io.active()) {
                try { const current = await io.get(); if (validGroupMaintenanceView(current, frozen.groupId)) row.matchingAfterUnconfirmed = matchesEnd(current, row, frozen); } catch { /* Read only; uncertainty stays visible. */ }
                publish();
            }
            break;
        }
    }
    publish(); return rows;
}
