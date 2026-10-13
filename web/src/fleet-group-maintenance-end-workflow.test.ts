import { describe, expect, it, vi } from 'vitest';
import { APIError } from './api';
import { applyGroupMaintenanceEnd, reviewGroupMaintenanceEnd } from './fleet-group-maintenance-end-workflow';
import type { GroupMaintenanceEnd, GroupMaintenanceEndIO } from './fleet-group-maintenance-end-workflow';
import { groupMaintenanceEndFixture } from './fleet-group-maintenance-fixture';
import type { GroupMaintenanceView } from './fleet-group-maintenance-workflow';
const clone = <T,>(value: T): T => structuredClone(value);
function setup() {
    let view = groupMaintenanceEndFixture(), active = true;
    const keys = view.members.flatMap(member => member.targets.filter(target => target.windows.length).map(target => target.key));
    const bodies: GroupMaintenanceEnd[] = [];
    const io: GroupMaintenanceEndIO = { active: () => active, get: vi.fn(async () => clone(view)), end: vi.fn(async body => {
        bodies.push(clone(body)); const target = view.members.flatMap(member => member.targets).find(target => target.key === body.key)!;
        target.revision++; target.changedAt = view.serverNow; target.windows[0].endedAt = view.serverNow; return clone(view);
    }) };
    const review = reviewGroupMaintenanceEnd(clone(view), clone(view), keys, 0);
    return { io, bodies, review, keys, get view() { return view; }, set view(next: GroupMaintenanceView) { view = next; }, stop: () => { active = false; } };
}
describe('reviewed exact group maintenance early ends', () => {
    it('ends only reviewed identity/scope/window revisions sequentially, retaining different original ends', async () => {
        const s = setup(), original = clone(s.review);
        const rows = await applyGroupMaintenanceEnd(s.review, s.io, () => {});
        expect(rows.map(row => row.status)).toEqual(['ended', 'ended', 'ended']);
        expect(s.bodies).toEqual(original.members.map(member => ({ groupRevision: 2, key: member.target.key, revision: 1, windowId: 1 })));
        for (const member of original.members) { const target = s.view.members.flatMap(m => m.targets).find(t => t.key === member.target.key)!; expect(target.windows[0].endsAt).toBe(member.target.windows[0].endsAt); }
        await expect(applyGroupMaintenanceEnd(s.review, s.io, () => {})).rejects.toThrow(/fresh/); expect(s.bodies).toHaveLength(3);
    });
    it('uses a private review copy and does not let callbacks expand or rewrite the approved sequence', async () => {
        const s = setup(), originalKeys = [...s.keys]; s.review.members[0].target.key = 'f'.repeat(64); s.review.members.push(s.review.members[1]); s.review.groupRevision++;
        const rows = await applyGroupMaintenanceEnd(s.review, s.io, rows => { rows[0].target.key = 'e'.repeat(64); rows.splice(1); });
        expect(rows).toHaveLength(3); expect(s.bodies.map(body => body.key)).toEqual(originalKeys); expect(s.bodies.every(body => body.groupRevision === 2)).toBe(true);
    });
    it.each(['group', 'identity', 'revision', 'new-window', 'ended', 'expired', 'missing', 'authority'] as const)('blocks %s drift before any write', async change => {
        const s = setup(), target = s.view.members[0].targets.find(target => target.key === s.keys[0])!;
        if (change === 'group') s.view.groupRevision++;
        if (change === 'identity') target.key = 'f'.repeat(64);
        if (change === 'revision') target.revision++;
        if (change === 'new-window') { target.revision += 2; target.windows[0].id += 2; }
        if (change === 'ended') { target.revision++; target.windows[0].endedAt = s.view.serverNow; }
        if (change === 'expired') { s.view.serverNow = target.windows[0].endsAt; s.view.authorityExpiresAt = new Date(Date.parse(s.view.serverNow) + 120000).toISOString().replace('.000Z', 'Z'); }
        if (change === 'missing') s.view.members.shift();
        if (change === 'authority') { s.view.serverNow = s.review.authorityExpiresAt; s.view.authorityExpiresAt = new Date(Date.parse(s.view.serverNow) + 120000).toISOString().replace('.000Z', 'Z'); }
        const rows = await applyGroupMaintenanceEnd(s.review, s.io, () => {}); expect(rows.map(row => row.status)).toEqual(['conflict', 'not-attempted', 'not-attempted']); expect(s.bodies).toHaveLength(0);
    });
    it('rejects replaced identity or an ended window between selection and review', () => {
        const s = setup(), original = clone(s.view); s.view.members[0].targets.find(t => t.key === s.keys[0])!.key = 'f'.repeat(64);
        expect(() => reviewGroupMaintenanceEnd(original, s.view, s.keys, 0)).toThrow();
        const v = groupMaintenanceEndFixture(), t = v.members[0].targets.find(t => t.windows.length)!; t.revision++; t.windows[0].endedAt = v.serverNow;
        expect(() => reviewGroupMaintenanceEnd(v, v, [t.key], 0)).toThrow();
    });
    it('requires an explicit unique bounded selection and a live original authority', () => {
        const s = setup(); for (const keys of [[], [s.keys[0], s.keys[0]], Array(26).fill(s.keys[0])]) expect(() => reviewGroupMaintenanceEnd(s.view, s.view, keys, 0)).toThrow();
        for (const age of [-1, Infinity, 120000]) expect(() => reviewGroupMaintenanceEnd(s.view, s.view, s.keys, age)).toThrow();
    });
    it.each([false, true])('keeps matching readback uncertain after a committed end, conflict=%s, without another write', async conflict => {
        const s = setup(), original = s.io.end; s.io.end = vi.fn(async body => { await original(body); throw conflict ? new APIError('late guard', 409) : new Error('response lost'); });
        const rows = await applyGroupMaintenanceEnd(s.review, s.io, () => {});
        expect(rows.map(row => row.status)).toEqual([conflict ? 'conflict' : 'unconfirmed', 'not-attempted', 'not-attempted']); expect(rows[0].matchingAfterUnconfirmed).toBe(true); expect(s.bodies).toHaveLength(1); expect(s.io.get).toHaveBeenCalledTimes(2);
    });
    it('retains a confirmed first end on a later blocked POST and never attempts remaining windows', async () => {
        const s = setup(), original = s.io.end; s.io.end = vi.fn(async body => { if (s.bodies.length === 1) throw new APIError('changed', 409); return original(body); });
        const rows = await applyGroupMaintenanceEnd(s.review, s.io, () => {}); expect(rows.map(row => row.status)).toEqual(['ended', 'conflict', 'not-attempted']); expect(s.io.end).toHaveBeenCalledTimes(2);
    });
    it('stops unsent work and treats a stopped in-flight response as uncertain', async () => {
        const s = setup(), original = s.io.end; s.io.end = vi.fn(async body => { const response = await original(body); s.stop(); return response; });
        const rows = await applyGroupMaintenanceEnd(s.review, s.io, () => {}); expect(rows.map(row => row.status)).toEqual(['unconfirmed', 'not-attempted', 'not-attempted']); expect(s.io.get).toHaveBeenCalledTimes(1); expect(s.bodies).toHaveLength(1);
    });
    it('stops after a confirmed end when requested and requires a fresh review thereafter', async () => {
        const s = setup(); const rows = await applyGroupMaintenanceEnd(s.review, s.io, rows => { if (rows[0].status === 'ended') s.stop(); });
        expect(rows.map(row => row.status)).toEqual(['ended', 'not-attempted', 'not-attempted']); expect(s.bodies).toHaveLength(1);
        await expect(applyGroupMaintenanceEnd(s.review, s.io, () => {})).rejects.toThrow();
    });
});
