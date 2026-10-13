import { describe, expect, it, vi } from 'vitest';
import { APIError } from './api';
import { applyGroupMaintenance, reviewGroupMaintenance, validGroupMaintenanceView } from './fleet-group-maintenance-workflow';
import type { GroupMaintenanceIO, GroupMaintenanceStart, GroupMaintenanceView } from './fleet-group-maintenance-workflow';
import { groupMaintenanceFixture, maintenanceGroupId } from './fleet-group-maintenance-fixture';

const clone = <T,>(v: T): T => structuredClone(v);
function setup() {
    let view = groupMaintenanceFixture(), active = true;
    const bodies: GroupMaintenanceStart[] = [];
    const io: GroupMaintenanceIO = { active: () => active, get: vi.fn(async () => clone(view)), post: vi.fn(async body => { bodies.push(clone(body)); const row = view.members.flatMap(m => m.targets).find(t => t.key === body.key)!; row.revision++; row.changedAt = view.serverNow; row.windows = [{ id: row.revision, startedAt: view.serverNow, endsAt: body.endsAt, endedAt: null, intent: body.intent }]; return clone(view); }) };
    const review = reviewGroupMaintenance(clone(view), clone(view), view.members.map(m => m.deviceId), 'cpu', 'planned-work', 30, 0);
    return { io, bodies, review, get view() { return view; }, set view(next: GroupMaintenanceView) { view = next; }, stop: () => { active = false; } };
}
describe('bounded original-identity group maintenance', () => {
    it('uses a closed six-domain projection and never accepts guessed, duplicate or oversized members', () => {
        const v = groupMaintenanceFixture(); expect(validGroupMaintenanceView(v, maintenanceGroupId)).toBe(true);
        for (const patch of [{ secret: true }, { excludedLinuxMembers: 49 }, { authorityExpiresAt: '2099-01-01T00:00:00Z' }, { members: [...v.members, v.members[0]] }, { members: [{ ...v.members[0], targets: v.members[1].targets }] }]) expect(validGroupMaintenanceView({ ...v, ...patch }, maintenanceGroupId)).toBe(false);
    });
    it('freezes one absolute end, exact keys/revisions and a single-use review', async () => {
        const s = setup(), end = s.review.endsAt;
        // External mutation cannot expand or alter the private approved copy.
        s.review.endsAt = '2099-01-01T00:00:00Z'; s.review.members[0].target.key = 'f'.repeat(64);
        const rows = await applyGroupMaintenance(s.review, s.io, () => {});
        expect(rows.map(r => r.status)).toEqual(['started', 'started']); expect(s.bodies).toHaveLength(2);
        expect(s.bodies.every(b => b.endsAt === end && b.groupRevision === 2 && b.intent === 'planned-work' && b.revision === 0)).toBe(true);
        await expect(applyGroupMaintenance(s.review, s.io, () => {})).rejects.toThrow(/fresh review/); expect(s.bodies).toHaveLength(2);
    });
    it.each(['group', 'replacement', 'target', 'overlap', 'expiry'] as const)('rejects %s drift and never substitutes current authority', async drift => {
        const s = setup(), view = clone(s.view);
        if (drift === 'group') view.groupRevision++;
        if (drift === 'replacement') view.members[0].targets.forEach(t => { t.key = 'a'.repeat(63) + t.key.at(-1); });
        if (drift === 'target' || drift === 'overlap') { const t = view.members[0].targets[drift === 'overlap' ? 0 : 2]; t.revision = 1; t.changedAt = view.serverNow; t.windows = [{ id: 1, startedAt: view.serverNow, endsAt: s.review.endsAt, endedAt: null, intent: 'other' }]; }
        if (drift === 'expiry') { view.serverNow = view.authorityExpiresAt; view.authorityExpiresAt = new Date(Date.parse(view.serverNow) + 120000).toISOString().replace('.000Z', 'Z'); }
        s.view = view;
        const rows = await applyGroupMaintenance(s.review, s.io, () => {}); expect(rows.map(r => r.status)).toEqual(['conflict', 'not-attempted']); expect(s.bodies).toHaveLength(0);
    });
    it('retains earlier confirmed starts after conflict, then performs only readback', async () => {
        const s = setup(), post = s.io.post;
        s.io.post = vi.fn(async body => { if (s.bodies.length) throw new APIError('conflict', 409); return post(body); });
        const rows = await applyGroupMaintenance(s.review, s.io, () => {}); expect(rows.map(r => r.status)).toEqual(['started', 'conflict']); expect(s.io.post).toHaveBeenCalledTimes(2); expect(s.io.get).toHaveBeenCalledTimes(3);
    });
    it('preserves ambiguity after matching GET-only readback and stops the remaining sequence', async () => {
        const s = setup(), post = s.io.post;
        s.io.post = vi.fn(async body => { await post(body); throw new Error('response lost'); });
        const rows = await applyGroupMaintenance(s.review, s.io, () => {});
        expect(rows.map(r => r.status)).toEqual(['unconfirmed', 'not-attempted']); expect(rows[0].matchingAfterUnconfirmed).toBe(true); expect(s.io.post).toHaveBeenCalledTimes(1); expect(s.io.get).toHaveBeenCalledTimes(2);
    });
    it('Stop retains the first confirmed result, never posts later members and never silently rearms', async () => {
        const s = setup(); const rows = await applyGroupMaintenance(s.review, s.io, rows => { if (rows[0].status === 'started') s.stop(); });
        expect(rows.map(r => r.status)).toEqual(['started', 'not-attempted']); expect(s.bodies).toHaveLength(1);
        await expect(applyGroupMaintenance(s.review, s.io, () => {})).rejects.toThrow();
    });
    it('rejects a replaced target or changed group between draft and review', () => {
        const v = groupMaintenanceFixture(), changed = clone(v); changed.members[0].targets[0].key = 'f'.repeat(64);
        expect(() => reviewGroupMaintenance(v, changed, [v.members[0].deviceId], 'all', 'other', 30, 0)).toThrow();
        expect(() => reviewGroupMaintenance(v, { ...v, groupRevision: 3 }, [v.members[0].deviceId], 'all', 'other', 30, 0)).toThrow();
    });
});
