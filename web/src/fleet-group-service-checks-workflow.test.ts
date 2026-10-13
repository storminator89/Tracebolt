import { describe, expect, it, vi } from 'vitest';
import { APIError } from './api';
import { applyGroupServiceChecks, groupServiceChoices, groupServiceSettingAllowed, reviewGroupServiceChecks, validGroupServiceChecksView, validGroupServiceChoiceView } from './fleet-group-service-checks-workflow';
import type { GroupServiceBody, GroupServiceChecksIO, GroupServiceChoiceView, GroupServiceDraft } from './fleet-group-service-checks-workflow';
import { groupServiceChecksFixture, groupServiceChoiceFixture, serviceChecksGroupId } from './fleet-group-service-checks-fixture';
const clone = <T,>(v: T): T => structuredClone(v);
function setup() {
    const view = groupServiceChecksFixture(), choices = new Map(view.members.map(m => [m.key, groupServiceChoiceFixture(view, m.key)])); let active = true;
    const bodies: { key: string; body: GroupServiceBody }[] = [];
    const io: GroupServiceChecksIO = { active: () => active, get: vi.fn(async () => clone(view)), choice: vi.fn(async key => clone(choices.get(key)!)), post: vi.fn(async (key, body) => { bodies.push({ key, body: clone(body) }); const value = choices.get(key)!; value.member.policy = { enabled: body.enabled, services: [...body.services], revision: body.expectedRevision + 1 }; return clone(value); }) };
    const drafts: GroupServiceDraft[] = [...choices.values()].map(choice => ({ choice: clone(choice), desired: { enabled: true, services: ['Spooler', 'spooler'] } }));
    return { view, choices, io, drafts, bodies, stop: () => { active = false; }, review: () => reviewGroupServiceChecks(view, drafts, io) };
}
describe('closed original-identity group service checks', () => {
    it('rejects cross-scope, extra, duplicate, oversized, invalid-policy and expired data', () => {
        const v = groupServiceChecksFixture(); expect(validGroupServiceChecksView(v, serviceChecksGroupId)).toBe(true);
        for (const patch of [{ secret: true }, { groupId: `group_${'0'.repeat(32)}` }, { groupRevision: -0 }, { excludedLinuxMembers: 49 }, { authorityExpiresAt: '2099-01-01T00:00:00Z' }, { authorityExpiresAt: v.serverNow }, { members: [...v.members, v.members[0]] }, { members: Array.from({ length: 26 }, () => v.members[0]) }, { members: [{ ...v.members[0], key: '0'.repeat(64) }] }, { members: [{ ...v.members[0], policy: { enabled: true, revision: 0, services: ['Spooler'] } }] }]) expect(validGroupServiceChecksView({ ...v, ...patch }, serviceChecksGroupId)).toBe(false);
        const d = groupServiceChoiceFixture(v); expect(validGroupServiceChoiceView(d, v.groupId, d.member.key)).toBe(true);
        for (const patch of [{ secret: true }, { member: { ...d.member, pid: 4 } }, { member: { ...d.member, inventory: undefined } }, { member: { ...d.member, inventory: { ...d.member.inventory!, services: [...d.member.inventory!.services, d.member.inventory!.services[0]] } } }, { member: { ...d.member, inventory: { ...d.member.inventory!, collectedAt: '2026-10-07T11:58:09Z' } } }, { member: { ...d.member, policy: { enabled: false, services: ['spooler', 'Spooler'], revision: 1 } } }]) expect(validGroupServiceChoiceView({ ...d, ...patch }, v.groupId, d.member.key)).toBe(false);
    });
    it('retains exact case and supports removal/disable with unknown inventory but never newly added or re-enabled names', () => {
        const d = groupServiceChoiceFixture(groupServiceChecksFixture()); d.member.inventory = null; d.member.policy = { enabled: true, revision: 2, services: ['Spooler', 'spooler'] };
        expect(groupServiceSettingAllowed(d, { enabled: false, services: ['Spooler'] })).toBe(true);
        expect(groupServiceSettingAllowed(d, { enabled: true, services: ['Spooler'] })).toBe(true);
        expect(groupServiceSettingAllowed(d, { enabled: false, services: ['SPOOLER'] })).toBe(false);
        d.member.policy.enabled = false;
        expect(groupServiceSettingAllowed(d, { enabled: true, services: ['Spooler'] })).toBe(false);
        expect(groupServiceSettingAllowed(d, { enabled: false, services: [] })).toBe(true);
        d.member.inventory = groupServiceChoiceFixture(groupServiceChecksFixture()).member.inventory;
        expect(groupServiceChoices(d, 110001)).toEqual([]); expect(groupServiceSettingAllowed(d, { enabled: true, services: ['Spooler'] }, 110001)).toBe(false);
        expect(groupServiceSettingAllowed(d, { enabled: true, services: ['Spooler'] }, 0)).toBe(true);
    });
    it('freezes desired names, policies and exact targets independently of rendered-review mutation and consumes once', async () => {
        const s = setup(), review = await s.review(); review.members[0].key = 'f'.repeat(64); review.members[0].desired.services = ['evil']; review.members[0].policy.revision = 55; s.drafts[1].desired.enabled = false;
        const rows = await applyGroupServiceChecks(review, s.io, () => {}); expect(rows.map(r => r.status)).toEqual(['changed', 'changed']);
        expect(s.bodies[0]).toEqual({ key: s.view.members[0].key, body: { groupRevision: 2, expectedRevision: 0, enabled: true, services: ['Spooler', 'spooler'], consent: true } });
        expect(s.bodies[1].body.enabled).toBe(true); await expect(applyGroupServiceChecks(review, s.io, () => {})).rejects.toThrow(/fresh service review/); expect(s.bodies).toHaveLength(2);
    });
    it.each(['group', 'key', 'name', 'device', 'revision', 'policy', 'inventory', 'expiry'] as const)('stops before any POST after %s changes', async drift => {
        const s = setup(), review = await s.review(), d = s.choices.values().next().value as GroupServiceChoiceView;
        if (drift === 'group') d.groupRevision++;
        if (drift === 'key') d.member.key = 'f'.repeat(64);
        if (drift === 'name') d.member.name += ' replaced';
        if (drift === 'device') d.member.deviceId = `agent_${'f'.repeat(32)}`;
        if (drift === 'revision') d.member.policy.revision++;
        if (drift === 'policy') d.member.policy.services = ['FixtureService'];
        if (drift === 'inventory') d.member.inventory = null;
        if (drift === 'expiry') { d.serverNow = d.authorityExpiresAt; d.authorityExpiresAt = '2026-10-07T12:04:10Z'; d.member.inventory = null; }
        const rows = await applyGroupServiceChecks(review, s.io, () => {}); expect(rows.map(r => r.status)).toEqual(['conflict', 'not-attempted']); expect(s.bodies).toHaveLength(0);
    });
    it('reports currently matching without POST and preserves independent per-device desired policies', async () => {
        const s = setup(); s.drafts[0].desired = { enabled: false, services: [] }; const rows = await applyGroupServiceChecks(await s.review(), s.io, () => {});
        expect(rows.map(r => r.status)).toEqual(['currently-matching', 'changed']); expect(s.bodies).toHaveLength(1); expect(s.bodies[0].key).toBe(s.view.members[1].key);
    });
    it('keeps a lost response unconfirmed after matching GET-only readback, without trying the next member', async () => {
        const s = setup(), review = await s.review(), post = s.io.post; s.io.post = vi.fn(async (key, body) => { await post(key, body); throw new Error('response lost'); });
        const rows = await applyGroupServiceChecks(review, s.io, () => {}); expect(rows.map(r => r.status)).toEqual(['unconfirmed', 'not-attempted']); expect(rows[0].matchingAfterUnconfirmed).toBe(true); expect(s.io.post).toHaveBeenCalledTimes(1); expect(s.io.choice).toHaveBeenCalledTimes(4);
    });
    it('retains prior confirmed changes after conflict, reads back once and never retries', async () => {
        const s = setup(), review = await s.review(), post = s.io.post; s.io.post = vi.fn(async (key, body) => { if (s.bodies.length) throw new APIError('conflict', 409); return post(key, body); });
        const rows = await applyGroupServiceChecks(review, s.io, () => {}); expect(rows.map(r => r.status)).toEqual(['changed', 'conflict']); expect(s.io.post).toHaveBeenCalledTimes(2); expect(s.io.choice).toHaveBeenCalledTimes(5);
    });
    it('retains outcomes after Stop and never rearms the used review', async () => {
        const s = setup(), review = await s.review(); const rows = await applyGroupServiceChecks(review, s.io, rows => { if (rows[0].status === 'changed') s.stop(); });
        expect(rows.map(r => r.status)).toEqual(['changed', 'not-attempted']); expect(s.bodies).toHaveLength(1); await expect(applyGroupServiceChecks(review, s.io, () => {})).rejects.toThrow();
    });
    it('rejects unreviewed, duplicated and changed selections without writes', async () => {
        const s = setup(); s.drafts.push(s.drafts[0]); await expect(s.review()).rejects.toThrow(); s.drafts.pop(); s.choices.get(s.view.members[0].key)!.member.policy.revision++;
        await expect(s.review()).rejects.toThrow(); await expect(applyGroupServiceChecks({ ...s.view, members: [] }, s.io, () => {})).rejects.toThrow(); expect(s.bodies).toHaveLength(0);
    });
});
