import { describe, expect, it, vi } from 'vitest';
import { APIError } from './api';
import { completeGroupServiceChoiceFixture, completeGroupServiceFixture } from './fleet-group-service-checks-complete-fixture';
import { applyGroupCompleteServiceChecks, groupCompleteServiceEvidenceAllowed, groupCompleteServiceSettingAllowed, reviewGroupCompleteServiceChecks, validGroupCompleteServiceChecksView, validGroupCompleteServiceChoiceView } from './fleet-group-service-checks-complete-workflow';
import type { GroupCompleteServiceBody, GroupCompleteServiceChecksIO, GroupCompleteServiceDraft } from './fleet-group-service-checks-complete-workflow';
const clone = <T,>(value: T): T => structuredClone(value);
function setup() {
    const view = completeGroupServiceFixture(), choice = completeGroupServiceChoiceFixture(), configured = completeGroupServiceChoiceFixture(true), source = choice.member.inventory!.source;
    let active = true;
    const bodies: GroupCompleteServiceBody[] = [];
    const io: GroupCompleteServiceChecksIO = { active: () => active, get: vi.fn(async () => clone(view)), choice: vi.fn(async () => clone(choice)), post: vi.fn(async (_key, body) => { bodies.push(clone(body)); choice.member.policy = { enabled: body.enabled, services: [...body.services], revision: body.expectedRevision + 1, ...(body.source ? { source: { kind: body.source.kind, grantId: body.source.grantId, grantRevision: body.source.grantRevision } } : choice.member.policy.source ? { source: clone(choice.member.policy.source) } : {}) }; choice.member.inventory = body.source ? clone(configured.member.inventory) : null; return clone(choice); }) };
    const drafts: GroupCompleteServiceDraft[] = [{ choice: clone(choice), desired: { enabled: true, services: [...configured.member.policy.services], source: clone(source) }, evidence: { source: clone(source), names: [...configured.member.policy.services] } }];
    return { view, choice, configured, source, io, drafts, bodies, stop: () => { active = false; }, review: () => reviewGroupCompleteServiceChecks(view, drafts, io) };
}
describe('Go-exported complete-generation exact group policy workflow', () => {
    it('accepts exact Go DTOs and rejects legacy, unknown, duplicate and unbound source data', () => {
        const s = setup(); expect(s.source.rowCount).toBeGreaterThan(128);
        expect(validGroupCompleteServiceChecksView(s.view, s.view.groupId)).toBe(true);
        expect(validGroupCompleteServiceChoiceView(s.choice, s.view.groupId, s.choice.member.key)).toBe(true);
        for (const patch of [{ schemaVersion: 'tracebolt.fleet-group-service-checks.v1' }, { unexpected: true }, { members: [s.view.members[0], s.view.members[0]] }, { groupRevision: -0 }, { authorityExpiresAt: s.view.serverNow }]) expect(validGroupCompleteServiceChecksView({ ...s.view, ...patch }, s.view.groupId)).toBe(false);
        for (const patch of [{ schemaVersion: 'tracebolt.fleet-group-service-choice.v1' }, { member: { ...s.choice.member, inventory: { ...s.choice.member.inventory, source: { ...s.source, generationId: `sample_${'f'.repeat(32)}` } } } }, { member: { ...s.choice.member, inventory: { ...s.choice.member.inventory, services: Array.from({ length: 9 }, () => s.configured.member.inventory!.services[0]) } } }]) expect(validGroupCompleteServiceChoiceView({ ...s.choice, ...patch }, s.view.groupId, s.choice.member.key)).toBe(false);
    });
    it('requires proven selected names from exactly one fresh current generation', async () => {
        const s = setup(); expect(groupCompleteServiceSettingAllowed(s.choice, s.drafts[0].desired)).toBe(true);
        expect(groupCompleteServiceSettingAllowed(s.choice, s.drafts[0].desired, 300001)).toBe(false);
        for (const evidence of [null, { source: s.source, names: [] }, { source: { ...s.source, manifestSha256: 'f'.repeat(64) }, names: s.drafts[0].desired.services }]) { s.drafts[0].evidence = evidence; await expect(s.review()).rejects.toThrow(); }
        expect(groupCompleteServiceSettingAllowed(s.choice, { ...s.drafts[0].desired, services: Array.from({ length: 9 }, (_, i) => `Service${i}`) })).toBe(false);
        expect(groupCompleteServiceEvidenceAllowed(s.choice, { ...s.drafts[0].desired, services: [s.configured.member.policy.services[0].toLowerCase()] }, { source: s.source, names: s.configured.member.policy.services })).toBe(false);
        expect(s.bodies).toHaveLength(0);
    });
    it('freezes reviewed member, source and names and sends the source-only closed POST exactly once', async () => {
        const s = setup(), review = await s.review(), desired = clone(s.drafts[0].desired);
        review.members[0].desired.services = ['Unreviewed']; review.members[0].desired.source!.grantRevision++; review.members[0].key = 'f'.repeat(64);
        const rows = await applyGroupCompleteServiceChecks(review, s.io, () => {});
        expect(rows[0].status).toBe('changed'); expect(s.bodies).toEqual([{ ...desired, groupRevision: s.view.groupRevision, expectedRevision: s.view.members.find(m => m.key === s.choice.member.key)!.policy.revision, consent: true }]);
        await expect(applyGroupCompleteServiceChecks(review, s.io, () => {})).rejects.toThrow(); expect(s.bodies).toHaveLength(1);
    });
    it.each(['generation', 'manifest', 'grant', 'key', 'name', 'revision', 'group', 'expiry'] as const)('stops before POST when reviewed %s changes', async change => {
        const s = setup(), review = await s.review();
        if (change === 'generation') s.choice.member.inventory!.source.generationId = `sample_${'f'.repeat(32)}`;
        if (change === 'manifest') s.choice.member.inventory!.source.manifestSha256 = 'f'.repeat(64);
        if (change === 'grant') s.choice.member.inventory!.source.grantRevision++;
        if (change === 'key') s.choice.member.key = 'f'.repeat(64);
        if (change === 'name') s.choice.member.name += ' replacement';
        if (change === 'revision') s.choice.member.policy.revision++;
        if (change === 'group') s.choice.groupRevision++;
        if (change === 'expiry') s.choice.serverNow = s.choice.authorityExpiresAt;
        const rows = await applyGroupCompleteServiceChecks(review, s.io, () => {}); expect(rows[0].status).toBe('conflict'); expect(s.bodies).toHaveLength(0);
    });
    it('permits retained-name removal and disable with null source but blocks additions/re-enable', () => {
        const s = setup(), d = clone(s.configured); d.member.inventory = null;
        expect(groupCompleteServiceSettingAllowed(d, { enabled: false, services: d.member.policy.services, source: null })).toBe(true);
        expect(groupCompleteServiceSettingAllowed(d, { enabled: false, services: [], source: null })).toBe(true);
        expect(groupCompleteServiceSettingAllowed(d, { enabled: false, services: ['Unreviewed'], source: null })).toBe(false);
        d.member.policy.enabled = false;
        expect(groupCompleteServiceSettingAllowed(d, { enabled: true, services: d.member.policy.services, source: null })).toBe(false);
        expect(groupCompleteServiceEvidenceAllowed(d, { enabled: true, services: d.member.policy.services, source: s.source }, null)).toBe(false);
    });
    it('does not retry uncertain writes and matching readback remains unconfirmed', async () => {
        const s = setup(), review = await s.review(), post = s.io.post;
        s.io.post = vi.fn(async (key, body) => { await post(key, body); throw new Error('response lost'); });
        const rows = await applyGroupCompleteServiceChecks(review, s.io, () => {}); expect(rows[0].status).toBe('unconfirmed'); expect(rows[0].matchingAfterUnconfirmed).toBe(true); expect(s.io.post).toHaveBeenCalledTimes(1);
    });
    it('does not retry conflicts or writes after Stop', async () => {
        const s = setup(), review = await s.review(); s.io.post = vi.fn(async () => { throw new APIError('conflict', 409); });
        expect((await applyGroupCompleteServiceChecks(review, s.io, () => {}))[0].status).toBe('conflict'); expect(s.io.post).toHaveBeenCalledTimes(1);
        const next = setup(), stopped = await next.review(); next.stop(); expect((await applyGroupCompleteServiceChecks(stopped, next.io, () => {}))[0].status).toBe('not-attempted'); expect(next.bodies).toHaveLength(0);
    });
});
