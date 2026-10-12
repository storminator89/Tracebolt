import { describe, expect, it, vi } from 'vitest';
import { APIError } from './api';
import { applyGroupHealth, reviewGroupHealth } from './fleet-groups-workflow';
import type { GroupHealthIO, GroupHealthReview } from './fleet-groups-workflow';
import { validFleetGroupsView } from './fleet-groups-types';
import type { FleetGroupsView } from './fleet-groups-types';
import { windowsCapacityView } from './windows-capacity-fixture';
import { windowsResourceView } from './windows-resource-fixture';
const ids = ['1', '2', '3'].map(c => `agent_${c.repeat(32)}`);
function fixture() {
    const view: FleetGroupsView = { schemaVersion: 'tracebolt.fleet-groups.v1', serverNow: '2026-10-07T12:00:10Z', groups: [{ id: `group_${'4'.repeat(32)}`, name: 'Office', revision: 2, memberIds: [...ids], unavailableMembers: 0 }], devices: ids.map((id, i) => ({ id, name: `Device ${i}`, platform: 'windows' })) };
    const review: GroupHealthReview = { group: structuredClone(view.groups[0]), setting: { metric: 'disk', enabled: true, thresholdPercent: 90 }, members: view.devices.map(d => ({ ...d, policy: { enabled: false, thresholdPercent: 90, revision: 0 } })) };
    const policy = (id: string, enabled = false) => ({ ...windowsCapacityView(enabled ? 'unknown' : 'disabled'), deviceId: id });
    const get = vi.fn(async (path: string): Promise<unknown> => path.startsWith('/fleet') ? structuredClone(view) : policy(path.split('/')[2]));
    const post = vi.fn(async (path: string): Promise<unknown> => policy(path.split('/')[2], true));
    const io: GroupHealthIO = { get, post, active: () => true, accept: () => true };
    return { view, review, io, get, post, policy };
}
describe('manual group health workflow', () => {
    it('rejects excess or private projection fields and duplicate membership', () => {
        const { view } = fixture(); expect(validFleetGroupsView(view)).toBe(true);
        expect(validFleetGroupsView({ ...view, certificateHash: 'private' })).toBe(false);
        view.groups[0].memberIds.push(ids[0]); expect(validFleetGroupsView(view)).toBe(false);
    });
    it('freezes the reviewed exact IDs, names, settings and per-device revisions', async () => {
        const { view, io, review } = fixture();
        const frozen = await reviewGroupHealth(view.groups[0], view, [ids[0]], review.setting, io);
        view.groups[0].memberIds.push(`agent_${'a'.repeat(32)}`); view.devices[0].name = 'New'; review.setting.thresholdPercent = 99;
        expect(frozen.members[0].name).toBe('Device 0'); expect(frozen.setting.thresholdPercent).toBe(90); expect(frozen.group.memberIds).toHaveLength(3);
    });
    it('writes one metric sequentially to frozen members and never new members', async () => {
        const { review, io, post } = fixture();
        const result = await applyGroupHealth(review, io, () => {});
        expect(result.map(r => r.status)).toEqual(['changed', 'changed', 'changed']);
        expect(post.mock.calls.map(c => c[0])).toEqual(ids.map(id => `/devices/${id}/windows-capacity/policy`));
        expect(post.mock.calls.every(c => (c as unknown[])[1] && JSON.stringify((c as unknown[])[1]) === JSON.stringify({ enabled: true, thresholdPercent: 90, expectedRevision: 0 }))).toBe(true);
    });
    it('rejects changed group revision before any policy write', async () => {
        const { review, view, io, post } = fixture(); view.groups[0].revision++;
        const result = await applyGroupHealth(review, io, () => {}); expect(post).not.toHaveBeenCalled(); expect(result.map(r => r.status)).toEqual(['conflict', 'not-attempted', 'not-attempted']);
    });
    it('stops after optimistic conflict without trying remaining devices', async () => {
        const { review, io, post } = fixture(); post.mockRejectedValueOnce(new APIError('changed', 409));
        const result = await applyGroupHealth(review, io, () => {}); expect(post).toHaveBeenCalledTimes(1); expect(result.map(r => r.status)).toEqual(['conflict', 'not-attempted', 'not-attempted']);
    });
    it('reconciles an uncertain POST read-only without attributing another writer', async () => {
        const { review, view, io, post, get, policy } = fixture(); post.mockRejectedValueOnce(new APIError('uncertain', 503));
        get.mockResolvedValueOnce(view).mockResolvedValueOnce(policy(ids[0])).mockResolvedValueOnce(policy(ids[0], true));
        const result = await applyGroupHealth(review, io, () => {}); expect(post).toHaveBeenCalledTimes(1); expect(result[0].status).toBe('unconfirmed'); expect(result[0].matchingAfterUnconfirmed).toBe(true); expect(result[1].status).toBe('not-attempted');
    });
    it('cancellation after an in-flight POST never proceeds to the next member', async () => {
        const { review, io, post, policy } = fixture(); let active = true; io.active = () => active;
        post.mockImplementationOnce(async () => { active = false; return policy(ids[0], true); });
        const result = await applyGroupHealth(review, io, () => {}); expect(post).toHaveBeenCalledTimes(1); expect(result.map(r => r.status)).toEqual(['unconfirmed', 'not-attempted', 'not-attempted']);
    });
    it('leaves currently matching members unchanged and respects metric binding', async () => {
        const { view, io, review, get, post } = fixture(); review.setting.metric = 'cpu'; review.members = [review.members[0]]; review.members[0].policy = { enabled: true, thresholdPercent: 90, revision: 1 };
        get.mockResolvedValueOnce(view).mockResolvedValueOnce({ ...windowsResourceView('cpu', 'unknown'), deviceId: ids[0] });
        const result = await applyGroupHealth(review, io, () => {}); expect(result[0].status).toBe('currently-matching'); expect(post).not.toHaveBeenCalled();
    });
});
