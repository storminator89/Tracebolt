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
    const review: GroupHealthReview = { group: structuredClone(view.groups[0]), settings: [{ metric: 'disk', enabled: true, thresholdPercent: 90 }], members: view.devices.map(d => ({ ...d, metric: 'disk', policy: { enabled: false, thresholdPercent: 90, revision: 0 } })) };
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
        const frozen = await reviewGroupHealth(view.groups[0], view, [ids[0]], review.settings, io);
        view.groups[0].memberIds.push(`agent_${'a'.repeat(32)}`); view.devices[0].name = 'New'; review.settings[0].thresholdPercent = 99;
        expect(frozen.members[0].name).toBe('Device 0'); expect(frozen.settings[0].thresholdPercent).toBe(90); expect(frozen.group!.memberIds).toHaveLength(3);
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
        const { view, io, review, get, post } = fixture(); review.settings[0].metric = 'cpu'; review.members[0].metric = 'cpu'; review.members = [review.members[0]]; review.members[0].policy = { enabled: true, thresholdPercent: 90, revision: 1 };
        get.mockResolvedValueOnce(view).mockResolvedValueOnce({ ...windowsResourceView('cpu', 'unknown'), deviceId: ids[0] });
        const result = await applyGroupHealth(review, io, () => {}); expect(result[0].status).toBe('currently-matching'); expect(post).not.toHaveBeenCalled();
    });
});

describe('bounded multi-policy monitoring selection', () => {
    function bundle() {
        const base = fixture();
        const states = new Map<string, { enabled: boolean; thresholdPercent: number; revision: number }>();
        const viewFor = (path: string) => {
            const id = path.split('/')[2], metric = path.includes('/cpu') ? 'cpu' : path.includes('/memory') ? 'memory' : 'disk';
            const state = states.get(`${id}:${metric}`) ?? { enabled: false, thresholdPercent: 90, revision: 0 };
            return { ...(metric === 'disk' ? windowsCapacityView(state.enabled ? 'unknown' : 'disabled') : windowsResourceView(metric, state.enabled ? 'unknown' : 'disabled')), deviceId: id, policy: { ...state } };
        };
        const get = vi.fn(async (path: string): Promise<unknown> => path.startsWith('/fleet') ? structuredClone(base.view) : viewFor(path));
        const post = vi.fn(async (path: string, body: unknown): Promise<unknown> => {
            const value = body as { enabled: boolean; thresholdPercent: number; expectedRevision: number };
            const id = path.split('/')[2], metric = path.includes('/cpu') ? 'cpu' : path.includes('/memory') ? 'memory' : 'disk';
            expect(value.expectedRevision).toBe(states.get(`${id}:${metric}`)?.revision ?? 0);
            states.set(`${id}:${metric}`, { enabled: value.enabled, thresholdPercent: value.thresholdPercent, revision: value.expectedRevision + 1 });
            return viewFor(path);
        });
        const io: GroupHealthIO = { get, post, active: () => true, accept: () => true };
        const settings: GroupHealthReview['settings'] = [{ metric: 'disk', enabled: true, thresholdPercent: 85 }, { metric: 'cpu', enabled: true, thresholdPercent: 95 }, { metric: 'memory', enabled: false, thresholdPercent: 80 }];
        return { ...base, get, post, io, settings, states };
    }
    it('applies independent enable/disable/threshold values in frozen device-policy order', async () => {
        const { view, settings, io, post } = bundle();
        const review = await reviewGroupHealth(view.groups[0], view, ids.slice(0, 2), settings, io);
        expect(post).not.toHaveBeenCalled(); expect(review.members).toHaveLength(6);
        const result = await applyGroupHealth(review, io, () => {});
        expect(result.map(r => r.status)).toEqual(Array(6).fill('changed'));
        expect(post.mock.calls.map(([path]) => path)).toEqual(ids.slice(0, 2).flatMap(id => [`/devices/${id}/windows-capacity/policy`, `/devices/${id}/windows-resource/cpu/policy`, `/devices/${id}/windows-resource/memory/policy`]));
        expect(post.mock.calls.map(([, body]) => body)).toEqual([...settings, ...settings].map(({ enabled, thresholdPercent }) => ({ enabled, thresholdPercent, expectedRevision: 0 })));
        await expect(applyGroupHealth(review, io, () => {})).rejects.toThrow('new review'); expect(post).toHaveBeenCalledTimes(6);
    });
    it('keeps earlier policy success after a sibling conflict and skips the remaining policies/devices', async () => {
        const { view, settings, io, post } = bundle();
        const review = await reviewGroupHealth(view.groups[0], view, ids.slice(0, 2), settings, io);
        const normal = post.getMockImplementation()!;
        post.mockImplementation(async (path, body) => path.includes('/cpu') ? Promise.reject(new APIError('changed', 409)) : normal(path, body));
        const result = await applyGroupHealth(review, io, () => {});
        expect(post).toHaveBeenCalledTimes(2); expect(result.map(r => r.status)).toEqual(['changed', 'conflict', 'not-attempted', 'not-attempted', 'not-attempted', 'not-attempted']);
    });
    it('keeps an uncertain sibling result unconfirmed and never retries it', async () => {
        const { view, settings, io, post } = bundle();
        const review = await reviewGroupHealth(null, view, ids.slice(0, 2), settings, io);
        const normal = post.getMockImplementation()!;
        post.mockImplementation(async (path, body) => { const response = await normal(path, body); if (path.includes('/cpu')) throw new Error('lost'); return response; });
        const result = await applyGroupHealth(review, io, () => {});
        expect(post).toHaveBeenCalledTimes(2); expect(result[0].status).toBe('changed'); expect(result[1]).toMatchObject({ status: 'unconfirmed', matchingAfterUnconfirmed: true }); expect(result.slice(2).every(r => r.status === 'not-attempted')).toBe(true);
    });
    it('can select ungrouped devices without creating a group or including newer devices', async () => {
        const { view, settings, io, get, post } = bundle(); view.groups = [];
        const review = await reviewGroupHealth(null, view, [ids[1]], [settings[1]], io);
        view.devices.push({ id: `agent_${'9'.repeat(32)}`, name: 'New arrival', platform: 'windows' });
        const result = await applyGroupHealth(review, io, () => {});
        expect(review.group).toBeNull(); expect(get.mock.calls.some(([path]) => path === '/fleet/groups')).toBe(true); expect(post).toHaveBeenCalledTimes(1); expect(result[0]).toMatchObject({ id: ids[1], metric: 'cpu', status: 'changed' });
    });
    it('rejects removed or renamed exact selections before any policy write', async () => {
        const { view, settings, io, post } = bundle();
        const review = await reviewGroupHealth(null, view, [ids[0]], settings, io); view.devices[0].name = 'Replacement';
        const result = await applyGroupHealth(review, io, () => {}); expect(post).not.toHaveBeenCalled(); expect(result.map(r => r.status)).toEqual(['conflict', 'not-attempted', 'not-attempted']);
    });
    it('freezes all input objects before the first asynchronous read', async () => {
        const { view, settings, io, get } = bundle(); const selected = [ids[0], ids[1]];
        const normal = get.getMockImplementation()!;
        get.mockImplementationOnce(async path => { settings[1].thresholdPercent = 99; view.devices[1].name = 'Changed during read'; view.groups[0].revision++; selected.reverse(); return normal(path); });
        const review = await reviewGroupHealth(view.groups[0], view, selected, settings, io);
        expect(review.settings[1].thresholdPercent).toBe(95); expect(review.group!.revision).toBe(2); expect(review.members.map(r => r.name)).toEqual(['Device 0', 'Device 0', 'Device 0', 'Device 1', 'Device 1', 'Device 1']);
    });
    it('rejects empty or duplicate policies and duplicate selections without any source reads', async () => {
        const { view, settings, io, get } = bundle();
        for (const invalid of [[], [settings[0], settings[0]], [{ ...settings[0], thresholdPercent: 100 }]]) await expect(reviewGroupHealth(null, view, [ids[0]], invalid, io)).rejects.toThrow('Invalid');
        await expect(reviewGroupHealth(null, view, [ids[0], ids[0]], settings, io)).rejects.toThrow('Invalid'); expect(get).not.toHaveBeenCalled();
    });
});

// Four isolated enrollment domains can each advertise 25 organizational devices.
describe('mixed-platform organizational projection bounds', () => {
 it('accepts 100 available devices including Macs without raising the 50-member cap', () => {
  const view = fixture().view; view.groups = []; view.devices = Array.from({length:100}, (_, i) => ({id:`agent_${(i+1).toString(16).padStart(32, '0')}`, name:`Fixture ${i}`, platform:i % 3 === 0 ? 'macos' : i % 3 === 1 ? 'linux' : 'windows'}));
  expect(validFleetGroupsView(view)).toBe(true); view.groups = [{id:`group_${'4'.repeat(32)}`, name:'Mixed', revision:1, memberIds:view.devices.slice(0,50).map(d=>d.id), unavailableMembers:0}]; expect(validFleetGroupsView(view)).toBe(true);
  view.groups[0].memberIds.push(view.devices[50].id); expect(validFleetGroupsView(view)).toBe(false); view.groups=[]; view.devices.push({id:`agent_${'f'.repeat(32)}`,name:'Over bound',platform:'macos'}); expect(validFleetGroupsView(view)).toBe(false);
 });
});
