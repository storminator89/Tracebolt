import { describe, expect, it } from 'vitest';
import wire from '../../tests/fixtures/windows-maintenance-view.json';
import { windowsNow } from './windows-inventory-fixture';
import { windowsMaintenanceTarget, windowsMaintenanceView, windowsMaintenanceWindow } from './windows-maintenance-fixture';
import { validWindowsMaintenanceTime, validWindowsMaintenanceView, WINDOWS_MAINTENANCE_DOMAINS, windowsMaintenanceCanStart, windowsMaintenanceEndTime, windowsMaintenanceState } from './windows-maintenance-types';
import type { WindowsMaintenanceDomain, WindowsMaintenanceTarget, WindowsMaintenanceWindow } from './windows-maintenance-types';

function withWindows(domain: WindowsMaintenanceDomain, windows: WindowsMaintenanceWindow[], patch: Partial<WindowsMaintenanceTarget> = {}) {
    return windowsMaintenanceView(WINDOWS_MAINTENANCE_DOMAINS.map(value => windowsMaintenanceTarget(value, value === domain ? windows : [], value === domain ? patch : {})));
}
describe('bounded Windows maintenance metadata contract', () => {
    it('accepts actual Go-generated empty, active, ended and expired projections', () => {
        for (const view of Object.values(wire)) expect(validWindowsMaintenanceView(view)).toBe(true);
        const active = wire.active.targets.find(target => target.domain === 'disk')!;
        const ended = wire.ended.targets.find(target => target.domain === 'disk')!;
        const expired = wire.expired.targets.find(target => target.domain === 'disk')!;
        expect(active.key).toBe(ended.key); expect(active.key).toBe(expired.key);
        expect(active.revision).toBe(1); expect(ended.revision).toBe(2); expect(expired.revision).toBe(1);
        expect(ended.windows[0].endsAt).toBe(active.windows[0].endsAt);
        expect(expired.windows[0]).toEqual(active.windows[0]);
    });
    it('accepts empty fleet and exactly six ordered targets per identity', () => {
        expect(validWindowsMaintenanceView(windowsMaintenanceView([]))).toBe(true);
        expect(validWindowsMaintenanceView(windowsMaintenanceView())).toBe(true);
        expect(validWindowsMaintenanceView(withWindows('disk', [windowsMaintenanceWindow()]))).toBe(true);
    });
    it('accepts active, expired and early-ended records without changing their original end', () => {
        const window = windowsMaintenanceWindow();
        const ended = { ...window, endedAt: windowsNow };
        const expired = { ...window, startedAt: '2026-10-07T11:00:00Z', endsAt: '2026-10-07T11:30:00Z' };
        for (const value of [window, ended, expired]) expect(validWindowsMaintenanceView(withWindows('cpu', [value]))).toBe(true);
        expect(windowsMaintenanceState(window, windowsNow, 0)).toBe('active');
        expect(windowsMaintenanceState(window, windowsNow, 29 * 60000)).toBe('expired');
        expect(windowsMaintenanceState(ended, windowsNow, 86400000)).toBe('ended');
        expect(windowsMaintenanceState(expired, windowsNow, 0)).toBe('expired');
        expect(windowsMaintenanceState(window, windowsNow, Infinity)).toBe('unknown');
    });
    it('accepts latest-four ordered history with start-assigned IDs and end revisions', () => {
        const windows = [4, 3, 2, 1].map(id => windowsMaintenanceWindow({ id, startedAt: `2026-10-07T0${id}:00:00Z`, endsAt: `2026-10-07T0${id}:30:00Z` }));
        expect(validWindowsMaintenanceView(withWindows('service', windows))).toBe(true);
        expect(validWindowsMaintenanceView(withWindows('service', [...windows, { ...windows[3], id: 0 }]))).toBe(false);
        const endedOlder = windowsMaintenanceWindow({ id: 1, startedAt: '2026-10-07T10:00:00Z', endsAt: '2026-10-07T10:30:00Z', endedAt: '2026-10-07T10:15:00Z' });
        expect(validWindowsMaintenanceView(withWindows('disk', [windowsMaintenanceWindow({ id: 3 }), endedOlder]))).toBe(true);
        expect(validWindowsMaintenanceView(withWindows('disk', [windowsMaintenanceWindow({ id: 2 }), endedOlder]))).toBe(false);
    });
    it('rejects missing, duplicate, reordered and cross-device target sets', () => {
        const view = windowsMaintenanceView();
        const invalid = [view.targets.slice(1), [...view.targets].reverse(), view.targets.map((target, index) => index === 1 ? view.targets[0] : target), view.targets.map((target, index) => index === 1 ? { ...target, deviceId: `agent_${'8'.repeat(32)}` } : target), [...view.targets, ...view.targets]];
        for (const targets of invalid) expect(validWindowsMaintenanceView({ ...view, targets })).toBe(false);
    });
    it('rejects unknown health/action fields at every level', () => {
        const view = withWindows('disk', [windowsMaintenanceWindow()]);
        expect(validWindowsMaintenanceView({ ...view, suppressed: true })).toBe(false);
        expect(validWindowsMaintenanceView({ ...view, targets: view.targets.map(target => ({ ...target, healthy: true })) })).toBe(false);
        expect(validWindowsMaintenanceView(withWindows('disk', [{ ...windowsMaintenanceWindow(), command: 'forbidden' } as WindowsMaintenanceWindow]))).toBe(false);
    });
    it('rejects malformed target identity, revision and change floors', () => {
        const window = windowsMaintenanceWindow();
        for (const patch of [{ key: 'A'.repeat(64) }, { key: 'x' }, { deviceId: `agent_${'0'.repeat(32)}` }, { revision: 0 }, { revision: 2 }, { revision: Number.MAX_SAFE_INTEGER + 1 }, { changedAt: null }, { changedAt: '2099-01-01T00:00:00Z' }, { changedAt: windowsNow }]) expect(validWindowsMaintenanceView(withWindows('disk', [window], patch))).toBe(false);
        expect(validWindowsMaintenanceView(withWindows('disk', [], { revision: 1, changedAt: windowsNow }))).toBe(false);
        expect(validWindowsMaintenanceView(withWindows('disk', [], { changedAt: windowsNow }))).toBe(false);
    });
    it('enforces canonical UTC, precise duration bounds and irreversible early end', () => {
        expect(validWindowsMaintenanceTime('2026-10-07T12:00:00.123456789Z')).toBe(true);
        for (const time of ['2026-10-07T12:00:00.000Z', '2026-10-07T12:00:00.10Z', '2026-10-07T12:00:00+00:00', '2026-02-31T00:00:00Z']) expect(validWindowsMaintenanceTime(time)).toBe(false);
        const base = windowsMaintenanceWindow({ startedAt: '2026-10-07T12:00:00Z', endsAt: '2026-10-07T12:01:00Z' });
        expect(validWindowsMaintenanceView(withWindows('all', [base]))).toBe(true);
        expect(validWindowsMaintenanceView(withWindows('all', [{ ...base, endsAt: '2026-10-08T12:00:00Z' }]))).toBe(true);
        for (const patch of [{ endsAt: '2026-10-07T12:00:59.999999999Z' }, { endsAt: '2026-10-08T12:00:00.000000001Z' }, { startedAt: '2026-10-07T12:01:00Z' }, { endedAt: '2026-10-07T11:59:59Z' }, { endedAt: base.endsAt }, { endedAt: '2026-10-07T12:00:11Z' }, { intent: 'free text' }, { id: 0 }]) expect(validWindowsMaintenanceView(withWindows('all', [{ ...base, ...patch } as WindowsMaintenanceWindow]))).toBe(false);
    });
    it('rejects overlapping retained windows, while allowing exact end/start boundaries', () => {
        const latest = windowsMaintenanceWindow({ id: 2 }), older = windowsMaintenanceWindow();
        expect(validWindowsMaintenanceView(withWindows('disk', [latest, older]))).toBe(false);
        const boundary = { ...older, startedAt: '2026-10-07T11:00:00Z', endsAt: latest.startedAt };
        expect(validWindowsMaintenanceView(withWindows('disk', [latest, boundary]))).toBe(true);
    });
    it('blocks all/domain overlap without treating sibling domains as one scope', () => {
        const all = withWindows('all', [windowsMaintenanceWindow()]);
        expect(windowsMaintenanceCanStart(all, all.targets[3], 0)).toBe(false);
        const disk = withWindows('disk', [windowsMaintenanceWindow()]);
        expect(windowsMaintenanceCanStart(disk, disk.targets[0], 0)).toBe(false);
        expect(windowsMaintenanceCanStart(disk, disk.targets[2], 0)).toBe(true);
        expect(windowsMaintenanceCanStart(disk, disk.targets[3], 29 * 60000)).toBe(true);
        expect(validWindowsMaintenanceView({ ...all, targets: all.targets.map(target => target.domain === 'disk' ? windowsMaintenanceTarget('disk', [windowsMaintenanceWindow()]) : target) })).toBe(false);
    });
    it('uses manager time plus conservative elapsed only to make a bounded review', () => {
        expect(windowsMaintenanceEndTime(windowsNow, 123, 15)).toBe('2026-10-07T12:15:10.123Z');
        expect(windowsMaintenanceEndTime(windowsNow, 100, 30)).toBe('2026-10-07T12:30:10.1Z');
        expect(windowsMaintenanceEndTime(windowsNow, 0, 30)).toBe('2026-10-07T12:30:10Z');
        expect(windowsMaintenanceEndTime(windowsNow, 1500, 1440)).toBe('2026-10-08T12:00:10Z');
        for (const age of [-1, Infinity, 120000]) expect(windowsMaintenanceEndTime(windowsNow, age, 30)).toBeNull();
        expect(windowsMaintenanceEndTime(windowsNow, 0, 1)).toBeNull();
    });
});
