import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { setLocale } from './i18n';
import { scheduledMaintenanceOverviewRows, WindowsMaintenanceScheduleOverview } from './windows-maintenance-schedule-overview';
import type { WindowsMaintenanceScheduleView } from './windows-maintenance-schedule-types';
import goFixture from '../../tests/fixtures/windows-maintenance-schedule-view.json';

const fixture = (kind: keyof typeof goFixture): WindowsMaintenanceScheduleView => structuredClone(goFixture[kind]) as WindowsMaintenanceScheduleView;
beforeEach(() => setLocale('en', false));
afterEach(cleanup);
it.each(['empty', 'cancelled', 'ended', 'expired'] as const)('excludes %s from current and upcoming windows', kind => {
    expect(scheduledMaintenanceOverviewRows(fixture(kind), 0)).toEqual([]);
});
it.each(['pending', 'active'] as const)('preserves the actual Go %s projection without changing original evidence', kind => {
    const view = fixture(kind), original = structuredClone(view), rows = scheduledMaintenanceOverviewRows(view, 0);
    expect(rows).toHaveLength(1);
    expect(rows[0].state).toBe(kind);
    expect(rows[0].target).toBe(view.targets[0]);
    expect(rows[0].window).toBe(view.targets[0].windows[0]);
    expect(view).toEqual(original);
});
it('requires a fresh manager read when browser elapsed time crosses a pending start', () => {
    const view = fixture('pending'); view.serverNow = '2026-10-07T12:59:00Z';
    expect(scheduledMaintenanceOverviewRows(view, 59999)[0].state).toBe('pending');
    expect(scheduledMaintenanceOverviewRows(view, 60000)[0].state).toBe('unknown');
    expect(scheduledMaintenanceOverviewRows(fixture('active'), 0)[0].state).toBe('active');
});
it('removes an expired active window without inventing recovery', () => {
    const view = fixture('active'); view.serverNow = '2026-10-07T13:59:00Z';
    expect(scheduledMaintenanceOverviewRows(view, 59999)[0].state).toBe('active');
    expect(scheduledMaintenanceOverviewRows(view, 60000)).toEqual([]);
});
it('orders next transitions exactly, preserving independent identities and nanosecond starts', () => {
    const view = fixture('pending'), target = view.targets[0], window = target.windows[0];
    view.serverNow = '2026-10-07T13:00:00Z';
    view.targets = [
        { ...target, key: 'c'.repeat(64), windows: [{ ...window, startsAt: '2026-10-07T13:00:10.000000002Z' }] },
        { ...target, key: 'b'.repeat(64), windows: [{ ...window, startsAt: '2026-10-07T13:00:10.000000001Z' }] },
        { ...target, key: 'd'.repeat(64), windows: [{ ...window, startsAt: '2026-10-07T13:00:01Z' }] },
        { ...target, key: 'a'.repeat(64) },
    ];
    expect(scheduledMaintenanceOverviewRows(view, 1000).map(row => row.target.key[0])).toEqual(['d', 'a', 'b', 'c']);
    expect(scheduledMaintenanceOverviewRows(view, 1000).map(row => row.state)).toEqual(['unknown', 'active', 'pending', 'pending']);
});
it('uses only the latest window of each target, not old pending-looking history', () => {
    const view = fixture('ended'); view.targets[0].windows.push(fixture('pending').targets[0].windows[0]);
    expect(scheduledMaintenanceOverviewRows(view, 0)).toEqual([]);
});
it('shows bounded identity-qualified rows and original local time fields without actions', () => {
    const view = fixture('pending'), onSelect = vi.fn();
    render(<WindowsMaintenanceScheduleOverview view={view} age={0} label={() => '<script>same name</script>'} isUncertain={() => false} disabled={false} onSelect={onSelect}/>);
    const region = screen.getByRole('region', { name: 'Upcoming and active schedules' });
    expect(within(region).getByText('Upcoming: 1')).toBeVisible();
    expect(within(region).getByText('Active: 0')).toBeVisible();
    expect(within(region).getByText(view.targets[0].deviceId)).toBeVisible();
    expect(within(region).getByText('<script>same name</script>')).toBeVisible();
    expect(region.querySelector('script')).toBeNull();
    const times = [...region.querySelectorAll('time')].map(node => node.getAttribute('datetime'));
    expect(times).toEqual([view.serverNow, view.targets[0].windows[0].startsAt, view.targets[0].windows[0].endsAt]);
    expect(within(region).queryByRole('checkbox')).toBeNull();
    fireEvent.click(within(region).getByRole('button', { name: /^View window:/ }));
    expect(onSelect).toHaveBeenCalledExactlyOnceWith(view.targets[0].key);
});
it('keeps uncertainty explicit and disables selection during the existing write', () => {
    const onSelect = vi.fn();
    render(<WindowsMaintenanceScheduleOverview view={fixture('active')} age={0} label={() => 'Desk'} isUncertain={() => true} disabled onSelect={onSelect}/>);
    expect(screen.getByText(/A change is unconfirmed/)).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: /^View window:/ }));
    expect(onSelect).not.toHaveBeenCalled();
});
it('labels a crossed start neutrally in German', () => {
    setLocale('de', false);
    const view = fixture('pending'); view.serverNow = '2026-10-07T12:59:00Z';
    render(<WindowsMaintenanceScheduleOverview view={view} age={60000} label={() => 'Rechner'} isUncertain={() => false} disabled={false} onSelect={vi.fn()}/>);
    expect(screen.getByText('Status aktualisieren: 1')).toBeVisible();
    expect(screen.getByText('Aktiv: 0')).toBeVisible();
    expect(screen.getByRole('button', { name: /^Fenster ansehen:/ })).toBeVisible();
    expect(screen.getByText(/Ein geplanter Start ist seit diesem Abruf verstrichen/)).toBeVisible();
});
