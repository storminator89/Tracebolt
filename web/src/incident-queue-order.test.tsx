import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import healthWire from './health-go-fixture.json';
import windowsWire from '../../tests/fixtures/windows-incident-inbox-view.json';
import type { HealthView } from './health-types';
import { ageInvestigations, validInvestigationsView } from './investigations-types';
import type { InvestigationsView } from './investigations-types';
import type { InvestigationsResource } from './investigations-resource';
import { completeIncidentFixture } from './windows-complete-incident-inbox-fixture';
import type { WindowsInboxView } from './windows-complete-incident-inbox-types';
import { validWindowsIncidentInboxView } from './windows-incident-inbox-types';
import { filterIncidentQueue, incidentQueueRows, orderIncidentQueue } from './incident-work-queue-model';
import type { QueueRow } from './incident-work-queue-model';
import { incidentLifecycle } from './incident-timeline-model';
import { IncidentWorkQueue } from './incident-work-queue';
import { setLocale } from './i18n';
import { useWindowsIncidentInbox } from './windows-incident-inbox-resource';
import { mutate, request } from './api';

vi.mock('./windows-incident-inbox-resource', () => ({ useWindowsIncidentInbox: vi.fn() }));
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), mutate: vi.fn(), request: vi.fn() }));
function linuxFixture(): InvestigationsView {
    const health = structuredClone(healthWire) as HealthView;
    const view: InvestigationsView = { schemaVersion: 'tracebolt.investigations.v1', serverNow: health.serverNow, scope: 'all', offset: 0, total: health.incidents.length, counts: { open: health.incidents.length, recovered: 0, closed: 0, all: health.incidents.length }, items: health.incidents.map(incident => ({ deviceId: health.deviceId, incident })), devices: [{ ...health, incidents: [] }] };
    if (!validInvestigationsView(view, 'all', 0)) throw new Error('Invalid Linux fixture');
    return view;
}
function windowsFixture(): WindowsInboxView {
    const view = structuredClone(windowsWire.active);
    if (!validWindowsIncidentInboxView(view, 'active', 'all', 0)) throw new Error('Invalid Windows fixture');
    return view;
}
function resource(view: InvestigationsView | null): InvestigationsResource { return { view, counts: view?.counts ?? null, readiness: 'unknown', pending: false, failure: null, locked: false, refresh: vi.fn() }; }
function props() { return { devices: [], sessionKey: 'session-a', linux: resource(linuxFixture()), scope: 'all' as const, onScope: vi.fn(), linuxOffset: 0, onLinuxPage: vi.fn() }; }
let windows: ReturnType<typeof useWindowsIncidentInbox>;
beforeEach(() => {
    setLocale('en', false);
    windows = { view: windowsFixture(), age: 0, loading: false, writing: false, error: false, notice: null, refresh: vi.fn(), acknowledge: vi.fn(), isUncertain: () => false };
    vi.mocked(useWindowsIncidentInbox).mockImplementation(() => windows);
    vi.mocked(request).mockReset(); vi.mocked(mutate).mockReset();
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });
const order = () => screen.getByRole('combobox', { name: 'Order loaded incidents' });
const changeOrder = (value: string) => fireEvent.change(order(), { target: { value } });
const choices = () => screen.getAllByRole('checkbox', { name: /^Compare episode:/ });
const choiceNames = () => choices().map(element => element.getAttribute('aria-label'));
function row(identity: string, openedAt: string, seenAt: string | null = null): QueueRow { return { ...incidentQueueRows(linuxFixture(), null)[0], identity, openedAt, seenAt }; }

describe('bounded incident order model', () => {
    it('orders distinct UTC fractional openings without millisecond rounding or source mutation', () => {
        const rows = [row('later', '2026-10-05T00:02:00.000000900Z'), row('whole', '2026-10-05T00:02:00Z'), row('earlier', '2026-10-05T00:02:00.000000001Z')];
        const before = JSON.stringify(rows);
        expect(orderIncidentQueue(rows, 'oldest').map(value => value.identity)).toEqual(['whole', 'earlier', 'later']);
        expect(orderIncidentQueue(rows, 'newest').map(value => value.identity)).toEqual(['later', 'earlier', 'whole']);
        expect(JSON.stringify(rows)).toBe(before);
        expect(orderIncidentQueue(rows, 'newest')[0]).toBe(rows[0]);
    });
    it('retains every equal opening with source-qualified stable ties in either direction', () => {
        const rows = [row('source-z', '2026-10-05T00:02:00.1Z'), row('source-a', '2026-10-05T00:02:00.100000000Z'), row('source-m', '2026-10-05T00:02:00.100Z')];
        for (const mode of ['newest', 'oldest', 'unseen-oldest'] as const) {
            expect(orderIncidentQueue(rows, mode).map(value => value.identity)).toEqual(['source-a', 'source-m', 'source-z']);
            expect(orderIncidentQueue([...rows].reverse(), mode).map(value => value.identity)).toEqual(['source-a', 'source-m', 'source-z']);
        }
    });
    it('places unseen first and orders oldest within both seen categories without changing outcomes', () => {
        const rows = [row('seen-old', '2026-10-04T00:02:00Z', '2026-10-05T00:02:00Z'), row('unseen-new', '2026-10-05T00:02:00Z'), row('seen-new', '2026-10-06T00:02:00Z', '2026-10-07T00:02:00Z'), row('unseen-old', '2026-10-04T00:02:00Z')];
        const before = rows.map(incidentLifecycle);
        expect(orderIncidentQueue(rows, 'unseen-oldest').map(value => value.identity)).toEqual(['unseen-old', 'unseen-new', 'seen-old', 'seen-new']);
        expect(rows.map(incidentLifecycle)).toEqual(before);
        expect(orderIncidentQueue(rows, 'unseen-oldest').every(value => incidentLifecycle(value) === 'open')).toBe(true);
    });
    it('preserves real source/domain collisions, totals and current-evidence aging', () => {
        const linux = linuxFixture(), windows = windowsFixture(), complete = completeIncidentFixture('active');
        const before = JSON.stringify({ linux, windows, complete });
        const rows = [...incidentQueueRows(linux, windows), ...incidentQueueRows(null, complete)];
        for (const mode of ['newest', 'oldest', 'unseen-oldest'] as const) {
            const sorted = orderIncidentQueue(rows, mode);
            expect(new Set(sorted.map(value => value.identity)).size).toBe(rows.length);
            expect(sorted).toHaveLength(rows.length);
            expect(sorted.filter(value => value.platform === 'windows' && value.item.incidentId === 'wcapacity_0000000000000001')).toHaveLength(3);
        }
        expect(orderIncidentQueue(incidentQueueRows(ageInvestigations(linux, 121000), null), 'oldest').map(value => value.item)).toEqual(incidentQueueRows(linux, null).map(value => value.item));
        expect(JSON.stringify({ linux, windows, complete })).toBe(before);
    });
    it('orders filtered and partial pages without recovering or silently excluding closed episodes', () => {
        const linux = linuxFixture();
        linux.items[0].incident.resolvedAt = linux.serverNow; linux.items[0].incident.closedReason = 'monitoring_stopped';
        const rows = incidentQueueRows(linux, windowsFixture());
        const stopped = filterIncidentQueue(rows, 'all', 'all', 'all', 'stopped');
        expect(orderIncidentQueue(stopped, 'unseen-oldest')).toHaveLength(1);
        expect(incidentLifecycle(orderIncidentQueue(stopped, 'oldest')[0])).toBe('stopped');
        expect(orderIncidentQueue(rows, 'oldest')).toHaveLength(rows.length);
        expect(orderIncidentQueue(incidentQueueRows(null, null), 'oldest')).toEqual([]);
    });
});

describe('incident queue ordering workflow', () => {
    it('defaults newest, changes repeatedly and keeps native labeled control and decorative icon accessible', () => {
        render(<IncidentWorkQueue {...props()}/>);
        expect(order()).toHaveValue('newest');
        const names = choiceNames();
        changeOrder('oldest'); expect(choiceNames()[0]).toMatch(/^Compare episode: Linux Health/);
        changeOrder('unseen-oldest'); expect(choiceNames()).toHaveLength(names.length);
        changeOrder('newest'); expect(choiceNames()).toEqual(names);
        const icon = order().closest('label')!.querySelector('svg');
        expect(icon).toHaveAttribute('aria-hidden', 'true'); expect(icon).toHaveAttribute('focusable', 'false');
        expect(screen.getByText(/Loaded pages only. Opening order does not measure uninterrupted downtime/)).toBeInTheDocument();
    });
    it('keeps exact comparison choices and expanded timeline attached to their episode through reordering', () => {
        render(<IncidentWorkQueue {...props()}/>);
        const selected = choices().slice(0, 2).map(element => element.getAttribute('aria-label')!);
        for (const name of selected) fireEvent.click(screen.getByRole('checkbox', { name }));
        fireEvent.click(screen.getByRole('button', { name: 'Open comparison' }));
        const originalRow = screen.getByRole('checkbox', { name: selected[0] }).closest('li')!;
        fireEvent.click(within(originalRow).getByText('Incident timeline'));
        const timeline = originalRow.querySelector('details.incident-timeline')!;
        expect(timeline).toHaveAttribute('open');
        const originalText = timeline.textContent;
        for (const value of ['oldest', 'unseen-oldest', 'newest']) {
            changeOrder(value);
            for (const name of selected) expect(screen.getByRole('checkbox', { name })).toBeChecked();
            expect(screen.getByRole('button', { name: 'Close comparison' })).toBeInTheDocument();
            expect(screen.getByRole('checkbox', { name: selected[0] }).closest('li')!.querySelector('details.incident-timeline')).toBe(timeline);
            expect(timeline).toHaveAttribute('open'); expect(timeline.textContent).toBe(originalText);
        }
    });
    it('composes with literal filters and clearing without changing source scope, paging, counts or order', () => {
        const p = props(); render(<IncidentWorkQueue {...p}/>);
        const counts = [...document.querySelectorAll('.incident-queue-source')].map(element => element.textContent);
        changeOrder('oldest');
        fireEvent.change(screen.getByRole('combobox', { name: 'Platform on loaded pages' }), { target: { value: 'windows' } });
        expect(choiceNames().every(name => name!.includes('Windows'))).toBe(true);
        fireEvent.change(screen.getByRole('searchbox', { name: 'Search loaded incidents' }), { target: { value: 'not-[a-regex]' } });
        expect(screen.queryByRole('checkbox', { name: /^Compare episode:/ })).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Clear page filters' }));
        expect(order()).toHaveValue('oldest'); expect(choiceNames()[0]).toMatch(/Linux Health/);
        expect([...document.querySelectorAll('.incident-queue-source')].map(element => element.textContent)).toEqual(counts);
        expect(p.onScope).not.toHaveBeenCalled(); expect(p.onLinuxPage).not.toHaveBeenCalled();
    });
    it('never reads, writes, acknowledges, persists or starts a timer from ordering interactions', () => {
        const p = props(); render(<IncidentWorkQueue {...p}/>);
        const reads = vi.mocked(useWindowsIncidentInbox).mock.calls.map(call => JSON.stringify(call));
        const storage = vi.spyOn(Storage.prototype, 'setItem'), timer = vi.spyOn(window, 'setInterval');
        for (const value of ['oldest', 'unseen-oldest', 'newest']) changeOrder(value);
        expect(request).not.toHaveBeenCalled(); expect(mutate).not.toHaveBeenCalled();
        expect(windows.acknowledge).not.toHaveBeenCalled(); expect(windows.refresh).not.toHaveBeenCalled(); expect(p.linux.refresh).not.toHaveBeenCalled();
        expect(storage).not.toHaveBeenCalled(); expect(timer).not.toHaveBeenCalled();
        expect(new Set(vi.mocked(useWindowsIncidentInbox).mock.calls.map(call => JSON.stringify(call)))).toEqual(new Set(reads));
    });
    it('keeps partial-source warnings and removes lost-source rows and exact choices without resurrection', () => {
        const p = props(); const { rerender } = render(<IncidentWorkQueue {...p}/>);
        const selected = screen.getByRole('checkbox', { name: /^Compare episode: Linux Health/ }).getAttribute('aria-label')!;
        fireEvent.click(screen.getByRole('checkbox', { name: selected })); changeOrder('oldest');
        const saved = p.linux.view; p.linux = resource(null); rerender(<IncidentWorkQueue {...p}/>);
        expect(screen.queryByRole('checkbox', { name: selected })).not.toBeInTheDocument();
        expect(screen.getByText(/Source coverage is incomplete/)).toBeInTheDocument();
        changeOrder('unseen-oldest'); p.linux = resource(saved); rerender(<IncidentWorkQueue {...p}/>);
        expect(screen.getByRole('checkbox', { name: selected })).not.toBeChecked();
        windows = { ...windows, view: null, error: true }; p.linux = resource(null); rerender(<IncidentWorkQueue {...p}/>);
        expect(screen.queryByRole('checkbox', { name: /^Compare episode:/ })).not.toBeInTheDocument();
        expect(screen.getByText(/Missing source rows and totals remain unknown/)).toBeInTheDocument();
    });
    it('retains the local order on refresh and paging but restores default after queue remount', () => {
        const p = props(); const { unmount } = render(<IncidentWorkQueue {...p}/>);
        changeOrder('oldest'); fireEvent.click(screen.getByRole('button', { name: 'Refresh work queue' }));
        expect(order()).toHaveValue('oldest'); expect(p.linux.refresh).toHaveBeenCalledTimes(1); expect(windows.refresh).toHaveBeenCalledTimes(1);
        unmount(); render(<IncidentWorkQueue {...p} linuxOffset={50}/>);
        expect(order()).toHaveValue('newest'); changeOrder('unseen-oldest');
        fireEvent.click(screen.getByRole('button', { name: 'Linux Health: Previous' }));
        expect(p.onLinuxPage).toHaveBeenCalledWith(0); expect(order()).toHaveValue('unseen-oldest');
    });
    it('localizes label, choices and boundaries without changing the selected ordering', () => {
        render(<IncidentWorkQueue {...props()}/>); changeOrder('oldest');
        act(() => setLocale('de', false));
        const control = screen.getByRole('combobox', { name: 'Geladene Vorfälle sortieren' });
        expect(control).toHaveValue('oldest');
        expect(within(control).getByRole('option', { name: 'Ungesehen, älteste Eröffnung zuerst' })).toBeInTheDocument();
        expect(screen.getByText(/Nur geladene Seiten. Die Eröffnungsreihenfolge/)).toBeInTheDocument();
    });
});
