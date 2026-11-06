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
import { incidentQueueRows } from './incident-work-queue-model';
import { incidentLifecycle, incidentTimeline } from './incident-timeline-model';
import { filterQueueCurrentCheck } from './incident-current-check-filter';
import { IncidentWorkQueue } from './incident-work-queue';
import { setLocale } from './i18n';
import { useWindowsIncidentInbox } from './windows-incident-inbox-resource';
import { mutate, request } from './api';

vi.mock('./windows-incident-inbox-resource', () => ({ useWindowsIncidentInbox: vi.fn() }));
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), mutate: vi.fn(), request: vi.fn() }));
function assertLinux(view: InvestigationsView) {
    if (!validInvestigationsView(view, 'all', 0)) throw new Error('Invalid Linux fixture');
    return view;
}
function linuxFixture(state: 'open' | 'pending' | 'unknown' | 'ok' = 'open'): InvestigationsView {
    const health = structuredClone(healthWire) as HealthView;
    health.checks[1].state = state;
    if (state === 'unknown') health.checks[1].value = null;
    return assertLinux({ schemaVersion: 'tracebolt.investigations.v1', serverNow: health.serverNow, scope: 'all', offset: 0, total: health.incidents.length, counts: { open: health.incidents.length, recovered: 0, closed: 0, all: health.incidents.length }, items: health.incidents.map(incident => ({ deviceId: health.deviceId, incident })), devices: [{ ...health, incidents: [] }] });
}
function windowsFixture(scene: 'active' | 'resolved' = 'active'): WindowsInboxView {
    const view = structuredClone(windowsWire[scene]);
    if (!validWindowsIncidentInboxView(view, scene, 'all', 0)) throw new Error('Invalid Windows fixture');
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
const control = () => screen.getByRole('combobox', { name: 'Current check on loaded pages' });
const choose = (value: string) => fireEvent.change(control(), { target: { value } });
const choices = () => screen.queryAllByRole('checkbox', { name: /^Compare episode:/ });

describe('separate current-check filtering', () => {
    it('uses existing Linux and Windows native current states without changing input rows, order or totals', () => {
        const linux = linuxFixture(), windows = windowsFixture();
        const rows = incidentQueueRows(linux, windows), before = JSON.stringify({ linux, windows, rows });
        expect(filterQueueCurrentCheck(rows, 'all', linux, windows.serverNow, 0)).toBe(rows);
        const unknown = filterQueueCurrentCheck(rows, 'unknown', linux, windows.serverNow, 0);
        expect(unknown).toHaveLength(1); expect(unknown[0].platform).toBe('windows');
        if (unknown[0].platform === 'windows') expect(unknown[0].item.domain).toBe('contact');
        const attention = filterQueueCurrentCheck(rows, 'attention', linux, windows.serverNow, 0);
        expect(attention).toEqual(rows.filter(row => !unknown.includes(row)));
        expect(filterQueueCurrentCheck(rows, 'pending', linux, windows.serverNow, 0)).toEqual([]);
        expect(filterQueueCurrentCheck(rows, 'inactive', linux, windows.serverNow, 0)).toEqual([]);
        expect(JSON.stringify({ linux, windows, rows })).toBe(before);
    });
    it('keeps pending and unknown distinct and does not call currently good evidence episode recovery', () => {
        for (const state of ['pending', 'unknown', 'ok'] as const) {
            const view = linuxFixture(state), rows = incidentQueueRows(view, null);
            expect(filterQueueCurrentCheck(rows, 'pending', view, null, 0)).toHaveLength(state === 'pending' ? 1 : 0);
            expect(filterQueueCurrentCheck(rows, 'unknown', view, null, 0)).toHaveLength(state === 'unknown' ? 1 : 0);
            expect(incidentLifecycle(rows[0])).toBe('open');
        }
    });
    it('retains recovered and administrative outcomes when a later current check is attention', () => {
        for (const closedReason of ['recovered', 'monitoring_stopped'] as const) {
            const view = linuxFixture(); view.items[0].incident.resolvedAt = view.serverNow; view.items[0].incident.closedReason = closedReason;
            view.items[0].incident.acknowledgedAt = view.serverNow;
            view.counts = { open: 0, recovered: closedReason === 'recovered' ? 1 : 0, closed: closedReason === 'monitoring_stopped' ? 1 : 0, all: 1 }; assertLinux(view);
            const rows = incidentQueueRows(view, null), selected = filterQueueCurrentCheck(rows, 'attention', view, null, 0);
            expect(selected).toHaveLength(1); expect(selected[0]).toBe(rows[0]);
            expect(incidentLifecycle(selected[0])).toBe(closedReason === 'recovered' ? 'recovered' : 'stopped');
        }
    });
    it('preserves the original distinction between removed Linux monitoring and disabled Windows policy', () => {
        const linux = linuxFixture(); const incident = linux.items[0].incident;
        Object.assign(incident, { kind: 'service', key: 'service:sshd.service', target: 'sshd.service', resolvedAt: linux.serverNow, closedReason: 'monitoring_stopped' });
        linux.devices[0].monitoredServices = []; linux.devices[0].checks = linux.devices[0].checks.filter(check => check.kind !== 'service');
        linux.counts = { open: 0, recovered: 0, closed: 1, all: 1 }; assertLinux(linux);
        const windows = windowsFixture('resolved'), rows = incidentQueueRows(linux, windows);
        const result = filterQueueCurrentCheck(rows, 'inactive', linux, windows.serverNow, 0);
        expect(result).toHaveLength(2);
        expect(result.map(row => incidentTimeline(row, linux, windows.serverNow, 0).current.state).sort()).toEqual(['disabled', 'not-monitored']);
        expect(result.every(row => incidentLifecycle(row) === 'stopped')).toBe(true);
        // Defensive projection only: missing current context never establishes removal.
        const missing = filterQueueCurrentCheck(incidentQueueRows(linux, null), 'unknown', null, null, 0);
        expect(missing).toHaveLength(1); expect(filterQueueCurrentCheck(missing, 'inactive', null, null, 0)).toEqual([]);
    });
    it('ages original Linux checks and independent Windows deadlines without modifying retained episodes', () => {
        const linux = linuxFixture(), windows = windowsFixture(), rows = incidentQueueRows(linux, windows);
        const before = rows.map(row => row.item);
        const aged = ageInvestigations(linux, 121000);
        expect(filterQueueCurrentCheck(rows, 'unknown', aged, windows.serverNow, 121000)).toHaveLength(rows.length);
        expect(filterQueueCurrentCheck(rows, 'attention', aged, windows.serverNow, 121000)).toEqual([]);
        expect(rows.map(row => row.item)).toEqual(before);
        expect(rows.every(row => incidentLifecycle(row) === 'open')).toBe(true);
    });
    it('keeps complete-source provenance historical when the current deadline expires or age is invalid', () => {
        const windows = completeIncidentFixture('active'), rows = incidentQueueRows(null, windows), before = JSON.stringify(windows);
        expect(filterQueueCurrentCheck(rows, 'attention', null, windows.serverNow, 0)).toHaveLength(1);
        for (const age of [121000, NaN, Infinity, -1]) {
            expect(filterQueueCurrentCheck(rows, 'unknown', null, windows.serverNow, age)).toHaveLength(1);
            expect(filterQueueCurrentCheck(rows, 'attention', null, windows.serverNow, age)).toEqual([]);
            expect(incidentTimeline(rows[0], null, windows.serverNow, age).sources).toHaveLength(2);
        }
        expect(filterQueueCurrentCheck(rows, 'unknown', null, null, 0)).toHaveLength(1);
        expect(JSON.stringify(windows)).toBe(before);
    });
    it('never fabricates unknown rows from a missing source or collapses independent Windows domains', () => {
        expect(filterQueueCurrentCheck(incidentQueueRows(null, null), 'unknown', null, null, 0)).toEqual([]);
        const windows = windowsFixture(), rows = incidentQueueRows(null, windows);
        const matches = filterQueueCurrentCheck(rows, 'attention', null, windows.serverNow, 0);
        const collisions = matches.filter(row => row.platform === 'windows' && row.item.incidentId === 'wcapacity_0000000000000001');
        expect(collisions).toHaveLength(3); expect(new Set(collisions.map(row => row.identity)).size).toBe(3);
    });
});

describe('local current-check triage', () => {
    it('defaults to all and supports repeated labeled choices, keyboard-native options and EN/DE explanation', () => {
        render(<IncidentWorkQueue {...props()}/>); expect(control()).toHaveValue('all'); expect(choices()).toHaveLength(6);
        choose('unknown'); expect(choices()).toHaveLength(1); choose('attention'); expect(choices()).toHaveLength(5);
        choose('pending'); expect(choices()).toHaveLength(0); choose('inactive'); expect(choices()).toHaveLength(0);
        choose('all'); expect(choices()).toHaveLength(6);
        const icon = control().closest('label')!.querySelector('svg');
        expect(icon).toHaveAttribute('aria-hidden', 'true'); expect(icon).toHaveAttribute('focusable', 'false');
        expect(screen.getByText(/Current checks are separate from episode outcomes/)).toBeInTheDocument();
        act(() => setLocale('de', false));
        const translated = screen.getByRole('combobox', { name: 'Aktuelle Prüfung auf geladenen Seiten' });
        expect(translated).toHaveValue('all');
        expect(within(translated).getByRole('option', { name: 'Überwachung deaktiviert oder entfernt' })).toBeInTheDocument();
    });
    it('resets current filter with the other local filters without changing source paging or scope', () => {
        const p = props(); render(<IncidentWorkQueue {...p}/>);
        const sourceText = [...document.querySelectorAll('.incident-queue-source')].map(element => element.textContent);
        choose('unknown'); fireEvent.change(screen.getByRole('combobox', { name: 'Platform on loaded pages' }), { target: { value: 'linux' } });
        expect(choices()).toHaveLength(0); expect(screen.getByRole('button', { name: 'Clear page filters' })).toBeEnabled();
        fireEvent.click(screen.getByRole('button', { name: 'Clear page filters' }));
        expect(control()).toHaveValue('all'); expect(choices()).toHaveLength(6);
        expect(screen.getByRole('button', { name: 'Clear page filters' })).toBeDisabled();
        expect([...document.querySelectorAll('.incident-queue-source')].map(element => element.textContent)).toEqual(sourceText);
        expect(p.onScope).not.toHaveBeenCalled(); expect(p.onLinuxPage).not.toHaveBeenCalled();
    });
    it('clears exact comparison choices on filter change without selecting rows that later match', () => {
        render(<IncidentWorkQueue {...props()}/>);
        fireEvent.click(choices()[0]); fireEvent.click(choices()[1]);
        fireEvent.click(screen.getByRole('button', { name: 'Open comparison' }));
        choose('attention');
        expect(choices().every(input => !(input as HTMLInputElement).checked)).toBe(true);
        expect(screen.queryByRole('button', { name: 'Close comparison' })).not.toBeInTheDocument();
        choose('all'); expect(choices().every(input => !(input as HTMLInputElement).checked)).toBe(true);
    });
    it('removes matching rows and disclosures on aging and does not restore selection with later fresh context', () => {
        const p = props(); const { rerender } = render(<IncidentWorkQueue {...p}/>);
        choose('attention'); const name = choices()[0].getAttribute('aria-label')!;
        fireEvent.click(screen.getByRole('checkbox', { name }));
        fireEvent.click(within(screen.getByRole('checkbox', { name }).closest('li')!).getByText('Incident timeline'));
        const oldTimeline = screen.getByRole('checkbox', { name }).closest('li')!.querySelector('.incident-timeline');
        const fresh = p.linux.view!; p.linux = resource(ageInvestigations(fresh, 121000)); windows = { ...windows, age: 121000 };
        rerender(<IncidentWorkQueue {...p}/>); expect(choices()).toHaveLength(0); expect(oldTimeline).not.toBeInTheDocument();
        p.linux = resource(fresh); windows = { ...windows, age: 0 }; rerender(<IncidentWorkQueue {...p}/>);
        expect(screen.getByRole('checkbox', { name })).not.toBeChecked();
        expect(screen.getByRole('checkbox', { name }).closest('li')!.querySelector('.incident-timeline')).not.toHaveAttribute('open');
    });
    it('keeps unavailable source coverage explicit with zero matches and never converts source loss to unknown episode rows', () => {
        const p = props(); const { rerender } = render(<IncidentWorkQueue {...p}/>); choose('unknown');
        windows = { ...windows, view: null, error: true }; rerender(<IncidentWorkQueue {...p}/>);
        expect(choices()).toHaveLength(0);
        expect(screen.getByText(/Source coverage is incomplete/)).toBeInTheDocument();
        expect(screen.getByText(/Missing source rows and totals remain unknown/)).toBeInTheDocument();
        p.linux = resource(null); rerender(<IncidentWorkQueue {...p}/>); expect(choices()).toHaveLength(0);
        expect(screen.getByText('No current Linux investigation data.')).toBeInTheDocument();
    });
    it('makes no request, mutation, acknowledgement, storage write or timer from filtering', () => {
        const p = props(); render(<IncidentWorkQueue {...p}/>);
        const calls = new Set(vi.mocked(useWindowsIncidentInbox).mock.calls.map(call => JSON.stringify(call)));
        const storage = vi.spyOn(Storage.prototype, 'setItem'), timer = vi.spyOn(window, 'setInterval');
        for (const value of ['unknown', 'attention', 'pending', 'inactive', 'all']) choose(value);
        expect(request).not.toHaveBeenCalled(); expect(mutate).not.toHaveBeenCalled();
        expect(windows.acknowledge).not.toHaveBeenCalled(); expect(windows.refresh).not.toHaveBeenCalled(); expect(p.linux.refresh).not.toHaveBeenCalled();
        expect(storage).not.toHaveBeenCalled(); expect(timer).not.toHaveBeenCalled();
        expect(new Set(vi.mocked(useWindowsIncidentInbox).mock.calls.map(call => JSON.stringify(call)))).toEqual(calls);
    });
    it('keeps the chosen filter through refresh and paging but defaults again after remount', () => {
        const p = props(); const { unmount } = render(<IncidentWorkQueue {...p} linuxOffset={50}/>);
        choose('unknown'); fireEvent.click(screen.getByRole('button', { name: 'Linux Health: Previous' }));
        expect(p.onLinuxPage).toHaveBeenCalledWith(0); expect(control()).toHaveValue('unknown');
        fireEvent.click(screen.getByRole('button', { name: 'Refresh work queue' })); expect(control()).toHaveValue('unknown');
        expect(windows.refresh).toHaveBeenCalledTimes(1);
        unmount(); render(<IncidentWorkQueue {...p}/>); expect(control()).toHaveValue('all');
    });
});
