import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, abortProtectedRequests, request } from './api';
import { setLocale } from './i18n';
import { WindowsFleetUpdateTriage } from './windows-fleet-update-triage';
import { emptyFleetUpdateFilters, filterFleetUpdateGroups } from './windows-fleet-update-triage-model';
import { useFleetUpdateTriage, type FleetUpdateGroup } from './windows-fleet-update-triage-resource';
import { windowsUpdates, windowsUpdatesView } from './windows-updates-fixture';
import type { UpdateSelection } from './windows-update-jobs-types';
import type { WindowsUpdate } from './windows-updates-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
const now = '2026-10-07T12:00:10Z', expiry = '2026-10-07T13:00:00Z';
const devices = [{ id: `agent_${'1'.repeat(32)}`, name: 'Workstation A' }, { id: `agent_${'2'.repeat(32)}`, name: 'Workstation B' }];
const rows = windowsUpdates(15).rows;
function group(index: number, values: Array<Partial<WindowsUpdate>> = [{}]): FleetUpdateGroup {
    const reports = values.map((value, device) => ({ deviceId: devices[device]?.id ?? `agent_${device}`, row: { ...rows[index], ...value } }));
    return { updateId: rows[index].updateId, revision: rows[index].revision, reports, downloaded: reports.filter(report => report.row.downloaded).length };
}
function inventory(id: string) {
    const value = { ...windowsUpdatesView(12), deviceId: id };
    if (id === devices[0].id) value.updates.rows[0].downloaded = false;
    else value.updates.rows[0].severity = 'low';
    return value;
}
const flush = () => act(async () => {});
function LiveTriage({ selected = null, onSelect = vi.fn() }: { selected?: UpdateSelection | null; onSelect?: (value: UpdateSelection | null) => void }) {
    const triage = useFleetUpdateTriage(devices.map(device => device.id), expiry, true, vi.fn());
    return <WindowsFleetUpdateTriage triage={triage} devices={devices} selected={selected} onSelect={onSelect}/>;
}
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime(now); setLocale('en', false);
    vi.mocked(request).mockReset().mockImplementation(async path => inventory(path.split('/')[2]) as never);
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

it('matches severity, download flag and search within one report, never across devices', () => {
    const mixed = group(0, [{ title: 'Alpha critical', severity: 'critical', downloaded: false }, { title: 'Beta downloaded', severity: 'low', downloaded: true }]);
    const filters = { ...emptyFleetUpdateFilters(), severity: 'critical' as const, downloaded: 'downloaded' as const };
    expect(filterFleetUpdateGroups([mixed], filters, 'en')).toEqual([]);
    expect(filterFleetUpdateGroups([mixed], { ...filters, downloaded: 'all', query: 'Beta' }, 'en')).toEqual([]);
    const result = filterFleetUpdateGroups([mixed], { ...filters, downloaded: 'not-downloaded', query: 'alpha' }, 'en');
    expect(result).toHaveLength(1); expect(result[0]).toBe(mixed);
    expect(result[0].reports).toHaveLength(2); expect(result[0].downloaded).toBe(1);
});

it('searches literal titles, KBs, exact identity text and revisions without altering original evidence', () => {
    const a = group(0, [{ title: '<b>Literal [patch]</b>', kbArticleIds: ['KB12345'] }]), b = group(1);
    const input = [b, a], before = structuredClone(input);
    for (const query of ['[patch]', 'kb12345', 'kb12345 critical', a.updateId.toUpperCase(), '10']) {
        expect(filterFleetUpdateGroups(input, { ...emptyFleetUpdateFilters(), query }, 'en')).toContain(a);
    }
    expect(filterFleetUpdateGroups(input, { ...emptyFleetUpdateFilters(), query: '.*' }, 'en')).toEqual([]);
    expect(input).toEqual(before); expect(input[0]).toBe(b);
});

it('orders by the highest original reported severity with unspecified last and stable exact-identity ties', () => {
    const unknown = group(0, [{ severity: 'unspecified' }]), low = group(1, [{ severity: 'low' }]);
    const mixed = group(2, [{ severity: 'low' }, { severity: 'critical' }]), critical = group(3, [{ severity: 'critical' }]);
    const input = [unknown, critical, mixed, low];
    expect(filterFleetUpdateGroups(input, { ...emptyFleetUpdateFilters(), sort: 'severity' }, 'en')).toEqual([mixed, critical, low, unknown]);
    expect(filterFleetUpdateGroups(input, { ...emptyFleetUpdateFilters(), sort: 'reporting' }, 'en')).toEqual([mixed, unknown, low, critical]);
    const revision2 = { ...critical, revision: 2 }, revision11 = { ...critical, revision: 11 };
    expect(filterFleetUpdateGroups([revision11, revision2], emptyFleetUpdateFilters(), 'en')).toEqual([revision2, revision11]);
    expect(input).toEqual([unknown, critical, mixed, low]);
});

it('keeps unspecified severity distinct and permits an empty retained result', () => {
    const unknown = group(2), known = group(0);
    expect(filterFleetUpdateGroups([known, unknown], { ...emptyFleetUpdateFilters(), severity: 'unspecified' }, 'de')).toEqual([unknown]);
    expect(filterFleetUpdateGroups([], emptyFleetUpdateFilters(), 'en')).toEqual([]);
});

it.each(['en', 'de'] as const)('filters existing cache evidence without requests or selection changes in %s', async locale => {
    const de = locale === 'de', onSelect = vi.fn(); setLocale(locale, false);
    render(<LiveTriage selected={{ updateId: rows[0].updateId, revision: rows[0].revision }} onSelect={onSelect}/>);
    expect(request).not.toHaveBeenCalled(); expect(screen.queryByRole('combobox')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: de ? 'Cache-Updates lesen' : 'Read cached updates' })); await flush();
    expect(request).toHaveBeenCalledTimes(2);
    fireEvent.change(screen.getByRole('combobox', { name: de ? 'Gemeldeter Herstellerschweregrad' : 'Reported vendor severity' }), { target: { value: 'critical' } });
    fireEvent.change(screen.getByRole('combobox', { name: de ? 'Downloadkennzeichen im Cache' : 'Cached download flag' }), { target: { value: 'downloaded' } });
    expect(screen.getByText(de ? 'Passende Updates: 1 / 12 gespeicherte Updates' : 'Matching updates: 1 / 12 retained updates')).toBeVisible();
    expect(document.querySelectorAll('.windows-fleet-update-triage-list > li')).toHaveLength(1);
    expect(screen.getByText(de ? /Das ausgewählte Update ist durch/ : /The selected update is hidden/)).toBeVisible();
    fireEvent.change(screen.getByRole('combobox', { name: de ? 'Gespeicherte Updates ordnen' : 'Order retained updates' }), { target: { value: 'reporting' } });
    const card = document.querySelector('.windows-fleet-update-triage-list > li')!;
    expect(card).toHaveTextContent(de ? 'Gemeldet: 2' : 'Reported: 2');
    expect(request).toHaveBeenCalledTimes(2); expect(onSelect).not.toHaveBeenCalled();
    fireEvent.click(within(card as HTMLElement).getByRole('button'));
    expect(onSelect).toHaveBeenCalledExactlyOnceWith({ updateId: rows[10].updateId, revision: rows[10].revision });
    for (const [, options] of vi.mocked(request).mock.calls) expect(options?.method ?? 'GET').toBe('GET');
});

it.each(['en', 'de'] as const)('resets search, filters, sorting and page locally and restores focus in %s', async locale => {
    const de = locale === 'de'; setLocale(locale, false); render(<LiveTriage/>);
    fireEvent.click(screen.getByRole('button', { name: de ? 'Cache-Updates lesen' : 'Read cached updates' })); await flush();
    fireEvent.click(screen.getByRole('button', { name: de ? 'Weiter' : 'Next' }));
    expect(screen.getByText(de ? 'Seite 2/2' : 'Page 2/2')).toBeVisible();
    const search = screen.getByRole('searchbox');
    fireEvent.change(search, { target: { value: 'nonexistent' } });
    fireEvent.change(screen.getByRole('combobox', { name: de ? 'Gemeldeter Herstellerschweregrad' : 'Reported vendor severity' }), { target: { value: 'critical' } });
    fireEvent.change(screen.getByRole('combobox', { name: de ? 'Downloadkennzeichen im Cache' : 'Cached download flag' }), { target: { value: 'not-downloaded' } });
    fireEvent.change(screen.getByRole('combobox', { name: de ? 'Gespeicherte Updates ordnen' : 'Order retained updates' }), { target: { value: 'severity' } });
    expect(screen.getByText(de ? /Keine passenden Cache-Zeilen/ : /No matching cached rows/)).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: de ? 'Ansicht zurücksetzen' : 'Reset view' }));
    expect(search).toHaveValue(''); expect(search).toHaveFocus();
    expect(screen.getAllByRole('combobox').map(input => (input as HTMLSelectElement).value)).toEqual(['all', 'all', 'identity']);
    expect(screen.getByText(de ? 'Seite 1/2' : 'Page 1/2')).toBeVisible(); expect(request).toHaveBeenCalledTimes(2);
    expect(search).toHaveAccessibleDescription(de ? /Alle Filter müssen zu einem Gerätebericht passen/ : /All filters must match one device report/);
});

it.each(['blur', 'pagehide', 'hashchange', 'popstate', AUTH_REQUIRED_EVENT, 'retention', 'cancel'])('clears filter state and private rows after %s', async event => {
    render(<LiveTriage/>); fireEvent.click(screen.getByRole('button', { name: 'Read cached updates' })); await flush();
    fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'private query' } });
    fireEvent.change(screen.getByRole('combobox', { name: 'Reported vendor severity' }), { target: { value: 'critical' } });
    act(() => { if (event === 'retention') vi.advanceTimersByTime(300000); else if (event === 'cancel') fireEvent.click(screen.getByRole('button', { name: 'Cancel and clear' })); else window.dispatchEvent(new Event(event)); });
    expect(screen.queryByRole('searchbox')).toBeNull(); expect(screen.queryByRole('combobox')).toBeNull();
    expect(document.querySelectorAll('.windows-fleet-update-triage-list > li')).toHaveLength(0); expect(request).toHaveBeenCalledTimes(2);
    if (event !== AUTH_REQUIRED_EVENT && event !== 'retention') {
        fireEvent.click(screen.getByRole('button', { name: 'Read cached updates' })); await flush();
        expect(screen.getByRole('searchbox')).toHaveValue('');
        expect(screen.getAllByRole('combobox').map(input => (input as HTMLSelectElement).value)).toEqual(['all', 'all', 'identity']);
    }
});

it('discards every filter when source presence changes, without pressing Read or Cancel', () => {
    const triage = { reports: [], groups: [group(0), group(1)], loading: false, hasRead: true, read: vi.fn(), clear: vi.fn() };
    const onSelect = vi.fn();
    const view = render(<WindowsFleetUpdateTriage triage={triage} devices={devices} selected={null} onSelect={onSelect}/>);
    fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'private query' } });
    fireEvent.change(screen.getByRole('combobox', { name: 'Reported vendor severity' }), { target: { value: 'critical' } });
    fireEvent.change(screen.getByRole('combobox', { name: 'Cached download flag' }), { target: { value: 'not-downloaded' } });
    fireEvent.change(screen.getByRole('combobox', { name: 'Order retained updates' }), { target: { value: 'severity' } });
    view.rerender(<WindowsFleetUpdateTriage triage={{ ...triage, hasRead: false, groups: [] }} devices={devices} selected={null} onSelect={onSelect}/>);
    expect(screen.queryByRole('searchbox')).toBeNull();
    view.rerender(<WindowsFleetUpdateTriage triage={triage} devices={devices} selected={null} onSelect={onSelect}/>);
    expect(screen.getByRole('searchbox')).toHaveValue('');
    expect(screen.getAllByRole('combobox').map(input => (input as HTMLSelectElement).value)).toEqual(['all', 'all', 'identity']);
    expect(triage.read).not.toHaveBeenCalled(); expect(triage.clear).not.toHaveBeenCalled(); expect(onSelect).not.toHaveBeenCalled();
    expect(request).not.toHaveBeenCalled();
});

it('keeps stale and partial source warnings and counts independent of filters', async () => {
    vi.mocked(request).mockImplementation(async path => {
        const value = inventory(path.split('/')[2]);
        if (value.deviceId === devices[0].id) { value.status = 'stale'; value.serverNow = '2026-10-07T12:03:00Z'; }
        else { value.updates.quality = 'partial'; value.updates.reason = 'windows_updates_partial_result'; }
        return value as never;
    });
    render(<LiveTriage/>); fireEvent.click(screen.getByRole('button', { name: 'Read cached updates' })); await flush();
    fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'none' } });
    expect(screen.getByText('Reports read: 2/2 · Partial / truncated: 1 · Stale: 1 · Unavailable: 0')).toBeVisible();
    expect(screen.getByText('Matching updates: 0 / 12 retained updates')).toBeVisible();
    expect(screen.getByText(/Empty results do not prove compliance/)).toBeVisible(); expect(request).toHaveBeenCalledTimes(2);
});
