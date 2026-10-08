import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT, request } from './api';
import { setLocale } from './i18n';
import { WindowsInventoryWorkspace } from './windows-inventory';
import { windowsDeviceId, windowsNow, windowsSection, windowsView } from './windows-inventory-fixture';
import { useWindowsInventory, type WindowsInventoryResource } from './windows-inventory-resource';
import { validWindowsInventoryView, type WindowsInventoryView } from './windows-inventory-types';
import { capturedInventoryTableRows, type WindowsInventoryTableKind } from './windows-inventory-tables';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
function tableView(count = 61): WindowsInventoryView {
    const view = windowsView();
    view.snapshot!.services = windowsSection(Array.from({ length: count }, (_, index) => ({ name: `Service-${String(index + 1).padStart(3, '0')}`, displayName: `Display ${index + 1}`, state: 'running' as const, pid: index + 1 })));
    view.snapshot!.software = windowsSection(Array.from({ length: count }, (_, index) => ({ name: `Application-${String(index + 1).padStart(3, '0')}`, version: `${index + 1}`, publisher: 'Fixture publisher', registryView: '64' as const })));
    return view;
}
function resource(view = tableView()): WindowsInventoryResource {
    return { serviceStartup: null, serviceStartupStale: false, elapsedMS: 0, view, snapshot: view.snapshot, status: view.status, loading: false, error: null, refresh: vi.fn(), processMetrics: null, processMetricsStale: false, network: null, networkStale: false, networkExpired: false, volumes: null, volumesStale: false, events: null, eventsStale: false };
}
function Harness({ id = windowsDeviceId, session = 'fixture' }: { id?: string; session?: string }) { return <WindowsInventoryWorkspace key={`${id}:${session}`} resource={useWindowsInventory(id, true, session)}/>; }
const select = (kind: WindowsInventoryTableKind, locale = 'en') => fireEvent.click(screen.getByRole('tab', { name: kind === 'services' ? locale === 'de' ? 'Dienste' : 'Services' : 'Software' }));
const names = () => within(screen.getByRole('table')).getAllByRole('row').slice(1).map(row => within(row).getAllByRole('cell')[0].textContent);
const flush = () => act(async () => {});
beforeEach(() => { setLocale('en', false); vi.mocked(request).mockReset(); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('bounded captured service/software rows', () => {
    it('uses numeric PIDs and literal text versions, preserves duplicates and missing values, and never mutates the source', () => {
        const view = tableView(4), snapshot = view.snapshot!;
        [2, 100, 10, 0].forEach((pid, index) => { snapshot.services.rows[index].pid = pid; });
        ['2', '10', '', '2'].forEach((version, index) => { snapshot.software.rows[index].version = version; snapshot.software.rows[index].name = 'Same application'; });
        snapshot.software.rows[3].registryView = '32';
        const before = JSON.stringify(snapshot);
        expect(capturedInventoryTableRows(snapshot, 'services', '', 'pid-asc', 'en').map(row => row.cells[3])).toEqual(['0', '2', '10', '100']);
        expect(capturedInventoryTableRows(snapshot, 'services', '', 'pid-desc', 'en').map(row => row.cells[3])).toEqual(['100', '10', '2', '0']);
        expect(capturedInventoryTableRows(snapshot, 'software', '', 'version-asc', 'en').map(row => row.cells[1])).toEqual(['10', '2', '2', 'Not reported']);
        expect(capturedInventoryTableRows(snapshot, 'software', '', 'version-desc', 'en').map(row => row.cells[1])).toEqual(['2', '2', '10', 'Not reported']);
        expect(capturedInventoryTableRows(snapshot, 'software', '', 'name-asc', 'en')).toHaveLength(4);
        expect(capturedInventoryTableRows(snapshot, 'software', '', 'version-asc', 'en').filter(row => row.cells[1] === '2').map(row => row.cells[3])).toEqual(['32-bit', '64-bit']);
        expect(JSON.stringify(snapshot)).toBe(before);
    });
    it('filters literal source fields and translated service states without interpreting labels or regex syntax', () => {
        const snapshot = tableView(2).snapshot!;
        snapshot.services.rows[0] = { name: '<img src=x onerror=alert(1)>', displayName: 'Special [a].*', state: 'start_pending', pid: 9123 };
        snapshot.software.rows[0] = { name: 'Thing[.*]', version: '12.7', publisher: 'A&B', registryView: '32' };
        const search = (kind: WindowsInventoryTableKind, query: string, locale: 'en' | 'de' = 'en') => capturedInventoryTableRows(snapshot, kind, query, 'name-asc', locale);
        for (const query of ['SPECIAL [a].*', '  9123 ', 'start_pending', 'Starting']) expect(search('services', query)).toHaveLength(1);
        expect(search('services', 'wird gestartet', 'de')).toHaveLength(1);
        expect(search('services', '[a-z]+')).toHaveLength(0);
        for (const query of ['[.*]', '12.7', 'a&b', '32', '32-bit']) expect(search('software', query)).toHaveLength(1);
        snapshot.software.rows[1].publisher = '';
        expect(search('software', 'Not reported')).toHaveLength(0);
    });
    it('uses deterministic full-row and original-ordinal ties without collapsing duplicate registrations', () => {
        const snapshot = tableView(3).snapshot!;
        snapshot.software.rows = [
            { name: 'Same', version: '1', publisher: 'B', registryView: '64' },
            { name: 'Same', version: '1', publisher: 'A', registryView: '64' },
            { name: 'Same', version: '1', publisher: 'A', registryView: '64' },
        ];
        expect(capturedInventoryTableRows(snapshot, 'software', '', 'name-asc', 'en').map(row => row.index)).toEqual([1, 2, 0]);
        expect(capturedInventoryTableRows(snapshot, 'software', '', 'name-desc', 'en').map(row => row.index)).toEqual([1, 2, 0]);
    });
});

for (const kind of ['services', 'software'] as const) describe(`captured ${kind} controls`, () => {
    it('pages every captured row once while retaining lower-bound/truncation truth', () => {
        const view = tableView(128);
        // Keep the complete frame within its existing 48 KiB budget.
        view.snapshot![kind === 'services' ? 'software' : 'services'].rows = [];
        const other = view.snapshot![kind === 'services' ? 'software' : 'services']; other.observedCount = 0;
        Object.assign(view.snapshot![kind], { quality: 'partial', complete: false, observedCount: 700, countExact: false, truncated: true });
        expect(validWindowsInventoryView(view, windowsDeviceId)).toBe(true);
        render(<WindowsInventoryWorkspace resource={resource(view)}/>); select(kind);
        expect(names()).toHaveLength(25); expect(screen.getByText('128 captured · at least 700 observed')).toBeVisible();
        expect(screen.getByText(/at most 128 captured/)).toBeVisible(); expect(screen.getByText('Rows omitted by collection or transfer limits')).toBeVisible();
        expect(screen.getByRole('button', { name: 'Previous page' })).toBeDisabled();
        const seen = [...names()];
        for (let page = 1; page < 6; page++) { fireEvent.click(screen.getByRole('button', { name: 'Next page' })); seen.push(...names()); }
        expect(seen).toHaveLength(128); expect(new Set(seen).size).toBe(128); expect(names()).toHaveLength(3);
        expect(screen.getByText('Rows 126–128 of 128 matching · 128 captured')).toBeVisible(); expect(screen.getByText('Page 6 of 6')).toBeVisible();
        expect(screen.getByRole('button', { name: 'Next page' })).toBeDisabled(); expect(request).not.toHaveBeenCalled();
    });
    it('resets to page one for repeated filter/sort changes and preserves the captured count', () => {
        render(<WindowsInventoryWorkspace resource={resource()}/>); select(kind);
        for (let repeat = 0; repeat < 2; repeat++) {
            fireEvent.click(screen.getByRole('button', { name: 'Next page' }));
            fireEvent.change(screen.getByRole('searchbox'), { target: { value: '061' } }); expect(names()).toHaveLength(1); expect(screen.getByText('61 captured · 61 observed')).toBeVisible(); expect(screen.getByText('Page 1 of 1')).toBeVisible();
            fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'no match [' } }); expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByText('Rows 0–0 of 0 matching · 61 captured')).toBeVisible();
            fireEvent.change(screen.getByRole('searchbox'), { target: { value: '' } }); expect(names()).toHaveLength(25); expect(screen.getByText('Page 1 of 3')).toBeVisible();
        }
        fireEvent.click(screen.getByRole('button', { name: 'Next page' })); fireEvent.change(screen.getByRole('combobox'), { target: { value: 'name-desc' } });
        expect(names()[0]).toContain('061'); expect(screen.getByText('Page 1 of 3')).toBeVisible(); expect(screen.getByRole('columnheader', { name: 'Name' })).toHaveAttribute('aria-sort', 'descending');
        expect(request).not.toHaveBeenCalled();
    });
    it('retains controls across a deferred same-generation poll but hides rows and controls while pending', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const view = tableView(); vi.mocked(request).mockResolvedValueOnce(view);
        render(<Harness/>); await flush(); select(kind);
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: kind === 'services' ? 'Service' : 'Application' } }); fireEvent.change(screen.getByRole('combobox'), { target: { value: 'name-desc' } }); fireEvent.click(screen.getByRole('button', { name: 'Next page' }));
        let resolve!: (view: WindowsInventoryView) => void; vi.mocked(request).mockReturnValueOnce(new Promise(done => { resolve = done; }));
        await act(async () => vi.advanceTimersByTimeAsync(15000)); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByRole('searchbox')).toBeNull();
        await act(async () => resolve({ ...view, serverNow: '2026-10-07T12:00:25Z' }));
        expect(screen.getByRole('searchbox')).toHaveValue(kind === 'services' ? 'Service' : 'Application'); expect(screen.getByRole('combobox')).toHaveValue('name-desc'); expect(screen.getByText('Page 2 of 3')).toBeVisible(); expect(names()[0]).toContain('036');
    });
    it.each(['blur', 'pagehide', 'hashchange', AUTH_REQUIRED_EVENT])('clears private rows and filter/sort state on %s', async event => {
        vi.mocked(request).mockResolvedValue(tableView()); render(<Harness/>); await screen.findByText('fixture.exe'); select(kind);
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'private-query' } }); fireEvent.change(screen.getByRole('combobox'), { target: { value: 'name-desc' } });
        act(() => window.dispatchEvent(new Event(event))); expect(screen.queryByRole('searchbox')).toBeNull(); expect(screen.queryByRole('table')).toBeNull(); expect(document.body).not.toHaveTextContent('private-query');
        if (event !== AUTH_REQUIRED_EVENT) { act(() => window.dispatchEvent(new Event('focus'))); await screen.findByRole('searchbox'); expect(screen.getByRole('searchbox')).toHaveValue(''); expect(screen.getByRole('combobox')).toHaveValue('name-asc'); }
    });
    it('resets controls on device/capture changes, tab departure, and tab changes during a pending poll', () => {
        const view = tableView(), ui = render(<WindowsInventoryWorkspace resource={resource(view)}/>); select(kind);
        const edit = () => { fireEvent.change(screen.getByRole('searchbox'), { target: { value: kind === 'services' ? 'Service' : 'Application' } }); fireEvent.change(screen.getByRole('combobox'), { target: { value: 'name-desc' } }); fireEvent.click(screen.getByRole('button', { name: 'Next page' })); };
        const reset = () => { expect(screen.getByRole('searchbox')).toHaveValue(''); expect(screen.getByRole('combobox')).toHaveValue('name-asc'); expect(screen.getByText('Page 1 of 3')).toBeVisible(); };
        edit(); const next = tableView(); next.deviceId = `agent_${'8'.repeat(32)}`; ui.rerender(<WindowsInventoryWorkspace resource={resource(next)}/>); reset();
        edit(); next.snapshot!.generationId = `sample_${'b'.repeat(32)}`; ui.rerender(<WindowsInventoryWorkspace resource={resource(next)}/>); reset();
        edit(); next.snapshot!.collectedAt = '2026-10-07T12:00:01Z'; ui.rerender(<WindowsInventoryWorkspace resource={resource(next)}/>); reset();
        edit(); select(kind === 'services' ? 'software' : 'services'); select(kind); reset();
        edit(); ui.rerender(<WindowsInventoryWorkspace resource={{ ...resource(next), snapshot: null, view: null, loading: true }}/>);
        select(kind === 'services' ? 'software' : 'services'); select(kind);
        ui.rerender(<WindowsInventoryWorkspace resource={resource(next)}/>); reset();
    });
    it.each(['revoked', 'unavailable', 'awaiting', 'not_configured'] as const)('discards controls and rows on %s instead of keeping a stale page', status => {
        const view = tableView(), ui = render(<WindowsInventoryWorkspace resource={resource(view)}/>); select(kind);
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'private-query' } });
        ui.rerender(<WindowsInventoryWorkspace resource={{ ...resource(view), snapshot: null, view: { ...view, snapshot: null, status }, status }}/>);
        expect(screen.queryByRole('searchbox')).toBeNull(); expect(screen.queryByRole('table')).toBeNull();
        ui.rerender(<WindowsInventoryWorkspace resource={resource(view)}/>); expect(screen.getByRole('searchbox')).toHaveValue('');
    });
    it('keeps denied/unavailable distinct from healthy zero and escapes row text', () => {
        const view = tableView(0), ui = render(<WindowsInventoryWorkspace resource={resource(view)}/>); select(kind);
        expect(screen.getByText('No rows observed within this collection scope.')).toBeVisible(); expect(screen.queryByRole('searchbox')).toBeNull();
        for (const quality of ['denied', 'unavailable'] as const) { Object.assign(view.snapshot![kind], { quality, complete: false, countExact: false }); ui.rerender(<WindowsInventoryWorkspace resource={resource(view)}/>); expect(screen.getByText('No rows available. This does not establish an empty inventory.')).toBeVisible(); expect(screen.queryByRole('searchbox')).toBeNull(); }
        const text = tableView(1); text.snapshot![kind].rows[0].name = '<img src=x onerror=alert(1)>'; ui.rerender(<WindowsInventoryWorkspace resource={resource(text)}/>); expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeVisible(); expect(document.querySelector('img')).toBeNull();
    });
    it('uses keyboard-operable controls outside mobile-hidden headers and localizes German text', async () => {
        setLocale('de', false); const user = userEvent.setup(); render(<WindowsInventoryWorkspace resource={resource()}/>); select(kind, 'de');
        const search = screen.getByRole('searchbox', { name: kind === 'services' ? 'Erfasste Dienste filtern' : 'Erfasste Software filtern' }), sort = screen.getByRole('combobox');
        expect(screen.getByText('61 erfasst · 61 beobachtet')).toBeVisible(); expect(screen.getByText('Zeilen 1–25 von 61 Treffern · 61 erfasst')).toBeVisible();
        search.focus(); await user.keyboard('061'); expect(names()).toHaveLength(1); await user.clear(search); await user.tab(); expect(sort).toHaveFocus(); await user.selectOptions(sort, 'name-desc');
        await user.tab(); expect(screen.getByRole('button', { name: 'Nächste Seite' })).toHaveFocus(); await user.keyboard('{Enter}'); expect(screen.getByText('Seite 2 von 3')).toBeVisible();
        expect(search.closest('thead')).toBeNull(); expect(sort.closest('thead')).toBeNull(); expect(within(screen.getAllByRole('row')[1]).getAllByRole('cell').every(cell => cell.hasAttribute('data-label'))).toBe(true);
    });
    it('hides every page at original capture expiry without a reread or age refresh', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const view = tableView(); view.status = 'stale'; view.snapshot!.collectedAt = '2026-10-06T12:00:11Z'; vi.mocked(request).mockResolvedValue(view);
        render(<Harness/>); await flush(); select(kind); fireEvent.click(screen.getByRole('button', { name: 'Next page' })); expect(names()[0]).toContain('026');
        await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByRole('searchbox')).toBeNull(); expect(screen.queryByText(/Service-026|Application-026/)).toBeNull();
    });
});
