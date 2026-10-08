import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, request } from './api';
import { setLocale } from './i18n';
import { WindowsInventoryWorkspace } from './windows-inventory';
import { windowsDeviceId, windowsNow, windowsSection, windowsView } from './windows-inventory-fixture';
import { useWindowsInventory, type WindowsInventoryResource } from './windows-inventory-resource';
import type { WindowsInventoryView } from './windows-inventory-types';
import type { WindowsProcessMetrics } from './windows-process-metrics-types';
import { capturedProcessRows, type WindowsProcessSort } from './windows-processes';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
function processView(count = 61): WindowsInventoryView {
    const view = windowsView();
    view.snapshot!.processes = windowsSection(Array.from({ length: count }, (_, index) => ({ name: `fixture-${String(index + 1).padStart(3, '0')}.exe`, pid: index + 1, parentPid: 4000, threads: 7000 })));
    return view;
}
function metrics(view: WindowsInventoryView): WindowsProcessMetrics {
    return { schemaVersion: 'tracebolt.windows-process-metrics.v1', scope: 'windows-process-metrics-v1', grantId: 'e'.repeat(32), generationId: view.snapshot!.generationId, collectedAt: '2026-10-07T12:00:02Z', observedCount: view.snapshot!.processes.rows.length, truncated: false, rows: view.snapshot!.processes.rows.map(row => ({ pid: row.pid, cpuPercent: row.pid, cpuQuality: 'observed', memoryBytes: String(row.pid), memoryQuality: 'observed' })) };
}
function resource(view = processView()): WindowsInventoryResource {
    return { elapsedMS: 0, view, snapshot: view.snapshot, status: view.status, loading: false, error: null, refresh: vi.fn(), processMetrics: view.processMetrics ?? null, processMetricsStale: false, network: null, networkStale: false, networkExpired: false, volumes: null, volumesStale: false, events: null, eventsStale: false };
}
function Harness() { return <WindowsInventoryWorkspace resource={useWindowsInventory(windowsDeviceId, true, 'fixture')}/>; }
const displayedNames = () => within(screen.getByRole('table', { name: 'Processes' })).getAllByRole('row').slice(1).map(row => within(row).getAllByRole('cell')[0].textContent);
const orderedPids = (view: WindowsInventoryView, sort: WindowsProcessSort, query = '', locale: 'en' | 'de' = 'en') => capturedProcessRows(view.snapshot!, view.processMetrics, query, sort, locale).map(({ process }) => process.pid);
beforeEach(() => { setLocale('en', false); vi.mocked(request).mockReset(); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('bounded process sorting', () => {
    it('sorts actual numeric CPU and exact uint64 RAM, with missing values last in either direction', () => {
        const view = processView(8); view.processMetrics = metrics(view);
        const rows = view.processMetrics.rows;
        [2, 100, 10, 0].forEach((cpuPercent, index) => { rows[index].cpuPercent = cpuPercent; });
        ['9007199254740993', '9007199254740992', '18446744073709551615', '0'].forEach((memoryBytes, index) => { rows[index].memoryBytes = memoryBytes; });
        (['first-sample', 'reset', 'denied', 'unavailable'] as const).forEach((cpuQuality, index) => { Object.assign(rows[index + 4], { cpuQuality, cpuPercent: null, memoryQuality: index % 2 ? 'unavailable' : 'denied', memoryBytes: null }); });
        expect(orderedPids(view, 'cpu-desc')).toEqual([2, 3, 1, 4, 5, 6, 7, 8]);
        expect(orderedPids(view, 'cpu-asc')).toEqual([4, 1, 3, 2, 5, 6, 7, 8]);
        expect(orderedPids(view, 'ram-desc')).toEqual([3, 1, 2, 4, 5, 6, 7, 8]);
        expect(orderedPids(view, 'ram-asc')).toEqual([4, 2, 1, 3, 5, 6, 7, 8]);
        expect(orderedPids(view, 'cpu-desc', '', 'de')).toEqual([2, 3, 1, 4, 5, 6, 7, 8]);
        expect(view.snapshot!.processes.rows.map(row => row.pid)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
        expect(rows.map(row => row.pid)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    });
    it('keeps tied measurements deterministic, treats trimmed or foreign-generation metrics as unknown', () => {
        const view = processView(4); view.processMetrics = metrics(view); view.processMetrics.rows = view.processMetrics.rows.slice(0, 2); view.processMetrics.truncated = true;
        view.processMetrics.rows.forEach(row => { row.cpuPercent = 5; row.memoryBytes = '5'; });
        expect(orderedPids(view, 'cpu-desc')).toEqual([1, 2, 3, 4]);
        expect(orderedPids(view, 'ram-asc')).toEqual([1, 2, 3, 4]);
        view.processMetrics.generationId = `sample_${'b'.repeat(32)}`;
        expect(capturedProcessRows(view.snapshot!, view.processMetrics, '', 'cpu-desc', 'en').every(row => row.metric === undefined)).toBe(true);
    });
    it('filters only captured names and PIDs, with case-insensitive text and numeric PID sort', () => {
        const view = processView(12); view.processMetrics = metrics(view);
        view.snapshot!.processes.rows[0].name = 'My-App.EXE';
        expect(orderedPids(view, 'pid-asc', ' MY-APP ')).toEqual([1]);
        expect(orderedPids(view, 'pid-asc', '12')).toEqual([12]);
        expect(orderedPids(view, 'pid-asc', '4000')).toEqual([]);
        expect(orderedPids(view, 'pid-asc', '7000')).toEqual([]);
        expect(orderedPids(view, 'pid-desc')).toEqual([12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]);
        expect(orderedPids(view, 'name-asc').at(-1)).toBe(1);
        expect(orderedPids(view, 'name-desc')[0]).toBe(1);
    });
});

describe('captured process controls', () => {
    it('pages exactly the captured 128 rows and keeps the bounded observed count distinct', () => {
        const view = processView(128); Object.assign(view.snapshot!.processes, { quality: 'partial', complete: false, observedCount: 700, countExact: false, truncated: true });
        render(<WindowsInventoryWorkspace resource={resource(view)}/>);
        expect(displayedNames()).toHaveLength(25); expect(screen.getByText('128 captured · at least 700 observed')).toBeVisible();
        expect(screen.getByText(/at most 128 captured process rows/)).toBeVisible();
        expect(screen.getByText('Rows 1–25 of 128 matching · 128 captured')).toBeVisible();
        expect(screen.getByRole('button', { name: 'Previous page' })).toBeDisabled();
        for (let page = 1; page < 6; page++) fireEvent.click(screen.getByRole('button', { name: 'Next page' }));
        expect(displayedNames()).toEqual(['fixture-126.exe', 'fixture-127.exe', 'fixture-128.exe']);
        expect(screen.getByText('Rows 126–128 of 128 matching · 128 captured')).toBeVisible(); expect(screen.getByText('Page 6 of 6')).toBeVisible();
        expect(screen.getByRole('button', { name: 'Next page' })).toBeDisabled();
        fireEvent.click(screen.getByRole('button', { name: 'Previous page' })); expect(displayedNames()[0]).toBe('fixture-101.exe');
        expect(request).not.toHaveBeenCalled();
    });
    it('labels metric totals as captured independently of page and filter size', () => {
        const view = processView(); view.processMetrics = metrics(view); render(<WindowsInventoryWorkspace resource={resource(view)}/>);
        expect(screen.getByText('61 captured · 61 observed within bounded scope')).toBeVisible(); expect(displayedNames()).toHaveLength(25);
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: '061' } });
        expect(displayedNames()).toHaveLength(1); expect(screen.getByText('61 captured · 61 observed within bounded scope')).toBeVisible(); expect(screen.queryByText(/^61 shown/)).toBeNull();
    });
    it('retains controls through a deferred same-snapshot poll but never retains visible private rows', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const view = processView(); view.processMetrics = metrics(view); vi.mocked(request).mockResolvedValueOnce(view);
        render(<Harness/>); await act(async () => {});
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'fixture' } }); fireEvent.change(screen.getByRole('combobox'), { target: { value: 'cpu-desc' } }); fireEvent.click(screen.getByRole('button', { name: 'Next page' }));
        let resolve!: (view: WindowsInventoryView) => void; vi.mocked(request).mockReturnValueOnce(new Promise(done => { resolve = done; }));
        await act(async () => vi.advanceTimersByTimeAsync(15000)); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByRole('searchbox')).toBeNull();
        await act(async () => resolve({ ...view, serverNow: '2026-10-07T12:00:25Z' }));
        expect(screen.getByRole('searchbox')).toHaveValue('fixture'); expect(screen.getByRole('combobox')).toHaveValue('cpu-desc'); expect(screen.getByText('Page 2 of 3')).toBeVisible(); expect(displayedNames()[0]).toBe('fixture-036.exe');
    });
    it.each(['blur', 'pagehide', 'hashchange', AUTH_REQUIRED_EVENT])('drops controls with private data on %s', async event => {
        const view = processView(); vi.mocked(request).mockResolvedValue(view); render(<Harness/>); await screen.findByText('fixture-001.exe');
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'fixture' } }); fireEvent.change(screen.getByRole('combobox'), { target: { value: 'pid-desc' } });
        act(() => window.dispatchEvent(new Event(event))); expect(screen.queryByRole('searchbox')).toBeNull(); expect(screen.queryByRole('table')).toBeNull();
        if (event !== AUTH_REQUIRED_EVENT) {
            act(() => window.dispatchEvent(new Event('focus'))); await screen.findByText('fixture-001.exe'); expect(screen.getByRole('searchbox')).toHaveValue(''); expect(screen.getByRole('combobox')).toHaveValue('pid-asc');
        }
    });
    it('resets pages on every filter and sort change, including zero matches and repeated edits', () => {
        render(<WindowsInventoryWorkspace resource={resource()}/>);
        const search = screen.getByRole('searchbox', { name: 'Filter captured processes by name or PID' });
        for (let repeat = 0; repeat < 2; repeat++) {
            fireEvent.click(screen.getByRole('button', { name: 'Next page' }));
            fireEvent.change(search, { target: { value: '061' } }); expect(displayedNames()).toEqual(['fixture-061.exe']); expect(screen.getByText('Page 1 of 1')).toBeVisible();
            fireEvent.change(search, { target: { value: 'absent' } }); expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByText('Rows 0–0 of 0 matching · 61 captured')).toBeVisible(); expect(screen.getByText('No captured processes match this filter.')).toBeVisible();
            fireEvent.change(search, { target: { value: '' } }); expect(displayedNames()[0]).toBe('fixture-001.exe'); expect(screen.getByText('Page 1 of 3')).toBeVisible();
        }
        fireEvent.click(screen.getByRole('button', { name: 'Next page' }));
        fireEvent.change(screen.getByRole('combobox', { name: 'Sort captured processes' }), { target: { value: 'pid-desc' } });
        expect(displayedNames()[0]).toBe('fixture-061.exe'); expect(screen.getByRole('columnheader', { name: 'PID' })).toHaveAttribute('aria-sort', 'descending'); expect(screen.getByText('Page 1 of 3')).toBeVisible(); expect(request).not.toHaveBeenCalled();
    });
    it('clears controls on device, snapshot and absence changes without keeping old row text', () => {
        const first = processView(); const ui = render(<WindowsInventoryWorkspace resource={resource(first)}/>);
        const edit = () => { fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'fixture' } }); fireEvent.change(screen.getByRole('combobox'), { target: { value: 'pid-desc' } }); fireEvent.click(screen.getByRole('button', { name: 'Next page' })); };
        const expectReset = () => { expect(screen.getByRole('searchbox')).toHaveValue(''); expect(screen.getByRole('combobox')).toHaveValue('pid-asc'); expect(screen.getByText('Page 1 of 3')).toBeVisible(); };
        edit(); const device = processView(); device.deviceId = `agent_${'8'.repeat(32)}`; ui.rerender(<WindowsInventoryWorkspace resource={resource(device)}/>); expectReset();
        edit(); const generation = processView(); generation.deviceId = device.deviceId; generation.snapshot!.generationId = `sample_${'b'.repeat(32)}`; ui.rerender(<WindowsInventoryWorkspace resource={resource(generation)}/>); expectReset();
        edit(); ui.rerender(<WindowsInventoryWorkspace resource={{ ...resource(generation), snapshot: null, status: 'unavailable' }}/>); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByRole('searchbox')).toBeNull();
        ui.rerender(<WindowsInventoryWorkspace resource={resource(generation)}/>); expectReset();
        edit(); fireEvent.click(screen.getByRole('tab', { name: 'Services' })); fireEvent.click(screen.getByRole('tab', { name: 'Processes' })); expectReset();
    });
    it('keeps native keyboard controls outside the mobile-hidden table header', async () => {
        const user = userEvent.setup(); render(<WindowsInventoryWorkspace resource={resource()}/>);
        const search = screen.getByRole('searchbox'), sort = screen.getByRole('combobox');
        search.focus(); await user.keyboard('061'); expect(displayedNames()).toEqual(['fixture-061.exe']);
        await user.clear(search); await user.tab(); expect(sort).toHaveFocus(); await user.selectOptions(sort, 'pid-desc');
        await user.tab(); expect(screen.getByRole('button', { name: 'Next page' })).toHaveFocus(); await user.keyboard('{Enter}'); expect(screen.getByText('Page 2 of 3')).toBeVisible();
        expect(sort.closest('thead')).toBeNull(); expect(search.closest('thead')).toBeNull();
        expect(within(screen.getAllByRole('row')[1]).getAllByRole('cell').every(cell => cell.hasAttribute('data-label'))).toBe(true);
    });
    it('localizes all controls and count explanations in German', () => {
        setLocale('de', false); render(<WindowsInventoryWorkspace resource={resource()}/>);
        expect(screen.getByRole('searchbox', { name: 'Erfasste Prozesse nach Name oder PID filtern' })).toBeVisible(); expect(screen.getByRole('combobox', { name: 'Erfasste Prozesse sortieren' })).toBeVisible();
        expect(screen.getByText('61 erfasst · 61 beobachtet')).toBeVisible(); expect(screen.getByText('Zeilen 1–25 von 61 Treffern · 61 erfasst')).toBeVisible();
        fireEvent.click(screen.getByRole('button', { name: 'Nächste Seite' })); expect(screen.getByText('Seite 2 von 3')).toBeVisible(); expect(screen.getByRole('navigation', { name: 'Seiten der erfassten Prozesse' })).toBeVisible();
    });
    it('keeps healthy empty, denied and unavailable inventories distinct and does not add controls', () => {
        const view = processView(0), ui = render(<WindowsInventoryWorkspace resource={resource(view)}/>);
        expect(screen.getByText('No rows observed within this collection scope.')).toBeVisible(); expect(screen.queryByRole('searchbox')).toBeNull();
        for (const quality of ['denied', 'unavailable'] as const) {
            Object.assign(view.snapshot!.processes, { quality, complete: false, countExact: false }); ui.rerender(<WindowsInventoryWorkspace resource={resource(view)}/>);
            expect(screen.getByText('No rows available. This does not establish an empty inventory.')).toBeVisible(); expect(screen.queryByRole('searchbox')).toBeNull();
        }
    });
    it('expires metric values while sorted and paged without hiding younger process rows', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const view = processView(); view.processMetrics = metrics(view); view.processMetrics.collectedAt = '2026-10-06T12:00:11Z'; vi.mocked(request).mockResolvedValue(view);
        render(<Harness/>); await act(async () => {});
        fireEvent.change(screen.getByRole('combobox'), { target: { value: 'cpu-desc' } }); fireEvent.click(screen.getByRole('button', { name: 'Next page' })); expect(displayedNames()[0]).toBe('fixture-036.exe');
        await act(async () => vi.advanceTimersByTimeAsync(1000));
        expect(displayedNames()[0]).toBe('fixture-026.exe'); expect(screen.getByText(/Separate local consent is required/)).toBeVisible(); expect(screen.queryByText('36 %')).toBeNull(); expect(screen.getByText('Page 2 of 3')).toBeVisible();
        expect(within(screen.getAllByRole('row')[1]).getAllByRole('cell')[4]).toHaveTextContent('Unavailable');
    });
    it('hides the entire captured page on original inventory expiry', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const view = processView(); view.status = 'stale'; view.snapshot!.collectedAt = '2026-10-06T12:00:11Z'; vi.mocked(request).mockResolvedValue(view);
        render(<Harness/>); await act(async () => {}); fireEvent.click(screen.getByRole('button', { name: 'Next page' })); expect(displayedNames()[0]).toBe('fixture-026.exe');
        await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByRole('searchbox')).toBeNull(); expect(screen.queryByText('fixture-026.exe')).toBeNull();
    });
});
