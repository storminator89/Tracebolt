import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, abortProtectedRequests, AUTH_REQUIRED_EVENT, request } from './api';
import { setLocale } from './i18n';
import { WindowsInventoryWorkspace } from './windows-inventory';
import { useWindowsInventory, type WindowsInventoryResource } from './windows-inventory-resource';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import { windowsServiceStartup, windowsServiceStartupView } from './windows-service-startup-fixture';
import { windowsServicesDigest } from './windows-service-startup-types';
import { capturedInventoryTableRows } from './windows-inventory-tables';
import { serviceStartupCell } from './windows-service-startup';
import { validWindowsInventoryView, type WindowsInventoryView } from './windows-inventory-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
const flush = () => act(async () => {});
function resource(view: WindowsInventoryView = windowsServiceStartupView()): WindowsInventoryResource {
    return { elapsedMS: 0, view, snapshot: view.snapshot, status: view.status, loading: false, error: null, refresh: vi.fn(), serviceStartup: view.serviceStartup ?? null, serviceStartupStale: view.status === 'stale', processMetrics: null, processMetricsStale: false, network: null, networkStale: false, networkExpired: false, volumes: null, volumesStale: false, events: null, eventsStale: false };
}
function Harness({ id = windowsDeviceId, session = 'fixture', enabled = true }: { id?: string; session?: string; enabled?: boolean }) { return <WindowsInventoryWorkspace key={`${id}:${session}`} resource={useWindowsInventory(id, enabled, session)}/>; }
const selectServices = (locale = 'en') => fireEvent.click(screen.getByRole('tab', { name: locale === 'de' ? 'Dienste' : 'Services' }));
const cells = (name: string) => within(screen.getByText(name).closest('tr')!).getAllByRole('cell').map(cell => cell.textContent);
const rows = () => within(screen.getByRole('table')).getAllByRole('row').slice(1).map(row => within(row).getAllByRole('cell').map(cell => cell.textContent));
beforeEach(() => { setLocale('en', false); vi.mocked(request).mockReset().mockResolvedValue(windowsServiceStartupView()); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('localized startup mode in the existing Services table', () => {
    it('adds one column and preserves name/display name/state/PID independently of configuration', () => {
        render(<WindowsInventoryWorkspace resource={resource()}/>); selectServices();
        expect(screen.getAllByRole('columnheader').map(cell => cell.textContent)).toEqual(['Name', 'Display name', 'State', 'PID', 'Startup mode']);
        expect(cells('Service-001')).toEqual(['Service-001', 'Synthetic display 1', 'Running', '1', 'Automatic (delayed)']);
        expect(cells('Service-002')).toEqual(['Service-002', 'Synthetic display 2', 'Stopped', '0', 'Automatic (not delayed)']);
        expect(cells('Service-003')[4]).toBe('Manual'); expect(cells('Service-004')[4]).toBe('Disabled');
        expect(cells('Service-005')[4]).toBe('Access denied'); expect(cells('Service-006')[4]).toBe('Unavailable'); expect(cells('Service-007')[4]).toBe('Unknown');
        expect(cells('Service-008')[4]).toBe('Automatic · delayed status: Access denied (partial)');
        expect(cells('Service-009')[4]).toBe('Automatic · delayed status: Unavailable (partial)');
        expect(cells('Service-010')[4]).toBe('Automatic · delayed status: Unknown (partial)');
        expect(screen.getByText(/Captured startup configuration is separate/)).toHaveTextContent('Trigger information is not collected.');
        expect(screen.queryByRole('link')).toBeNull(); expect(screen.queryByRole('button', { name: /grant|enable|start service|stop service|restart|apply/i })).toBeNull();
        expect(request).not.toHaveBeenCalled();
    });
    it.each(['en', 'de'] as const)('keeps base ordinal binding under %s mode/name sorting and localized search', locale => {
        const view = windowsServiceStartupView(), snapshot = view.snapshot!, startup = view.serviceStartup, before = JSON.stringify(view);
        for (const sort of ['name-asc', 'name-desc', 'pid-asc', 'pid-desc', 'state-asc', 'state-desc', 'startup-asc', 'startup-desc'] as const) {
            const sorted = capturedInventoryTableRows(snapshot, 'services', '', sort, locale, startup);
            for (const row of sorted) expect(row.cells[4]).toBe(serviceStartupCell(startup.rows.find(s => s.serviceIndex === row.index), startup, locale));
        }
        const asc = capturedInventoryTableRows(snapshot, 'services', '', 'startup-asc', locale, startup), desc = capturedInventoryTableRows(snapshot, 'services', '', 'startup-desc', locale, startup);
        expect(asc.slice(-3).map(row => row.index)).toEqual([4, 5, 6]); expect(desc.slice(-3).map(row => row.index)).toEqual([4, 5, 6]);
        expect(asc[0].index).toBe(0); expect(desc[0].index).toBe(2);
        expect(capturedInventoryTableRows(snapshot, 'services', locale === 'en' ? 'manual' : 'manuell', 'startup-asc', locale, startup).map(row => row.index)).toEqual([2]);
        expect(capturedInventoryTableRows(snapshot, 'services', locale === 'en' ? 'partial' : 'teilweise', 'startup-desc', locale, startup).map(row => row.index)).toEqual([7, 8, 9]);
        expect(capturedInventoryTableRows(snapshot, 'services', 'denied', 'name-asc', locale, startup).map(row => row.index)).toEqual([4, 7]);
        expect(capturedInventoryTableRows(snapshot, 'services', 'automatic', 'name-asc', locale, startup)).toHaveLength(5);
        expect(JSON.stringify(view)).toBe(before);
    });
    it('keeps duplicate names as distinct original indices even after non-prefix metadata trimming', () => {
        const view = windowsServiceStartupView(); view.snapshot!.services.rows.forEach(row => { row.name = 'Same service'; }); view.serviceStartup.servicesSHA256 = windowsServicesDigest(view.snapshot!.services.rows);
        view.serviceStartup.rows = [view.serviceStartup.rows[2], view.serviceStartup.rows[8]]; view.serviceStartup.truncated = true;
        expect(validWindowsInventoryView(view, windowsDeviceId)).toBe(true);
        render(<WindowsInventoryWorkspace resource={resource(view)}/>); selectServices(); fireEvent.change(screen.getByRole('combobox'), { target: { value: 'startup-desc' } });
        expect(rows()).toHaveLength(10); expect(rows()[0]).toEqual(['Same service', 'Synthetic display 3', 'Running', '3', 'Manual']);
        expect(rows()[1][4]).toBe('Automatic · delayed status: Unavailable (partial)');
        expect(screen.getAllByText('Not captured (trimmed)')).toHaveLength(8);
        expect(screen.getByText(/Startup rows omitted/)).toBeVisible(); expect(screen.getByText('2 startup rows captured · 10 base service rows requested')).toBeVisible();
    });
    it('pages all 128 base rows once with startup values still bound to their original indices', () => {
        const view = windowsServiceStartupView(128); view.serviceStartup.rows = view.serviceStartup.rows.slice(0, 50); view.serviceStartup.truncated = true;
        expect(validWindowsInventoryView(view, windowsDeviceId)).toBe(true);
        render(<WindowsInventoryWorkspace resource={resource(view)}/>); selectServices(); fireEvent.change(screen.getByRole('combobox'), { target: { value: 'name-desc' } });
        const seen: string[] = [];
        for (let page = 0; page < 6; page++) {
            for (const row of rows()) {
                const name = row[0]!, index = Number(name.slice(-3)) - 1; seen.push(name);
                expect(row[4]).toBe(serviceStartupCell(view.serviceStartup.rows.find(r => r.serviceIndex === index), view.serviceStartup, 'en'));
            }
            if (page < 5) fireEvent.click(screen.getByRole('button', { name: 'Next page' }));
        }
        expect(new Set(seen).size).toBe(128); expect(seen).toHaveLength(128); expect(screen.getByRole('button', { name: 'Next page' })).toBeDisabled();
        fireEvent.change(screen.getByRole('combobox'), { target: { value: 'startup-asc' } }); expect(screen.getByText('Page 1 of 6')).toBeVisible();
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'trimmed' } }); expect(screen.getByText('Rows 1–25 of 78 matching · 128 captured')).toBeVisible();
        expect(request).not.toHaveBeenCalled();
    });
    it.each(['en', 'de'] as const)('localizes %s keyboard controls, sort metadata and mobile labels', async locale => {
        setLocale(locale, false); const user = userEvent.setup(); render(<WindowsInventoryWorkspace resource={resource(windowsServiceStartupView(61))}/>); selectServices(locale);
        const search = screen.getByRole('searchbox'), sort = screen.getByRole('combobox'); search.focus(); await user.tab(); expect(sort).toHaveFocus();
        await user.selectOptions(sort, 'startup-desc'); expect(screen.getByRole('columnheader', { name: locale === 'en' ? 'Startup mode' : 'Starttyp' })).toHaveAttribute('aria-sort', 'descending');
        await user.selectOptions(sort, 'startup-asc'); expect(screen.getByRole('columnheader', { name: locale === 'en' ? 'Startup mode' : 'Starttyp' })).toHaveAttribute('aria-sort', 'ascending');
        fireEvent.change(search, { target: { value: locale === 'en' ? 'Access denied' : 'Zugriff verweigert' } }); expect(rows().length).toBeGreaterThan(0);
        expect(rows().every(row => row[4]!.includes(locale === 'en' ? 'Access denied' : 'Zugriff verweigert'))).toBe(true);
        expect(screen.getAllByRole('cell').filter(cell => cell.getAttribute('data-label') === (locale === 'en' ? 'Startup mode' : 'Starttyp')).length).toBe(rows().length);
        expect(search.closest('thead')).toBeNull(); expect(sort.closest('thead')).toBeNull();
    });
    it('distinguishes absent scope, trimmed rows and successful zero without inventing disabled', () => {
        const ui = render(<WindowsInventoryWorkspace resource={resource(windowsView())}/>); selectServices();
        expect(screen.getByText('Not configured or not captured')).toBeVisible(); expect(screen.getByText(/Service startup metadata is not configured/)).toBeVisible();
        expect(screen.queryByText('Disabled')).toBeNull();
        const v = windowsServiceStartupView(0); ui.rerender(<WindowsInventoryWorkspace resource={resource(v)}/>);
        expect(screen.getByText('0 startup rows captured · 0 base service rows requested')).toBeVisible(); expect(screen.getByText('No rows observed within this collection scope.')).toBeVisible(); expect(screen.queryByRole('table')).toBeNull();
    });
    it('keeps labels as inert text and does not search them as regex or convert them to links', () => {
        const view = windowsServiceStartupView(); view.snapshot!.services.rows[0].name = '<img src=x onerror=alert(1)>'; view.snapshot!.services.rows[0].displayName = '[.*] https://fixture.invalid/'; view.serviceStartup.servicesSHA256 = windowsServicesDigest(view.snapshot!.services.rows);
        render(<WindowsInventoryWorkspace resource={resource(view)}/>); selectServices();
        expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeVisible(); expect(document.querySelector('img')).toBeNull(); expect(screen.queryByRole('link')).toBeNull();
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: '[.*]' } }); expect(rows()).toHaveLength(1);
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: '[a-z]+' } }); expect(screen.queryByRole('table')).toBeNull();
    });
});

describe('startup metadata shares the protected resource lifetime', () => {
    it('hides metadata during a same-generation retry and retains only table controls', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const view = windowsServiceStartupView(61); vi.mocked(request).mockResolvedValueOnce(view);
        render(<Harness/>); await flush(); selectServices(); fireEvent.change(screen.getByRole('combobox'), { target: { value: 'startup-desc' } }); fireEvent.click(screen.getByRole('button', { name: 'Next page' }));
        let resolve!: (view: WindowsInventoryView) => void; vi.mocked(request).mockReturnValueOnce(new Promise(done => { resolve = done; }));
        await act(async () => vi.advanceTimersByTimeAsync(15000)); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByText(/startup rows captured/)).toBeNull();
        await act(async () => resolve({ ...view, serverNow: '2026-10-07T12:00:25Z' }));
        expect(screen.getByRole('combobox')).toHaveValue('startup-desc'); expect(screen.getByText('Page 2 of 3')).toBeVisible();
        expect(document.querySelectorAll(`time[datetime="${view.serviceStartup.collectedAt}"]`).length).toBe(2);
    });
    it('clears mode controls on a new generation and never carries old startup data into a capability-absent response', async () => {
        render(<Harness/>); await flush(); selectServices(); fireEvent.change(screen.getByRole('combobox'), { target: { value: 'startup-desc' } });
        const next = windowsServiceStartupView(); next.snapshot!.generationId = `sample_${'b'.repeat(32)}`; next.serviceStartup = windowsServiceStartup(next.snapshot!); next.serviceStartup.rows[0] = { serviceIndex: 0, startupMode: 'disabled', startupQuality: 'observed', delayedAutoStart: null, delayedAutoQuality: 'not-applicable' };
        vi.mocked(request).mockResolvedValueOnce(next); fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); await flush(); expect(screen.getByRole('combobox')).toHaveValue('name-asc'); expect(cells('Service-001')[4]).toBe('Disabled');
        vi.mocked(request).mockResolvedValueOnce(windowsView()); fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); await flush(); expect(screen.getByText('Not configured or not captured')).toBeVisible(); expect(screen.queryByText('Disabled')).toBeNull();
    });
    it('resets startup filtering and sort on tab departure and capture replacement', () => {
        const view = windowsServiceStartupView(61), ui = render(<WindowsInventoryWorkspace resource={resource(view)}/>); selectServices();
        const edit = () => { fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'automatic' } }); fireEvent.change(screen.getByRole('combobox'), { target: { value: 'startup-desc' } }); };
        edit(); fireEvent.click(screen.getByRole('tab', { name: 'Software' })); selectServices();
        expect(screen.getByRole('searchbox')).toHaveValue(''); expect(screen.getByRole('combobox')).toHaveValue('name-asc');
        edit(); const next = windowsServiceStartupView(61); next.snapshot!.collectedAt = '2026-10-07T12:00:01Z'; next.serviceStartup.collectedAt = next.snapshot!.collectedAt;
        ui.rerender(<WindowsInventoryWorkspace resource={resource(next)}/>); expect(screen.getByRole('searchbox')).toHaveValue(''); expect(screen.getByRole('combobox')).toHaveValue('name-asc');
    });
    it('suppresses the original response when a newer device request has already succeeded', async () => {
        let original!: (view: WindowsInventoryView) => void; vi.mocked(request).mockReturnValueOnce(new Promise(done => { original = done; }));
        const ui = render(<Harness/>), next = windowsServiceStartupView(); next.deviceId = `agent_${'8'.repeat(32)}`; next.snapshot!.generationId = `sample_${'b'.repeat(32)}`; next.serviceStartup = windowsServiceStartup(next.snapshot!); next.snapshot!.services.rows[0].name = 'New device service'; next.serviceStartup.servicesSHA256 = windowsServicesDigest(next.snapshot!.services.rows);
        vi.mocked(request).mockResolvedValueOnce(next); ui.rerender(<Harness id={next.deviceId}/>); await flush(); selectServices(); expect(screen.getByText('New device service')).toBeVisible();
        await act(async () => original(windowsServiceStartupView())); expect(screen.getByText('New device service')).toBeVisible(); expect(screen.queryByText('Service-001')).toBeNull();
    });
    it.each(['blur', 'pagehide', 'hashchange', AUTH_REQUIRED_EVENT])('discards startup data and suppresses a late response after %s', async event => {
        render(<Harness/>); await flush(); selectServices(); expect(screen.getByText('Automatic (delayed)')).toBeVisible();
        let resolve!: (view: WindowsInventoryView) => void; vi.mocked(request).mockReturnValueOnce(new Promise(done => { resolve = done; })); fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' }));
        act(() => window.dispatchEvent(new Event(event))); await act(async () => resolve(windowsServiceStartupView()));
        expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByText('Automatic (delayed)')).toBeNull(); expect(screen.queryByText(/startup rows captured/)).toBeNull();
    });
    it('discards startup data on hidden visibility, session replacement, device changes and disabled resource', async () => {
        const ui = render(<Harness/>); await flush(); selectServices();
        vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); expect(screen.queryByRole('table')).toBeNull();
        vi.restoreAllMocks(); ui.rerender(<Harness session="replacement"/>); await flush(); selectServices(); expect(screen.getByText('Automatic (delayed)')).toBeVisible();
        ui.rerender(<Harness id={`agent_${'8'.repeat(32)}`} session="replacement"/>); expect(screen.queryByText('Automatic (delayed)')).toBeNull(); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('inconsistent');
        ui.rerender(<Harness enabled={false}/>); expect(screen.queryByRole('table')).toBeNull();
    });
    it.each(['revoked', 'unavailable', 'awaiting', 'not_configured'] as const)('hides startup and base rows for %s', async status => {
        render(<Harness/>); await flush(); selectServices();
        vi.mocked(request).mockResolvedValue({ ...windowsView(), status, snapshot: null, ...(['awaiting', 'not_configured'].includes(status) ? { sequence: null, receivedAt: null } : {}) });
        fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); await flush(); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByText('Automatic (delayed)')).toBeNull();
    });
    it('marks stale configuration and expires it at the original base capture even if startup capture is later', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const view = windowsServiceStartupView(); view.snapshot!.collectedAt = '2026-10-06T12:00:11Z'; view.serviceStartup.collectedAt = '2026-10-06T12:00:12Z'; view.status = 'stale'; vi.mocked(request).mockResolvedValue(view);
        render(<Harness/>); await flush(); selectServices(); expect(screen.getByText(/Stale startup configuration/)).toBeVisible(); expect(screen.getByText('Automatic (delayed)')).toBeVisible();
        await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByText(/startup rows captured/)).toBeNull(); expect(screen.queryByText(/Stale startup configuration/)).toBeNull();
    });
    it('rejects regressed/replayed server time without renewing original capture', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); render(<Harness/>); await flush(); selectServices();
        await act(async () => vi.advanceTimersByTimeAsync(15000)); expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('time reference changed');
    });
    it('clears all startup values after an untrusted browser clock step', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); render(<Harness/>); await flush(); selectServices(); vi.setSystemTime('2026-10-07T11:00:00Z');
        await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('time reference changed');
    });
    it('fails closed on a mismatched row digest and never echoes unknown private fields or raw errors', async () => {
        const bad = windowsServiceStartupView(); bad.snapshot!.services.rows.reverse(); vi.mocked(request).mockResolvedValue(bad); render(<Harness/>); await flush(); selectServices(); expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('inconsistent');
        vi.mocked(request).mockResolvedValue({ ...windowsServiceStartupView(), serviceStartup: { ...bad.serviceStartup, private: 'private-raw-secret' } }); fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); await flush(); expect(document.body).not.toHaveTextContent('private-raw-secret');
        vi.mocked(request).mockRejectedValue(new APIError('private-raw-secret', 401)); fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('Sign in again'); expect(document.body).not.toHaveTextContent('private-raw-secret');
    });
});
