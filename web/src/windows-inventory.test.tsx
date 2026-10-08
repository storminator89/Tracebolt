import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, APIError, AUTH_REQUIRED_EVENT, mutate, request } from './api';
import { useOperator } from './auth';
import { DeviceDetail } from './details';
import { setLocale } from './i18n';
import { useWindowsInventory } from './windows-inventory-resource';
import { WindowsInventoryWorkspace } from './windows-inventory';
import { windowsDevice, windowsDeviceId, windowsNow, windowsSection, windowsView } from './windows-inventory-fixture';
import { historyFixture } from './resource-history-fixture';
import { WINDOWS_INVENTORY_VIEW_BYTES, type WindowsInventoryView } from './windows-inventory-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: '2026-10-07T13:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
function Harness({ id = windowsDeviceId, enabled = true, session = 'fixture' }: { id?: string; enabled?: boolean; session?: string }) { return <WindowsInventoryWorkspace resource={useWindowsInventory(id, enabled, session)}/>; }
function deferred<T>() { let resolve!: (v: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { resolve, promise }; }
const flush = () => act(async () => {});
beforeEach(() => { setLocale('en', false); vi.mocked(request).mockReset().mockResolvedValue(windowsView()); vi.mocked(mutate).mockReset(); vi.mocked(useOperator).mockReturnValue(operator); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('Windows inventory within the shared device UI', () => {
    it('renders all five read-only subviews with original capture and accepted times', async () => {
        render(<Harness/>); await screen.findByText('fixture.exe'); expect(screen.getByText('Recent observation')).toBeVisible(); expect(document.querySelector('time[datetime="2026-10-07T12:00:00Z"]')).not.toBeNull(); expect(document.querySelector('time[datetime="2026-10-07T12:00:01Z"]')).not.toBeNull();
        fireEvent.click(screen.getByRole('tab', { name: 'Services' })); expect(screen.getByText('FixtureService')).toBeVisible(); expect(screen.getByText('Running')).toBeVisible();
        fireEvent.click(screen.getByRole('tab', { name: 'Software' })); expect(screen.getByText('Synthetic Application')).toBeVisible(); expect(screen.getByText('64-bit')).toBeVisible();
        fireEvent.click(screen.getByRole('tab', { name: 'Hostname' })); expect(screen.getByText('fixture-windows')).toBeVisible();
        fireEvent.click(screen.getByRole('tab', { name: 'Interfaces' })); expect(screen.getByText('192.0.2.40')).toBeVisible(); expect(screen.getByText('2001:db8::40')).toBeVisible(); expect(screen.queryByRole('link')).toBeNull();
        expect(request).toHaveBeenCalledWith(`/devices/${windowsDeviceId}/windows-inventory`, { signal: expect.any(AbortSignal) }, WINDOWS_INVENTORY_VIEW_BYTES); expect(mutate).not.toHaveBeenCalled();
    });
    it('shows truncated exact and lower-bound counts, and keeps denied separate from healthy empty', async () => {
        const v = windowsView(); v.snapshot!.processes = { ...v.snapshot!.processes, quality: 'partial', observedCount: 180, truncated: true, complete: false }; v.snapshot!.services = { ...windowsSection([]), quality: 'denied', complete: false, countExact: false }; v.snapshot!.software = windowsSection([]); vi.mocked(request).mockResolvedValue(v);
        render(<Harness/>); await screen.findByText('fixture.exe'); expect(screen.getByText('1 shown · 180 observed')).toBeVisible(); expect(screen.getByText('Partial observation')).toBeVisible(); expect(screen.getByText(/Rows omitted by/)).toBeVisible();
        fireEvent.click(screen.getByRole('tab', { name: 'Services' })); expect(screen.getByText('Permission denied')).toBeVisible(); expect(screen.getByText('No rows available. This does not establish an empty inventory.')).toBeVisible(); expect(screen.queryByText('0 shown · 0 observed')).toBeNull();
        fireEvent.click(screen.getByRole('tab', { name: 'Software' })); expect(screen.getByText('No rows observed within this collection scope.')).toBeVisible();
        v.snapshot!.processes.countExact = false; vi.mocked(request).mockResolvedValue(v); fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); await screen.findByText('No rows observed within this collection scope.'); fireEvent.click(screen.getByRole('tab', { name: 'Processes' })); expect(screen.getByText('1 shown · at least 180 observed')).toBeVisible();
    });
    it('filters only visible rows and supports keyboard tabs without interpreting labels as markup', async () => {
        const v = windowsView(); v.snapshot!.processes.rows[0].name = '<img src=x onerror=alert(1)>'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await screen.findByText('<img src=x onerror=alert(1)>'); expect(document.querySelector('img')).toBeNull();
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'unmatched' } }); expect(screen.getByText('No displayed rows match this filter.')).toBeVisible(); expect(screen.getByText('1 shown · 1 observed')).toBeVisible();
        fireEvent.keyDown(screen.getByRole('tab', { name: 'Processes' }), { key: 'ArrowRight' }); expect(screen.getByRole('tab', { name: 'Services' })).toHaveFocus(); expect(screen.getByText('FixtureService')).toBeVisible(); expect(screen.getByRole('searchbox')).toHaveValue('');
    });
    it('renders German labels and explicit stale metadata', async () => {
        setLocale('de', false); const v = windowsView(); v.status = 'stale'; v.snapshot!.collectedAt = '2026-10-07T11:55:00Z'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await screen.findByText('fixture.exe'); expect(screen.getByText('Veraltete Beobachtung')).toBeVisible(); expect(screen.getByRole('tab', { name: 'Schnittstellen' })).toBeVisible(); expect(screen.getByText(/ursprüngliche Erfassung/)).toBeVisible();
    });
    it.each(['en', 'de'] as const)('labels the inventory capture without claiming a denied hostname in %s', async locale => {
        setLocale(locale, false); const value = windowsView();
        value.snapshot!.hostname = { ...windowsSection([]), quality: 'denied', complete: false, countExact: false };
        const history = historyFixture(); history.deviceId = windowsDeviceId;
        vi.mocked(request).mockImplementation(async path => path === `/devices/${windowsDeviceId}` ? windowsDevice() : path.endsWith('/windows-inventory') ? value : path.endsWith('/resource-history') ? history : Promise.reject(new Error('Unexpected fixture route')));
        render(<DeviceDetail id={windowsDeviceId} onClose={vi.fn()} onCase={vi.fn()}/>);
        await screen.findByRole('heading', { name: windowsDeviceId });
        await waitFor(() => expect(document.querySelector('.device-detail-heading .detail-time')).toHaveTextContent(locale === 'de' ? 'Inventar erfasst' : 'Inventory observed'));
        expect(document.querySelector('.device-detail-heading')).not.toHaveTextContent(/Hostname observed|Hostname erfasst|fixture-windows/);
        expect(document.querySelector('.device-detail-heading time')).toHaveAttribute('datetime', value.snapshot!.collectedAt);
        fireEvent.click(screen.getByRole('tab', { name: locale === 'de' ? 'Inventar' : 'Inventory' }));
        fireEvent.click(screen.getByRole('tab', { name: 'Hostname' }));
        expect(screen.getByText(locale === 'de' ? 'Berechtigung verweigert' : 'Permission denied')).toBeVisible();
        expect(document.querySelector('.windows-inventory-table')).toBeNull();
    });
    it('mounts Windows inventory and existing resource charts without Linux endpoints or tabs', async () => {
        const history = historyFixture(); history.deviceId = windowsDeviceId;
        vi.mocked(request).mockImplementation(async path => path === `/devices/${windowsDeviceId}` ? windowsDevice() : path.endsWith('/windows-inventory') ? windowsView() : path.endsWith('/resource-history') ? history : Promise.reject(new Error(`Unexpected fixture path: ${path}`)));
        render(<DeviceDetail id={windowsDeviceId} onClose={vi.fn()} onCase={vi.fn()}/>); await screen.findByRole('heading', { name: 'fixture-windows' }); await screen.findByRole('img', { name: /^System volume/ }); expect(screen.getAllByRole('img')).toHaveLength(3); expect(screen.queryByText('cached candidates')).toBeNull(); expect(screen.queryByRole('tab', { name: /CVE|Logs|Security coverage/ })).toBeNull();
        fireEvent.click(screen.getByRole('tab', { name: /Health/ })); await screen.findByText('No current event scope reported. Health unknown.');
        fireEvent.click(screen.getByRole('tab', { name: 'Inventory' })); await screen.findByText('fixture.exe'); fireEvent.click(screen.getByRole('tab', { name: 'Interfaces' })); expect(screen.getByText('192.0.2.40')).toBeVisible();
        expect(vi.mocked(request).mock.calls.map(([path]) => path).every(path => path === `/devices/${windowsDeviceId}` || path.endsWith('/windows-inventory') || path.endsWith('/resource-history'))).toBe(true);
    });
});

describe('Windows inventory request boundaries', () => {
    it('makes no protected request when disabled or initially hidden', async () => {
        const view = render(<Harness enabled={false}/>); await flush(); expect(request).not.toHaveBeenCalled(); view.unmount(); vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); render(<Harness/>); await flush(); expect(request).not.toHaveBeenCalled();
    });
    it('rejects unknown fields and raw errors without exposing their contents', async () => {
        vi.mocked(request).mockResolvedValue({ ...windowsView(), private: 'fixture-secret-do-not-display' }); render(<Harness/>); await screen.findByRole('alert'); expect(screen.getByRole('alert')).toHaveTextContent('inconsistent or unsupported'); expect(document.body).not.toHaveTextContent('fixture-secret-do-not-display');
        vi.mocked(request).mockRejectedValue(new APIError('fixture-secret-do-not-display')); fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('unavailable')); expect(document.body).not.toHaveTextContent('fixture-secret-do-not-display');
    });
    it.each(['revoked', 'unavailable', 'awaiting', 'not_configured'] as const)('clears retained rows when the manager returns %s', async status => {
        render(<Harness/>); await screen.findByText('fixture.exe'); const empty = { ...windowsView(), status, snapshot: null, ...(['awaiting', 'not_configured'].includes(status) ? { sequence: null, receivedAt: null } : {}) }; vi.mocked(request).mockResolvedValue(empty); fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); await waitFor(() => expect(screen.queryByText('Checking Windows inventory…')).not.toBeInTheDocument()); expect(screen.queryByText('fixture.exe')).toBeNull(); expect(screen.queryByRole('table')).toBeNull();
    });
    it('aborts a late response on device navigation and session changes', async () => {
        const late = deferred<WindowsInventoryView>(); vi.mocked(request).mockReturnValueOnce(late.promise); const result = render(<Harness/>); await flush(); const signal = vi.mocked(request).mock.calls[0][1]?.signal;
        const id = `agent_${'8'.repeat(32)}`, next = windowsView(); next.deviceId = id; next.snapshot!.processes.rows[0].name = 'second.exe'; vi.mocked(request).mockResolvedValue(next); result.rerender(<Harness id={id} session="new-session"/>); await screen.findByText('second.exe'); expect(signal?.aborted).toBe(true); await act(async () => late.resolve(windowsView())); expect(screen.queryByText('fixture.exe')).toBeNull(); expect(screen.getByText('second.exe')).toBeVisible();
    });
    it('clears on pagehide and ignores the canceled response until a visible reread', async () => {
        const late = deferred<WindowsInventoryView>(); render(<Harness/>); await screen.findByText('fixture.exe'); vi.mocked(request).mockReturnValueOnce(late.promise); fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); act(() => window.dispatchEvent(new Event('pagehide'))); await act(async () => late.resolve(windowsView())); expect(screen.queryByText('fixture.exe')).toBeNull(); act(() => window.dispatchEvent(new Event('pageshow'))); await screen.findByText('fixture.exe');
    });
    it('locks on authentication loss, clears rows, and prevents manual rereads', async () => {
        render(<Harness/>); await screen.findByText('fixture.exe'); act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); expect(screen.queryByText('fixture.exe')).toBeNull(); expect(screen.getByRole('button', { name: 'Refresh Windows inventory' })).toBeDisabled(); expect(screen.getByRole('alert')).toHaveTextContent('Sign in again'); const count = vi.mocked(request).mock.calls.length; fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); expect(request).toHaveBeenCalledTimes(count);
    });
    it('bounds request duration and ignores a response delivered after timeout', async () => {
        vi.useFakeTimers(); const late = deferred<WindowsInventoryView>(); vi.mocked(request).mockReturnValue(late.promise); render(<Harness/>); await flush(); await act(async () => vi.advanceTimersByTimeAsync(10001)); expect(screen.getByRole('alert')).toHaveTextContent('timed out'); await act(async () => late.resolve(windowsView())); expect(screen.queryByText('fixture.exe')).toBeNull();
    });
    it('never refreshes capture time and rejects a regressed manager clock', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); render(<Harness/>); await flush(); const v = windowsView(); v.serverNow = '2026-10-07T11:59:59Z'; v.receivedAt = '2026-10-07T11:59:58Z'; v.snapshot!.collectedAt = '2026-10-07T11:59:57Z'; vi.mocked(request).mockResolvedValue(v); fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('time reference changed'); expect(screen.queryByText('fixture.exe')).toBeNull();
    });
    it('keeps one cumulative clock floor across rapid tolerated identical replies', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); render(<Harness/>); await flush();
        fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); await flush(); expect(screen.getByText('fixture.exe')).toBeVisible();
        await act(async () => vi.advanceTimersByTimeAsync(1000)); fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); await flush(); expect(screen.getByText('fixture.exe')).toBeVisible();
        await act(async () => vi.advanceTimersByTimeAsync(1000)); fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); await flush();
        expect(screen.queryByText('fixture.exe')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('time reference changed');
    });
    it.each([0, 1000])('rejects repeatedly replayed or slowly advancing manager time (%i ms)', async advance => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); render(<Harness/>); await flush();
        expect(screen.getByText('fixture.exe')).toBeVisible();
        const replay = windowsView(); replay.serverNow = new Date(Date.parse(replay.serverNow) + advance).toISOString(); vi.mocked(request).mockResolvedValue(replay);
        await act(async () => vi.advanceTimersByTimeAsync(15000));
        expect(screen.queryByText('fixture.exe')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('time reference changed');
        // A failed read must not erase the original successful response anchor.
        await act(async () => vi.advanceTimersByTimeAsync(15000));
        expect(screen.queryByText('fixture.exe')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('time reference changed');
        // Recovery requires a time reference that actually progressed.
        const current = windowsView(); current.serverNow = new Date(Date.parse(current.serverNow) + 30000).toISOString(); vi.mocked(request).mockResolvedValue(current);
        fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); await flush();
        expect(screen.getByText('fixture.exe')).toBeVisible();
    });
    it('clears sensitive rows after an untrusted browser clock jump', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); render(<Harness/>); await flush(); vi.setSystemTime('2026-10-07T14:00:00Z'); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.queryByText('fixture.exe')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('time reference changed');
    });
});
