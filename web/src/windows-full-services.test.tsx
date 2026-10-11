import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { WindowsFullServicesPanel } from './windows-full-services';
import { WindowsInventoryWorkspace } from './windows-inventory';
import { useWindowsInventory } from './windows-inventory-resource';
import { fullServiceRows, fullServicesComplete, fullServicesDevice, fullServicesNow, fullServicesPage, fullServicesQuery, fullServicesUnavailable, replaceFullServicesGeneration } from './windows-full-services-fixtures';
import { FULL_SERVICES_PAGE_BYTES } from './windows-full-services-types';
import type { FullServicesPage, FullServicesQuery } from './windows-full-services-types';
import { DeviceDetail } from './details';
import { windowsDevice, windowsView } from './windows-inventory-fixture';

vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
const deferred = <T,>() => { let resolve!: (v: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; };
const flush = async () => { await act(async () => { for (let i = 0; i < 12; i++) await Promise.resolve(); }); };
function fixtureServer() {
    const rows = fullServiceRows(), complete = fullServicesComplete(), began = Date.now();
    const issued = new Map<string, { search: string; sort: string; generation: string; offset: number; expiry: string }>();
    const state = { rows, complete, requests: [] as FullServicesQuery[], status: null as FullServicesPage['status'] | null, failure: 0, change: null as ((page: FullServicesPage) => void) | null };
    const fetch = vi.fn(async (path: string, options?: RequestInit): Promise<Response> => {
        if (path === `/api/devices/${fullServicesDevice}`) return response({ ...windowsDevice(), id: fullServicesDevice });
        if (path === '/api/session') return response({ csrfToken: 'synthetic-csrf' });
        if (path.endsWith('/windows-inventory')) { const preview = windowsView(); preview.deviceId = fullServicesDevice; return response(preview); }
        if (path !== `/api/devices/${fullServicesDevice}/windows-full-services/query`) return response({}, 404);
        const query = JSON.parse(options!.body as string) as FullServicesQuery; state.requests.push(query);
        if (state.failure) return response({ error: { code: 'synthetic_error', message: 'PRIVATE-ERROR-DO-NOT-RENDER' } }, state.failure);
        const cursor = issued.get(query.cursor);
        if (query.cursor && (!cursor || cursor.search !== query.search || cursor.sort !== query.sort || cursor.generation !== state.complete.manifest.generationId)) return response({ error: { code: 'windows_full_services_restart_required' } }, 409);
        const page = state.status && state.status !== 'ready' ? { ...fullServicesUnavailable(state.status), search: query.search, sort: query.sort, limit: query.limit } : fullServicesPage(query, state.rows, state.complete, cursor?.offset ?? 0);
        page.serverNow = new Date(Date.parse(fullServicesNow) + Date.now() - began).toISOString();
        if (page.status === 'ready') {
            page.cursorExpiresAt = cursor?.expiry ?? new Date(Math.min(Date.parse(page.serverNow) + 900000, Date.parse(page.complete!.manifest.expiresAt), Date.parse(page.authorityUntil!))).toISOString();
            if (page.nextCursor) {
                page.nextCursor = `cursor_${issued.size}_${page.offset + page.rows.length}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`;
                issued.set(page.nextCursor, { search: query.search, sort: query.sort, generation: page.complete!.manifest.generationId, offset: page.offset + page.rows.length, expiry: page.cursorExpiresAt });
            }
        }
        state.change?.(page);
        return response(page);
    });
    vi.stubGlobal('fetch', fetch); return { ...state, state, fetch };
}
const open = (enabled = true, session = 'session-a') => render(<WindowsFullServicesPanel deviceId={fullServicesDevice} sessionKey={session} enabled={enabled}/>);
const names = () => Array.from(document.querySelectorAll('.windows-full-services tbody tr')).map(row => row.querySelector('td')!.textContent);
const search = (value: string) => fireEvent.change(screen.getByRole('searchbox'), { target: { value } });
const apply = () => fireEvent.click(screen.getByRole('button', { name: /Apply search and sort|Suche und Sortierung anwenden/ }));
beforeEach(() => { setLocale('en', false); vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, expiresAt: 'synthetic-session', insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() }); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('complete Windows service browsing through released protected fetch', () => {
    it.each(['en', 'de'] as const)('browses all 617 Go-generated rows in bounded pages with later search and literal labels (%s)', async locale => {
        setLocale(locale, false); const server = fixtureServer(); open(); await screen.findByRole('table');
        expect(names()).toHaveLength(100); expect(screen.getByRole('button', { name: locale === 'en' ? 'Previous service page' : 'Vorherige Dienstseite' })).toBeDisabled();
        const details = document.querySelector('.windows-full-services-details')!;
        expect(details).not.toHaveAttribute('open');
        expect(within(details as HTMLElement).getByText(locale === 'en' ? /All Win32 services/ : /Alle Win32-Dienste/)).not.toBeVisible();
        expect(document.querySelector('.windows-full-services-summary')).toHaveTextContent(locale === 'en' ? '617 services' : '617 Dienste');
        const originalReceipt = details.querySelector(`time[datetime="${server.complete.receivedAt}"]`)!;
        expect(originalReceipt).not.toBeVisible(); fireEvent.click(details.querySelector('summary')!); expect(originalReceipt).toBeVisible();
        fireEvent.click(details.querySelector('summary')!); expect(originalReceipt).not.toBeVisible();
        const seen = [...names()];
        for (let i = 1; i <= 6; i++) { fireEvent.click(screen.getByRole('button', { name: locale === 'en' ? 'Next service page' : 'Nächste Dienstseite' })); await waitFor(() => expect(names()[0]).toBe(`FixtureService${String(i * 100).padStart(4, '0')}`)); expect(names().length).toBeLessThanOrEqual(100); seen.push(...names()); }
        expect(seen).toEqual(server.rows.map(row => row.name)); expect(names()).toHaveLength(17); expect(screen.getByRole('button', { name: locale === 'en' ? 'Next service page' : 'Nächste Dienstseite' })).toBeDisabled();
        expect(screen.getByText('<img src=x onerror=alert(1)> [.*] ÄÖÜ & 🛠')).toBeVisible(); expect(document.querySelector('img,script:not([src])')).toBeNull(); expect(screen.queryByRole('link')).toBeNull();
        expect(screen.getAllByText(locale === 'en' ? 'Unavailable in this capture' : 'In dieser Erfassung nicht verfügbar')).toHaveLength(8);
        search('[.*]'); expect(screen.queryByRole('table')).toBeNull(); apply(); await screen.findByText('FixtureService0616'); expect(names()).toEqual(['FixtureService0616']);
        const requests = server.fetch.mock.calls.filter(([path]) => path.endsWith('/query'));
        expect(requests.at(-1)![1]).toMatchObject({ method: 'POST', credentials: 'same-origin', headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-CSRF-Token': 'synthetic-csrf' } });
        expect(JSON.parse(requests.at(-1)![1]!.body as string)).toEqual({ ...fullServicesQuery, search: '[.*]' });
        expect(server.fetch.mock.calls.every(([path]) => !path.includes('?') && !path.includes('[.*]') && !path.includes('cursor_'))).toBe(true);
        expect(document.querySelector(`time[datetime="${server.complete.manifest.captureStartedAt}"]`)).not.toBeNull(); expect(document.querySelector(`time[datetime="${server.complete.receivedAt}"]`)).not.toBeNull(); expect(document.querySelector(`time[datetime="${server.complete.manifest.expiresAt}"]`)).not.toBeNull();
    });
    it('uses six deterministic server sorts with original counts, backwards pages, and missing fields last', async () => {
        const server = fixtureServer(); open(); await screen.findByRole('table');
        fireEvent.change(screen.getByRole('combobox'), { target: { value: 'pid-desc' } }); apply(); await waitFor(() => expect(names()[0]).toBe('FixtureService0616'));
        expect(screen.getByRole('columnheader', { name: 'PID' })).toHaveAttribute('aria-sort', 'descending');
        fireEvent.click(screen.getByRole('button', { name: 'Next service page' })); await waitFor(() => expect(names()[0]).toBe('FixtureService0466'));
        fireEvent.click(screen.getByRole('button', { name: 'Previous service page' })); await waitFor(() => expect(names()[0]).toBe('FixtureService0616'));
        for (const sort of ['name-desc', 'state-asc', 'state-desc', 'pid-asc', 'name-asc']) { fireEvent.change(screen.getByRole('combobox'), { target: { value: sort } }); apply(); await screen.findByRole('table'); expect(server.state.requests.at(-1)!.sort).toBe(sort); }
        expect(screen.getByText('Captured rows').nextElementSibling).toHaveTextContent('617'); expect(screen.getByText('Matching rows in the whole generation').nextElementSibling).toHaveTextContent('617'); expect(screen.getByText('Visible rows on this page').nextElementSibling).toHaveTextContent('100');
    });
    it('retains controls and exact page across same-generation refresh but hides them while pending', async () => {
        const server = fixtureServer(); open(); await screen.findByRole('table'); search('Fixture'); fireEvent.change(screen.getByRole('combobox'), { target: { value: 'name-desc' } }); apply(); await screen.findByRole('table'); fireEvent.click(screen.getByRole('button', { name: 'Next service page' })); await waitFor(() => expect(names()[0]).toBe('FixtureService0516'));
        const late = deferred<Response>(), original = server.fetch.getMockImplementation()!;
        server.fetch.mockImplementationOnce((path, options) => original(path, options)).mockImplementationOnce(() => late.promise);
        fireEvent.click(screen.getByRole('button', { name: 'Refresh service page' })); await flush(); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByRole('searchbox')).toBeNull();
        await act(async () => late.resolve(await original(`/api/devices/${fullServicesDevice}/windows-full-services/query`, { body: JSON.stringify(server.state.requests.at(-1)) })));
        await waitFor(() => expect(names()[0]).toBe('FixtureService0516')); expect(screen.getByRole('searchbox')).toHaveValue('Fixture'); expect(screen.getByRole('combobox')).toHaveValue('name-desc');
    });
    it.each(['continuation', 'refresh', 'search'] as const)('requires explicit restart when generation changes during %s', async action => {
        const server = fixtureServer(); open(); await screen.findByRole('table'); replaceFullServicesGeneration(server.state.complete, server.state.rows);
        if (action === 'continuation') fireEvent.click(screen.getByRole('button', { name: 'Next service page' }));
        else if (action === 'search') { search('Fixture'); apply(); } else fireEvent.click(screen.getByRole('button', { name: 'Refresh service page' }));
        await screen.findByRole('alert'); expect(screen.getByRole('alert')).toHaveTextContent('Restart explicitly'); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByRole('searchbox')).toBeNull();
        fireEvent.click(screen.getByRole('button', { name: 'Restart with latest service generation' })); await screen.findByRole('table'); expect(screen.getByRole('searchbox')).toHaveValue(''); expect(names()[0]).toBe('FixtureService0000');
    });
    it('keeps failed latest attempts separate and positive complete zero different from no matches', async () => {
        const server = fixtureServer(); server.state.change = page => { page.latestAttempt = { sequence: 2, attemptedAt: '2026-10-11T06:00:09Z', status: 'source_failed', reason: 'access_denied' }; }; open(); await screen.findByRole('table');
        expect(within(screen.getByRole('region', { name: 'Latest collection attempt' })).getByText(/Collection failed/)).toHaveTextContent('Access denied'); expect(screen.getByText(/Showing the previous complete capture/)).toBeVisible(); expect(screen.getByText(/A newer attempt has not replaced/)).not.toBeVisible();
        search('no such service'); apply(); await screen.findByText('No services in the complete captured generation match this search.'); expect(screen.getByText('Captured rows').nextElementSibling).toHaveTextContent('617');
        cleanup(); server.state.complete = fullServicesComplete(true); server.state.rows = []; server.state.change = null; open(); await screen.findByText('Successful complete enumeration returned zero caller-visible Win32 services.'); expect(screen.getByText('Captured rows').nextElementSibling).toHaveTextContent('0');
    });
    it.each(['not_configured', 'disabled', 'awaiting', 'unavailable'] as const)('does not present %s as healthy empty', async status => {
        const server = fixtureServer(); server.state.status = status; open(); await screen.findByText(/No complete service generation is available/); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByRole('searchbox')).toBeNull(); expect(screen.queryByText(/Successful complete enumeration/)).toBeNull();
    });
});

describe('full-service private resource lifecycle', () => {
    it('does not request disabled, hidden, or unauthenticated resources', async () => {
        const server = fixtureServer(); const ui = open(false); await flush(); expect(server.fetch).not.toHaveBeenCalled(); ui.unmount(); vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); open(); await flush(); expect(server.fetch).not.toHaveBeenCalled(); cleanup(); vi.mocked(useOperator).mockReturnValue(null); open(); expect(screen.getByText(/Authenticated LAN/)).toBeVisible(); expect(server.fetch).not.toHaveBeenCalled();
    });
    it.each(['blur', 'pagehide', 'hashchange', AUTH_REQUIRED_EVENT])('clears all rows, labels, controls and cursors after %s', async event => {
        const server = fixtureServer(); open(); await screen.findByRole('table'); search('private-query'); act(() => window.dispatchEvent(new Event(event))); expect(screen.queryByRole('searchbox')).toBeNull(); expect(screen.queryByRole('table')).toBeNull(); expect(document.body).not.toHaveTextContent('private-query');
        if (event === AUTH_REQUIRED_EVENT) { expect(screen.getByRole('button', { name: 'Refresh service page' })).toBeDisabled(); const count = server.fetch.mock.calls.length; act(() => window.dispatchEvent(new Event('focus'))); await flush(); expect(server.fetch).toHaveBeenCalledTimes(count); }
        else { act(() => window.dispatchEvent(new Event('focus'))); await screen.findByRole('table'); expect(screen.getByRole('searchbox')).toHaveValue(''); expect(server.state.requests.at(-1)!.cursor).toBe(''); }
    });
    it('clears on visibility loss and discards a late result after device/session navigation', async () => {
        const server = fixtureServer(), visible = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible'); const ui = open(); await screen.findByRole('table'); visible.mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); expect(screen.queryByRole('table')).toBeNull(); visible.mockReturnValue('visible'); act(() => document.dispatchEvent(new Event('visibilitychange'))); await screen.findByRole('table');
        const late = deferred<Response>(); server.fetch.mockImplementationOnce(async () => response({ csrfToken: 'synthetic-csrf' })).mockImplementationOnce(() => late.promise); fireEvent.click(screen.getByRole('button', { name: 'Refresh service page' })); await flush(); const signal = server.fetch.mock.calls.at(-1)![1]!.signal;
        ui.rerender(<WindowsFullServicesPanel deviceId={`agent_${'8'.repeat(32)}`} sessionKey="new-session"/>); expect(signal?.aborted).toBe(true); await act(async () => late.resolve(response(fullServicesPage()))); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByText('FixtureService0000')).toBeNull();
    });
    it.each([400, 403, 404, 409, 429, 503])('clears on HTTP %i without exposing raw private error text', async status => {
        const server = fixtureServer(); open(); await screen.findByRole('table'); server.state.failure = status; fireEvent.click(screen.getByRole('button', { name: 'Refresh service page' })); await screen.findByRole('alert'); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByRole('searchbox')).toBeNull(); expect(document.body).not.toHaveTextContent('PRIVATE-ERROR');
    });
    it.each(['csrf', 'query'] as const)('locks on HTTP401 during %s', async stage => {
        const server = fixtureServer(); server.fetch.mockImplementation(async path => stage === 'csrf' || path.endsWith('/query') ? response({}, 401) : response({ csrfToken: 'synthetic-csrf' })); open(); await screen.findByRole('alert'); expect(screen.getByRole('alert')).toHaveTextContent('session has ended'); expect(screen.getByRole('button', { name: 'Refresh service page' })).toBeDisabled();
    });
    it('never sends a page POST after a protected epoch changes during CSRF acquisition', async () => {
        const late = deferred<Response>(), fetch = vi.fn(() => late.promise); vi.stubGlobal('fetch', fetch); open(); await flush(); act(() => { abortProtectedRequests(); window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)); }); await act(async () => late.resolve(response({ csrfToken: 'synthetic-csrf' }))); expect(fetch).toHaveBeenCalledTimes(1); expect(screen.queryByRole('table')).toBeNull();
    });
    it('enforces the 256KiB response bound and rejects wrong query echoes', async () => {
        const server = fixtureServer(); server.fetch.mockImplementation(async path => path === '/api/session' ? response({ csrfToken: 'synthetic-csrf' }) : new Response(' '.repeat(FULL_SERVICES_PAGE_BYTES + 1))); open(); await screen.findByRole('alert'); expect(screen.queryByRole('table')).toBeNull(); cleanup(); fixtureServer().state.change = page => { page.search = 'private-other-query'; }; open(); await screen.findByRole('alert'); expect(document.body).not.toHaveTextContent('private-other-query'); expect(screen.queryByRole('table')).toBeNull();
    });
    it('times out and ignores a late response without background querying or persistence', async () => {
        vi.useFakeTimers(); const server = fixtureServer(), late = deferred<Response>(); server.fetch.mockImplementation(async path => path === '/api/session' ? response({ csrfToken: 'synthetic-csrf' }) : late.promise); const writes = vi.spyOn(Storage.prototype, 'setItem'); open(); await flush(); await act(async () => vi.advanceTimersByTimeAsync(10001)); expect(screen.getByRole('alert')).toHaveTextContent('timed out'); await act(async () => late.resolve(response(fullServicesPage()))); expect(screen.queryByRole('table')).toBeNull(); await act(async () => vi.advanceTimersByTimeAsync(60000)); expect(server.fetch).toHaveBeenCalledTimes(2); expect(writes).not.toHaveBeenCalled();
    });
    it('expires original authority/source/cursor locally and rejects replayed time', async () => {
        vi.useFakeTimers(); const server = fixtureServer(); server.state.change = page => { page.authorityUntil = '2026-10-11T06:00:11Z'; page.cursorExpiresAt = page.authorityUntil; }; open(); await flush(); expect(names()).toHaveLength(100); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('expired');
        cleanup(); const second = fixtureServer(); second.state.change = page => { page.serverNow = fullServicesNow; page.cursorExpiresAt = '2026-10-11T06:15:10Z'; }; open(); await flush(); await act(async () => vi.advanceTimersByTimeAsync(2000)); fireEvent.click(screen.getByRole('button', { name: 'Refresh service page' })); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('time reference'); expect(screen.queryByRole('table')).toBeNull();
    });
    it.each(['source', 'authority', 'cursor'] as const)('honors the original %s deadline without waiting for another request', async kind => {
        vi.useFakeTimers(); const server = fixtureServer();
        server.state.change = page => {
            page.serverNow = '2026-10-12T05:59:59Z'; page.authorityUntil = kind === 'authority' ? '2026-10-12T06:00:00Z' : '2026-10-13T06:00:00Z';
            page.cursorExpiresAt = kind === 'cursor' ? '2026-10-12T05:59:59.5Z' : '2026-10-12T06:00:00Z';
        };
        open(); await flush(); expect(names()).toHaveLength(100); await act(async () => vi.advanceTimersByTimeAsync(kind === 'cursor' ? 500 : 1000)); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByRole('searchbox')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('expired'); expect(server.state.requests).toHaveLength(1);
    });
    it('does not renew the original paging deadline on a page-one refresh', async () => {
        vi.useFakeTimers(); const server = fixtureServer(); let reads = 0;
        server.state.change = page => { page.cursorExpiresAt = reads++ === 0 ? '2026-10-11T06:00:11Z' : '2026-10-11T06:15:10Z'; };
        open(); await flush(); await act(async () => vi.advanceTimersByTimeAsync(500)); fireEvent.click(screen.getByRole('button', { name: 'Refresh service page' })); await flush(); expect(names()).toHaveLength(100); expect(document.querySelector('time[datetime="2026-10-11T06:00:11Z"]')).not.toBeNull(); await act(async () => vi.advanceTimersByTimeAsync(500)); expect(screen.queryByRole('table')).toBeNull();
    });
    it('keeps successful pages bounded without hidden repeat queries, sorts, or browser persistence', async () => {
        vi.useFakeTimers(); const server = fixtureServer(), writes = vi.spyOn(Storage.prototype, 'setItem'); open(); await flush(); expect(names()).toHaveLength(100); await act(async () => vi.advanceTimersByTimeAsync(60000)); expect(names()).toHaveLength(100); expect(server.state.requests).toHaveLength(1); expect(writes).not.toHaveBeenCalled();
    });
    it('rejects over-byte-limit draft search without losing the explicit original capture', async () => {
        const server = fixtureServer(); open(); await screen.findByRole('table'); search('😀'.repeat(65)); apply(); expect(screen.getByRole('alert')).toHaveTextContent('256 UTF-8 bytes'); expect(server.state.requests).toHaveLength(1); expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByText('Captured rows').nextElementSibling).toHaveTextContent('617');
    });
    it('clears after an untrusted browser clock jump', async () => {
        vi.useFakeTimers(); fixtureServer(); open(); await flush(); expect(names()).toHaveLength(100); vi.setSystemTime(Date.now() + 5000); await act(async () => vi.advanceTimersByTimeAsync(250)); expect(screen.getByRole('alert')).toHaveTextContent('time reference'); expect(screen.queryByRole('table')).toBeNull();
    });
    it('keeps full-generation controls during unrelated DeviceDetail metadata refreshes', async () => {
        const server = fixtureServer(); render(<DeviceDetail id={fullServicesDevice} onClose={vi.fn()} onCase={vi.fn()}/>);
        await screen.findByRole('tab', { name: 'Inventory' }); fireEvent.click(screen.getByRole('tab', { name: 'Inventory' })); fireEvent.click(screen.getByRole('tab', { name: 'Services' })); await screen.findByText('FixtureService0000');
        const region = screen.getByRole('region', { name: 'Complete caller-visible services' }); fireEvent.change(within(region).getByRole('searchbox'), { target: { value: 'Fixture' } }); fireEvent.change(within(region).getByRole('combobox'), { target: { value: 'name-desc' } }); fireEvent.click(within(region).getByRole('button', { name: 'Apply search and sort' })); await waitFor(() => expect(names()[0]).toBe('FixtureService0616'));
        const count = server.state.requests.length; fireEvent.click(screen.getByRole('button', { name: 'Refresh device metadata' })); await waitFor(() => expect(screen.getByRole('button', { name: 'Refresh device metadata' })).not.toBeDisabled());
        expect(within(region).getByRole('searchbox')).toHaveValue('Fixture'); expect(within(region).getByRole('combobox')).toHaveValue('name-desc'); expect(names()[0]).toBe('FixtureService0616'); expect(server.state.requests).toHaveLength(count);
    });
    it('mounts independently only in Services and resets on subtab departure', async () => {
        const server = fixtureServer(); function Workspace() { const resource = useWindowsInventory(fullServicesDevice, true, 'session-a'); return <WindowsInventoryWorkspace resource={resource} fullServices={{ deviceId: fullServicesDevice, sessionKey: 'session-a', enabled: true }}/>; }
        render(<Workspace/>); await screen.findByText('fixture.exe'); expect(server.state.requests).toHaveLength(0); fireEvent.click(screen.getByRole('tab', { name: 'Services' })); await screen.findByText('FixtureService0000'); expect(screen.getByText('Bounded service preview: separate source, at most 128 rows')).toBeVisible();
        const region = screen.getByRole('region', { name: 'Complete caller-visible services' }); fireEvent.change(within(region).getByRole('searchbox'), { target: { value: 'private-search' } }); fireEvent.click(screen.getByRole('tab', { name: 'Software' })); expect(screen.queryByRole('region', { name: 'Complete caller-visible services' })).toBeNull(); fireEvent.click(screen.getByRole('tab', { name: 'Services' })); await screen.findByText('FixtureService0000'); expect(within(screen.getByRole('region', { name: 'Complete caller-visible services' })).getByRole('searchbox')).toHaveValue('');
    });
});
