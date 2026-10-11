import { WindowsInventoryWorkspace } from './windows-inventory';
import { useWindowsInventory } from './windows-inventory-resource';
import { DeviceDetail } from './details';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { WindowsFullProcessesPanel } from './windows-full-processes';
import { fullProcessesRows, fullProcessesComplete, fullProcessesDevice, fullProcessesNow, fullProcessesPage, fullProcessesQuery, fullProcessesUnavailable, replaceFullProcessesGeneration } from './windows-full-processes-fixtures';
import { FULL_PROCESSES_PAGE_BYTES } from './windows-full-processes-types';
import type { FullProcessesPage, FullProcessesQuery } from './windows-full-processes-types';
import { windowsDevice, windowsView } from './windows-inventory-fixture';

vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
const deferred = <T,>() => { let resolve!: (v: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; };
const flush = async () => { await act(async () => { for (let i = 0; i < 12; i++) await Promise.resolve(); }); };
function fixtureServer() {
    const rows = fullProcessesRows(), complete = fullProcessesComplete(), began = Date.now();
    const issued = new Map<string, { search: string; sort: string; generation: string; offset: number; expiry: string }>();
    const state = { rows, complete, requests: [] as FullProcessesQuery[], status: null as FullProcessesPage['status'] | null, failure: 0, change: null as ((page: FullProcessesPage) => void) | null };
    const fetch = vi.fn(async (path: string, options?: RequestInit): Promise<Response> => {
        if (path === `/api/devices/${fullProcessesDevice}`) return response({ ...windowsDevice(), id: fullProcessesDevice });
        if (path === '/api/session') return response({ csrfToken: 'synthetic-csrf' });
        if (path.endsWith('/windows-inventory')) { const preview = windowsView(); preview.deviceId = fullProcessesDevice; return response(preview); }
        if (path !== `/api/devices/${fullProcessesDevice}/windows-full-processes/query`) return response({}, 404);
        const query = JSON.parse(options!.body as string) as FullProcessesQuery; state.requests.push(query);
        if (state.failure) return response({ error: { code: 'synthetic_error', message: 'PRIVATE-ERROR-DO-NOT-RENDER' } }, state.failure);
        const cursor = issued.get(query.cursor);
        if (query.cursor && (!cursor || cursor.search !== query.search || cursor.sort !== query.sort || cursor.generation !== state.complete.manifest.generationId)) return response({ error: { code: 'windows_full_processes_restart_required' } }, 409);
        const page = state.status && state.status !== 'ready' ? { ...fullProcessesUnavailable(state.status), search: query.search, sort: query.sort, limit: query.limit } : fullProcessesPage(query, state.rows, state.complete, cursor?.offset ?? 0);
        page.serverNow = new Date(Date.parse(fullProcessesNow) + Date.now() - began).toISOString();
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
const open = (enabled = true, session = 'session-a') => render(<WindowsFullProcessesPanel deviceId={fullProcessesDevice} sessionKey={session} enabled={enabled}/>);
const names = () => Array.from(document.querySelectorAll('.windows-full-processes tbody tr')).map(row => row.querySelector('td')!.textContent);
const search = (value: string) => fireEvent.change(screen.getByRole('searchbox'), { target: { value } });
const apply = () => fireEvent.click(screen.getByRole('button', { name: /Apply|Anwenden/ }));
beforeEach(() => { setLocale('en', false); vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, expiresAt: 'synthetic-session', insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() }); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('complete Windows software browsing through released protected fetch', () => {
    it.each(['en', 'de'] as const)('browses all 617 invented rows in bounded pages with later search and literal labels (%s)', async locale => {
        setLocale(locale, false); const server = fixtureServer(); open(); await screen.findByRole('table');
        expect(names()).toHaveLength(100); expect(screen.getByRole('button', { name: locale === 'en' ? 'Previous process page' : 'Vorherige Prozessseite' })).toBeDisabled();
        const seen = [...names()];
        for (let i = 1; i <= 6; i++) { fireEvent.click(screen.getByRole('button', { name: locale === 'en' ? 'Next process page' : 'Nächste Prozessseite' })); await waitFor(() => expect(names()[0]).toBe(`Fixture Process ${String(i * 100).padStart(4, '0')}`)); expect(names().length).toBeLessThanOrEqual(100); seen.push(...names()); }
        expect(seen).toEqual(server.rows.map(row => row.name)); expect(names()).toHaveLength(17); expect(screen.getByRole('button', { name: locale === 'en' ? 'Next process page' : 'Nächste Prozessseite' })).toBeDisabled();
        search('0616'); expect(screen.queryByRole('table')).toBeNull(); apply(); await screen.findByText('Fixture Process 0616'); expect(names()).toEqual(['Fixture Process 0616']);
        const requests = server.fetch.mock.calls.filter(([path]) => path.endsWith('/query'));
        expect(requests.at(-1)![1]).toMatchObject({ method: 'POST', credentials: 'same-origin', headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-CSRF-Token': 'synthetic-csrf' } });
        expect(JSON.parse(requests.at(-1)![1]!.body as string)).toEqual({ ...fullProcessesQuery, search: '0616' });
        expect(server.fetch.mock.calls.every(([path]) => !path.includes('?') && !path.includes('[.*]') && !path.includes('cursor_'))).toBe(true);
        expect(document.querySelector(`time[datetime="${server.complete.manifest.captureStartedAt}"]`)).not.toBeNull(); expect(document.querySelector(`time[datetime="${server.complete.receivedAt}"]`)).not.toBeNull(); expect(document.querySelector(`time[datetime="${server.complete.manifest.expiresAt}"]`)).not.toBeNull();
    });
    it('uses all eight server sorts and bounded backwards pages', async () => {
        const server = fixtureServer(); open(); await screen.findByRole('table');
        for (const sort of ['name-desc', 'name-asc', 'parentPid-asc', 'parentPid-desc', 'threads-asc', 'threads-desc', 'pid-desc', 'pid-asc']) {
            fireEvent.change(screen.getByRole('combobox'), { target: { value: sort } }); apply(); await screen.findByRole('table');
            expect(server.state.requests.at(-1)!.sort).toBe(sort);
            const heading = sort.startsWith('parentPid') ? 'Snapshot parent PID' : sort.startsWith('threads') ? 'Threads' : sort.startsWith('pid') ? 'Snapshot PID' : 'Name';
            expect(screen.getByRole('columnheader', { name: heading })).toHaveAttribute('aria-sort', sort.endsWith('desc') ? 'descending' : 'ascending');
        }
        fireEvent.click(screen.getByRole('button', { name: 'Next process page' })); await waitFor(() => expect(names()[0]).toBe('Fixture Process 0100'));
        fireEvent.click(screen.getByRole('button', { name: 'Previous process page' })); await waitFor(() => expect(names()[0]).toBe('Fixture Process 0000'));
        expect(screen.getByText('Captured').nextElementSibling).toHaveTextContent('617'); expect(screen.getByText('Matching').nextElementSibling).toHaveTextContent('617'); expect(screen.getByText('On page').nextElementSibling).toHaveTextContent('100');
    });
    it('retains controls and exact page across same-generation refresh but hides them while pending', async () => {
        const server = fixtureServer(); open(); await screen.findByRole('table'); search('Fixture'); fireEvent.change(screen.getByRole('combobox'), { target: { value: 'name-desc' } }); apply(); await screen.findByRole('table'); fireEvent.click(screen.getByRole('button', { name: 'Next process page' })); await waitFor(() => expect(names()[0]).toBe('Fixture Process 0516'));
        const late = deferred<Response>(), original = server.fetch.getMockImplementation()!;
        server.fetch.mockImplementationOnce((path, options) => original(path, options)).mockImplementationOnce(() => late.promise);
        fireEvent.click(screen.getByRole('button', { name: 'Refresh process inventory' })); await flush(); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByRole('searchbox')).toBeNull();
        await act(async () => late.resolve(await original(`/api/devices/${fullProcessesDevice}/windows-full-processes/query`, { body: JSON.stringify(server.state.requests.at(-1)) })));
        await waitFor(() => expect(names()[0]).toBe('Fixture Process 0516')); expect(screen.getByRole('searchbox')).toHaveValue('Fixture'); expect(screen.getByRole('combobox')).toHaveValue('name-desc');
    });
    it.each(['continuation', 'refresh', 'search'] as const)('requires explicit restart when generation changes during %s', async action => {
        const server = fixtureServer(); open(); await screen.findByRole('table'); replaceFullProcessesGeneration(server.state.complete, server.state.rows);
        if (action === 'continuation') fireEvent.click(screen.getByRole('button', { name: 'Next process page' }));
        else if (action === 'search') { search('Fixture'); apply(); } else fireEvent.click(screen.getByRole('button', { name: 'Refresh process inventory' }));
        await screen.findByRole('alert'); expect(screen.getByRole('alert')).toHaveTextContent('Reload latest'); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByRole('searchbox')).toBeNull();
        fireEvent.click(screen.getByRole('button', { name: 'Reload latest process capture' })); await screen.findByRole('table'); expect(screen.getByRole('searchbox')).toHaveValue(''); expect(names()[0]).toBe('Fixture Process 0000');
    });
    it('keeps failed latest attempts separate and positive complete zero different from no matches', async () => {
        const server = fixtureServer(); server.state.change = page => { page.latestAttempt = { sequence: 2, attemptedAt: '2026-10-11T06:00:09Z', status: 'source_failed', reason: 'resource_limit' }; }; open(); await screen.findByRole('table');
        expect(screen.getByText(/Latest capture failed/)).toHaveTextContent('Capture limit reached'); expect(screen.getByText(/Showing earlier capture/)).toBeVisible();
        search('no such service'); apply(); await screen.findByText('No matches in this capture.'); expect(screen.getByText('Captured').nextElementSibling).toHaveTextContent('617');
        cleanup(); server.state.complete = fullProcessesComplete(true); server.state.rows = []; server.state.change = null; open(); await screen.findByText('No caller-visible processes in this complete snapshot.'); expect(screen.getByText('Captured').nextElementSibling).toHaveTextContent('0');
    });
    it.each(['not_configured', 'disabled', 'awaiting', 'unavailable'] as const)('does not present %s as healthy empty', async status => {
        const server = fixtureServer(); server.state.status = status; open(); await screen.findByText({not_configured:'Local consent required',disabled:'Collection disabled',awaiting:'Waiting for first complete capture',unavailable:'Process inventory unavailable'}[status]); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByRole('searchbox')).toBeNull(); expect(screen.queryByText(/No caller-visible processes/)).toBeNull();
    });
});

describe('full-processes private resource lifecycle', () => {
    it('does not request disabled, hidden, or unauthenticated resources', async () => {
        const server = fixtureServer(); const ui = open(false); await flush(); expect(server.fetch).not.toHaveBeenCalled(); ui.unmount(); vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); open(); await flush(); expect(server.fetch).not.toHaveBeenCalled(); cleanup(); vi.mocked(useOperator).mockReturnValue(null); open(); expect(screen.getByText(/Sign in as a LAN operator/)).toBeVisible(); expect(server.fetch).not.toHaveBeenCalled();
    });
    it.each(['blur', 'pagehide', 'hashchange', AUTH_REQUIRED_EVENT])('clears all rows, labels, controls and cursors after %s', async event => {
        const server = fixtureServer(); open(); await screen.findByRole('table'); search('private-query'); act(() => window.dispatchEvent(new Event(event))); expect(screen.queryByRole('searchbox')).toBeNull(); expect(screen.queryByRole('table')).toBeNull(); expect(document.body).not.toHaveTextContent('private-query');
        if (event === AUTH_REQUIRED_EVENT) { expect(screen.getByRole('button', { name: 'Refresh process inventory' })).toBeDisabled(); const count = server.fetch.mock.calls.length; act(() => window.dispatchEvent(new Event('focus'))); await flush(); expect(server.fetch).toHaveBeenCalledTimes(count); }
        else { act(() => window.dispatchEvent(new Event('focus'))); await screen.findByRole('table'); expect(screen.getByRole('searchbox')).toHaveValue(''); expect(server.state.requests.at(-1)!.cursor).toBe(''); }
    });
    it('clears on visibility loss and discards a late result after device/session navigation', async () => {
        const server = fixtureServer(), visible = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible'); const ui = open(); await screen.findByRole('table'); visible.mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); expect(screen.queryByRole('table')).toBeNull(); visible.mockReturnValue('visible'); act(() => document.dispatchEvent(new Event('visibilitychange'))); await screen.findByRole('table');
        const late = deferred<Response>(); server.fetch.mockImplementationOnce(async () => response({ csrfToken: 'synthetic-csrf' })).mockImplementationOnce(() => late.promise); fireEvent.click(screen.getByRole('button', { name: 'Refresh process inventory' })); await flush(); const signal = server.fetch.mock.calls.at(-1)![1]!.signal;
        ui.rerender(<WindowsFullProcessesPanel deviceId={`agent_${'8'.repeat(32)}`} sessionKey="new-session"/>); expect(signal?.aborted).toBe(true); await act(async () => late.resolve(response(fullProcessesPage()))); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByText('Fixture Process 0000')).toBeNull();
    });
    it.each([400, 403, 404, 409, 429, 503])('clears on HTTP %i without exposing raw private error text', async status => {
        const server = fixtureServer(); open(); await screen.findByRole('table'); server.state.failure = status; fireEvent.click(screen.getByRole('button', { name: 'Refresh process inventory' })); await screen.findByRole('alert'); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByRole('searchbox')).toBeNull(); expect(document.body).not.toHaveTextContent('PRIVATE-ERROR');
    });
    it.each(['csrf', 'query'] as const)('locks on HTTP401 during %s', async stage => {
        const server = fixtureServer(); server.fetch.mockImplementation(async path => stage === 'csrf' || path.endsWith('/query') ? response({}, 401) : response({ csrfToken: 'synthetic-csrf' })); open(); await screen.findByRole('alert'); expect(screen.getByRole('alert')).toHaveTextContent('session has ended'); expect(screen.getByRole('button', { name: 'Refresh process inventory' })).toBeDisabled();
    });
    it('never sends a page POST after a protected epoch changes during CSRF acquisition', async () => {
        const late = deferred<Response>(), fetch = vi.fn(() => late.promise); vi.stubGlobal('fetch', fetch); open(); await flush(); act(() => { abortProtectedRequests(); window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)); }); await act(async () => late.resolve(response({ csrfToken: 'synthetic-csrf' }))); expect(fetch).toHaveBeenCalledTimes(1); expect(screen.queryByRole('table')).toBeNull();
    });
    it('enforces the 256KiB response bound and rejects wrong query echoes', async () => {
        const server = fixtureServer(); server.fetch.mockImplementation(async path => path === '/api/session' ? response({ csrfToken: 'synthetic-csrf' }) : new Response(' '.repeat(FULL_PROCESSES_PAGE_BYTES + 1))); open(); await screen.findByRole('alert'); expect(screen.queryByRole('table')).toBeNull(); cleanup(); fixtureServer().state.change = page => { page.search = 'private-other-query'; }; open(); await screen.findByRole('alert'); expect(document.body).not.toHaveTextContent('private-other-query'); expect(screen.queryByRole('table')).toBeNull();
    });
    it('times out and ignores a late response without background querying or persistence', async () => {
        vi.useFakeTimers(); const server = fixtureServer(), late = deferred<Response>(); server.fetch.mockImplementation(async path => path === '/api/session' ? response({ csrfToken: 'synthetic-csrf' }) : late.promise); const writes = vi.spyOn(Storage.prototype, 'setItem'); open(); await flush(); await act(async () => vi.advanceTimersByTimeAsync(10001)); expect(screen.getByRole('alert')).toHaveTextContent('timed out'); await act(async () => late.resolve(response(fullProcessesPage()))); expect(screen.queryByRole('table')).toBeNull(); await act(async () => vi.advanceTimersByTimeAsync(60000)); expect(server.fetch).toHaveBeenCalledTimes(2); expect(writes).not.toHaveBeenCalled();
    });
    it('expires original authority/source/cursor locally and rejects replayed time', async () => {
        vi.useFakeTimers(); const server = fixtureServer(); server.state.change = page => { page.authorityUntil = '2026-10-11T06:00:11Z'; page.cursorExpiresAt = page.authorityUntil; }; open(); await flush(); expect(names()).toHaveLength(100); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('expired');
        cleanup(); const second = fixtureServer(); second.state.change = page => { page.serverNow = fullProcessesNow; page.cursorExpiresAt = '2026-10-11T06:15:10Z'; }; open(); await flush(); await act(async () => vi.advanceTimersByTimeAsync(2000)); fireEvent.click(screen.getByRole('button', { name: 'Refresh process inventory' })); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('Time reference'); expect(screen.queryByRole('table')).toBeNull();
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
        open(); await flush(); await act(async () => vi.advanceTimersByTimeAsync(500)); fireEvent.click(screen.getByRole('button', { name: 'Refresh process inventory' })); await flush(); expect(names()).toHaveLength(100); expect(document.querySelector('time[datetime="2026-10-11T06:00:11Z"]')).not.toBeNull(); await act(async () => vi.advanceTimersByTimeAsync(500)); expect(screen.queryByRole('table')).toBeNull();
    });
    it('keeps successful pages bounded without hidden repeat queries, sorts, or browser persistence', async () => {
        vi.useFakeTimers(); const server = fixtureServer(), writes = vi.spyOn(Storage.prototype, 'setItem'); open(); await flush(); expect(names()).toHaveLength(100); await act(async () => vi.advanceTimersByTimeAsync(60000)); expect(names()).toHaveLength(100); expect(server.state.requests).toHaveLength(1); expect(writes).not.toHaveBeenCalled();
    });
    it('rejects over-byte-limit draft search without losing the explicit original capture', async () => {
        const server = fixtureServer(); open(); await screen.findByRole('table'); search('😀'.repeat(65)); apply(); expect(screen.getByRole('alert')).toHaveTextContent('256 UTF-8 bytes'); expect(server.state.requests).toHaveLength(1); expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByText('Captured').nextElementSibling).toHaveTextContent('617');
    });
    it('clears after an untrusted browser clock jump', async () => {
        vi.useFakeTimers(); fixtureServer(); open(); await flush(); expect(names()).toHaveLength(100); vi.setSystemTime(Date.now() + 5000); await act(async () => vi.advanceTimersByTimeAsync(250)); expect(screen.getByRole('alert')).toHaveTextContent('Time reference'); expect(screen.queryByRole('table')).toBeNull();
    });
});

describe('complete process rows remain separate from bounded telemetry', () => {
    it('renders hostile names as text and never adds CPU/RAM columns to the full inventory', async () => {
        const server = fixtureServer(); server.state.rows[0].name = '<img src=x onerror=alert(1)> [.*] Ä & 🛠'; server.state.rows[1].name = null; server.state.rows[1].nameQuality = 'unavailable'; replaceFullProcessesGeneration(server.state.complete, server.state.rows, 1);
        open(); await screen.findByRole('table'); expect(screen.getByText('<img src=x onerror=alert(1)> [.*] Ä & 🛠')).toBeVisible(); expect(screen.getByText('Unavailable')).toBeVisible(); expect(document.querySelector('img,script:not([src])')).toBeNull(); expect(screen.queryByRole('link')).toBeNull();
        expect(screen.getAllByRole('columnheader').map(node => node.textContent)).toEqual(['Name', 'Snapshot PID', 'Snapshot parent PID', 'Threads']);
        search('[.*]'); apply(); await screen.findByRole('table'); expect(names()).toHaveLength(1); expect(server.state.requests.at(-1)?.search).toBe('[.*]');
    });
    it('opens the old preview only when no completed generation is available and keeps its labels separate', async () => {
        const server = fixtureServer(); server.state.status = 'awaiting';
        const ui = render(<WindowsFullProcessesPanel deviceId={fullProcessesDevice} sessionKey="session"><p>Invented bounded sample with separate CPU and RAM</p></WindowsFullProcessesPanel>);
        await screen.findByText('Waiting for first complete capture'); expect(document.querySelector('.windows-full-processes-preview')).toHaveAttribute('open'); expect(screen.getByText('Process preview & metrics · up to 128 rows')).toBeVisible();
        server.state.status = 'ready'; fireEvent.click(screen.getByRole('button', { name: 'Refresh process inventory' })); await screen.findByRole('table'); expect(document.querySelector('.windows-full-processes-preview')).not.toHaveAttribute('open');
        expect(document.querySelector('.windows-full-processes-details')).not.toHaveAttribute('open'); ui.unmount();
    });
    it('does not relabel a failed source attempt as complete or refresh the age of a retained capture', async () => {
        const server = fixtureServer(); const started = server.state.complete.manifest.captureStartedAt;
        server.state.change = page => { page.latestAttempt = { sequence: 2, attemptedAt: '2026-10-11T06:00:09Z', status: 'source_failed', reason: 'resource_limit' }; }; open(); await screen.findByRole('table');
        expect(screen.getByText(/Latest capture failed/)).toHaveTextContent('Showing earlier capture'); expect(document.querySelector('.windows-full-processes-age time')).toHaveAttribute('datetime', started);
        expect(screen.getByText('Complete visible snapshot')).toBeVisible(); expect(screen.queryByText('Latest capture complete')).toBeNull();
    });
});


describe('process inventory workspace integration', () => {
    it.each(['not_configured', 'unavailable', 'missing'] as const)('preserves the separate bounded preview’s %s state without inventing rows', async status => {
        const server = fixtureServer(), original = server.fetch.getMockImplementation()!; server.state.status = 'not_configured';
        server.fetch.mockImplementation(async (path, options) => {
            if (!path.endsWith('/windows-inventory')) return original(path, options);
            if (status === 'missing') return response({ error: { code: 'not_found', message: 'PRIVATE-MISSING-PREVIEW' } }, 404);
            return response({ ...windowsView(), deviceId: fullProcessesDevice, status, sequence: null, receivedAt: null, snapshot: null });
        });
        function Workspace() { const resource = useWindowsInventory(fullProcessesDevice, true, 'session-a'); return <WindowsInventoryWorkspace resource={resource} fullServices={{ deviceId: fullProcessesDevice, sessionKey: 'session-a', enabled: true }}/>; }
        render(<Workspace/>); await screen.findByText('Local consent required');
        const preview = document.querySelector('.windows-full-processes-preview') as HTMLElement;
        expect(preview).toHaveAttribute('open'); expect(within(preview).getByText('Process preview & metrics · up to 128 rows')).toBeVisible();
        await within(preview).findByText(status === 'not_configured' ? 'Windows inventory is not configured for this identity.' : 'Windows inventory is unavailable.');
        expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByText('Complete visible snapshot')).toBeNull(); expect(screen.queryByText('No caller-visible processes in this complete snapshot.')).toBeNull(); expect(document.body).not.toHaveTextContent('PRIVATE-MISSING-PREVIEW');
    });
    it('reads independently only in Processes and resets after tab departure', async () => {
        const server = fixtureServer(); function Workspace() { const resource = useWindowsInventory(fullProcessesDevice, true, 'session-a'); return <WindowsInventoryWorkspace resource={resource} fullServices={{ deviceId: fullProcessesDevice, sessionKey: 'session-a', enabled: true }}/>; }
        render(<Workspace/>); await screen.findByText('Fixture Process 0000'); await screen.findByText('fixture.exe');
        expect(document.querySelector('.windows-full-processes-preview')).not.toHaveAttribute('open');
        const full = screen.getByRole('region', { name: 'Process inventory' }); fireEvent.change(within(full).getByRole('searchbox', { name: 'Search captured processes' }), { target: { value: 'private-search' } });
        const count = server.state.requests.length; fireEvent.click(screen.getByRole('tab', { name: 'Hostname' })); expect(screen.queryByRole('region', { name: 'Process inventory' })).toBeNull(); expect(server.state.requests).toHaveLength(count);
        fireEvent.click(screen.getByRole('tab', { name: 'Processes' })); await screen.findByText('Fixture Process 0000'); expect(within(screen.getByRole('region', { name: 'Process inventory' })).getByRole('searchbox', { name: 'Search captured processes' })).toHaveValue(''); expect(server.state.requests.at(-1)?.cursor).toBe('');
    });
    it('does not reset inventory controls or request another page on DeviceDetail metadata refresh', async () => {
        const server = fixtureServer(); render(<DeviceDetail id={fullProcessesDevice} onClose={vi.fn()} onCase={vi.fn()}/>);
        await screen.findByRole('tab', { name: 'Inventory' }); fireEvent.click(screen.getByRole('tab', { name: 'Inventory' })); await screen.findByText('Fixture Process 0000');
        const full = screen.getByRole('region', { name: 'Process inventory' }); fireEvent.change(within(full).getByRole('searchbox', { name: 'Search captured processes' }), { target: { value: 'Fixture' } }); fireEvent.change(within(full).getByRole('combobox', { name: 'Sort process inventory' }), { target: { value: 'pid-desc' } }); fireEvent.click(within(full).getByRole('button', { name: 'Apply' })); await waitFor(() => expect(names()[0]).toBe('Fixture Process 0616'));
        const count = server.state.requests.length; fireEvent.click(screen.getByRole('button', { name: 'Refresh device metadata' })); await waitFor(() => expect(screen.getByRole('button', { name: 'Refresh device metadata' })).not.toBeDisabled());
        expect(within(full).getByRole('searchbox', { name: 'Search captured processes' })).toHaveValue('Fixture'); expect(within(full).getByRole('combobox', { name: 'Sort process inventory' })).toHaveValue('pid-desc'); expect(names()[0]).toBe('Fixture Process 0616'); expect(server.state.requests).toHaveLength(count);
    });
});
