import { WindowsInventoryWorkspace } from './windows-inventory';
import { useWindowsInventory } from './windows-inventory-resource';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { WindowsNetworkContextPanel } from './windows-network-context';
import { networkContextRows, networkContextComplete, networkContextDevice, networkContextNow, networkContextPage, networkContextQuery, networkContextUnavailable, replaceNetworkContextGeneration } from './windows-network-context-fixtures';
import { NETWORK_CONTEXT_PAGE_BYTES } from './windows-network-context-types';
import type { NetworkContextPage, NetworkContextQuery } from './windows-network-context-types';
import { windowsDevice, windowsView } from './windows-inventory-fixture';

vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
const deferred = <T,>() => { let resolve!: (v: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; };
const flush = async () => { await act(async () => { for (let i = 0; i < 12; i++) await Promise.resolve(); }); };
function fixtureServer() {
    const rows = networkContextRows(), complete = networkContextComplete(), began = Date.now();
    const issued = new Map<string, { kind: string; search: string; sort: string; generation: string; offset: number; expiry: string }>();
    const state = { rows, complete, requests: [] as NetworkContextQuery[], status: null as NetworkContextPage['status'] | null, failure: 0, change: null as ((page: NetworkContextPage) => void) | null };
    const fetch = vi.fn(async (path: string, options?: RequestInit): Promise<Response> => {
        if (path === `/api/devices/${networkContextDevice}`) return response({ ...windowsDevice(), id: networkContextDevice });
        if (path === '/api/session') return response({ csrfToken: 'synthetic-csrf' });
        if (path.endsWith('/windows-inventory')) { const preview = windowsView(); preview.deviceId = networkContextDevice; return response(preview); }
        if (path !== `/api/devices/${networkContextDevice}/windows-network-context/query`) return response({}, 404);
        const query = JSON.parse(options!.body as string) as NetworkContextQuery; state.requests.push(query);
        if (state.failure) return response({ error: { code: 'synthetic_error', message: 'PRIVATE-ERROR-DO-NOT-RENDER' } }, state.failure);
        const cursor = issued.get(query.cursor);
        if (query.cursor && (!cursor || cursor.kind !== query.kind || cursor.search !== query.search || cursor.sort !== query.sort || cursor.generation !== state.complete.manifest.generationId)) return response({ error: { code: 'windows_full_processes_restart_required' } }, 409);
        const page = state.status && state.status !== 'ready' ? { ...networkContextUnavailable(state.status, query), search: query.search, sort: query.sort, limit: query.limit } : networkContextPage(query, state.rows, state.complete, cursor?.offset ?? 0);
        page.serverNow = new Date(Date.parse(networkContextNow) + Date.now() - began).toISOString();
        if (page.status === 'ready') {
            page.cursorExpiresAt = cursor?.expiry ?? new Date(Math.min(Date.parse(page.serverNow) + 900000, Date.parse(page.complete!.manifest.expiresAt), Date.parse(page.authorityUntil!))).toISOString();
            if (page.nextCursor) {
                page.nextCursor = `cursor_${issued.size}_${page.offset + page.rows.length}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`;
                issued.set(page.nextCursor, { kind: query.kind, search: query.search, sort: query.sort, generation: page.complete!.manifest.generationId, offset: page.offset + page.rows.length, expiry: page.cursorExpiresAt });
            }
        }
        state.change?.(page);
        return response(page);
    });
    vi.stubGlobal('fetch', fetch); return { ...state, state, fetch };
}
const open = (enabled = true, session = 'session-a') => render(<WindowsNetworkContextPanel deviceId={networkContextDevice} sessionKey={session} enabled={enabled}/>);
const names = () => Array.from(document.querySelectorAll('.windows-network-context tbody tr')).map(row => row.querySelector('td')!.textContent);
const search = (value: string) => fireEvent.change(screen.getByRole('searchbox'), { target: { value } });
const apply = () => fireEvent.click(screen.getByRole('button', { name: /Apply|Anwenden/ }));
beforeEach(() => { setLocale('en', false); vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, expiresAt: 'synthetic-session', insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() }); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('network-context private resource lifecycle', () => {
    it('does not request disabled, hidden, or unauthenticated resources', async () => {
        const server = fixtureServer(); const ui = open(false); await flush(); expect(server.fetch).not.toHaveBeenCalled(); ui.unmount(); vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); open(); await flush(); expect(server.fetch).not.toHaveBeenCalled(); cleanup(); vi.mocked(useOperator).mockReturnValue(null); open(); expect(screen.getByText(/Sign in as a LAN operator/)).toBeVisible(); expect(server.fetch).not.toHaveBeenCalled();
    });
    it.each(['blur', 'pagehide', 'hashchange', AUTH_REQUIRED_EVENT])('clears all rows, labels, controls and cursors after %s', async event => {
        const server = fixtureServer(); open(); await screen.findByRole('table'); search('private-query'); act(() => window.dispatchEvent(new Event(event))); expect(screen.queryByRole('searchbox')).toBeNull(); expect(screen.queryByRole('table')).toBeNull(); expect(document.body).not.toHaveTextContent('private-query');
        if (event === AUTH_REQUIRED_EVENT) { expect(screen.getByRole('button', { name: 'Refresh routes and counters' })).toBeDisabled(); const count = server.fetch.mock.calls.length; act(() => window.dispatchEvent(new Event('focus'))); await flush(); expect(server.fetch).toHaveBeenCalledTimes(count); }
        else { act(() => window.dispatchEvent(new Event('focus'))); await screen.findByRole('table'); expect(screen.getByRole('searchbox')).toHaveValue(''); expect(server.state.requests.at(-1)!.cursor).toBe(''); }
    });
    it('clears on visibility loss and discards a late result after device/session navigation', async () => {
        const server = fixtureServer(), visible = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible'); const ui = open(); await screen.findByRole('table'); visible.mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); expect(screen.queryByRole('table')).toBeNull(); visible.mockReturnValue('visible'); act(() => document.dispatchEvent(new Event('visibilitychange'))); await screen.findByRole('table');
        const late = deferred<Response>(); server.fetch.mockImplementationOnce(async () => response({ csrfToken: 'synthetic-csrf' })).mockImplementationOnce(() => late.promise); fireEvent.click(screen.getByRole('button', { name: 'Refresh routes and counters' })); await flush(); const signal = server.fetch.mock.calls.at(-1)![1]!.signal;
        ui.rerender(<WindowsNetworkContextPanel deviceId={`agent_${'8'.repeat(32)}`} sessionKey="new-session"/>); expect(signal?.aborted).toBe(true); await act(async () => late.resolve(response(networkContextPage()))); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByText('192.0.0.0/24')).toBeNull();
    });
    it.each([400, 403, 404, 409, 429, 503])('clears on HTTP %i without exposing raw private error text', async status => {
        const server = fixtureServer(); open(); await screen.findByRole('table'); server.state.failure = status; fireEvent.click(screen.getByRole('button', { name: 'Refresh routes and counters' })); await screen.findByRole('alert'); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByRole('searchbox')).toBeNull(); expect(document.body).not.toHaveTextContent('PRIVATE-ERROR');
    });
    it.each(['csrf', 'query'] as const)('locks on HTTP401 during %s', async stage => {
        const server = fixtureServer(); server.fetch.mockImplementation(async path => stage === 'csrf' || path.endsWith('/query') ? response({}, 401) : response({ csrfToken: 'synthetic-csrf' })); open(); await screen.findByRole('alert'); expect(screen.getByRole('alert')).toHaveTextContent('session has ended'); expect(screen.getByRole('button', { name: 'Refresh routes and counters' })).toBeDisabled();
    });
    it('never sends a page POST after a protected epoch changes during CSRF acquisition', async () => {
        const late = deferred<Response>(), fetch = vi.fn(() => late.promise); vi.stubGlobal('fetch', fetch); open(); await flush(); act(() => { abortProtectedRequests(); window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)); }); await act(async () => late.resolve(response({ csrfToken: 'synthetic-csrf' }))); expect(fetch).toHaveBeenCalledTimes(1); expect(screen.queryByRole('table')).toBeNull();
    });
    it('enforces the 256KiB response bound and rejects wrong query echoes', async () => {
        const server = fixtureServer(); server.fetch.mockImplementation(async path => path === '/api/session' ? response({ csrfToken: 'synthetic-csrf' }) : new Response(' '.repeat(NETWORK_CONTEXT_PAGE_BYTES + 1))); open(); await screen.findByRole('alert'); expect(screen.queryByRole('table')).toBeNull(); cleanup(); fixtureServer().state.change = page => { page.search = 'private-other-query'; }; open(); await screen.findByRole('alert'); expect(document.body).not.toHaveTextContent('private-other-query'); expect(screen.queryByRole('table')).toBeNull();
    });
    it('times out and ignores a late response without background querying or persistence', async () => {
        vi.useFakeTimers(); const server = fixtureServer(), late = deferred<Response>(); server.fetch.mockImplementation(async path => path === '/api/session' ? response({ csrfToken: 'synthetic-csrf' }) : late.promise); const writes = vi.spyOn(Storage.prototype, 'setItem'); open(); await flush(); await act(async () => vi.advanceTimersByTimeAsync(10001)); expect(screen.getByRole('alert')).toHaveTextContent('timed out'); await act(async () => late.resolve(response(networkContextPage()))); expect(screen.queryByRole('table')).toBeNull(); await act(async () => vi.advanceTimersByTimeAsync(60000)); expect(server.fetch).toHaveBeenCalledTimes(2); expect(writes).not.toHaveBeenCalled();
    });
    it('expires original authority/source/cursor locally and rejects replayed time', async () => {
        vi.useFakeTimers(); const server = fixtureServer(); server.state.change = page => { page.authorityUntil = '2026-10-11T06:00:11Z'; page.cursorExpiresAt = page.authorityUntil; }; open(); await flush(); expect(names()).toHaveLength(100); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('expired');
        cleanup(); const second = fixtureServer(); second.state.change = page => { page.serverNow = networkContextNow; page.cursorExpiresAt = '2026-10-11T06:15:10Z'; }; open(); await flush(); await act(async () => vi.advanceTimersByTimeAsync(2000)); fireEvent.click(screen.getByRole('button', { name: 'Refresh routes and counters' })); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('Time reference'); expect(screen.queryByRole('table')).toBeNull();
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
        open(); await flush(); await act(async () => vi.advanceTimersByTimeAsync(500)); fireEvent.click(screen.getByRole('button', { name: 'Refresh routes and counters' })); await flush(); expect(names()).toHaveLength(100); expect(document.querySelector('time[datetime="2026-10-11T06:00:11Z"]')).not.toBeNull(); await act(async () => vi.advanceTimersByTimeAsync(500)); expect(screen.queryByRole('table')).toBeNull();
    });
    it('keeps successful pages bounded without hidden repeat queries, sorts, or browser persistence', async () => {
        vi.useFakeTimers(); const server = fixtureServer(), writes = vi.spyOn(Storage.prototype, 'setItem'); open(); await flush(); expect(names()).toHaveLength(100); await act(async () => vi.advanceTimersByTimeAsync(60000)); expect(names()).toHaveLength(100); expect(server.state.requests).toHaveLength(1); expect(writes).not.toHaveBeenCalled();
    });
    it('rejects over-byte-limit draft search without losing the explicit original capture', async () => {
        const server = fixtureServer(); open(); await screen.findByRole('table'); search('😀'.repeat(65)); apply(); expect(screen.getByRole('alert')).toHaveTextContent('256 UTF-8 bytes'); expect(server.state.requests).toHaveLength(1); expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByText('Both tables').nextElementSibling).toHaveTextContent('208');
    });
    it('clears after an untrusted browser clock jump', async () => {
        vi.useFakeTimers(); fixtureServer(); open(); await flush(); expect(names()).toHaveLength(100); vi.setSystemTime(Date.now() + 5000); await act(async () => vi.advanceTimersByTimeAsync(250)); expect(screen.getByRole('alert')).toHaveTextContent('Time reference'); expect(screen.queryByRole('table')).toBeNull();
    });
});


describe('compact route and raw counter browser', () => {
    it.each(['en', 'de'] as const)('pages all routes and searches beyond first page (%s)', async locale => {
        setLocale(locale, false); const server = fixtureServer(); open(); await screen.findByRole('table'); expect(names()).toHaveLength(100);
        fireEvent.click(screen.getByRole('button', { name: locale === 'en' ? 'Next network page' : 'Nächste Netzwerkseite' })); await waitFor(() => expect(names()[0]).toBe('192.0.100.0/24'));
        fireEvent.click(screen.getByRole('button', { name: locale === 'en' ? 'Next network page' : 'Nächste Netzwerkseite' })); await waitFor(() => expect(names()).toHaveLength(6)); expect(screen.getByText('fe80::1%7')).toBeVisible(); expect(screen.getByText(locale === 'en' ? 'Not used' : 'Nicht verwendet')).toBeVisible();
        fireEvent.click(screen.getByText('2001:db8::/32')); expect(screen.getByText(locale === 'en' ? 'Destination scope ID: 7' : 'Ziel-Scope-ID: 7')).toBeVisible();
        search('192.0.204.0'); expect(screen.queryByRole('table')).toBeNull(); apply(); await waitFor(() => expect(names()).toEqual(['192.0.204.0/24']));
        expect(server.state.requests.at(-1)).toEqual({ ...networkContextQuery, search: '192.0.204.0' });
        const call = server.fetch.mock.calls.filter(([path]) => path.endsWith('/query')).at(-1)!; expect(call[1]).toMatchObject({ method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': 'synthetic-csrf' } }); expect(call[0]).not.toContain('?');
        expect(document.querySelector('.windows-network-context-details')).not.toHaveAttribute('open');
    });
    it('retains exact max/unsafe uint64 and zero counters, unavailable alias and literal text', async () => {
        fixtureServer(); render(<WindowsNetworkContextPanel deviceId={networkContextDevice} sessionKey="session" kind="interface"/>); await screen.findByRole('table');
        expect(screen.getAllByText('18446744073709551615')).toHaveLength(2); expect(screen.getByText('9007199254740993')).toBeVisible(); expect(screen.getAllByText('0').length).toBeGreaterThan(6); expect(screen.getByText('Fixture <adapter> [.*]')).toBeVisible(); expect(screen.getByText('Unavailable')).toBeVisible(); expect(document.querySelector('adapter,img,a')).toBeNull();
        expect(screen.getAllByRole('columnheader').map(v => v.textContent)).toEqual(['Alias', 'Snapshot interface index', 'Input octets', 'Output octets', 'Input errors', 'Output errors', 'Input discards', 'Output discards']);
        search('[.*]'); apply(); await waitFor(() => expect(names()).toHaveLength(1));
    });
    it('clears kind-bound rows, search and cursors on source change and rejects late source responses', async () => {
        const server = fixtureServer(), ui = open(); await screen.findByRole('table'); search('private'); const late = deferred<Response>(); const original = server.fetch.getMockImplementation()!;
        server.fetch.mockImplementationOnce((path, options) => original(path, options)).mockImplementationOnce(() => late.promise); apply(); await flush(); const signal = server.fetch.mock.calls.at(-1)![1]!.signal;
        ui.rerender(<WindowsNetworkContextPanel deviceId={networkContextDevice} sessionKey="session-a" kind="interface"/>); expect(signal?.aborted).toBe(true); await screen.findByText('9007199254740993'); await act(async () => late.resolve(response(networkContextPage())));
        expect(screen.getByRole('searchbox')).toHaveValue(''); expect(names()).toHaveLength(2); expect(server.state.requests.at(-1)?.kind).toBe('interface'); expect(server.state.requests.at(-1)?.cursor).toBe(''); expect(screen.queryByText('192.0.0.0/24')).toBeNull();
    });
    it('retains original capture age after failed attempt and requires reload on new generation', async () => {
        const server = fixtureServer(); server.state.change = page => { page.latestAttempt = { sequence: 2, attemptedAt: '2026-10-11T06:00:09Z', status: 'source_failed', reason: 'resource_limit' }; }; open(); await screen.findByRole('table');
        expect(screen.getByText(/Latest capture failed/)).toHaveTextContent('Showing earlier capture'); expect(document.querySelector('.windows-network-context-age time')).toHaveAttribute('datetime', server.complete.manifest.captureStartedAt);
        replaceNetworkContextGeneration(server.state.complete, server.rows, 3); server.state.change = null; fireEvent.click(screen.getByRole('button', { name: 'Refresh routes and counters' })); await screen.findByRole('alert'); expect(screen.queryByRole('table')).toBeNull();
        fireEvent.click(screen.getByRole('button', { name: 'Reload latest network capture' })); await screen.findByRole('table'); expect(server.state.requests.at(-1)?.cursor).toBe('');
    });
    it.each(['not_configured', 'disabled', 'awaiting', 'unavailable'] as const)('never renders %s as healthy empty', async status => {
        const server = fixtureServer(); server.state.status = status; open(); await screen.findByText({ not_configured: 'Local consent required', disabled: 'Collection disabled', awaiting: 'Waiting for first complete capture', unavailable: 'Routes and counters unavailable' }[status]); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByText(/No caller-visible routes/)).toBeNull();
    });
    it('only queries the selected independent Network source and clears on tab departure', async () => {
        const server = fixtureServer(); function Workspace() { const resource = useWindowsInventory(networkContextDevice, true, 'session'); return <WindowsInventoryWorkspace resource={resource} fullServices={{ deviceId: networkContextDevice, sessionKey: 'session', enabled: true }}/>; }
        render(<Workspace/>); fireEvent.click(screen.getByRole('tab', { name: 'Network' })); expect(server.state.requests).toHaveLength(0);
        fireEvent.change(screen.getByRole('combobox', { name: 'Network source' }), { target: { value: 'route' } }); await screen.findByText('192.0.0.0/24');
        const panel = screen.getByRole('region', { name: 'Routes' }); fireEvent.change(within(panel).getByRole('searchbox'), { target: { value: 'private' } });
        fireEvent.change(screen.getByRole('combobox', { name: 'Network source' }), { target: { value: 'interface' } }); await screen.findByText('9007199254740993'); expect(screen.getByRole('searchbox')).toHaveValue('');
        fireEvent.click(screen.getByRole('tab', { name: 'Hostname' })); expect(screen.queryByText('9007199254740993')).toBeNull(); const count = server.state.requests.length;
        fireEvent.click(screen.getByRole('tab', { name: 'Network' })); expect(screen.getByRole('combobox', { name: 'Network source' })).toHaveValue('legacy'); expect(server.state.requests).toHaveLength(count);
    });
});
