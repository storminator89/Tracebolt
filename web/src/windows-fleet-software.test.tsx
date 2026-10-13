import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT } from './api';
import { LOGOUT_INTENT_KEY, useOperator } from './auth';
import { setLocale } from './i18n';
import { WindowsFleetSoftwareLookup } from './windows-fleet-software';
import { FLEET_SOFTWARE_PAGE_BYTES } from './windows-fleet-software-types';
import type { FleetSoftwarePage, FleetSoftwareQuery } from './windows-fleet-software-types';
import { fleetSoftwareDevice, fleetSoftwareNow, fleetSoftwarePage, fleetSoftwareSession } from './windows-fleet-software-fixtures';
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const response = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
const flush = async () => act(async () => { for (let i = 0; i < 30; i++) await Promise.resolve(); });
function fixtureServer(total = 6) {
    const state = { total, failure: 0, transform: null as ((page: FleetSoftwarePage) => void) | null, requests: [] as FleetSoftwareQuery[] };
    const fetch = vi.fn(async (path: string, options?: RequestInit): Promise<Response> => {
        if (path === '/api/session') return response({ csrfToken: 'fixture-csrf' });
        if (path !== '/api/fleet/windows-software/query') return response({}, 404);
        const query = JSON.parse(options!.body as string) as FleetSoftwareQuery; state.requests.push(query);
        if (state.failure) return response({ error: { code: 'test_only', message: 'PRIVATE-ERROR-MUST-NOT-RENDER' } }, state.failure);
        const page = fleetSoftwarePage(query, state.total); page.serverNow = new Date().toISOString(); state.transform?.(page); return response(page);
    });
    vi.stubGlobal('fetch', fetch); return { state, fetch };
}
function open(locale: 'en' | 'de' = 'en') {
    setLocale(locale, false); const ui = render(<WindowsFleetSoftwareLookup/>);
    fireEvent.click(screen.getByRole('button', { name: locale === 'en' ? 'Find software across Windows devices' : 'Software auf Windows-Geräten suchen' })); return ui;
}
const changeName = (name: string, locale = 'en') => fireEvent.change(screen.getByRole('searchbox', { name: locale === 'en' ? 'Application name' : 'Anwendungsname' }), { target: { value: name } });
const changeVersion = (version: string, locale = 'en') => fireEvent.change(screen.getByRole('searchbox', { name: locale === 'en' ? 'Literal version' : 'Wörtliche Version' }), { target: { value: version } });
const submit = async (locale = 'en') => { fireEvent.click(screen.getByRole('button', { name: locale === 'en' ? 'Search reported software' : 'Gemeldete Software suchen' })); await flush(); };
const rows = () => document.querySelectorAll('.windows-fleet-software tbody tr');
const operator = () => ({ mode: 'lan' as const, authenticated: true, expiresAt: fleetSoftwareSession, insecureTestMode: false, loginMode: 'named' as const, actorId: `operator_${'a'.repeat(32)}`, capabilities: ['read' as const], hasExplicitMetadata: true, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() });
beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(fleetSoftwareNow); vi.mocked(useOperator).mockReturnValue(operator()); localStorage.removeItem(LOGOUT_INTENT_KEY); sessionStorage.removeItem(LOGOUT_INTENT_KEY); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); localStorage.removeItem(LOGOUT_INTENT_KEY); sessionStorage.removeItem(LOGOUT_INTENT_KEY); });

describe('fleet software lookup UI', () => {
    it.each(['en', 'de'] as const)('explicit protected search and replacing fleet/detail pages without action navigation (%s)', async locale => {
        const server = fixtureServer(); open(locale); expect(server.fetch).not.toHaveBeenCalled();
        changeName('Fixture', locale); expect(server.fetch).not.toHaveBeenCalled(); await submit(locale); expect(rows()).toHaveLength(15);
        expect(screen.getByText(locale === 'en' ? 'Devices: 1–5 of 6' : 'Geräte: 1–5 von 6')).toBeVisible();
        expect(screen.getAllByText(new RegExp(locale === 'en' ? 'Registrations with unavailable queried fields: 4' : 'Registrierungen mit nicht verfügbaren Suchfeldern: 4'))).toHaveLength(5);
        expect(screen.getAllByText(locale === 'en' ? 'Empty value' : 'Leerer Wert')).toHaveLength(5);
        fireEvent.click(screen.getByRole('button', { name: locale === 'en' ? 'Next devices' : 'Nächste Geräte' })); await flush(); expect(rows()).toHaveLength(3); expect(screen.queryByText(fleetSoftwareDevice(0))).toBeNull();
        const hash = window.location.hash;
        fireEvent.click(screen.getByRole('button', { name: `${locale === 'en' ? 'View all matching registrations' : 'Alle passenden Registrierungen ansehen'}: ${fleetSoftwareDevice(5)}` })); await flush(); expect(rows()).toHaveLength(20); expect(window.location.hash).toBe(hash);
        fireEvent.click(screen.getByRole('button', { name: locale === 'en' ? 'Next matching registrations' : 'Nächste passende Registrierungen' })); await flush(); expect(rows()).toHaveLength(3); expect(screen.queryByText('Fixture [.*] Ä 0')).toBeNull();
        expect(server.state.requests.map(q => q.cursor === '')).toEqual([true, false, false, false]);
        for (const [path, options] of server.fetch.mock.calls.filter(([path]) => path.endsWith('/query'))) {
            expect(path).toBe('/api/fleet/windows-software/query'); expect(options).toMatchObject({ method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': 'fixture-csrf', 'Content-Type': 'application/json' } });
            expect(Object.keys(JSON.parse(options!.body as string))).toEqual(['name', 'version', 'cursor']);
        }
        expect(screen.queryByRole('link')).toBeNull(); expect(screen.queryByRole('button', { name: /install|update|restart|export|execute/i })).toBeNull();
        fireEvent.click(screen.getByRole('button', { name: locale === 'en' ? 'Back to search' : 'Zurück zur Suche' })); expect(rows()).toHaveLength(0); expect(server.state.requests).toHaveLength(4);
    }, 15000);
    it('keeps literal input in private bodies, clears on editing and distinguishes zero matches', async () => {
        const server = fixtureServer(1); open(); changeName('[.*]'); changeVersion('1.2.3+literal'); await submit(); expect(rows()).toHaveLength(3);
        expect(server.state.requests[0]).toEqual({ name: '[.*]', version: '1.2.3+literal', cursor: '' });
        const store = vi.spyOn(Storage.prototype, 'setItem'); changeName('Private query'); expect(rows()).toHaveLength(0); expect(server.state.requests).toHaveLength(1); await submit();
        expect(server.fetch.mock.calls.every(([path]) => !path.includes('?') && !path.includes('Private') && !path.includes('cursor_'))).toBe(true); expect(store).not.toHaveBeenCalled();
        expect(screen.getByText('No reported match. This does not prove the application is absent.')).toBeVisible();
    });
    it('separates stale earlier captures, failed attempts, source coverage and nonready states', async () => {
        const server = fixtureServer(5); server.state.transform = page => {
            page.items[0].latestAttempt = { sequence: 2, attemptedAt: '2026-10-11T06:00:09Z', status: 'source_failed', reason: 'access_denied' };
            for (const [index, status] of (['not_configured', 'disabled', 'awaiting', 'unavailable'] as const).entries()) Object.assign(page.items[index + 1], { status, complete: null, latestAttempt: null, matchingCount: 0, unknownCount: 0, rows: [], detailCursor: '' });
        };
        vi.setSystemTime('2026-10-11T06:03:00Z'); open(); changeName('Fixture'); await submit();
        expect(screen.getByText('Stale capture')).toBeVisible(); expect(screen.getByText(/Latest capture failed/)).toHaveTextContent('Showing the earlier complete capture with its original age.');
        for (const label of ['Machine-software consent not configured', 'Collection disabled', 'Waiting for first complete capture', 'Software report unavailable']) expect(screen.getByText(label)).toBeVisible();
        expect(rows()).toHaveLength(3); expect(screen.queryByText('No reported match. This does not prove the application is absent.')).toBeNull();
        expect(document.querySelector('time[datetime="2026-10-11T06:00:00Z"]')).not.toBeNull();
    });
    it('ages capture freshness and clears at original deadline without polling', async () => {
        const server = fixtureServer(1); open(); changeName('Fixture'); await submit(); expect(screen.getByText('Fresh capture')).toBeVisible();
        act(() => vi.advanceTimersByTime(121000)); expect(screen.getByText('Stale capture')).toBeVisible(); expect(server.state.requests).toHaveLength(1);
        act(() => vi.advanceTimersByTime(179000)); expect(rows()).toHaveLength(0); expect(screen.getByRole('alert')).toHaveTextContent('expired'); expect(screen.getByRole('searchbox', { name: 'Application name' })).toHaveValue(''); expect(server.state.requests).toHaveLength(1);
    });
    it('distinguishes a missing manager schema from an empty authorized roster', async () => {
        const server = fixtureServer(0); open(); changeName('Fixture'); await submit(); expect(screen.getByText('No currently authorized Windows devices.')).toBeVisible();
        server.state.transform = page => { page.status = 'not_configured'; page.cursorExpiresAt = null; }; await submit(); expect(screen.getByRole('status')).toHaveTextContent('not configured'); expect(screen.queryByText('No currently authorized Windows devices.')).toBeNull();
    });
    it('escapes source text and denies unauthenticated, non-LAN or missing named-read authority', async () => {
        const server = fixtureServer(1); server.state.transform = page => { page.items[0].rows[0].name = '<img src=x onerror=alert(1)>'; }; open(); changeName('Fixture'); await submit(); expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeVisible(); expect(document.querySelector('img, script:not([src]), a')).toBeNull(); cleanup();
        for (const value of [null, { ...operator(), authenticated: false }, { ...operator(), mode: 'development' as const }, { ...operator(), capabilities: [] }]) { vi.mocked(useOperator).mockReturnValue(value); const ui = render(<WindowsFleetSoftwareLookup/>); expect(screen.queryByRole('button')).toBeNull(); ui.unmount(); }
    });
    it('rejects empty, oversized UTF-8, NUL and malformed queries before network', async () => {
        const server = fixtureServer(); open(); expect(screen.getByRole('button', { name: 'Search reported software' })).toBeDisabled();
        for (const query of ['🛠'.repeat(65), 'x\0', '\ud800']) { changeName(query); await submit(); expect(screen.getByRole('alert')).toHaveTextContent('256 UTF-8 bytes'); }
        expect(server.fetch).not.toHaveBeenCalled();
    });
});

describe('fleet lookup privacy and response guards', () => {
    it.each(['blur', 'pagehide', 'popstate', 'hashchange', AUTH_REQUIRED_EVENT, 'hidden', 'close', 'clear', 'unmount'])('purges controls, rows, details and late responses on %s', async event => {
        const server = fixtureServer(1), ui = open(); changeName('Fixture'); changeVersion('literal'); await submit(); expect(rows()).toHaveLength(3);
        let resolve!: (value: Response) => void; const original = server.fetch.getMockImplementation()!;
        server.fetch.mockImplementation((path, options) => path === '/api/session' ? original(path, options) : new Promise(done => { resolve = done; }));
        fireEvent.click(screen.getByRole('button', { name: /View all matching registrations:/ })); await flush(); const signal = server.fetch.mock.calls.at(-1)![1]!.signal;
        act(() => {
            if (event === 'unmount') ui.unmount();
            else if (event === 'close') fireEvent.click(screen.getByRole('button', { name: 'Close software lookup' }));
            else if (event === 'clear') fireEvent.click(screen.getByRole('button', { name: 'Clear search' }));
            else if (event === 'hidden') { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); document.dispatchEvent(new Event('visibilitychange')); }
            else window.dispatchEvent(new Event(event));
        });
        expect(signal?.aborted).toBe(true); await act(async () => resolve(response(fleetSoftwarePage()))); expect(rows()).toHaveLength(0); expect(document.body).not.toHaveTextContent(fleetSoftwareDevice(0)); for (const input of screen.queryAllByRole('searchbox')) expect(input).toHaveValue('');
        const calls = server.fetch.mock.calls.length; act(() => window.dispatchEvent(new Event('focus'))); await flush(); expect(server.fetch).toHaveBeenCalledTimes(calls);
    });
    it.each(['actor', 'session', 'epoch', 'logout', 'clock'])('invalidates evidence and controls on %s loss', async change => {
        const server = fixtureServer(1), ui = open(); changeName('Fixture'); await submit(); expect(rows()).toHaveLength(3);
        if (change === 'actor' || change === 'session') { vi.mocked(useOperator).mockReturnValue({ ...operator(), ...(change === 'actor' ? { actorId: `operator_${'b'.repeat(32)}` } : { expiresAt: '2026-10-11T08:00:00Z' }) }); ui.rerender(<WindowsFleetSoftwareLookup/>); }
        else act(() => { if (change === 'epoch') abortProtectedRequests(); if (change === 'logout') localStorage.setItem(LOGOUT_INTENT_KEY, '1'); if (change === 'clock') vi.setSystemTime(Date.now() - 5000); vi.advanceTimersByTime(250); });
        expect(rows()).toHaveLength(0); expect(document.body).not.toHaveTextContent(fleetSoftwareDevice(0)); for (const input of screen.queryAllByRole('searchbox')) expect(input).toHaveValue(''); expect(server.state.requests).toHaveLength(1);
    });
    it('honors session expiry and rejects a cursor deadline beyond it', async () => {
        vi.mocked(useOperator).mockReturnValue({ ...operator(), expiresAt: '2026-10-11T06:00:11Z' });
        const server = fixtureServer(1); open(); changeName('Fixture'); await submit(); expect(rows()).toHaveLength(0); expect(screen.getByRole('alert')).toHaveTextContent('Invalid response');
        server.state.transform = page => { page.cursorExpiresAt = '2026-10-11T06:00:11Z'; }; changeName('Fixture'); await submit(); expect(rows()).toHaveLength(3);
        act(() => vi.advanceTimersByTime(1000)); expect(rows()).toHaveLength(0); expect(screen.getByRole('alert')).toHaveTextContent('session has ended');
    });
    it('times out ignored aborts and discards their late response without polling', async () => {
        const server = fixtureServer(1); let resolve!: (value: Response) => void; server.fetch.mockImplementation(async path => path === '/api/session' ? response({ csrfToken: 'fixture-csrf' }) : new Promise(done => { resolve = done; }));
        open(); changeName('Fixture'); await submit(); expect(screen.getByRole('status')).toHaveTextContent('Reading'); act(() => vi.advanceTimersByTime(10000)); expect(screen.getByRole('alert')).toHaveTextContent('timed out');
        await act(async () => resolve(response(fleetSoftwarePage()))); expect(rows()).toHaveLength(0); act(() => vi.advanceTimersByTime(20000)); expect(server.fetch).toHaveBeenCalledTimes(2);
    });
    it.each([401, 403, 409, 429, 503])('clears HTTP %i without rendering private error content', async status => {
        const server = fixtureServer(1); server.state.failure = status; open(); changeName('Fixture'); await submit(); expect(screen.getByRole('alert')).toBeVisible(); expect(document.body).not.toHaveTextContent('PRIVATE-ERROR'); expect(rows()).toHaveLength(0); expect(screen.getByRole('searchbox', { name: 'Application name' })).toHaveValue('');
        if (status === 401) expect(screen.getByRole('button', { name: 'Search reported software' })).toBeDisabled();
    });
    it('never sends the private POST after a protected epoch changes during CSRF acquisition', async () => {
        const server = fixtureServer(); let resolve!: (value: Response) => void; server.fetch.mockImplementation(() => new Promise(done => { resolve = done; })); open(); changeName('Fixture'); await submit();
        act(() => abortProtectedRequests()); await act(async () => resolve(response({ csrfToken: 'fixture-csrf' }))); await flush(); expect(server.fetch).toHaveBeenCalledTimes(1); expect(rows()).toHaveLength(0);
    });
    it.each(['oversized', 'deadline', 'identity', 'device-order'])('rejects hostile %s continuation', async variant => {
        const server = fixtureServer(variant === 'device-order' ? 6 : 1); open(); changeName('Fixture'); await submit(); expect(rows().length).toBeGreaterThan(0);
        if (variant === 'oversized') server.fetch.mockImplementation(async path => path === '/api/session' ? response({ csrfToken: 'fixture-csrf' }) : new Response(' '.repeat(FLEET_SOFTWARE_PAGE_BYTES + 1)));
        else { act(() => vi.advanceTimersByTime(2000)); server.state.transform = page => { if (variant === 'deadline') page.cursorExpiresAt = '2026-10-11T06:05:11Z'; else if (variant === 'identity') page.items[0].identity = 'b'.repeat(64); else page.items[0] = fleetSoftwarePage({ name: page.name, version: page.version, cursor: '' }).items[0]; }; }
        fireEvent.click(screen.getByRole('button', { name: variant === 'device-order' ? 'Next devices' : /View all matching registrations:/ })); await flush(); expect(screen.getByRole('alert')).toBeVisible(); expect(rows()).toHaveLength(0);
    });
});
