import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT } from './api';
import { LOGOUT_INTENT_KEY, useOperator } from './auth';
import { setLocale } from './i18n';
import { WindowsFleetSoftwareLookup } from './windows-fleet-software';
import { fleetHistoryDevice, fleetHistoryNow, fleetHistoryPage, fleetHistorySession } from './windows-fleet-software-history-fixtures';
import type { FleetHistoryPage, FleetHistoryQuery } from './windows-fleet-software-history-types';
import { softwareHistoryState } from './windows-software-history-fixtures';
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const response = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
const flush = async () => act(async () => { for (let i = 0; i < 30; i++) await Promise.resolve(); });
function server(total = 6) {
    const state = { requests: [] as FleetHistoryQuery[], transform: null as ((p: FleetHistoryPage) => void) | null, fail: 0 };
    const fetch = vi.fn(async (path: string, options?: RequestInit) => {
        if (path === '/api/session') return response({ csrfToken: 'fixture-csrf' });
        if (path !== '/api/fleet/windows-software/query') return response({}, 404);
        const q = JSON.parse(options!.body as string) as FleetHistoryQuery; state.requests.push(q);
        if (state.fail) return response({ error: { code: 'failure', message: 'PRIVATE-ERROR-NOT-FOR-DISPLAY' } }, state.fail);
        const p = fleetHistoryPage(q, total); p.serverNow = new Date().toISOString(); state.transform?.(p); return response(p);
    });
    vi.stubGlobal('fetch', fetch); return { state, fetch };
}
function open(locale: 'en' | 'de' = 'en') {
    setLocale(locale, false); const ui = render(<WindowsFleetSoftwareLookup/>);
    fireEvent.click(screen.getByRole('button', { name: locale === 'en' ? 'Find software across Windows devices' : 'Software auf Windows-Geräten suchen' }));
    fireEvent.click(screen.getByRole('button', { name: locale === 'en' ? 'Observed changes' : 'Beobachtete Änderungen' })); return ui;
}
const read = async (locale = 'en') => { fireEvent.click(screen.getByRole('button', { name: locale === 'en' ? 'Read software changes' : 'Softwareänderungen lesen' })); await flush(); };
const rows = () => document.querySelectorAll('[data-history-id]');
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime(fleetHistoryNow);
    vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, expiresAt: fleetHistorySession, insecureTestMode: false, loginMode: 'named', actorId: `operator_${'a'.repeat(32)}`, capabilities: ['read'], hasExplicitMetadata: true, logout: vi.fn(), theme: 'light', setTheme: vi.fn() });
    localStorage.removeItem(LOGOUT_INTENT_KEY); sessionStorage.removeItem(LOGOUT_INTENT_KEY);
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); localStorage.removeItem(LOGOUT_INTENT_KEY); sessionStorage.removeItem(LOGOUT_INTENT_KEY); });

describe('fleet history private review', () => {
    it.each(['en', 'de'] as const)('uses explicit bounded source reads and exact drilldown (%s)', async locale => {
        const s = server(); open(locale); expect(s.fetch).not.toHaveBeenCalled(); await read(locale); expect(rows()).toHaveLength(15);
        fireEvent.click(screen.getByRole('button', { name: locale === 'en' ? 'Next devices' : 'Nächste Geräte' })); await flush(); expect(rows()).toHaveLength(3); expect(screen.queryByText(fleetHistoryDevice(0))).toBeNull();
        fireEvent.click(screen.getByRole('button', { name: `${locale === 'en' ? 'View matching changes' : 'Passende Änderungen ansehen'}: ${fleetHistoryDevice(5)}` })); await flush(); expect(rows()).toHaveLength(20);
        fireEvent.click(screen.getByRole('button', { name: locale === 'en' ? 'Next changes' : 'Nächste Änderungen' })); await flush(); expect(rows()).toHaveLength(4);
        expect(s.state.requests).toHaveLength(4); expect(s.state.requests.every(q => q.view === 'history' && q.version === '')).toBe(true);
        expect(s.fetch.mock.calls.every(([path]) => path === '/api/session' || path === '/api/fleet/windows-software/query')).toBe(true);
        expect(screen.queryByRole('link')).toBeNull(); expect(screen.queryByRole('button', { name: /install|export|execute|grant|remediate/i })).toBeNull();
    });
    it('separates unconfigured, disabled, awaiting, empty and gap evidence', async () => {
        const s = server(5); s.state.transform = p => {
            for (const [i, status] of (['not_configured', 'disabled', 'awaiting'] as const).entries()) {
                const h = softwareHistoryState(status, { search: '', sort: 'observed-desc', limit: 3, cursor: '' });
                p.items[i].history = { ...h, schemaVersion: 'tracebolt.windows-fleet-software-history-device.v1', deviceId: p.items[i].deviceId }; p.items[i].detailCursor = '';
            }
            Object.assign(p.items[3].history, { retainedCount: 0, matchingCount: 0, rows: [], gapCount: 1, omittedChanges: 1200 });
            p.items[3].history.comparison = { ...p.items[3].history.comparison!, status: 'gap', reason: 'resource_limit', observedChanges: 1200 };
        };
        open(); await read();
        for (const text of ['Software history has not been separately approved.', 'Software history disabled.', 'Waiting for comparable captures.', 'No matching retained changes for this device.']) expect(screen.getByText(text)).toBeVisible();
        expect(screen.getAllByText(/Comparison gaps: 1/)).toHaveLength(1); expect(rows()).toHaveLength(3);
    });
    it('clears private rows and search on blur, view switch, expiry, and access loss without polling', async () => {
        const s = server(1); open(); await read(); expect(rows()).toHaveLength(3);
        fireEvent(window, new Event('blur')); expect(rows()).toHaveLength(0);
        fireEvent(window, new Event('focus')); expect(s.state.requests).toHaveLength(1); await read();
        fireEvent.click(screen.getByRole('button', { name: 'Current inventory' })); expect(rows()).toHaveLength(0);
        fireEvent.click(screen.getByRole('button', { name: 'Observed changes' })); expect(s.state.requests).toHaveLength(2); await read();
        act(() => vi.advanceTimersByTime(300000)); expect(rows()).toHaveLength(0); expect(s.state.requests).toHaveLength(3);
        expect(screen.getByRole('alert')).toHaveTextContent('expired');
        fireEvent(window, new Event(AUTH_REQUIRED_EVENT)); expect(screen.getByRole('alert')).toHaveTextContent('session');
    });
    it('does not persist or put literal private search into URLs', async () => {
        const s = server(1); open(); const store = vi.spyOn(Storage.prototype, 'setItem');
        fireEvent.change(screen.getByRole('searchbox', { name: 'Search observed changes' }), { target: { value: 'Private [.*] 東京' } }); await read();
        expect(s.state.requests[0]).toEqual({ name: 'Private [.*] 東京', version: '', cursor: '', view: 'history' });
        expect(store).not.toHaveBeenCalled(); expect(rows()).toHaveLength(0); expect(screen.getByText('No matching retained changes for this device.')).toBeVisible();
        s.state.fail = 503; await read(); expect(screen.queryByText('PRIVATE-ERROR-NOT-FOR-DISPLAY')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('unavailable');
    });
    it('preserves nanosecond ordering across a detail page boundary with opposite IDs', async () => {
        const s = server(1); s.state.transform = p => {
            if (p.mode !== 'device') return;
            for (const row of p.items[0].history.rows) {
                row.afterObservedAt = p.offset === 0 ? '2026-10-11T06:00:01.000900000Z' : '2026-10-11T06:00:01.000100000Z';
                if (p.offset === 0) row.id = 'f' + row.id.slice(1);
            }
        };
        open(); await read(); fireEvent.click(screen.getByRole('button', { name: `View matching changes: ${fleetHistoryDevice(0)}` })); await flush(); expect(rows()).toHaveLength(20);
        fireEvent.click(screen.getByRole('button', { name: 'Next changes' })); await flush(); expect(rows()).toHaveLength(4); expect(screen.queryByRole('alert')).toBeNull();
    });
    it('discards a late private response after the lookup closes and does not reload on reopen', async () => {
        let deliver: ((value: Response) => void) | undefined;
        const fetch = vi.fn(async (path: string) => {
            if (path === '/api/session') return response({ csrfToken: 'fixture-csrf' });
            return new Promise<Response>(resolve => { deliver = resolve; });
        });
        vi.stubGlobal('fetch', fetch); open(); await read();
        expect(deliver).toBeDefined();
        fireEvent.click(screen.getByRole('button', { name: 'Close software lookup' }));
        deliver!(response(fleetHistoryPage(undefined, 1))); await flush(); expect(rows()).toHaveLength(0);
        const calls = fetch.mock.calls.length;
        fireEvent.click(screen.getByRole('button', { name: 'Find software across Windows devices' }));
        await flush(); expect(fetch.mock.calls).toHaveLength(calls); expect(rows()).toHaveLength(0);
    });
    it('rejects a frozen manager time reference on a later explicit read', async () => {
        const s = server(1); open(); await read(); expect(rows()).toHaveLength(3);
        act(() => vi.advanceTimersByTime(2500)); s.state.transform = p => { p.serverNow = fleetHistoryNow; };
        await read(); expect(rows()).toHaveLength(0); expect(screen.getByRole('alert')).toHaveTextContent('Time reference changed');
    });

});
