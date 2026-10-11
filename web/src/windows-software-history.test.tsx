import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { WindowsSoftwareHistoryPanel, WindowsSoftwareWorkspace } from './windows-software-history';
import { SOFTWARE_HISTORY_PAGE_BYTES, softwareHistoryVisible, validSoftwareHistoryPage } from './windows-software-history-types';
import type { SoftwareHistoryPage, SoftwareHistoryQuery } from './windows-software-history-types';
import { softwareHistoryDevice, softwareHistoryNow, softwareHistoryPage, softwareHistoryQuery, softwareHistoryScenario } from './windows-software-history-fixtures';

vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const response = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
function server() {
    const began = Date.now(), state = { requests: [] as SoftwareHistoryQuery[], scenario: 'normal', failure: 0, transform: null as ((p: SoftwareHistoryPage) => void) | null, hold: null as Promise<void> | null };
    const fetch = vi.fn(async (path: string, options?: RequestInit) => {
        if (path === '/api/session') return response({ csrfToken: 'synthetic-csrf' });
        if (!path.endsWith('/windows-software-history/query')) return response({}, 404);
        const q = JSON.parse(options!.body as string) as SoftwareHistoryQuery; state.requests.push(q);
        if (state.failure) return response({ error: { code: 'synthetic', message: 'PRIVATE-ERROR-DO-NOT-RENDER' } }, state.failure);
        const offset = q.cursor ? Number(q.cursor.match(/^history_(\d+)\./)?.[1]) : 0;
        const p = softwareHistoryScenario(state.scenario, q, offset); p.deviceId = path.split('/')[3]; p.serverNow = new Date(Date.parse(softwareHistoryNow) + Date.now() - began).toISOString(); state.transform?.(p);
        if (state.hold) await state.hold;
        return response(p);
    });
    vi.stubGlobal('fetch', fetch); return { state, fetch };
}
const open = (sessionKey = 'session-a', deviceId = softwareHistoryDevice, enabled = true) => render(<WindowsSoftwareHistoryPanel deviceId={deviceId} sessionKey={sessionKey} enabled={enabled}/>);
const rows = () => Array.from(document.querySelectorAll('.windows-software-history tbody>tr'));
const flush = () => act(async () => { for (let i = 0; i < 12; i++) await Promise.resolve(); });
beforeEach(() => { setLocale('en', false); vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, expiresAt: 'synthetic-session', insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() }); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('bounded software history DTO', () => {
    it.each(['normal', 'not_configured', 'disabled', 'awaiting', 'baseline', 'source_gap', 'incomparable', 'resource_limit', 'expired-counts'])('accepts explicit %s semantics', name => {
        const p = softwareHistoryScenario(name); expect(validSoftwareHistoryPage(p, softwareHistoryDevice, softwareHistoryQuery, 0)).toBe(true);
    });
    it('rejects inferred unknown version changes and wrong identities, ordering, bounds, clocks and paging', () => {
        const changes: ((p: SoftwareHistoryPage) => void)[] = [p => p.rows[3].changedFields.push('version'), p => p.rows[0].before = p.rows[0].after, p => p.rows[2].after!.registrationId = 'c'.repeat(64), p => p.rows.reverse(), p => p.rows[2].expiresAt = '2026-10-18T06:00:00Z', p => p.rows[2].afterObservedAt = '2026-10-12T00:00:00Z', p => p.rows.push(p.rows[0]), p => p.offset = 1, p => p.retainedCount = 1025, p => p.matchingCount = 1, p => p.nextCursor = '', p => p.cursorExpiresAt = '2026-10-11T07:00:00Z', p => p.grantId = null, p => p.historyDigest = '', p => p.rows[2].changedFields = [], p => p.comparison!.reason = 'no_baseline'];
        for (const change of changes) { const p = softwareHistoryPage(); change(p); expect(validSoftwareHistoryPage(p, softwareHistoryDevice, softwareHistoryQuery, 0)).toBe(false); }
        expect(validSoftwareHistoryPage({ ...softwareHistoryPage(), unexpected: true }, softwareHistoryDevice, softwareHistoryQuery, 0)).toBe(false);
    });
    it('uses the original earliest deadline, including comparison expiry', () => {
        const p = softwareHistoryPage(); expect(softwareHistoryVisible(p, 1)).toBe(true); expect(softwareHistoryVisible(p, 900000)).toBe(false); expect(softwareHistoryVisible(p, Infinity)).toBe(false);
        p.comparison!.expiresAt = p.serverNow; expect(softwareHistoryVisible(p, 0)).toBe(false);
    });
});
describe('private bilingual software history', () => {
    it.each(['en', 'de'] as const)('renders compact observed evidence and private search/paging (%s)', async locale => {
        setLocale(locale, false); const s = server(); open(); await screen.findByRole('table'); expect(rows()).toHaveLength(100);
        const c = locale === 'en' ? { next: 'Next history page', previous: 'Previous history page', apply: 'Apply', details: 'Details', removed: 'Registration removed', unavailable: 'Unavailable' } : { next: 'Nächste Verlaufsseite', previous: 'Vorherige Verlaufsseite', apply: 'Anwenden', details: 'Details', removed: 'Registrierung entfernt', unavailable: 'Nicht verfügbar' };
        expect(document.querySelector('.windows-history-scope')).not.toHaveAttribute('open'); expect(document.querySelector('.windows-history-row-details')).not.toHaveAttribute('open'); expect(screen.getByText(c.removed)).toBeVisible();
        const unknown = rows()[3]; expect(unknown.querySelector('td:nth-child(2)')).toHaveTextContent(locale === 'en' ? 'Name' : 'Name'); expect(unknown.querySelector('td:nth-child(2)')).not.toHaveTextContent('Version'); fireEvent.click(within(unknown as HTMLElement).getByText(c.details)); expect(within(unknown as HTMLElement).getByText(`${locale === 'en' ? 'Before' : 'Vorher'}: ${c.unavailable}`)).toBeVisible();
        fireEvent.click(screen.getByRole('button', { name: c.next })); await waitFor(() => expect(rows()[0]).toHaveTextContent('Fixture Software 0101')); expect(rows()).toHaveLength(100);
        fireEvent.click(screen.getByRole('button', { name: c.next })); await waitFor(() => expect(rows()).toHaveLength(5)); expect(screen.getByRole('button', { name: c.next })).toBeDisabled();
        fireEvent.click(screen.getByRole('button', { name: c.previous })); await waitFor(() => expect(rows()[0]).toHaveTextContent('Fixture Software 0101'));
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: '[.*]' } }); expect(rows()).toHaveLength(0); fireEvent.click(screen.getByRole('button', { name: c.apply })); await waitFor(() => expect(rows()).toHaveLength(1)); fireEvent.click(within(rows()[0] as HTMLElement).getByText(c.details)); expect(screen.getByText(/<img src=x onerror=alert\(1\)>/)).toBeVisible(); expect(document.querySelector('.windows-software-history img,a,script:not([src])')).toBeNull();
        expect(s.state.requests.at(-1)).toEqual({ ...softwareHistoryQuery, search: '[.*]' }); const call = s.fetch.mock.calls.filter(([p]) => p.endsWith('/query')).at(-1)!; expect(call[0]).toBe(`/api/devices/${softwareHistoryDevice}/windows-software-history/query`); expect(call[1]).toMatchObject({ method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': 'synthetic-csrf' } });
    });
    it.each(['not_configured', 'disabled', 'awaiting', 'baseline', 'resource_limit', 'source_gap', 'expired-counts'])('exposes %s without inventing changes or grants', async scenario => {
        const s = server(); s.state.scenario = scenario; open(); await waitFor(() => expect(document.querySelector('[aria-busy="false"]')).toBeTruthy());
        expect(screen.queryByRole('button', { name: /enable|grant|install|export|upgrade/i })).toBeNull();
        if (['not_configured', 'disabled', 'awaiting', 'baseline', 'expired-counts'].includes(scenario)) expect(rows()).toHaveLength(0);
        if (scenario === 'not_configured') expect(await screen.findByText('History is off. Separate local consent is required.')).toBeVisible();
        if (scenario === 'baseline') expect(await screen.findByText(/Baseline captured/)).toBeVisible();
        if (scenario === 'resource_limit') { expect(await screen.findByText(/complete comparison exceeded/)).toBeVisible(); expect(screen.getByText('1500')).toBeVisible(); }
        if (scenario === 'expired-counts') { expect(await screen.findByText('205')).toBeVisible(); expect(screen.queryByText(/Latest captures compared/)).toBeNull(); }
    });
    it('keeps current inventory as default and does not query history until selected', async () => {
        const s = server(); render(<WindowsSoftwareWorkspace deviceId={softwareHistoryDevice} sessionKey="session-a"/>); await flush(); expect(s.state.requests).toHaveLength(0);
        fireEvent.click(screen.getByRole('button', { name: 'Change history' })); await screen.findByRole('table'); fireEvent.click(screen.getByRole('button', { name: 'Current inventory' })); expect(rows()).toHaveLength(0);
        fireEvent.click(screen.getByRole('button', { name: 'Change history' })); await screen.findByRole('table'); expect(s.state.requests.at(-1)!.cursor).toBe('');
    });
    it.each(['blur', 'pagehide', 'hashchange', 'visibility'])('clears rows, details, search and cursors at %s', async event => {
        const s = server(); open(); await screen.findByRole('table'); fireEvent.click(screen.getByRole('button', { name: 'Next history page' })); await waitFor(() => expect(rows()[0]).toHaveTextContent('Fixture Software 0101'));
        if (event === 'visibility') { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); fireEvent(document, new Event('visibilitychange')); } else fireEvent(window, new Event(event));
        expect(rows()).toHaveLength(0); expect(screen.queryByRole('searchbox')).toBeNull();
        if (event === 'visibility') { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible'); fireEvent(document, new Event('visibilitychange')); } else fireEvent(window, new Event('focus'));
        await screen.findByRole('table'); expect(s.state.requests.at(-1)).toEqual(softwareHistoryQuery);
    });
    it('discards delayed responses after session/device changes and disabled views', async () => {
        const s = server(); const view = open(); await screen.findByRole('table'); let release!: () => void; s.state.hold = new Promise(resolve => { release = resolve; }); fireEvent.click(screen.getByRole('button', { name: 'Refresh software history' })); expect(rows()).toHaveLength(0);
        view.rerender(<WindowsSoftwareHistoryPanel deviceId={`agent_${'b'.repeat(32)}`} sessionKey="session-b" enabled={false}/>); release(); await flush(); expect(rows()).toHaveLength(0); expect(screen.queryByRole('searchbox')).toBeNull();
        s.state.hold = null; view.rerender(<WindowsSoftwareHistoryPanel deviceId={`agent_${'b'.repeat(32)}`} sessionKey="session-b"/>); await screen.findByRole('table'); expect(s.state.requests.at(-1)).toEqual(softwareHistoryQuery);
    });
    it.each([401, 403, 409, 429])('clears on protected HTTP %s without rendering private server errors', async status => {
        const s = server(); open(); await screen.findByRole('table'); s.state.failure = status; fireEvent.click(screen.getByRole('button', { name: 'Refresh software history' })); await screen.findByRole('alert'); expect(rows()).toHaveLength(0); expect(document.body).not.toHaveTextContent('PRIVATE-ERROR');
    });
    it('rejects changed snapshot on paging and starts fresh only when asked', async () => {
        const s = server(); open(); await screen.findByRole('table'); s.state.transform = p => { p.historyDigest = 'c'.repeat(64); }; fireEvent.click(screen.getByRole('button', { name: 'Next history page' })); await screen.findByText('History or access changed. Reload history.'); expect(rows()).toHaveLength(0); fireEvent.click(screen.getByRole('button', { name: 'Reload history' })); await screen.findByRole('table'); expect(s.state.requests.at(-1)!.cursor).toBe('');
    });
    it('clears on session events, original deadline and oversized response', async () => {
        const s = server(); open(); await screen.findByRole('table'); fireEvent(window, new Event(AUTH_REQUIRED_EVENT)); expect(rows()).toHaveLength(0); cleanup();
        s.state.transform = p => { p.cursorExpiresAt = new Date(Date.parse(p.serverNow) + 150).toISOString(); }; open(); await screen.findByRole('table'); await screen.findByText('History or paging session expired. Reload history.'); expect(rows()).toHaveLength(0); cleanup();
        s.state.transform = p => { p.rows[0].after!.name = 'a'.repeat(SOFTWARE_HISTORY_PAGE_BYTES); }; open(); await screen.findByRole('alert'); expect(rows()).toHaveLength(0);
    });
    it('times out without background polling or browser persistence and discards the late page', async () => {
        vi.useFakeTimers(); const s = server(), writes = vi.spyOn(Storage.prototype, 'setItem'); let release!: () => void;
        s.state.hold = new Promise(resolve => { release = resolve; }); open(); await flush(); await act(async () => vi.advanceTimersByTimeAsync(10001)); expect(screen.getByRole('alert')).toHaveTextContent('timed out'); release(); await flush(); expect(rows()).toHaveLength(0); await act(async () => vi.advanceTimersByTimeAsync(60000)); expect(s.state.requests).toHaveLength(1); expect(writes).not.toHaveBeenCalled();
    });
    it('clears after untrusted wall-clock movement and rejects a frozen server time', async () => {
        vi.useFakeTimers(); server(); open(); await flush(); expect(rows()).toHaveLength(100); vi.setSystemTime(Date.now() + 5000); await act(async () => vi.advanceTimersByTimeAsync(250)); expect(screen.getByRole('alert')).toHaveTextContent('Time reference'); expect(rows()).toHaveLength(0); cleanup();
        const s = server(); s.state.transform = p => { p.serverNow = softwareHistoryNow; }; open(); await flush(); await act(async () => vi.advanceTimersByTimeAsync(2000)); fireEvent.click(screen.getByRole('button', { name: 'Refresh software history' })); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('Time reference'); expect(rows()).toHaveLength(0);
    });
    it('cannot renew the original paging lifetime by refreshing page one', async () => {
        vi.useFakeTimers(); const s = server(); s.state.transform = p => { p.cursorExpiresAt = new Date(Date.parse(p.serverNow) + 1000).toISOString(); }; open(); await flush(); expect(rows()).toHaveLength(100); await act(async () => vi.advanceTimersByTimeAsync(500)); fireEvent.click(screen.getByRole('button', { name: 'Refresh software history' })); await flush(); expect(rows()).toHaveLength(100); await act(async () => vi.advanceTimersByTimeAsync(500)); expect(rows()).toHaveLength(0); expect(screen.getByRole('alert')).toHaveTextContent('expired');
    });
    it('clears awaiting attempt metadata at current authority expiry', async () => {
        vi.useFakeTimers(); const s = server(); s.state.scenario = 'awaiting'; s.state.transform = p => { p.authorityUntil = new Date(Date.parse(p.serverNow) + 1000).toISOString(); p.latestAttempt = { sequence: 1, attemptedAt: '2026-10-11T06:00:00Z', status: 'pending', reason: '' }; }; open(); await flush(); expect(document.querySelector('.windows-history-scope')).toHaveTextContent('Pending'); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.getByRole('alert')).toHaveTextContent('expired'); expect(document.querySelector('.windows-history-scope')).not.toHaveTextContent('Pending');
    });

});
