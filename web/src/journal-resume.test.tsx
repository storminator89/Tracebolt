import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests } from './api';
import { JournalPanel } from './journal';
import { journalDevice, journalPage, journalSession, journalSessionExpiry, journalView } from './journal-fixtures';
import { setLocale } from './i18n';
const root = `/api/devices/${journalDevice}/journal`;
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
const advance = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
const flush = () => act(async () => {});
function server(unavailable = () => false, override?: (url: string) => Response | Promise<Response> | undefined) {
    const fetch = vi.fn(async (url: string, _init?: RequestInit) => {
        const intercepted = override?.(url); if (intercepted !== undefined) return intercepted;
        if (url === '/api/auth/session') return json(journalSession);
        if (url === '/api/session') return json({ csrfToken: 'synthetic-csrf' });
        if (url === root) { const v = journalView(); if (unavailable()) { v.contentStatus = v.request!.contentStatus = 'unavailable'; } return json(v); }
        if (url === `${root}/query`) return json(journalPage(Array.from({ length: 100 }, (_, i) => `Invented row ${i}`), '', 0, 106));
        throw new Error('Unexpected synthetic route');
    }); vi.stubGlobal('fetch', fetch); return fetch;
}
async function mount() { const r = render(<JournalPanel deviceId={journalDevice} insecureTestMode={false} sessionKey={journalSessionExpiry}/>); await flush(); return r; }
function noMutation(fetch: ReturnType<typeof server>) { expect(fetch.mock.calls.some(([url]) => url.endsWith('/create') || url.endsWith('/cancel'))).toBe(false); }
beforeEach(() => { vi.useFakeTimers(); setLocale('en', false); localStorage.clear(); sessionStorage.clear(); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
describe('journal visible suspension and safe resume, synthetic only', () => {
    it('does not clear an accepted106-row capture during four minutes of idle timers', async () => {
        const fetch = server(); await mount(); expect(screen.getByText('106 matches · 106 captured')).toBeVisible(); const calls = fetch.mock.calls.length;
        await advance(240000); expect(screen.getByText('Invented row 0')).toBeVisible(); expect(screen.getByLabelText('Exact service unit')).toBeVisible(); expect(screen.getByText('Captured snapshot available')).toBeVisible(); expect(fetch).toHaveBeenCalledTimes(calls); noMutation(fetch);
    });
    it('preserves disabled inputs and shows paused status after blur; explicit refresh resumes without a focus event', async () => {
        const fetch = server(); await mount(); fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'draft.service' } }); await advance(60000); const calls = fetch.mock.calls.length;
        act(() => window.dispatchEvent(new Event('blur'))); expect(document.visibilityState).toBe('visible'); expect(screen.getByRole('heading', { name: 'Service logs' })).toBeVisible(); expect(screen.getByLabelText('Exact service unit')).toHaveValue('draft.service'); expect(screen.getByLabelText('Exact service unit')).toBeDisabled(); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.getByRole('status')).toHaveTextContent('Log content is paused'); expect(screen.queryByRole('alert')).not.toBeInTheDocument();
        await advance(60000); expect(fetch).toHaveBeenCalledTimes(calls); noMutation(fetch);
        fireEvent.click(screen.getByRole('button', { name: 'Refresh status' })); await flush(); expect(screen.getByLabelText('Exact service unit')).toHaveValue('draft.service'); expect(screen.getByLabelText('Exact service unit')).toBeEnabled(); expect(screen.getByText('Invented row 0')).toBeVisible(); expect(fetch.mock.calls.filter(([url]) => url === root)).toHaveLength(2); noMutation(fetch);
    });
    it('focus resumes with fresh session/status and page reads, without a new capture', async () => {
        const fetch = server(); await mount(); act(() => window.dispatchEvent(new Event('blur'))); expect(screen.getByRole('status')).toHaveTextContent('Log content is paused'); act(() => window.dispatchEvent(new Event('focus'))); await flush();
        expect(screen.getByText('Invented row 0')).toBeVisible(); expect(screen.getByLabelText('Exact service unit')).toBeEnabled(); expect(fetch.mock.calls.filter(([url]) => url === '/api/auth/session')).toHaveLength(4); expect(fetch.mock.calls.filter(([url]) => url === root)).toHaveLength(2); noMutation(fetch);
    });
    it('keeps the disabled draft form while resumed status is held, and clears search and acknowledgements', async () => {
        let hold = false, finish!: (value: Response) => void; const fetch = server(() => false, url => hold && url === root ? new Promise<Response>(resolve => { finish = resolve; }) : undefined); await mount();
        fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'draft.service' } }); fireEvent.change(screen.getByLabelText('Literal text in captured messages'), { target: { value: 'private search draft' } }); fireEvent.click(screen.getByRole('checkbox'));
        act(() => window.dispatchEvent(new Event('blur'))); hold = true; fireEvent.click(screen.getByRole('button', { name: 'Refresh status' })); await flush();
        expect(screen.getByRole('status')).toHaveTextContent('Reading journal status'); expect(screen.getByLabelText('Exact service unit')).toHaveValue('draft.service'); expect(screen.getByLabelText('Exact service unit')).toBeDisabled(); expect(screen.getByRole('checkbox')).not.toBeChecked(); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.queryByLabelText('Literal text in captured messages')).not.toBeInTheDocument();
        await act(async () => finish(json(journalView()))); expect(screen.getByText('Invented row 0')).toBeVisible(); expect(screen.getByLabelText('Literal text in captured messages')).toHaveValue(''); noMutation(fetch);
    });
    it('never refreshes while hidden and rechecks access before visibility restoration', async () => {
        const fetch = server(); await mount(); const calls = fetch.mock.calls.length, visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange')));
        fireEvent.click(screen.getByRole('button', { name: 'Refresh status' })); await flush(); expect(fetch).toHaveBeenCalledTimes(calls); expect(screen.getByLabelText('Exact service unit')).toBeDisabled(); expect(screen.queryByRole('table')).not.toBeInTheDocument();
        visibility.mockReturnValue('visible'); act(() => document.dispatchEvent(new Event('visibilitychange'))); await flush(); expect(screen.getByText('Invented row 0')).toBeVisible(); expect(fetch.mock.calls.filter(([url]) => url === '/api/auth/session')).toHaveLength(4); noMutation(fetch);
    });
    it('shows an error with disabled form on resumed read failure and safely recovers by explicit refresh', async () => {
        let fail = false; const fetch = server(() => false, url => fail && url === root ? json({ error: { code: 'storage_busy' } }, 503) : undefined); await mount(); act(() => window.dispatchEvent(new Event('blur'))); fail = true; act(() => window.dispatchEvent(new Event('focus'))); await flush();
        expect(screen.getByRole('alert')).toHaveTextContent('could not be read'); expect(screen.getByLabelText('Exact service unit')).toBeVisible(); expect(screen.getByLabelText('Exact service unit')).toBeDisabled(); expect(screen.queryByRole('table')).not.toBeInTheDocument();
        fail = false; fireEvent.click(screen.getByRole('button', { name: 'Refresh status' })); await flush(); expect(screen.getByText('Invented row 0')).toBeVisible(); noMutation(fetch);
    });
    it('cannot resume after operator session denial', async () => {
        let denied = false; const fetch = server(() => false, url => denied && url === '/api/auth/session' ? json({}, 401) : undefined); await mount(); act(() => window.dispatchEvent(new Event('blur'))); denied = true; fireEvent.click(screen.getByRole('button', { name: 'Refresh status' })); await flush();
        expect(screen.getByRole('alert')).toHaveTextContent('session has ended'); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.queryByLabelText('Exact service unit')).not.toBeInTheDocument(); const calls = fetch.mock.calls.length; for (const event of ['blur', 'pagehide', 'hashchange']) { act(() => window.dispatchEvent(new Event(event))); expect(screen.getByRole('alert')).toHaveTextContent('session has ended'); expect(screen.queryByLabelText('Exact service unit')).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Refresh status' })).toBeDisabled(); } act(() => window.dispatchEvent(new Event('focus'))); fireEvent.click(screen.getByRole('button', { name: 'Refresh status' })); await advance(901000); expect(fetch).toHaveBeenCalledTimes(calls); expect(screen.getByRole('alert')).toHaveTextContent('session has ended'); expect(screen.queryByLabelText('Exact service unit')).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Refresh status' })).toBeDisabled(); noMutation(fetch);
    });
    it('resets draft inputs on a new device or session scope rather than carrying them across', async () => {
        const fetch = server(); const mounted = await mount(); fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'draft.service' } }); mounted.rerender(<JournalPanel deviceId={journalDevice} insecureTestMode={false} sessionKey={null}/>); await flush(); expect(screen.getByLabelText('Exact service unit')).toHaveValue(''); noMutation(fetch);
    });
    it('shows explicit German pause guidance', async () => {
        setLocale('de', false); const fetch = server(); await mount(); act(() => window.dispatchEvent(new Event('blur'))); expect(screen.getByRole('status')).toHaveTextContent('Log-Inhalte sind pausiert'); expect(screen.getByLabelText('Exakte Service-Unit')).toBeDisabled(); noMutation(fetch);
    });
    it('normal retention expiry keeps an explicit status and form rather than the blank shell', async () => {
        const fetch = server(); await mount(); await advance(900000); expect(screen.getByText('Expired', { selector: 'strong' })).toBeVisible(); expect(screen.getByLabelText('Exact service unit')).toBeVisible(); expect(screen.queryByRole('table')).not.toBeInTheDocument(); noMutation(fetch);
    });
    it('a clock fault is visible rather than silent', async () => {
        const fetch = server(); await mount(); vi.spyOn(Date, 'now').mockReturnValue(Date.now() - 10000); await advance(250); expect(screen.getByRole('alert')).toHaveTextContent('time or request sequence'); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.getByLabelText('Exact service unit')).toBeDisabled(); noMutation(fetch);
    });
    it('accepted plus unavailable after resume requires a changed read response, not client cancel', async () => {
        let unavailable = false; const fetch = server(() => unavailable); await mount(); act(() => window.dispatchEvent(new Event('blur'))); unavailable = true; act(() => window.dispatchEvent(new Event('focus'))); await flush();
        expect(screen.getByText('Captured content unavailable')).toBeVisible(); expect(screen.getByText(/The manager reports that retained content is unavailable/)).toBeVisible(); expect(document.body.textContent).not.toContain('restart'); expect(screen.getByLabelText('Exact service unit')).toBeVisible(); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(fetch.mock.calls.filter(([url]) => url === `${root}/query`)).toHaveLength(1); noMutation(fetch);
    });
});
