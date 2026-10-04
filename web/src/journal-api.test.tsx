import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT } from './api';
import { LOGOUT_INTENT_KEY } from './auth';
import { setLocale } from './i18n';
import { JournalPanel } from './journal';
import { journalDevice, journalIdentity, journalNow, journalPage, journalSession, journalSessionExpiry, journalView } from './journal-fixtures';
import { JOURNAL_PAGE_BYTES } from './journal-types';
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
const root = `/api/devices/${journalDevice}/journal`;
type FetchOverride = (url: string, init?: RequestInit) => Response | Promise<Response> | undefined;
function server(override?: FetchOverride) {
    const fetch = vi.fn(async (url: string, init?: RequestInit) => {
        const overridden = override?.(url, init); if (overridden !== undefined) return overridden;
        if (url === '/api/auth/session') return json(journalSession);
        if (url === '/api/session') return json({ csrfToken: 'synthetic-csrf' });
        if (url === root) return json(journalView());
        if (url === `${root}/query`) return json(journalPage());
        throw new Error('Unexpected synthetic route');
    }); vi.stubGlobal('fetch', fetch); return fetch;
}
function open(deviceId = journalDevice) { return render(<JournalPanel deviceId={deviceId} insecureTestMode={false} sessionKey={journalSessionExpiry}/>); }
beforeEach(() => { setLocale('en', false); localStorage.clear(); sessionStorage.clear(); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
describe('bounded journal API and lifetime', () => {
    it('rechecks operator session for every page, pins identity/digest and keeps query text out of URLs', async () => {
        const fetch = server((url, init) => {
            if (url !== `${root}/query`) return;
            const body = JSON.parse(String(init?.body));
            return json(journalPage(body.search ? ['SYNTHETIC Needle'] : ['Synthetic fixture message'], body.search));
        }); open(); await screen.findByText('Synthetic fixture message');
        fireEvent.change(screen.getByLabelText('Literal text in captured messages'), { target: { value: 'needle' } }); fireEvent.click(screen.getByRole('button', { name: 'Search capture' })); await screen.findByText('Needle', { selector: 'mark' });
        const calls = fetch.mock.calls, queries = calls.filter(([url]) => url === `${root}/query`);
        expect(queries).toHaveLength(2); expect(calls.filter(([url]) => url === '/api/auth/session')).toHaveLength(3);
        expect(JSON.parse(String(queries[1][1]?.body))).toEqual({ identity: journalIdentity, snapshotDigest: journalView().request!.receipt!.resultDigest, search: 'needle', offset: 0, limit: 100 });
        expect(queries[1][1]).toMatchObject({ method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': 'synthetic-csrf' } }); expect(calls.every(([url]) => !url.includes('needle'))).toBe(true);
    });
    it('navigates next and previous with a stable search, request and digest', async () => {
        const fetch = server((url, init) => { if (url === `${root}/query`) { const body = JSON.parse(String(init?.body)); return json(journalPage([body.offset === 0 ? 'First fixture row' : 'Second fixture row'], body.search, body.offset, 2)); } });
        open(); await screen.findByText('First fixture row'); fireEvent.click(screen.getByRole('button', { name: 'Next page' })); expect(screen.queryByText('First fixture row')).not.toBeInTheDocument(); await screen.findByText('Second fixture row'); fireEvent.click(screen.getByRole('button', { name: 'Previous page' })); await screen.findByText('First fixture row');
        expect(fetch.mock.calls.filter(([url]) => url === `${root}/query`).map(([, init]) => JSON.parse(String(init?.body)).offset)).toEqual([0, 1, 0]);
    });
    it('requires unchecked content acknowledgement and submits expectedFloor exactly once', async () => {
        let created = false;
        const fetch = server((url) => { if (url === root) return json(journalView(created ? 'pending' : 'awaiting')); if (url === `${root}/create`) { created = true; return json(journalView('pending')); } });
        open(); await screen.findByText('Awaiting a request'); const ack = screen.getByRole('checkbox'); expect(ack).not.toBeChecked(); fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'fixture.service' } });
        expect(screen.getByRole('button', { name: 'Capture logs' })).toBeDisabled(); fireEvent.click(ack); fireEvent.click(screen.getByRole('button', { name: 'Capture logs' })); fireEvent.click(screen.getByRole('button', { name: 'Capture logs' })); await screen.findByText('Pending');
        const creates = fetch.mock.calls.filter(([url]) => url === `${root}/create`); expect(creates).toHaveLength(1); expect(JSON.parse(String(creates[0][1]?.body))).toMatchObject({ expectedFloor: '0', acknowledgeLogContent: true, acknowledgePlaintext: false }); expect(screen.getByRole('checkbox')).not.toBeChecked();
    });
    it('does not replay an uncertain create and refreshes status before another action', async () => {
        let tried = false;
        const fetch = server((url) => { if (url === root) return json(journalView(tried ? 'pending' : 'awaiting')); if (url === `${root}/create`) { tried = true; return Promise.reject(new Error('Synthetic disconnected response')); } });
        open(); await screen.findByText('Awaiting a request'); fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'fixture.service' } }); fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Capture logs' })); await screen.findByText('Pending');
        expect(fetch.mock.calls.filter(([url]) => url === `${root}/create`)).toHaveLength(1); expect(fetch.mock.calls.filter(([url]) => url === root)).toHaveLength(2); expect(screen.getByRole('checkbox')).not.toBeChecked();
    });
    it('clears captured content on cancel without replaying it', async () => {
        const fetch = server(url => url === `${root}/cancel` ? json(journalView('canceled')) : undefined); open(); await screen.findByText('Synthetic fixture message'); fireEvent.click(screen.getByRole('button', { name: 'Cancel request / discard content' })); expect(screen.queryByText('Synthetic fixture message')).not.toBeInTheDocument(); await screen.findByText('Canceled'); expect(fetch.mock.calls.filter(([url]) => url === `${root}/cancel`)).toHaveLength(1);
    });
    it.each(['declared', 'streamed'] as const)('rejects an oversized %s page before exposing any rows', async kind => {
        let canceled = false;
        server(url => { if (url !== `${root}/query`) return; const stream = new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode(' '.repeat(JOURNAL_PAGE_BYTES + 1))); }, cancel() { canceled = true; } }); return new Response(stream, kind === 'declared' ? { headers: { 'Content-Length': String(JOURNAL_PAGE_BYTES + 1) } } : undefined); });
        open(); await screen.findByRole('alert'); expect(canceled).toBe(true); expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });
    it('drops mismatched request content and refuses late results after hiding', async () => {
        let finish!: (r: Response) => void;
        const fetch = server(url => url === `${root}/query` ? new Promise<Response>(resolve => { finish = resolve; }) : undefined); open(); await waitFor(() => expect(finish).toBeDefined());
        act(() => window.dispatchEvent(new Event('pagehide'))); await act(async () => finish(json(journalPage(['Late synthetic row'])))); expect(screen.queryByText('Late synthetic row')).not.toBeInTheDocument(); expect(fetch.mock.calls.find(([url]) => url === `${root}/query`)?.[1]?.signal?.aborted).toBe(true);
    });
    it.each(['auth', 'logout', 'epoch', 'device'] as const)('clears rows for %s changes', async kind => {
        server(); const rendered = open(); await screen.findByText('Synthetic fixture message');
        if (kind === 'auth') act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));
        if (kind === 'logout') act(() => { localStorage.setItem(LOGOUT_INTENT_KEY, '1'); });
        if (kind === 'epoch') act(() => abortProtectedRequests());
        if (kind === 'device') rendered.rerender(<JournalPanel deviceId="agent_other" insecureTestMode={false} sessionKey={journalSessionExpiry}/>);
        await waitFor(() => expect(screen.queryByText('Synthetic fixture message')).not.toBeInTheDocument());
    });
    it('locks after a denied operator page session and cannot resurrect via focus', async () => {
        let sessions = 0; const fetch = server(url => url === '/api/auth/session' && ++sessions === 2 ? json({}, 401) : undefined); open(); await screen.findByText('Your session has ended. Sign in again.'); expect(screen.queryByRole('table')).not.toBeInTheDocument(); const count = fetch.mock.calls.length; act(() => window.dispatchEvent(new Event('focus'))); expect(fetch.mock.calls).toHaveLength(count);
    });
    it('latches original expiry and refuses an older available response on refresh', async () => {
        server(); open(); await screen.findByText('Synthetic fixture message');
        const mono = performance.now(), wall = Date.now(); vi.spyOn(performance, 'now').mockReturnValue(mono + 900100); vi.spyOn(Date, 'now').mockReturnValue(wall + 900100);
        await screen.findByText('Expired'); expect(screen.queryByText('Synthetic fixture message')).not.toBeInTheDocument(); fireEvent.click(screen.getByRole('button', { name: 'Refresh status' })); await screen.findByRole('alert'); expect(screen.queryByText('Synthetic fixture message')).not.toBeInTheDocument();
    });
    it('clears rows on wall-clock rollback', async () => {
        server(); open(); await screen.findByText('Synthetic fixture message'); vi.spyOn(Date, 'now').mockReturnValue(Date.now() - 10000); await screen.findByText('The time or request sequence is no longer reliable. Rows were cleared; refresh status.'); expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });
    it('clears rows after page conflict rather than rendering empty success', async () => {
        let queries = 0; server(url => url === `${root}/query` && ++queries === 2 ? json({}, 409) : undefined); open(); await screen.findByText('Synthetic fixture message'); fireEvent.click(screen.getByRole('button', { name: 'Search capture' })); await screen.findByRole('alert'); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.queryByText('The complete capture contains no matching journal entries.')).not.toBeInTheDocument();
    });
    it('uses the fixed server time for UTC query defaults', async () => {
        server(url => url === root ? json(journalView('awaiting')) : undefined); open(); await screen.findByText('Awaiting a request');
        // The status commit precedes the effect that initializes UTC fields.
        await waitFor(() => {
            expect(screen.getByLabelText('To (UTC)')).toHaveValue(journalNow.slice(0, 16));
            expect(screen.getByLabelText('From (UTC)')).toHaveValue('2026-10-04T11:45');
        });
    });
});

it('rejects a page when the rechecked session identity lifetime changed', async () => {
    let sessions = 0;
    const fetch = server(url => url === '/api/auth/session' && ++sessions === 2 ? json({ ...journalSession, expiresAt: '2026-10-04T12:30:00Z' }) : undefined);
    open(); await screen.findByText('Your session has ended. Sign in again.'); expect(fetch.mock.calls.filter(([url]) => url === `${root}/query`)).toHaveLength(0); expect(screen.queryByRole('table')).not.toBeInTheDocument();
});
it('checks every page digest and erases prior rows before an inconsistent response', async () => {
    let pages = 0; server(url => url === `${root}/query` && ++pages === 2 ? json({ ...journalPage(['Different synthetic content']), snapshotDigest: `sha256:${'9'.repeat(64)}` }) : undefined);
    open(); await screen.findByText('Synthetic fixture message'); fireEvent.click(screen.getByRole('button', { name: 'Search capture' })); await screen.findByText('The manager returned inconsistent or unsupported journal data. Rows were cleared.'); expect(screen.queryByRole('table')).not.toBeInTheDocument();
});
it('clears rows on hidden visibility and revalidates before restoring', async () => {
    const fetch = server(); open(); await screen.findByText('Synthetic fixture message');
    const visible = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); expect(screen.queryByText('Synthetic fixture message')).not.toBeInTheDocument();
    visible.mockReturnValue('visible'); act(() => document.dispatchEvent(new Event('visibilitychange'))); await screen.findByText('Synthetic fixture message'); expect(fetch.mock.calls.filter(([url]) => url === '/api/auth/session')).toHaveLength(4);
});
it('does not replay an uncertain cancel after the refreshed terminal state', async () => {
    let tried = false; const fetch = server(url => { if (url === root && tried) return json(journalView('canceled')); if (url === `${root}/cancel`) { tried = true; return Promise.reject(new Error('Synthetic lost response')); } });
    open(); await screen.findByText('Synthetic fixture message'); fireEvent.click(screen.getByRole('button', { name: 'Cancel request / discard content' })); await screen.findByText('Canceled'); expect(fetch.mock.calls.filter(([url]) => url === `${root}/cancel`)).toHaveLength(1); expect(screen.queryByRole('table')).not.toBeInTheDocument();
});

it('never slides original retention on repeated equal-server-time reads before expiry', async () => {
    server(); open(); await screen.findByText('Synthetic fixture message');
    const mono = performance.now(), wall = Date.now(); const monoSpy = vi.spyOn(performance, 'now').mockReturnValue(mono + 840000), wallSpy = vi.spyOn(Date, 'now').mockReturnValue(wall + 840000);
    fireEvent.click(screen.getByRole('button', { name: 'Refresh status' })); await screen.findByText('Synthetic fixture message');
    monoSpy.mockReturnValue(mono + 900100); wallSpy.mockReturnValue(wall + 900100);
    await screen.findByText('Expired'); expect(screen.queryByRole('table')).not.toBeInTheDocument();
});

it('blocks a stale create immediately when the protected epoch changes, before the timer ticks', async () => {
    const fetch = server(url => url === root ? json(journalView('awaiting')) : undefined); open(); await screen.findByText('Awaiting a request');
    fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'fixture.service' } }); fireEvent.click(screen.getByRole('checkbox'));
    act(() => abortProtectedRequests()); fireEvent.click(screen.getByRole('button', { name: 'Capture logs' }));
    await act(async () => undefined); expect(fetch.mock.calls.filter(([url]) => url === `${root}/create`)).toHaveLength(0);
});
