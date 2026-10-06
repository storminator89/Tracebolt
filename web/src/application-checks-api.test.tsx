import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests } from './api';
import App from './App';
import { AuthBoundary } from './auth';
import { ApplicationChecksPanel } from './application-checks';
import { applicationNow, applicationRow, applicationView, disabledApplicationView } from './application-checks-fixtures';
import { APPLICATION_CHECKS_BYTES } from './application-checks-types';
import { setLocale } from './i18n';

const session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'synthetic-only', serverNow: applicationNow, expiresAt: '2026-10-06T13:00:00Z', expiresInSeconds: 3600 };
const overview = { generatedAt: applicationNow, stats: { totalDevices: 0, healthyDevices: 0, attentionDevices: 0, openCases: 0, criticalCases: 0 }, devices: [], cases: [], activity: [] };
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
const reads = (fetch: ReturnType<typeof server>) => fetch.mock.calls.filter(([url]) => url === '/api/application-checks/status');
const refresh = () => screen.getByRole('button', { name: 'Reload application status' });
function server() { const fetch = vi.fn(async (url: string, _options?: RequestInit) => url === '/api/auth/session' ? json(session) : url === '/api/overview' ? json(overview) : json(applicationView())); vi.stubGlobal('fetch', fetch); return fetch; }
const panel = () => <AuthBoundary><ApplicationChecksPanel/></AuthBoundary>;
beforeEach(() => { localStorage.clear(); sessionStorage.clear(); setLocale('en', false); window.location.hash = '/overview'; vi.spyOn(document, 'hasFocus').mockReturnValue(true); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('application status protected API boundary', () => {
    it('uses one bounded same-origin GET per reload with no request to the application or mutation API', async () => {
        const fetch = server(); render(panel()); await screen.findByText('204 · 2xx');
        fetch.mockResolvedValueOnce(json(applicationView([applicationRow({ httpStatus: 200 })]))); fireEvent.click(refresh()); await screen.findByText('200 · 2xx');
        expect(reads(fetch)).toHaveLength(2); const options = reads(fetch)[1][1]!;
        expect(options).toMatchObject({ credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' } }); expect(options.signal).toBeInstanceOf(AbortSignal); expect(options.method).toBeUndefined(); expect(options.body).toBeUndefined();
        expect(fetch.mock.calls.every(([url]) => ['/api/auth/session', '/api/application-checks/status'].includes(url))).toBe(true);
    });
    it.each(['declared', 'streamed'] as const)('rejects a %s oversized status response and clears old green evidence', async kind => {
        const fetch = server(); render(panel()); await screen.findByText('204 · 2xx');
        let canceled = false; const stream = new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode(' '.repeat(APPLICATION_CHECKS_BYTES + 1))); }, cancel() { canceled = true; } });
        fetch.mockResolvedValueOnce(new Response(stream, kind === 'declared' ? { headers: { 'Content-Length': String(APPLICATION_CHECKS_BYTES + 1) } } : undefined));
        fireEvent.click(refresh()); await screen.findByRole('alert'); expect(canceled).toBe(true); expect(screen.queryByText('204 · 2xx')).not.toBeInTheDocument(); expect(document.querySelector('.application-expiry')).toBeNull(); expect(refresh()).toBeEnabled();
    });
    it('rejects unexpected destination details in otherwise valid response data', async () => {
        const fetch = server(); fetch.mockImplementation(async url => url === '/api/auth/session' ? json(session) : json({ ...applicationView(), items: [{ ...applicationRow(), url: 'https://invented.invalid/do-not-render' }] }));
        render(panel()); await screen.findByRole('alert'); expect(document.body.textContent).not.toContain('invented.invalid'); expect(document.querySelector('.application-ok')).toBeNull();
    });
    it('clears the authenticated panel after a real 401 and ignores focus retries', async () => {
        const fetch = server(); render(panel()); await screen.findByText('204 · 2xx');
        fetch.mockResolvedValueOnce(json({}, 401)); fireEvent.click(refresh()); await screen.findByLabelText('Operator password');
        expect(screen.queryByRole('region', { name: 'Application checks' })).not.toBeInTheDocument(); act(() => window.dispatchEvent(new Event('focus'))); expect(reads(fetch)).toHaveLength(2);
    });
    it('aborts and discards an actual delayed response when unmounted', async () => {
        const fetch = server(); const mounted = render(panel()); await screen.findByText('204 · 2xx');
        let finish!: (response: Response) => void; fetch.mockImplementationOnce(() => new Promise<Response>(resolve => { finish = resolve; })); fireEvent.click(refresh()); await waitFor(() => expect(finish).toBeDefined());
        const signal = reads(fetch)[1][1]!.signal!; mounted.unmount(); expect(signal.aborted).toBe(true); await act(async () => finish(json(applicationView()))); expect(screen.queryByText('204 · 2xx')).not.toBeInTheDocument();
    });
    it('discards an interrupted response if visibility revalidation ends the operator session', async () => {
        const fetch = server(); render(panel()); await screen.findByText('204 · 2xx');
        let finish!: (response: Response) => void; fetch.mockImplementationOnce(() => new Promise<Response>(resolve => { finish = resolve; })); fireEvent.click(refresh()); await waitFor(() => expect(finish).toBeDefined());
        const visible = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); expect(screen.queryByText('204 · 2xx')).not.toBeInTheDocument();
        fetch.mockResolvedValueOnce(json({ ...session, authenticated: false, csrfToken: null, expiresAt: null, expiresInSeconds: null })); visible.mockReturnValue('visible'); act(() => document.dispatchEvent(new Event('visibilitychange'))); await screen.findByLabelText('Operator password');
        await act(async () => finish(json(applicationView()))); expect(screen.queryByText('204 · 2xx')).not.toBeInTheDocument(); expect(reads(fetch)).toHaveLength(2);
    });
    it('integrates only into LAN Overview, preserving the other routes', async () => {
        const fetch = server(); fetch.mockImplementation(async url => url === '/api/auth/session' ? json(session) : url === '/api/overview' ? json(overview) : json(disabledApplicationView()));
        render(<App/>); await screen.findByRole('heading', { name: 'Overview', level: 1 }); await screen.findByText('Disabled · no application checks configured.'); expect(reads(fetch)).toHaveLength(1);
        act(() => { window.location.hash = '/cases'; window.dispatchEvent(new Event('hashchange')); }); await screen.findByRole('heading', { name: 'Investigations', level: 1 }); expect(screen.queryByRole('region', { name: 'Application checks' })).not.toBeInTheDocument();
        act(() => { window.location.hash = '/overview'; window.dispatchEvent(new Event('hashchange')); }); await screen.findByText('Disabled · no application checks configured.'); expect(reads(fetch)).toHaveLength(2);
    });
    it('does not issue the LAN-only status request from actual development Overview', async () => {
        const fetch = server(); fetch.mockImplementation(async url => url === '/api/auth/session' ? json({ ...session, mode: 'development', authenticationRequired: false, authenticated: false, csrfToken: null, expiresAt: null, expiresInSeconds: null }) : json(overview));
        render(<App/>); await screen.findByRole('heading', { name: 'Overview', level: 1 }); expect(reads(fetch)).toHaveLength(0); expect(screen.queryByRole('region', { name: 'Application checks' })).not.toBeInTheDocument();
    });
});
