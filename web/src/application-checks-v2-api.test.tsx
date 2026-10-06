import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests } from './api';
import { AuthBoundary } from './auth';
import { ApplicationChecksPanel } from './application-checks';
import { applicationNow } from './application-checks-fixtures';
import { applicationDNSRow, applicationViewV2 } from './application-checks-v2-fixtures';
import { APPLICATION_CHECKS_BYTES } from './application-checks-types';
import { setLocale } from './i18n';

const session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'synthetic-only', serverNow: applicationNow, expiresAt: '2026-10-06T13:00:00Z', expiresInSeconds: 3600 };
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
function server() { const fetch = vi.fn(async (url: string, _options?: RequestInit) => url === '/api/auth/session' ? json(session) : json(applicationViewV2())); vi.stubGlobal('fetch', fetch); return fetch; }
const reads = (fetch: ReturnType<typeof server>) => fetch.mock.calls.filter(([url]) => url === '/api/application-checks/status');
const panel = () => <AuthBoundary><ApplicationChecksPanel/></AuthBoundary>;
const refresh = () => screen.getByRole('button', { name: 'Reload application status' });
beforeEach(() => { localStorage.clear(); sessionStorage.clear(); setLocale('en', false); vi.spyOn(document, 'hasFocus').mockReturnValue(true); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('v2 mixed observations at the real protected API boundary', () => {
    it('uses only one bounded same-origin retained GET per reload with no destination calls', async () => {
        const fetch = server(); render(panel()); await screen.findByText('Resolved'); expect(screen.getByText('Connected')).toBeInTheDocument(); expect(screen.getByText('204 · 2xx')).toBeInTheDocument();
        fireEvent.click(refresh()); await waitFor(() => expect(reads(fetch)).toHaveLength(2)); await waitFor(() => expect(refresh()).toBeEnabled());
        const options = reads(fetch)[1][1]!;
        expect(options).toMatchObject({ credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' } }); expect(options.signal).toBeInstanceOf(AbortSignal); expect(options.method).toBeUndefined(); expect(options.body).toBeUndefined();
        expect(fetch.mock.calls.every(([url]) => ['/api/auth/session', '/api/application-checks/status'].includes(url))).toBe(true);
    });

    it.each(['declared', 'streamed'] as const)('rejects %s over-limit mixed status bytes and clears every kind', async kind => {
        const fetch = server(); render(panel()); await screen.findByText('Resolved');
        let canceled = false; const stream = new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode(' '.repeat(APPLICATION_CHECKS_BYTES + 1))); }, cancel() { canceled = true; } });
        fetch.mockResolvedValueOnce(new Response(stream, kind === 'declared' ? { headers: { 'Content-Length': String(APPLICATION_CHECKS_BYTES + 1) } } : undefined));
        fireEvent.click(refresh()); await screen.findByRole('alert'); expect(canceled).toBe(true);
        expect(screen.queryByText('Resolved')).not.toBeInTheDocument(); expect(screen.queryByText('Connected')).not.toBeInTheDocument(); expect(screen.queryByText('204 · 2xx')).not.toBeInTheDocument();
        expect(document.querySelector('.application-expiry')).toBeNull(); expect(refresh()).toBeEnabled();
    });

    it.each([{ hostname: 'invented.invalid' }, { targetScheme: 'https' }, { httpStatus: null }, { tls: { state: 'not_applicable', expiresAt: null } }])('rejects foreign or private DNS fields before display: %j', async patch => {
        const fetch = server(); render(panel()); await screen.findByText('Resolved');
        fetch.mockResolvedValueOnce(json({ ...applicationViewV2(), items: [{ ...applicationDNSRow(), ...patch }], maxAgeSeconds: 70 }));
        fireEvent.click(refresh()); await screen.findByRole('alert'); expect(document.body.textContent).not.toContain('invented.invalid'); expect(document.querySelector('.application-ok')).toBeNull();
    });

    it('clears all mixed evidence when the real API invalidates the session', async () => {
        const fetch = server(); render(panel()); await screen.findByText('Connected');
        fetch.mockResolvedValueOnce(json({}, 401)); fireEvent.click(refresh()); await screen.findByLabelText('Operator password');
        expect(screen.queryByRole('region', { name: 'Application checks' })).not.toBeInTheDocument(); act(() => window.dispatchEvent(new Event('focus'))); expect(reads(fetch)).toHaveLength(2);
    });

    it('aborts and ignores an actual delayed mixed response after unmount', async () => {
        const fetch = server(); const mounted = render(panel()); await screen.findByText('Resolved');
        let finish!: (response: Response) => void; fetch.mockImplementationOnce(() => new Promise<Response>(resolve => { finish = resolve; })); fireEvent.click(refresh()); await waitFor(() => expect(finish).toBeDefined());
        const signal = reads(fetch)[1][1]!.signal!; mounted.unmount(); expect(signal.aborted).toBe(true);
        await act(async () => finish(json(applicationViewV2()))); expect(screen.queryByText('Resolved')).not.toBeInTheDocument(); expect(screen.queryByText('Connected')).not.toBeInTheDocument();
    });
});
