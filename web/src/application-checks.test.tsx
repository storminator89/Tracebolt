import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, APIError, AUTH_REQUIRED_EVENT, hasPendingAPIRequests, request } from './api';
import { LOGOUT_INTENT_KEY, useOperator } from './auth';
import { ApplicationChecksPanel } from './application-checks';
import { applicationNow, applicationRow, applicationView, disabledApplicationView } from './application-checks-fixtures';
import { APPLICATION_CHECKS_BYTES } from './application-checks-types';
import type { ApplicationChecksView } from './application-checks-types';
import { setLocale } from './i18n';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), hasPendingAPIRequests: vi.fn(), request: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: '2026-10-06T14:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
const flush = () => act(async () => {}), advance = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
const refresh = () => screen.getByRole('button', { name: 'Reload application status' });
const panel = () => screen.getByRole('region', { name: 'Application checks' });
const successful = () => document.querySelectorAll('.application-ok, .application-tls-valid, .application-tls-expiring, .application-tls-expired');
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { resolve, promise }; }
async function start() { const mounted = render(<ApplicationChecksPanel/>); await flush(); return mounted; }
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime(applicationNow); localStorage.clear(); sessionStorage.clear(); setLocale('en', false);
    vi.spyOn(document, 'hasFocus').mockReturnValue(true); vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
    vi.mocked(useOperator).mockReturnValue(operator); vi.mocked(hasPendingAPIRequests).mockReset().mockReturnValue(false); vi.mocked(request).mockReset().mockResolvedValue(applicationView());
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('compact retained application observations', () => {
    it('shows independent HTTP success and expiring leaf certificate with original observation time', async () => {
        await start(); const content = panel(); expect(content).toHaveTextContent('204 · 2xx'); expect(content).toHaveTextContent('Expiring soon');
        expect(content).toHaveTextContent('HTTP/TLS checks from the manager.'); expect(content).toHaveTextContent('0s ago');
        expect(content.querySelector('td:last-child time')).toHaveAttribute('datetime', applicationNow); expect(content.querySelectorAll('tbody tr')).toHaveLength(1);
        expect(within(content).getAllByRole('button')).toHaveLength(1); expect(content.querySelector('input,select')).toBeNull();
        expect(vi.mocked(request).mock.calls[0]).toEqual(['/application-checks/status', { signal: expect.any(AbortSignal), cache: 'no-store' }, APPLICATION_CHECKS_BYTES]);
    });
    it('does not conflate an HTTP failure with a leaf expiry more than 30 days away', async () => {
        vi.mocked(request).mockResolvedValue(applicationView([applicationRow({ state: 'http_error', reason: 'http_status', httpStatus: 503, tls: { state: 'valid', expiresAt: '2027-03-01T00:00:00Z' } })]));
        await start(); expect(panel()).toHaveTextContent('503 · HTTP error'); expect(panel()).toHaveTextContent('Expiry > 30 days'); expect(document.querySelector('.application-ok')).toBeNull();
    });
    it('keeps prior HTTP success separate from a now-expired verified leaf', async () => {
        const view = applicationView([applicationRow({ observedAt: '2026-10-06T11:59:50Z', tls: { state: 'expired', expiresAt: '2026-10-06T11:59:55Z' } })]);
        vi.mocked(request).mockResolvedValue(view); await start(); expect(panel()).toHaveTextContent('204 · 2xx'); expect(panel()).toHaveTextContent('Expired');
    });
    it('marks plaintext HTTP explicitly without implying a certificate', async () => {
        vi.mocked(request).mockResolvedValue(applicationView([applicationRow({ targetScheme: 'http', tls: { state: 'not_applicable', expiresAt: null } })]));
        await start(); expect(panel()).toHaveTextContent('HTTP · plaintext'); expect(panel()).toHaveTextContent('No TLS'); expect(panel().querySelector('.application-expiry')).toBeNull();
    });
    it('has a concise disabled state without configuration or check controls', async () => {
        vi.mocked(request).mockResolvedValue(disabledApplicationView()); await start(); expect(panel()).toHaveTextContent('Disabled · no application checks running.');
        expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(within(panel()).getAllByRole('button')).toHaveLength(1);
        await advance(59999); expect(request).toHaveBeenCalledTimes(1); await advance(1); expect(request).toHaveBeenCalledTimes(2);
    });
    it('renders German labels and switches language without another request', async () => {
        await start(); act(() => setLocale('de', false)); const content = screen.getByRole('region', { name: 'Anwendungsprüfungen' });
        expect(content).toHaveTextContent('Läuft bald ab'); expect(content).toHaveTextContent('Blattzertifikat'); expect(content).toHaveTextContent('vor 0 s'); expect(request).toHaveBeenCalledTimes(1);
    });
    it('shows loading without success then clears evidence after transport or malformed errors', async () => {
        const held = deferred<ApplicationChecksView>(); vi.mocked(request).mockReturnValueOnce(held.promise); render(<ApplicationChecksPanel/>);
        expect(screen.getByRole('status')).toHaveTextContent('Loading application status'); expect(successful()).toHaveLength(0);
        await act(async () => held.resolve(applicationView())); expect(successful()).toHaveLength(2);
        vi.mocked(request).mockRejectedValueOnce(new Error('https://must-not-render.invalid/private')); fireEvent.click(refresh()); await flush();
        expect(screen.getByRole('alert')).toHaveTextContent('Application status unavailable'); expect(successful()).toHaveLength(0); expect(panel()).not.toHaveTextContent('must-not-render');
        vi.mocked(request).mockResolvedValueOnce({ ...applicationView(), extra: 'invalid' }); fireEvent.click(refresh()); await flush(); expect(successful()).toHaveLength(0);
    });
    it.each(['unknown', 'stale', 'future'] as const)('keeps %s observations unknown and removes HTTP/verified expiry', async kind => {
        const row = kind === 'unknown' ? applicationRow({ observedAt: null, state: 'unknown', reason: 'not_checked', httpStatus: null, tls: { state: 'unknown', expiresAt: null } }) : applicationRow({ observedAt: kind === 'future' ? '2026-10-06T12:00:00.000000001Z' : '2026-10-06T11:00:00Z' });
        vi.mocked(request).mockResolvedValue(applicationView([row])); await start(); expect(successful()).toHaveLength(0); expect(panel()).not.toHaveTextContent('204'); expect(panel().querySelector('.application-expiry')).toBeNull();
    });
});

describe('application retained-status lifecycle', () => {
    it('polls only the status route every 15 seconds and repeated reload cannot overlap', async () => {
        await start(); const held = deferred<ApplicationChecksView>(); vi.mocked(request).mockReturnValueOnce(held.promise);
        await advance(14999); expect(request).toHaveBeenCalledTimes(1); await advance(1); expect(request).toHaveBeenCalledTimes(2);
        fireEvent.click(refresh()); fireEvent.click(refresh()); expect(request).toHaveBeenCalledTimes(2); expect(refresh()).toBeDisabled();
        await act(async () => held.resolve(applicationView())); fireEvent.click(refresh()); fireEvent.click(refresh()); await flush(); expect(request).toHaveBeenCalledTimes(3);
        expect(vi.mocked(request).mock.calls.every(([path]) => path === '/application-checks/status')).toBe(true);
    });
    it('yields initial, automatic and explicit reads to other pending API work', async () => {
        vi.mocked(hasPendingAPIRequests).mockReturnValue(true); await start(); expect(request).not.toHaveBeenCalled(); await advance(15000); expect(request).not.toHaveBeenCalled();
        fireEvent.click(refresh()); expect(request).not.toHaveBeenCalled(); vi.mocked(hasPendingAPIRequests).mockReturnValue(false); await advance(1000); expect(request).toHaveBeenCalledTimes(1);
        vi.mocked(hasPendingAPIRequests).mockReturnValue(true); await advance(15000); expect(request).toHaveBeenCalledTimes(1);
    });
    it('ages successful retained replies without renewing the original observation', async () => {
        await start(); await advance(71000); expect(successful()).toHaveLength(0); expect(panel()).toHaveTextContent('Unknown · stale');
        expect(panel().querySelector('td:last-child time')).toHaveAttribute('datetime', applicationNow); expect(panel()).not.toHaveTextContent('204');
    });
    it('ages between polls and reclassifies a leaf as expired without a new handshake', async () => {
        vi.mocked(request).mockResolvedValue(applicationView([applicationRow({ tls: { state: 'expiring', expiresAt: '2026-10-06T12:00:01Z' } })]));
        await start(); await advance(1000); expect(panel()).toHaveTextContent('Expired'); expect(panel()).toHaveTextContent('204'); expect(request).toHaveBeenCalledTimes(1);
        vi.mocked(hasPendingAPIRequests).mockReturnValue(true); await advance(70000); expect(successful()).toHaveLength(0);
    });
    it('times out and ignores late responses after another reload starts', async () => {
        await start(); const held = deferred<ApplicationChecksView>(); vi.mocked(request).mockReturnValueOnce(held.promise); fireEvent.click(refresh());
        const signal = vi.mocked(request).mock.calls[1][1]!.signal!; await advance(10000); expect(signal.aborted).toBe(true); expect(successful()).toHaveLength(0); expect(refresh()).toBeEnabled();
        vi.mocked(request).mockResolvedValueOnce(disabledApplicationView()); fireEvent.click(refresh()); await flush(); await act(async () => held.resolve(applicationView())); expect(panel()).toHaveTextContent('Disabled'); expect(successful()).toHaveLength(0);
    });
    it('retains the clock watermark through failed reads and old repeated replies', async () => {
        await start(); vi.mocked(request).mockRejectedValue(new Error('fixture')); await advance(75000);
        vi.mocked(request).mockResolvedValue(applicationView()); fireEvent.click(refresh()); await flush(); expect(panel()).toHaveTextContent('Unknown · stale'); expect(successful()).toHaveLength(0);
    });
    it('aborts on blur, reads nothing while hidden, and does not rejuvenate on resume', async () => {
        await start(); const held = deferred<ApplicationChecksView>(); vi.mocked(request).mockReturnValueOnce(held.promise); fireEvent.click(refresh());
        const signal = vi.mocked(request).mock.calls[1][1]!.signal!; act(() => window.dispatchEvent(new Event('blur'))); expect(signal.aborted).toBe(true); expect(successful()).toHaveLength(0);
        await advance(75000); expect(request).toHaveBeenCalledTimes(2); await act(async () => held.resolve(applicationView())); expect(successful()).toHaveLength(0);
        act(() => window.dispatchEvent(new Event('focus'))); await advance(0); expect(request).toHaveBeenCalledTimes(3); expect(panel()).toHaveTextContent('Unknown · stale'); expect(successful()).toHaveLength(0);
    });
    it('never starts a read in an initially hidden or unfocused window', async () => {
        vi.mocked(document.hasFocus).mockReturnValue(false); await start(); await advance(60000); expect(request).not.toHaveBeenCalled();
        vi.mocked(document.hasFocus).mockReturnValue(true); act(() => window.dispatchEvent(new Event('focus'))); await advance(0); expect(request).toHaveBeenCalledTimes(1);
    });
    it('clears success on local clock discontinuity', async () => {
        await start(); vi.setSystemTime('2026-10-06T11:00:00Z'); await advance(1000); expect(successful()).toHaveLength(0); expect(panel()).toHaveTextContent('Unknown · stale');
    });
    it('does not reset old age for a tiny server-time advance after a clock jump', async () => {
        await start(); vi.mocked(hasPendingAPIRequests).mockReturnValue(true); await advance(75000);
        vi.setSystemTime('2026-10-06T13:00:00Z'); vi.mocked(hasPendingAPIRequests).mockReturnValue(false);
        vi.mocked(request).mockResolvedValue({ ...applicationView(), serverNow: '2026-10-06T12:00:00.001Z' }); fireEvent.click(refresh()); await flush();
        expect(successful()).toHaveLength(0); expect(panel()).toHaveTextContent('Unknown · stale');
    });
    it.each(['event', 'epoch', 'logout'] as const)('clears private rows and ignores late reads after %s invalidation', async kind => {
        await start(); const held = deferred<ApplicationChecksView>(); vi.mocked(request).mockReturnValueOnce(held.promise); fireEvent.click(refresh()); const count = vi.mocked(request).mock.calls.length;
        act(() => { if (kind === 'event') window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)); else if (kind === 'epoch') abortProtectedRequests(); else localStorage.setItem(LOGOUT_INTENT_KEY, '1'); });
        await advance(1000); await act(async () => held.resolve(applicationView())); expect(successful()).toHaveLength(0); expect(panel()).not.toHaveTextContent('fixture-app');
        await advance(60000); expect(request).toHaveBeenCalledTimes(count); expect(refresh()).toBeDisabled();
    });
    it('aborts on unmount and binds delayed replies to the original operator session', async () => {
        const held = deferred<ApplicationChecksView>(); vi.mocked(request).mockReturnValueOnce(held.promise); const mounted = await start(); const signal = vi.mocked(request).mock.calls[0][1]!.signal!;
        vi.mocked(useOperator).mockReturnValue({ ...operator, actorId: 'operator_fixture', expiresAt: '2026-10-06T15:00:00Z' }); vi.mocked(request).mockResolvedValueOnce(disabledApplicationView()); mounted.rerender(<ApplicationChecksPanel/>); await flush();
        expect(signal.aborted).toBe(true); await act(async () => held.resolve(applicationView())); expect(panel()).toHaveTextContent('Disabled'); expect(successful()).toHaveLength(0);
        const current = deferred<ApplicationChecksView>(); vi.mocked(request).mockReturnValueOnce(current.promise); fireEvent.click(refresh()); const pending = vi.mocked(request).mock.calls.at(-1)![1]!.signal!; mounted.unmount(); expect(pending.aborted).toBe(true); await act(async () => current.resolve(applicationView())); expect(screen.queryByRole('region')).not.toBeInTheDocument();
    });
    it('treats denied access as terminal and backs off temporary errors', async () => {
        await start(); vi.mocked(request).mockRejectedValue(new APIError('fixture busy', 429)); await advance(15000); expect(request).toHaveBeenCalledTimes(2);
        await advance(29999); expect(request).toHaveBeenCalledTimes(2); await advance(1); expect(request).toHaveBeenCalledTimes(3);
        vi.mocked(request).mockRejectedValue(new APIError('fixture denied', 403)); await advance(60000); expect(request).toHaveBeenCalledTimes(4); expect(refresh()).toBeDisabled(); await advance(200000); expect(request).toHaveBeenCalledTimes(4);
    });
    it.each(['development', 'signed_out', 'no_context'] as const)('does not render or read in %s mode', async mode => {
        vi.mocked(useOperator).mockReturnValue(mode === 'no_context' ? null : { ...operator, mode: mode === 'development' ? 'development' : 'lan', authenticated: false });
        await start(); await advance(60000); expect(request).not.toHaveBeenCalled(); expect(screen.queryByRole('region')).not.toBeInTheDocument();
    });
});
