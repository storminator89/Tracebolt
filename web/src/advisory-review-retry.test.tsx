import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, APIError, AUTH_REQUIRED_EVENT, request } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { AdvisoryReviewPanel } from './advisory-review';
import { ADVISORY_REVIEW_RESPONSE_MAX_BYTES } from './advisory-review-types';
import { reviewDeviceId, reviewView, syntheticReviewView } from './advisory-review-fixtures';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: '2026-10-04T00:30:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
const busy = () => new APIError('private storage error', 429, 'storage_busy');
const open = () => fireEvent.click(screen.getByRole('button', { name: 'Conditional advisory review candidates' }));
const flush = () => act(async () => {});
const advance = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
function deferred<T>() { let resolve!: (value: T) => void, reject!: (reason: unknown) => void; const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; }); return { promise, resolve, reject }; }
async function start() { const mounted = render(<AdvisoryReviewPanel deviceId={reviewDeviceId} sessionKey="original"/>); open(); await flush(); return mounted; }
beforeEach(() => { vi.useFakeTimers(); setLocale('en', false); vi.mocked(useOperator).mockReturnValue(operator); vi.mocked(request).mockReset(); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('one bounded storage-contention read recovery', () => {
    it('waits exactly two seconds with no rows, then repeats only the same bounded GET and controller', async () => {
        vi.mocked(request).mockRejectedValueOnce(busy()).mockResolvedValueOnce(reviewView()); await start();
        expect(screen.getByRole('status')).toHaveTextContent('Storage is busy. One automatic read retry in 2 seconds.');
        expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Refresh review candidates' })).toBeDisabled();
        const first = vi.mocked(request).mock.calls[0]; expect(first).toEqual(['/devices/agent_fixture/security/review', { signal: expect.any(AbortSignal) }, ADVISORY_REVIEW_RESPONSE_MAX_BYTES]);
        await advance(1999); expect(request).toHaveBeenCalledTimes(1); await advance(1);
        expect(request).toHaveBeenCalledTimes(2); expect(vi.mocked(request).mock.calls[1]).toEqual(first); expect(screen.getByRole('article')).toBeVisible();
        expect(screen.queryByRole('status')).not.toBeInTheDocument(); expect(document.body.textContent).not.toContain('private storage error');
    });
    it('keeps a second storage_busy visibly busy and never starts a third automatic attempt', async () => {
        vi.mocked(request).mockRejectedValue(busy()); await start(); await advance(2000);
        expect(screen.getByRole('alert')).toHaveTextContent('Another review is in progress'); expect(screen.queryByRole('article')).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Refresh review candidates' })).toBeEnabled(); await advance(30000); expect(request).toHaveBeenCalledTimes(2);
    });
    it.each([
        new APIError('storage_busy', 429), new APIError('private', 401, 'storage_busy'), new APIError('private', 403, 'storage_busy'),
        new APIError('private', 409, 'storage_busy'), new APIError('private', 500, 'storage_busy'), new Error('storage_busy'),
        { status: 429, code: 'storage_busy' },
    ])('never retries an unqualified error (%j)', async failure => {
        vi.mocked(request).mockRejectedValue(failure); await start(); expect(screen.getByRole('alert')).toBeVisible(); await advance(3000); expect(request).toHaveBeenCalledTimes(1); expect(screen.queryByRole('article')).not.toBeInTheDocument();
    });
    it('uses German progress copy without exposing the server error', async () => {
        setLocale('de', false); vi.mocked(request).mockRejectedValue(busy()); render(<AdvisoryReviewPanel deviceId={reviewDeviceId}/>); fireEvent.click(screen.getByRole('button', { name: 'Bedingte Hinweis-Prüfkandidaten' })); await flush();
        expect(screen.getByRole('status')).toHaveTextContent('Ein automatischer Leseversuch folgt in 2 Sekunden.'); expect(document.body.textContent).not.toContain('private storage error');
    });
    it('clears existing rows throughout a recovering refresh', async () => {
        vi.mocked(request).mockResolvedValueOnce(reviewView()).mockRejectedValueOnce(busy()).mockResolvedValueOnce(reviewView()); await start(); expect(screen.getByRole('article')).toBeVisible();
        fireEvent.click(screen.getByRole('button', { name: 'Refresh review candidates' })); await flush(); expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(screen.getByRole('status')).toHaveTextContent('Storage is busy'); await advance(2000); expect(screen.getByRole('article')).toBeVisible(); expect(request).toHaveBeenCalledTimes(3);
    });
});

describe('retry cancellation retains the original private lifecycle', () => {
    it.each(['close', 'unmount', 'device', 'session', 'auth', 'pagehide', 'blur', 'hashchange', 'popstate', 'hidden', 'epoch', 'wall', 'monotonic'] as const)('does not start the delayed read after %s invalidation', async transition => {
        vi.mocked(request).mockRejectedValueOnce(busy()).mockResolvedValue(reviewView()); const mounted = await start(); const signal = vi.mocked(request).mock.calls[0][1]!.signal as AbortSignal;
        if (transition === 'close') open(); else if (transition === 'unmount') mounted.unmount(); else if (transition === 'device') mounted.rerender(<AdvisoryReviewPanel deviceId="agent_other" sessionKey="original"/>); else if (transition === 'session') mounted.rerender(<AdvisoryReviewPanel deviceId={reviewDeviceId} sessionKey="replacement"/>);
        else if (transition === 'hidden') { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); }
        else if (transition === 'epoch') act(() => abortProtectedRequests());
        else if (transition === 'wall') vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 5000);
        else if (transition === 'monotonic') vi.spyOn(performance, 'now').mockReturnValue(-1);
        else act(() => window.dispatchEvent(new Event(transition === 'auth' ? AUTH_REQUIRED_EVENT : transition)));
        await advance(3000); expect(signal.aborted).toBe(true); expect(request).toHaveBeenCalledTimes(1); expect(screen.queryByRole('article')).not.toBeInTheDocument();
    });
    it('cancels the old delay when a newer foreground request supersedes it', async () => {
        vi.mocked(request).mockRejectedValueOnce(busy()).mockResolvedValueOnce(syntheticReviewView()); await start(); const original = vi.mocked(request).mock.calls[0][1]!.signal as AbortSignal;
        act(() => window.dispatchEvent(new Event('focus'))); await flush(); expect(original.aborted).toBe(true); expect(screen.getByText('Synthetic catalog: no live review candidate rows are produced.')).toBeVisible();
        await advance(3000); expect(request).toHaveBeenCalledTimes(2); expect(screen.queryByRole('article')).not.toBeInTheDocument();
    });
    it.each(['pagehide', 'auth', 'close'] as const)('suppresses a late retry response after %s', async transition => {
        const second = deferred<ReturnType<typeof reviewView>>(); vi.mocked(request).mockRejectedValueOnce(busy()).mockReturnValueOnce(second.promise); await start(); await advance(2000); expect(request).toHaveBeenCalledTimes(2);
        const signal = vi.mocked(request).mock.calls[1][1]!.signal as AbortSignal; if (transition === 'close') open(); else act(() => window.dispatchEvent(new Event(transition === 'auth' ? AUTH_REQUIRED_EVENT : transition)));
        expect(signal.aborted).toBe(true); await act(async () => second.resolve(reviewView())); expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(document.body.textContent).not.toContain('fixture-binary');
    });
});

describe('retry never extends the request or evidence clock', () => {
    it('does not retry when the original ten-second deadline expires during the two-second delay', async () => {
        const first = deferred<unknown>(); vi.mocked(request).mockReturnValueOnce(first.promise).mockResolvedValue(reviewView()); await start(); await advance(9000); await act(async () => first.reject(busy())); expect(screen.getByRole('status')).toHaveTextContent('Storage is busy');
        await advance(999); expect(request).toHaveBeenCalledTimes(1); await advance(1); expect(screen.getByRole('alert')).toHaveTextContent('did not respond in time'); await advance(3000); expect(request).toHaveBeenCalledTimes(1);
    });
    it('aborts a held retry at the original deadline and ignores its later success', async () => {
        const second = deferred<ReturnType<typeof reviewView>>(); vi.mocked(request).mockRejectedValueOnce(busy()).mockReturnValueOnce(second.promise); await start(); await advance(2000); const signal = vi.mocked(request).mock.calls[1][1]!.signal as AbortSignal;
        await advance(7999); expect(signal.aborted).toBe(false); await advance(1); expect(signal.aborted).toBe(true); expect(screen.getByRole('alert')).toHaveTextContent('did not respond in time');
        await act(async () => second.resolve(reviewView())); expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(request).toHaveBeenCalledTimes(2);
    });
    it('subtracts the retry delay from the original sixty-second display lease', async () => {
        vi.mocked(request).mockRejectedValueOnce(busy()).mockResolvedValueOnce(reviewView()); await start(); await advance(2000); expect(screen.getByRole('article')).toBeVisible();
        await advance(57999); expect(screen.getByRole('article')).toBeVisible(); await advance(1); expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('expired or its time anchor changed');
    });
    it('never flashes rows when the retry delay consumes remaining collection freshness', async () => {
        const value = reviewView(); value.serverNow = '2026-10-04T00:01:59Z'; vi.mocked(request).mockRejectedValueOnce(busy()).mockResolvedValueOnce(value); await start(); await advance(2000);
        expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(document.body.textContent).not.toContain('fixture-binary'); expect(screen.getByRole('alert')).toHaveTextContent('expired or its time anchor changed');
    });
});
