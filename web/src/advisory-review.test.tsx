import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, AUTH_REQUIRED_EVENT, request } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { AdvisoryReviewPanel } from './advisory-review';
import { ADVISORY_REVIEW_RESPONSE_MAX_BYTES } from './advisory-review-types';
import { reviewDeviceId, reviewView, syntheticReviewView } from './advisory-review-fixtures';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: '2026-10-04T00:30:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
function defer<T>() { let resolve!: (value: T) => void; return { promise: new Promise<T>(done => { resolve = done; }), resolve }; }
function open() { fireEvent.click(screen.getByRole('button', { name: 'Conditional advisory review candidates' })); }
async function show(value = reviewView()) { vi.mocked(request).mockResolvedValue(value); const rendered = render(<AdvisoryReviewPanel deviceId={reviewDeviceId}/>); open(); await screen.findByText('Selected-scope inspection completed'); return rendered; }
beforeEach(() => { setLocale('en', false); vi.mocked(useOperator).mockReturnValue(operator); vi.mocked(request).mockReset(); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('conditional review candidate presentation', () => {
    it('is lazy, bounded, read-only, private and displays exact conditional evidence', async () => {
        vi.mocked(request).mockResolvedValue(reviewView()); const storage = vi.spyOn(Storage.prototype, 'setItem'); render(<AdvisoryReviewPanel deviceId={reviewDeviceId}/>); expect(request).not.toHaveBeenCalled(); open(); await screen.findByRole('article');
        expect(request).toHaveBeenCalledExactlyOnceWith('/devices/agent_fixture/security/review', { signal: expect.any(AbortSignal) }, ADVISORY_REVIEW_RESPONSE_MAX_BYTES);
        for (const text of ['2:1.0~rc1-2+b1', '2:1.0-2+deb13u1', 'Declared fix version (unverified)', 'Reported source version', 'Selected-scope inspection completed', `revision_${'a'.repeat(32)}`, 'c'.repeat(64), `sample_${'d'.repeat(32)}`, 'Conditional: reported source version is below the declared fix']) expect(screen.getByText(text)).toBeVisible();
        expect(screen.getByText(/Affected CVEs and available updates remain unknown./)).toBeVisible(); expect(screen.queryByRole('link')).not.toBeInTheDocument(); expect(storage).not.toHaveBeenCalled(); expect(screen.getAllByRole('button')).toHaveLength(2);
    });
    it('renders German review candidate language, null counts and unknown provenance', async () => {
        setLocale('de', false); vi.mocked(request).mockResolvedValue(reviewView()); render(<AdvisoryReviewPanel deviceId={reviewDeviceId}/>); fireEvent.click(screen.getByRole('button', { name: 'Bedingte Hinweis-Prüfkandidaten' })); await screen.findByRole('article'); expect(screen.getByText('Deklarierte Korrekturversion (unbestätigt)')).toBeVisible(); expect(screen.getByText(/Betroffene CVEs und verfügbare Updates bleiben unbekannt/)).toBeVisible(); expect(screen.getByText(/Katalogherkunft unbestätigt; Katalogaktualität unbekannt/)).toBeVisible(); expect(screen.queryByRole('link')).not.toBeInTheDocument();
    });
    it('distinguishes synthetic and empty selected results without implying security', async () => {
        vi.mocked(request).mockResolvedValue(syntheticReviewView()); render(<AdvisoryReviewPanel deviceId={reviewDeviceId}/>); open(); await screen.findByText('Synthetic catalog: no live review candidate rows are produced.'); expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(screen.getByText('Synthetic catalog is excluded from live review candidates.')).toBeVisible(); expect(screen.getByText(/No review candidate rows were returned/)).toHaveTextContent('not evidence of zero affected CVEs');
    });
    it.each(['not_configured', 'awaiting', 'stale', 'revoked', 'unavailable'] as const)('shows no rows for %s', async collectionStatus => {
        const value = reviewView(); Object.assign(value, { collectionStatus, review: null, ...(collectionStatus === 'not_configured' || collectionStatus === 'awaiting' ? { receivedAt: null, sequence: null } : {}) }); vi.mocked(request).mockResolvedValue(value); render(<AdvisoryReviewPanel deviceId={reviewDeviceId}/>); open(); await screen.findByText(/Review candidates require a fresh/); expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(document.body.textContent).not.toContain('fixture-binary');
    });
    it('does not fetch or expose review candidates outside authenticated LAN mode', () => {
        for (const changed of [null, { ...operator, authenticated: false }, { ...operator, mode: 'development' as const }]) { vi.mocked(useOperator).mockReturnValue(changed); const mounted = render(<AdvisoryReviewPanel deviceId={reviewDeviceId}/>); expect(screen.queryByRole('button')).not.toBeInTheDocument(); mounted.unmount(); } expect(request).not.toHaveBeenCalled();
    });
});

describe('review candidate lifecycle and stale-response protection', () => {
    it.each(['close', 'unmount', 'device', 'session', 'auth', 'pagehide', 'blur', 'hashchange', 'popstate', 'hidden'] as const)('aborts pending reads and suppresses late output on %s', async transition => {
        const pending = defer<ReturnType<typeof reviewView>>(); vi.mocked(request).mockReturnValue(pending.promise); const rendered = render(<AdvisoryReviewPanel deviceId={reviewDeviceId} sessionKey="one"/>); open(); await waitFor(() => expect(request).toHaveBeenCalledTimes(1)); const signal = vi.mocked(request).mock.calls[0][1]!.signal as AbortSignal;
        if (transition === 'close') open(); else if (transition === 'unmount') rendered.unmount(); else if (transition === 'device') rendered.rerender(<AdvisoryReviewPanel deviceId="agent_other" sessionKey="one"/>); else if (transition === 'session') rendered.rerender(<AdvisoryReviewPanel deviceId={reviewDeviceId} sessionKey="two"/>); else if (transition === 'hidden') { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); } else act(() => window.dispatchEvent(new Event(transition === 'auth' ? AUTH_REQUIRED_EVENT : transition)));
        expect(signal.aborted).toBe(true); await act(async () => pending.resolve(reviewView())); expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(document.body.textContent).not.toContain('fixture-binary');
    });
    it('clears rows before refresh, rejects invalid results and keeps raw error details private', async () => {
        await show(); const pending = defer<ReturnType<typeof reviewView>>(); vi.mocked(request).mockReturnValue(pending.promise); fireEvent.click(screen.getByRole('button', { name: 'Refresh review candidates' })); expect(screen.queryByRole('article')).not.toBeInTheDocument(); await act(async () => pending.resolve({ ...reviewView(), review: null })); expect(await screen.findByRole('alert')).toHaveTextContent('unsupported or inconsistent');
        vi.mocked(request).mockRejectedValue(new APIError('/private/secret review error', 500)); fireEvent.click(screen.getByRole('button', { name: 'Refresh review candidates' })); await screen.findByText('Review candidates could not be read. Refresh to try again.'); expect(document.body.textContent).not.toContain('/private/secret');
    });
    it.each([409, 429, 401])('handles HTTP %s without retaining output', async status => {
        await show(); vi.mocked(request).mockRejectedValue(new APIError('private error', status)); fireEvent.click(screen.getByRole('button', { name: 'Refresh review candidates' })); expect(await screen.findByRole('alert')).toHaveTextContent(status === 409 ? 'package snapshot or catalog changed' : status === 429 ? 'Another review is in progress' : 'session has ended'); expect(screen.queryByRole('article')).not.toBeInTheDocument(); if (status === 401) { expect(screen.getByRole('button', { name: 'Refresh review candidates' })).toBeDisabled(); const calls = vi.mocked(request).mock.calls.length; act(() => window.dispatchEvent(new Event('focus'))); expect(request).toHaveBeenCalledTimes(calls); }
    });
    it('drops old data on BFCache suspension and only restores through a new read', async () => {
        await show(); act(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }))); expect(screen.queryByRole('article')).not.toBeInTheDocument(); const pending = defer<ReturnType<typeof reviewView>>(); vi.mocked(request).mockReturnValue(pending.promise); act(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }))); expect(screen.queryByRole('article')).not.toBeInTheDocument(); await act(async () => pending.resolve(reviewView())); await screen.findByRole('article');
    });
    it('does not restore a hidden or auth-locked view on focus or BFCache events', async () => {
        await show(); vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); const calls = vi.mocked(request).mock.calls.length; act(() => { window.dispatchEvent(new Event('focus')); window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })); }); expect(request).toHaveBeenCalledTimes(calls); expect(screen.queryByRole('article')).not.toBeInTheDocument();
    });
    it('uses the newer restored request and never a suspended late response', async () => {
        const old = defer<ReturnType<typeof reviewView>>(); vi.mocked(request).mockReturnValue(old.promise); render(<AdvisoryReviewPanel deviceId={reviewDeviceId}/>); open(); act(() => window.dispatchEvent(new Event('blur'))); vi.mocked(request).mockResolvedValue(syntheticReviewView()); act(() => window.dispatchEvent(new Event('focus'))); await screen.findByText('Synthetic catalog: no live review candidate rows are produced.'); await act(async () => old.resolve(reviewView())); expect(screen.queryByRole('article')).not.toBeInTheDocument();
    });
    it.each(['lease', 'freshness', 'wall', 'monotonic'] as const)('clears visible output on %s invalidation', async kind => {
        const value = reviewView(); if (kind === 'freshness') value.serverNow = '2026-10-04T00:01:59Z'; await show(value); vi.useFakeTimers();
        // Timers installed before fake timers are real, so recreate the expanded resource.
        open(); open(); await act(async () => {});
        if (kind === 'wall') vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 5000); if (kind === 'monotonic') vi.spyOn(performance, 'now').mockReturnValue(-1);
        await act(async () => vi.advanceTimersByTimeAsync(kind === 'lease' ? 60000 : kind === 'freshness' ? 1002 : 1000)); expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('expired or its time anchor changed');
    });
    it('times out a pending read, aborts it and rejects its late success', async () => {
        vi.useFakeTimers(); const pending = defer<ReturnType<typeof reviewView>>(); vi.mocked(request).mockReturnValue(pending.promise); render(<AdvisoryReviewPanel deviceId={reviewDeviceId}/>); open(); const signal = vi.mocked(request).mock.calls[0][1]!.signal as AbortSignal; await act(async () => vi.advanceTimersByTimeAsync(10000)); expect(signal.aborted).toBe(true); expect(screen.getByRole('alert')).toHaveTextContent('did not respond in time'); await act(async () => pending.resolve(reviewView())); expect(screen.queryByRole('article')).not.toBeInTheDocument();
    });
});
