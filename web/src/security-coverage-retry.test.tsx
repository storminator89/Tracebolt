import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, APIError, AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { OfflineCatalogPanel, SecurityCoveragePanel } from './security-coverage';
import { SECURITY_RESPONSE_MAX_BYTES, SECURITY_VIEW_LEASE_MS } from './security-coverage-types';
import type { OfflineCatalogView, SecurityCoverageView } from './security-coverage-types';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: '2026-10-04T00:30:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
const revision = `revision_${'a'.repeat(32)}`;
function coverage(deviceId = 'agent_fixture'): SecurityCoverageView {
    return { schemaVersion: 'tracebolt.security-coverage.v1', deviceId, serverNow: '2026-10-04T00:00:10Z', maxAgeSeconds: 120, receivedAt: '2026-10-04T00:00:05Z', collectionStatus: 'fresh', inventory: { coverage: 'partial', freshness: 'fresh', reportedItemCount: 5, installedCount: null, observedCount: 500, countExact: true, truncated: true, collectedAt: '2026-10-04T00:00:00Z', generationId: `sample_${'e'.repeat(32)}`, scope: 'reported-installed-binary-packages', originAssurance: 'unverified' }, catalog: { configured: false, revision, sha256: null, originAssurance: 'unverified', freshness: 'unknown' }, offeredUpdates: { coverage: 'unknown', offeredCount: null, reason: 'native_update_adapter_unimplemented' }, vulnerabilities: { coverage: 'unknown', affectedCves: null, reviewCandidates: null, reasonCodes: ['advisory_snapshot_unavailable', 'source_package_mapping_unavailable', 'client_release_unverified', 'installed_artifact_origin_unverified'] } };
}
function catalog(): OfflineCatalogView {
    return { schemaVersion: 'tracebolt.offline-catalog.v1', enabled: true, serverNow: '2026-10-04T00:00:10Z', revision, storage: 'memory-only', resetsOnRestart: true, limits: { maxBytes: 2097152, maxRules: 10000, maxInFlight: 1 }, catalog: { id: `catalog_${'c'.repeat(32)}`, sha256: 'd'.repeat(64), format: 'debian-tracker-normalized-1', provider: 'debian-security-tracker', declaredRelease: 'trixie', importedAt: '2026-10-04T00:00:05Z', publishedAt: null, freshness: 'unknown', originAssurance: 'unverified', synthetic: true, byteCount: 100, ruleCount: 0, coveredSourceCount: 1 } };
}
const busy = () => new APIError('private storage error', 429, 'storage_busy');
const flush = () => act(async () => {});
const advance = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
function deferred<T>() { let resolve!: (value: T) => void, reject!: (reason: unknown) => void; const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; }); return { promise, resolve, reject }; }
async function start() { const mounted = render(<SecurityCoveragePanel deviceId="agent_fixture" sessionKey="original"/>); await flush(); return mounted; }
beforeEach(() => { vi.useFakeTimers(); setLocale('en', false); vi.mocked(useOperator).mockReturnValue(operator); vi.mocked(request).mockReset(); vi.mocked(mutateRaw).mockReset(); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('one bounded security-coverage storage read recovery', () => {
    it('waits exactly two seconds with no old data, then repeats only the same bounded GET and controller', async () => {
        vi.mocked(request).mockRejectedValueOnce(busy()).mockResolvedValueOnce(coverage()); await start();
        expect(screen.getByRole('status')).toHaveTextContent('Storage is busy. One automatic read retry in 2 seconds.');
        expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Refresh security coverage' })).toBeDisabled();
        const first = vi.mocked(request).mock.calls[0]; expect(first).toEqual(['/devices/agent_fixture/security', { signal: expect.any(AbortSignal) }, SECURITY_RESPONSE_MAX_BYTES]);
        await advance(1999); expect(request).toHaveBeenCalledTimes(1); await advance(1);
        expect(request).toHaveBeenCalledTimes(2); expect(vi.mocked(request).mock.calls[1]).toEqual(first); expect(screen.getByText('Partial inventory')).toBeVisible();
        expect(screen.queryByRole('status')).not.toBeInTheDocument(); expect(document.body.textContent).not.toContain('private storage error'); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('keeps a second storage_busy visibly busy with manual refresh and never a third automatic attempt', async () => {
        vi.mocked(request).mockRejectedValue(busy()); await start(); await advance(2000);
        expect(screen.getByRole('alert')).toHaveTextContent('Storage is busy. Refresh security coverage to try again.'); expect(screen.queryByRole('article')).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Refresh security coverage' })).toBeEnabled(); await advance(30000); expect(request).toHaveBeenCalledTimes(2);
    });
    it.each([
        new APIError('storage_busy', 429), new APIError('private', 401, 'storage_busy'), new APIError('private', 403, 'storage_busy'),
        new APIError('private', 409, 'storage_busy'), new APIError('private', 500, 'storage_busy'), new Error('storage_busy'),
        { status: 429, code: 'storage_busy' },
    ])('never retries an unqualified error (%j)', async failure => {
        vi.mocked(request).mockRejectedValue(failure); await start(); expect(screen.getByRole('alert')).toBeVisible(); await advance(3000); expect(request).toHaveBeenCalledTimes(1); expect(screen.queryByRole('article')).not.toBeInTheDocument();
    });
    it('uses German recovery and exhausted copy without rendering server errors', async () => {
        setLocale('de', false); vi.mocked(request).mockRejectedValue(busy()); render(<SecurityCoveragePanel deviceId="agent_fixture"/>); await flush();
        expect(screen.getByRole('status')).toHaveTextContent('Ein automatischer Leseversuch folgt in 2 Sekunden.'); await advance(2000);
        expect(screen.getByRole('alert')).toHaveTextContent('Die Sicherheitsabdeckung für einen neuen Versuch aktualisieren.'); expect(document.body.textContent).not.toContain('private storage error');
    });
    it('clears existing counts throughout a recovering refresh and re-enables a deliberate fresh read after exhaustion', async () => {
        vi.mocked(request).mockResolvedValueOnce(coverage()).mockRejectedValueOnce(busy()).mockRejectedValueOnce(busy()).mockResolvedValueOnce(coverage()); await start(); expect(screen.getByText('Partial inventory')).toBeVisible();
        fireEvent.click(screen.getByRole('button', { name: 'Refresh security coverage' })); await flush(); expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(screen.getByRole('status')).toHaveTextContent('Storage is busy');
        await advance(2000); expect(screen.queryByRole('article')).not.toBeInTheDocument(); fireEvent.click(screen.getByRole('button', { name: 'Refresh security coverage' })); await flush();
        expect(screen.getByText('Partial inventory')).toBeVisible(); expect(request).toHaveBeenCalledTimes(4);
    });
    it('does not opt the shared catalog GET into recovery', async () => {
        vi.mocked(request).mockRejectedValue(busy()); render(<OfflineCatalogPanel/>); await flush(); await advance(3000);
        expect(request).toHaveBeenCalledTimes(1); expect(vi.mocked(request).mock.calls[0][0]).toBe('/security/catalog'); expect(screen.getByRole('alert')).toHaveTextContent('Current status could not be confirmed');
    });
    it('does not retry a catalog clear mutation using the same hook', async () => {
        vi.mocked(request).mockResolvedValue(catalog()); vi.mocked(mutateRaw).mockRejectedValue(busy()); render(<OfflineCatalogPanel/>); await flush();
        fireEvent.click(screen.getByRole('button', { name: 'Clear catalog' })); fireEvent.click(screen.getByRole('button', { name: 'Confirm clear' })); await flush(); await advance(3000);
        expect(mutateRaw).toHaveBeenCalledTimes(1); expect(request).toHaveBeenCalledTimes(1); expect(screen.getByRole('alert')).toHaveTextContent('Another catalog import is in progress');
    });
});

describe('coverage retry cancellation keeps the original private lifecycle', () => {
    it.each(['unmount', 'auth', 'logout', 'pagehide', 'blur', 'hashchange', 'hidden', 'epoch', 'wall', 'monotonic'] as const)('does not start the delayed read after %s invalidation', async transition => {
        vi.mocked(request).mockRejectedValueOnce(busy()).mockResolvedValue(coverage()); const mounted = await start(); const signal = vi.mocked(request).mock.calls[0][1]!.signal as AbortSignal;
        if (transition === 'unmount') mounted.unmount();
        else if (transition === 'logout') { vi.mocked(useOperator).mockReturnValue(null); mounted.rerender(<SecurityCoveragePanel deviceId="agent_fixture" sessionKey="original"/>); }
        else if (transition === 'hidden') { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); }
        else if (transition === 'epoch') act(() => abortProtectedRequests());
        else if (transition === 'wall') vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 5000);
        else if (transition === 'monotonic') vi.spyOn(performance, 'now').mockReturnValue(-1);
        else act(() => window.dispatchEvent(new Event(transition === 'auth' ? AUTH_REQUIRED_EVENT : transition)));
        await advance(3000); expect(signal.aborted).toBe(true); expect(request).toHaveBeenCalledTimes(1); expect(screen.queryByRole('article')).not.toBeInTheDocument();
    });
    it.each(['device', 'session'] as const)('cancels the old retry while a new %s scope loads', async transition => {
        const second = coverage(transition === 'device' ? 'agent_other' : 'agent_fixture'); second.inventory.reportedItemCount = 6;
        vi.mocked(request).mockRejectedValueOnce(busy()).mockResolvedValueOnce(second); const mounted = await start(); const signal = vi.mocked(request).mock.calls[0][1]!.signal as AbortSignal;
        mounted.rerender(<SecurityCoveragePanel deviceId={second.deviceId} sessionKey={transition === 'session' ? 'replacement' : 'original'}/>); await flush();
        expect(signal.aborted).toBe(true); expect(screen.getByText('6', { selector: 'strong' })).toBeVisible(); await advance(3000); expect(request).toHaveBeenCalledTimes(2); expect(vi.mocked(request).mock.calls[1][1]!.signal).not.toBe(signal);
    });
    it('cancels the old delay when a newer foreground request supersedes it', async () => {
        vi.mocked(request).mockRejectedValueOnce(busy()).mockResolvedValueOnce(coverage()); await start(); const original = vi.mocked(request).mock.calls[0][1]!.signal as AbortSignal;
        act(() => window.dispatchEvent(new Event('focus'))); await flush(); expect(original.aborted).toBe(true); expect(screen.getByText('Partial inventory')).toBeVisible();
        await advance(3000); expect(request).toHaveBeenCalledTimes(2);
    });
    it.each(['pagehide', 'auth', 'logout'] as const)('suppresses a late retry response after %s', async transition => {
        const second = deferred<SecurityCoverageView>(); vi.mocked(request).mockRejectedValueOnce(busy()).mockReturnValueOnce(second.promise); const mounted = await start(); await advance(2000);
        const signal = vi.mocked(request).mock.calls[1][1]!.signal as AbortSignal;
        if (transition === 'logout') { vi.mocked(useOperator).mockReturnValue(null); mounted.rerender(<SecurityCoveragePanel deviceId="agent_fixture" sessionKey="original"/>); }
        else act(() => window.dispatchEvent(new Event(transition === 'auth' ? AUTH_REQUIRED_EVENT : transition)));
        expect(signal.aborted).toBe(true); await act(async () => second.resolve(coverage())); expect(screen.queryByRole('article')).not.toBeInTheDocument();
    });
    it('keeps revoked retained inventory historical after retry rather than making it fresh', async () => {
        const value = coverage(); value.collectionStatus = 'revoked'; value.inventory.freshness = 'stale'; vi.mocked(request).mockRejectedValueOnce(busy()).mockResolvedValueOnce(value); await start(); await advance(2000);
        expect(screen.getByText('Device identity revoked')).toBeVisible(); expect(screen.getByText('Stale / historical evidence')).toBeVisible(); expect(screen.queryByText('Within collection window')).not.toBeInTheDocument();
    });
    it.each([{ ...coverage(), deviceId: 'agent_other' }, { ...coverage(), extra: true }])('rejects inconsistent retry responses without old counts (%j)', async value => {
        vi.mocked(request).mockRejectedValueOnce(busy()).mockResolvedValueOnce(value); await start(); await advance(2000); expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('unsupported or inconsistent response');
    });
});

describe('coverage retry preserves the original request and evidence clocks', () => {
    it('does not retry when the original ten-second deadline expires during the two-second delay', async () => {
        const first = deferred<unknown>(); vi.mocked(request).mockReturnValueOnce(first.promise).mockResolvedValue(coverage()); await start(); await advance(9000); await act(async () => first.reject(busy()));
        expect(screen.getByRole('status')).toHaveTextContent('Storage is busy'); await advance(999); expect(request).toHaveBeenCalledTimes(1); await advance(1);
        expect(screen.getByRole('alert')).toHaveTextContent('did not respond in time'); await advance(3000); expect(request).toHaveBeenCalledTimes(1);
    });
    it('aborts a held retry at the original deadline and ignores its later success', async () => {
        const second = deferred<SecurityCoverageView>(); vi.mocked(request).mockRejectedValueOnce(busy()).mockReturnValueOnce(second.promise); await start(); await advance(2000); const signal = vi.mocked(request).mock.calls[1][1]!.signal as AbortSignal;
        await advance(7999); expect(signal.aborted).toBe(false); await advance(1); expect(signal.aborted).toBe(true); expect(screen.getByRole('alert')).toHaveTextContent('did not respond in time');
        await act(async () => second.resolve(coverage())); expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(request).toHaveBeenCalledTimes(2);
    });
    it('never renews collection or inventory freshness when retry consumes their remaining collection window', async () => {
        const value = coverage(); value.serverNow = '2026-10-04T00:01:59Z'; value.receivedAt = value.inventory.collectedAt;
        vi.mocked(request).mockRejectedValueOnce(busy()).mockResolvedValueOnce(value); await start(); await advance(2000);
        expect(screen.getByText('Collection is stale')).toBeVisible(); expect(screen.getByText('Stale / historical evidence')).toBeVisible(); expect(screen.queryByText('Within collection window')).not.toBeInTheDocument();
    });
    it('keeps the original sixty-second installed-view lease and removes its counts at expiry', async () => {
        vi.mocked(request).mockRejectedValueOnce(busy()).mockResolvedValueOnce(coverage()); await start(); await advance(2000);
        await advance(SECURITY_VIEW_LEASE_MS - 1); expect(screen.getByText('Partial inventory')).toBeVisible(); await advance(1);
        expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('Previous information is no longer shown'); expect(request).toHaveBeenCalledTimes(2);
    });
});
