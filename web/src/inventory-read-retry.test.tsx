import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, APIError, AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { useOperator } from './auth';
import { EndpointIdentityPanel } from './endpoint-identity';
import { useEndpointIdentity } from './endpoint-identity-resource';
import { endpointDevice, endpointView } from './endpoint-identity-fixtures';
import { CompleteOverviewPanel } from './complete-overview';
import { overviewDevice, overviewPage, overviewView, processRows, volumeRows } from './complete-overview-fixtures';
import { completeDevice, completeView } from './complete-packages-fixtures';
import { CompletePackagesPanel } from './complete-packages';
import { SoftwareOverview } from './software-overview';
import { setLocale } from './i18n';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
type Kind = 'endpoint' | 'overview' | 'software';
const kinds: Kind[] = ['endpoint', 'overview', 'software'];
const busy = () => new APIError('private storage diagnostics', 429, 'storage_busy');
const flush = () => act(async () => {});
const advance = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
function deferred<T>() { let resolve!: (value: T) => void, reject!: (error: unknown) => void; const promise = new Promise<T>((ok, fail) => { resolve = ok; reject = fail; }); return { promise, resolve, reject }; }
function Endpoint({ deviceId, sessionKey }: { deviceId: string; sessionKey: string }) { return <EndpointIdentityPanel resource={useEndpointIdentity(deviceId, true, sessionKey)}/>; }
const device = (kind: Kind) => kind === 'endpoint' ? endpointDevice : kind === 'overview' ? overviewDevice : completeDevice;
function panel(kind: Kind, sessionKey = 'original', deviceId = device(kind)) { return kind === 'endpoint' ? <Endpoint deviceId={deviceId} sessionKey={sessionKey}/> : kind === 'overview' ? <CompleteOverviewPanel deviceId={deviceId} section="processes" sessionKey={sessionKey}/> : <SoftwareOverview deviceId={deviceId} sessionKey={sessionKey} onOpenPackages={vi.fn()}/>; }
const payload = (kind: Kind) => kind === 'endpoint' ? endpointView() : kind === 'overview' ? overviewView() : completeView();
const marker = (kind: Kind) => kind === 'endpoint' ? 'fixture-linux' : kind === 'overview' ? 'fixture-process-000000' : 'Complete generation available';
const refresh = (kind: Kind) => screen.getByRole('button', { name: kind === 'endpoint' ? 'Refresh reported identity' : kind === 'overview' ? 'Refresh section and restart' : 'Refresh software overview' });
async function start(kind: Kind) { const mounted = render(panel(kind)); await flush(); return mounted; }
beforeEach(() => {
    vi.useFakeTimers(); setLocale('en', false); vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, expiresAt: '2026-10-04T20:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() });
    vi.mocked(request).mockReset(); vi.mocked(mutateRaw).mockReset().mockImplementation(async (_path, raw) => overviewPage(overviewView(), processRows(), volumeRows(), raw));
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe.each(kinds)('%s exact storage-contention GET recovery', kind => {
    it('waits two seconds without old data, then reuses exactly the same bounded read and controller', async () => {
        vi.mocked(request).mockRejectedValueOnce(busy()).mockResolvedValueOnce(payload(kind)); await start(kind);
        expect(screen.getByRole('status')).toHaveTextContent('Storage is busy. One automatic read retry in 2 seconds.'); expect(screen.queryByText(marker(kind))).not.toBeInTheDocument(); expect(refresh(kind)).toBeDisabled();
        const first = vi.mocked(request).mock.calls[0]; expect(first[1]).toEqual({ signal: expect.any(AbortSignal) }); expect(first[2]).toBeGreaterThan(0);
        await advance(1999); expect(request).toHaveBeenCalledTimes(1); await advance(1); expect(request).toHaveBeenCalledTimes(2); expect(vi.mocked(request).mock.calls[1]).toEqual(first); expect(screen.getByText(marker(kind))).toBeVisible(); expect(document.body.textContent).not.toContain('private storage diagnostics');
        if (kind !== 'overview') expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('stops after the second busy response and allows an explicit fresh attempt', async () => {
        vi.mocked(request).mockRejectedValue(busy()); await start(kind); await advance(2000); expect(screen.getByRole('alert')).toBeVisible(); expect(refresh(kind)).toBeEnabled(); await advance(30000); expect(request).toHaveBeenCalledTimes(2);
        vi.mocked(request).mockResolvedValue(payload(kind)); fireEvent.click(refresh(kind)); await flush(); expect(request).toHaveBeenCalledTimes(3); expect(screen.getByText(marker(kind))).toBeVisible();
    });
    it.each([new APIError('storage_busy', 429), new APIError('private', 401, 'storage_busy'), new APIError('private', 403, 'storage_busy'), new APIError('private', 409, 'storage_busy'), new APIError('private', 503, 'storage_busy'), new Error('storage_busy'), { status: 429, code: 'storage_busy' }])('does not retry an unqualified error (%j)', async failure => {
        vi.mocked(request).mockRejectedValue(failure); await start(kind); expect(screen.getByRole('alert')).toBeVisible(); await advance(3000); expect(request).toHaveBeenCalledTimes(1); expect(screen.queryByText(marker(kind))).not.toBeInTheDocument();
    });
    it('clears the previous successful values throughout refresh and held retry', async () => {
        const second = deferred<unknown>(); vi.mocked(request).mockResolvedValueOnce(payload(kind)).mockRejectedValueOnce(busy()).mockReturnValueOnce(second.promise); await start(kind); expect(screen.getByText(marker(kind))).toBeVisible();
        fireEvent.click(refresh(kind)); await flush(); expect(screen.queryByText(marker(kind))).not.toBeInTheDocument(); expect(screen.getByRole('status')).toHaveTextContent('Storage is busy'); await advance(2000); expect(screen.queryByText(marker(kind))).not.toBeInTheDocument(); await act(async () => second.resolve(payload(kind))); expect(screen.getByText(marker(kind))).toBeVisible();
    });
    it.each(['unmount', 'device', 'session', 'auth', 'pagehide', 'blur', 'hashchange', 'hidden', 'epoch', 'wall', 'monotonic'] as const)('cancels the delayed retry after %s invalidation', async transition => {
        vi.mocked(request).mockRejectedValue(busy()); const mounted = await start(kind); const signal = vi.mocked(request).mock.calls[0][1]!.signal as AbortSignal;
        if (transition === 'unmount') mounted.unmount(); else if (transition === 'device') mounted.rerender(panel(kind, 'original', `agent_${'9'.repeat(32)}`)); else if (transition === 'session') mounted.rerender(panel(kind, 'replacement'));
        else if (transition === 'hidden') { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); }
        else if (transition === 'epoch') act(() => abortProtectedRequests()); else if (transition === 'wall') vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 5000); else if (transition === 'monotonic') vi.spyOn(performance, 'now').mockReturnValue(-1);
        else act(() => window.dispatchEvent(new Event(transition === 'auth' ? AUTH_REQUIRED_EVENT : transition)));
        await advance(3000); expect(signal.aborted).toBe(true); expect(vi.mocked(request).mock.calls.filter(([, options]) => options?.signal === signal)).toHaveLength(1); expect(screen.queryByText(marker(kind))).not.toBeInTheDocument();
    });
    it('new focus supersedes the delayed attempt rather than allowing two retries', async () => {
        vi.mocked(request).mockRejectedValueOnce(busy()).mockResolvedValue(payload(kind)); await start(kind); const old = vi.mocked(request).mock.calls[0][1]!.signal as AbortSignal;
        act(() => window.dispatchEvent(new Event('focus'))); await flush(); expect(old.aborted).toBe(true); expect(screen.getByText(marker(kind))).toBeVisible(); await advance(3000); expect(request).toHaveBeenCalledTimes(2);
    });
    it.each(['pagehide', 'auth', 'unmount'] as const)('ignores late retry success after %s', async transition => {
        const second = deferred<unknown>(); vi.mocked(request).mockRejectedValueOnce(busy()).mockReturnValueOnce(second.promise); const mounted = await start(kind); await advance(2000); const signal = vi.mocked(request).mock.calls[1][1]!.signal as AbortSignal;
        if (transition === 'unmount') mounted.unmount(); else act(() => window.dispatchEvent(new Event(transition === 'auth' ? AUTH_REQUIRED_EVENT : transition)));
        expect(signal.aborted).toBe(true); await act(async () => second.resolve(payload(kind))); expect(screen.queryByText(marker(kind))).not.toBeInTheDocument(); expect(request).toHaveBeenCalledTimes(2);
    });
    it('does not retry when the original ten-second budget ends during the delay', async () => {
        const first = deferred<unknown>(); vi.mocked(request).mockReturnValueOnce(first.promise).mockResolvedValue(payload(kind)); await start(kind); await advance(9000); await act(async () => first.reject(busy())); expect(screen.getByRole('status')).toHaveTextContent('Storage is busy');
        await advance(1000); expect(screen.getByRole('alert')).toHaveTextContent(/time|respond/i); await advance(3000); expect(request).toHaveBeenCalledTimes(1); expect(screen.queryByText(marker(kind))).not.toBeInTheDocument();
    });
    it('aborts a held retry at the original deadline and suppresses later data', async () => {
        const second = deferred<unknown>(); vi.mocked(request).mockRejectedValueOnce(busy()).mockReturnValueOnce(second.promise); await start(kind); await advance(2000); const signal = vi.mocked(request).mock.calls[1][1]!.signal as AbortSignal;
        await advance(7999); expect(signal.aborted).toBe(false); await advance(1); expect(signal.aborted).toBe(true); expect(screen.getByRole('alert')).toBeVisible(); await act(async () => second.resolve(payload(kind))); expect(screen.queryByText(marker(kind))).not.toBeInTheDocument();
    });
    it('renders German progress text without raw server diagnostics', async () => {
        setLocale('de', false); vi.mocked(request).mockRejectedValue(busy()); await start(kind); expect(screen.getByRole('status')).toHaveTextContent('Ein automatischer Leseversuch folgt in 2 Sekunden.'); expect(document.body.textContent).not.toContain('private storage diagnostics');
    });
});

describe('original freshness and POST boundaries', () => {
    it.each(kinds)('%s subtracts retry delay from original retention age', async kind => {
        if (kind === 'endpoint') { const v = endpointView(); v.status = 'stale'; v.serverNow = '2026-10-05T11:59:57Z'; vi.mocked(request).mockRejectedValueOnce(busy()).mockResolvedValue(v); }
        else if (kind === 'software') { const v = completeView(); v.serverNow = '2026-10-04T23:59:57Z'; vi.mocked(request).mockRejectedValueOnce(busy()).mockResolvedValue(v); }
        else { const v = overviewView(); v.serverNow = '2026-10-05T18:29:57Z'; v.volumes.status = v.volumes.complete!.state = 'expired'; vi.mocked(request).mockRejectedValueOnce(busy()).mockResolvedValue(v); vi.mocked(mutateRaw).mockImplementation(async (_path, raw) => overviewPage(v, processRows(), volumeRows(), raw)); }
        await start(kind); await advance(2000); expect(screen.getByText(marker(kind))).toBeVisible(); await advance(999); expect(screen.getByText(marker(kind))).toBeVisible(); await advance(1); expect(screen.queryByText(marker(kind))).not.toBeInTheDocument();
    });
    it('does not replay an overview query POST even when exact storage_busy follows a recovered GET', async () => {
        vi.mocked(request).mockRejectedValueOnce(busy()).mockResolvedValue(overviewView()); vi.mocked(mutateRaw).mockRejectedValue(busy()); await start('overview'); await advance(2000); expect(screen.getByRole('alert')).toBeVisible(); await advance(3000); expect(request).toHaveBeenCalledTimes(2); expect(mutateRaw).toHaveBeenCalledTimes(1); expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });
    it('leaves non-metadata package GET and query retry behavior unchanged', async () => {
        vi.mocked(request).mockRejectedValue(busy()); const mounted = render(<CompletePackagesPanel deviceId={completeDevice} inline/>); await flush(); await advance(3000); expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).not.toHaveBeenCalled(); mounted.unmount();
        vi.mocked(request).mockReset().mockResolvedValue(completeView()); vi.mocked(mutateRaw).mockRejectedValue(busy()); render(<CompletePackagesPanel deviceId={completeDevice} inline/>); await flush(); await advance(3000); expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
});
