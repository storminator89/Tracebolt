import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, APIError, AUTH_REQUIRED_EVENT, hasPendingAPIRequests, mutate, mutateRaw, request } from './api';
import { LOGOUT_INTENT_KEY, useOperator } from './auth';
import { DeviceDetail } from './details';
import { emptyEndpointView } from './endpoint-identity-fixtures';
import { setLocale } from './i18n';
import type { Device, Metric } from './types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), hasPendingAPIRequests: vi.fn(), request: vi.fn(), mutate: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const id = `agent_${'3'.repeat(32)}`, otherId = `agent_${'4'.repeat(32)}`;
const now = '2026-10-05T12:00:00Z', expiresAt = '2026-10-05T14:00:00Z';
const operator = { mode: 'lan' as const, authenticated: true, expiresAt, insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
function device(value = 0.4, at = now, deviceId = id): Device {
    const metric: Metric = { value, unit: '%', quality: 'healthy', source: 'Synthetic live metric fixture', collectedAt: at };
    return { id: deviceId, name: 'Synthetic live metrics', platform: 'linux', os: 'Linux fixture', site: 'Fixture', group: 'Fixture', ip: null, status: 'unknown', source: 'lan', synthetic: false, lastSeen: at, agentVersion: 'fixture', cpu: metric, memory: { ...metric, value: 23.4 }, disk: { ...metric, value: 28 }, uptime: '', tags: [], capabilities: [], evidence: [], trend: [], caseIds: [], agentCertificate: { source: 'guided-enrollment', checkedAt: now, expiresAt } };
}
let latest: Device;
function answer(path: string) {
    if (path === `/devices/${id}` || path === `/devices/${otherId}`) return { ...latest, id: path.split('/')[2] };
    if (path.endsWith('/inventory/endpoint-identity')) return { ...emptyEndpointView(), deviceId: path.split('/')[2] };
    throw new Error('Unused synthetic overview summary');
}
function deferred<T>() { let resolve!: (value: T) => void, reject!: (value: unknown) => void; const promise = new Promise<T>((ok, fail) => { resolve = ok; reject = fail; }); return { resolve, reject, promise }; }
const flush = () => act(async () => {}), advance = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
const reads = () => vi.mocked(request).mock.calls.filter(([path]) => path === `/devices/${id}`);
const panel = (deviceId = id) => <main><DeviceDetail id={deviceId} onClose={vi.fn()} onCase={vi.fn()}/></main>;
const resources = () => screen.getByRole('region', { name: 'Resources' });
async function start() { const mounted = render(panel()); await flush(); return mounted; }
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime(now); localStorage.clear(); sessionStorage.clear(); setLocale('en', false); latest = device();
    vi.mocked(useOperator).mockReturnValue(operator); vi.mocked(hasPendingAPIRequests).mockReset().mockReturnValue(false);
    vi.mocked(request).mockReset().mockImplementation(async path => answer(path)); vi.mocked(mutate).mockReset(); vi.mocked(mutateRaw).mockReset();
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('live device Overview metadata', () => {
    it('updates only metadata every 15 seconds, retaining cards, scroll and original measurement time', async () => {
        await start(); const card = resources(), main = screen.getByRole('main'); main.scrollTop = 240;
        expect(card).toHaveTextContent('0.4%'); expect(card).toHaveTextContent('23.4%');
        expect(card.querySelector('time')).toHaveAttribute('datetime', now);
        const auxiliaryReads = vi.mocked(request).mock.calls.filter(([path]) => path !== `/devices/${id}`).length;
        await advance(14999); expect(reads()).toHaveLength(1);
        latest = device(12.6, '2026-10-05T12:00:10Z'); latest.agentCertificate!.checkedAt = '2026-10-05T12:00:15Z';
        await advance(1); expect(reads()).toHaveLength(2); expect(resources()).toBe(card); expect(card).toHaveTextContent('12.6%');
        expect(card.querySelector('time')).toHaveAttribute('datetime', latest.cpu.collectedAt); expect(main.scrollTop).toBe(240);
        expect(screen.getByRole('tab', { name: 'Overview' })).toHaveAttribute('aria-selected', 'true');
        expect(vi.mocked(request).mock.calls.filter(([path]) => path !== `/devices/${id}`)).toHaveLength(auxiliaryReads);
        expect(reads()[1][1]).toEqual({ signal: expect.any(AbortSignal) }); expect(reads()[1][2]).toBe(262144);
        expect(mutate).not.toHaveBeenCalled(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('keeps an unchanged sample time through successful checks and marks it stale using manager time', async () => {
        await start();
        vi.mocked(request).mockImplementation(async path => path === `/devices/${id}` ? { ...latest, agentCertificate: { ...latest.agentCertificate!, checkedAt: new Date().toISOString() } } : answer(path));
        await advance(121000);
        expect(resources()).toHaveTextContent('Stale'); expect(resources().querySelector('time')).toHaveAttribute('datetime', now);
        expect(document.querySelector('#device-metadata-status time')).not.toHaveAttribute('datetime', now);
        expect(resources()).toHaveTextContent('0.4%');
    });
    it('ages values during a prolonged read failure without restamping or upgrading denied/unknown values', async () => {
        latest.memory.quality = 'unknown'; latest.memory.value = null; latest.disk.quality = 'denied';
        await start(); vi.mocked(request).mockRejectedValue(new APIError('Synthetic unavailable', 503));
        await advance(121000); expect(resources()).toHaveTextContent('Stale'); expect(resources()).toHaveTextContent('Unavailable'); expect(resources()).toHaveTextContent('Access denied');
        expect(resources().querySelector('time')).toHaveAttribute('datetime', now); expect(document.querySelector('#device-metadata-status time')).toHaveAttribute('datetime', new Date(now).toISOString());
    });
    it('does not renew unchanged sample age through repeated legacy replies without manager time', async () => {
        delete latest.agentCertificate; await start(); await advance(121000);
        expect(reads().length).toBeGreaterThan(2); expect(resources()).toHaveTextContent('Stale'); expect(resources().querySelector('time')).toHaveAttribute('datetime', now);
        latest = { ...device(12.6, '2026-10-05T12:02:01Z'), agentCertificate: undefined };
        await advance(14000); expect(resources()).toHaveTextContent('12.6%'); expect(resources()).not.toHaveTextContent('Stale');
    });
    it('preserves German decimal precision from the actual sample', async () => {
        setLocale('de', false); await start(); expect(screen.getByRole('region', { name: 'Ressourcen' })).toHaveTextContent('0,4%'); expect(screen.getByRole('region', { name: 'Ressourcen' })).toHaveTextContent('23,4%');
    });
    it('serializes automatic and explicit reads, times out at ten seconds and discards the late result', async () => {
        await start(); const held = deferred<Device>(); vi.mocked(request).mockImplementation(path => path === `/devices/${id}` ? held.promise : Promise.resolve(answer(path)));
        await advance(15000); const signal = reads()[1][1]!.signal as AbortSignal;
        fireEvent.click(screen.getByRole('button', { name: 'Refresh device metadata' })); await advance(9999); expect(reads()).toHaveLength(2); expect(signal.aborted).toBe(false);
        await advance(1); expect(signal.aborted).toBe(true); expect(screen.getByRole('button', { name: 'Refresh device metadata' })).toBeEnabled();
        await act(async () => held.resolve(device(99))); expect(resources()).not.toHaveTextContent('99%');
        await advance(29999); expect(reads()).toHaveLength(2); await advance(1); expect(reads()).toHaveLength(3);
    });
    it('backs off 30, 60 and 120 seconds on busy/errors, then returns to 15-second checks after success', async () => {
        await start(); vi.mocked(request).mockImplementation(async path => { if (path === `/devices/${id}`) throw new APIError('Synthetic busy', 429, 'storage_busy'); return answer(path); });
        await advance(15000); expect(reads()).toHaveLength(2); expect(screen.getByText('↻ Waiting')).toBeVisible();
        await advance(29999); expect(reads()).toHaveLength(2); await advance(1); expect(reads()).toHaveLength(3);
        await advance(59999); expect(reads()).toHaveLength(3); await advance(1); expect(reads()).toHaveLength(4);
        await advance(119999); expect(reads()).toHaveLength(4);
        latest = device(40); vi.mocked(request).mockImplementation(async path => answer(path));
        await advance(1); expect(reads()).toHaveLength(5); expect(resources()).toHaveTextContent('40%'); expect(screen.queryByRole('alert')).not.toBeInTheDocument();
        await advance(14999); expect(reads()).toHaveLength(5); await advance(1); expect(reads()).toHaveLength(6);
    });
    it('defers polling while inventory or session revalidation is already in flight', async () => {
        await start(); vi.mocked(hasPendingAPIRequests).mockReturnValue(true); await advance(30000); expect(reads()).toHaveLength(1);
        vi.mocked(hasPendingAPIRequests).mockReturnValue(false); await advance(1000); expect(reads()).toHaveLength(2);
    });
    it('cancels an automatic request when leaving Overview and preserves the new tab and disclosure', async () => {
        await start(); const held = deferred<Device>(); vi.mocked(request).mockImplementation(path => path === `/devices/${id}` ? held.promise : Promise.resolve(answer(path)));
        await advance(15000); const signal = reads()[1][1]!.signal as AbortSignal;
        fireEvent.click(screen.getByRole('tab', { name: 'Details' })); await flush(); expect(signal.aborted).toBe(true);
        const details = screen.getByText('Device profile & technical details').closest('details')!; fireEvent.click(screen.getByText('Device profile & technical details'));
        await act(async () => held.resolve(device(99))); await advance(180000);
        expect(screen.getByRole('tab', { name: 'Details' })).toHaveAttribute('aria-selected', 'true'); expect(details).toHaveAttribute('open'); expect(reads()).toHaveLength(2);
        vi.mocked(request).mockImplementation(async path => answer(path)); fireEvent.click(screen.getByRole('tab', { name: 'Overview' })); await flush(); await advance(15000); expect(reads()).toHaveLength(3);
    });
    it.each(['hidden', 'pagehide', 'blur', 'unmount'] as const)('cancels automatic reads on %s without accepting a late sample', async transition => {
        const mounted = await start(), held = deferred<Device>(); vi.mocked(request).mockImplementation(path => path === `/devices/${id}` ? held.promise : Promise.resolve(answer(path)));
        await advance(15000); const signal = reads()[1][1]!.signal as AbortSignal;
        if (transition === 'unmount') mounted.unmount();
        else if (transition === 'hidden') { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); }
        else act(() => window.dispatchEvent(new Event(transition)));
        expect(signal.aborted).toBe(true); await act(async () => held.resolve(device(99))); await advance(180000); expect(reads()).toHaveLength(2); expect(document.body).not.toHaveTextContent('99%');
    });
    it('resumes visible polling without an immediate burst or resetting the selected Overview', async () => {
        await start(); const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); await advance(60000); expect(reads()).toHaveLength(1);
        visibility.mockReturnValue('visible'); act(() => document.dispatchEvent(new Event('visibilitychange'))); await flush(); expect(reads()).toHaveLength(1);
        await advance(15000); expect(reads()).toHaveLength(2); expect(screen.getByRole('tab', { name: 'Overview' })).toHaveAttribute('aria-selected', 'true');
    });
    it.each([401, 403, 404, 410])('discards prior data and stops automatic requests on HTTP %s', async status => {
        await start(); vi.mocked(request).mockRejectedValue(new APIError('Unavailable', status)); await advance(15000);
        expect(screen.queryByRole('region', { name: 'Resources' })).not.toBeInTheDocument(); await advance(180000); expect(reads()).toHaveLength(2);
    });
    it.each(['event', 'epoch', 'logout'] as const)('stops waiting polls and removes prior values after %s', async transition => {
        await start();
        if (transition === 'event') act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));
        else if (transition === 'epoch') act(() => abortProtectedRequests());
        else localStorage.setItem(LOGOUT_INTENT_KEY, '1');
        await advance(180000); expect(reads()).toHaveLength(1); expect(screen.queryByRole('region', { name: 'Resources' })).not.toBeInTheDocument();
    });
    it('rejects late automatic replies across device or session changes', async () => {
        const mounted = await start(), held = deferred<Device>(); vi.mocked(request).mockImplementation(path => path === `/devices/${id}` ? held.promise : Promise.resolve(answer(path)));
        await advance(15000); const signal = reads()[1][1]!.signal as AbortSignal;
        mounted.rerender(panel(otherId)); await flush(); expect(signal.aborted).toBe(true); await act(async () => held.resolve(device(99))); expect(resources()).not.toHaveTextContent('99%');
        vi.mocked(useOperator).mockReturnValue({ ...operator, expiresAt: '2026-10-05T15:00:00Z' }); mounted.rerender(panel(otherId)); await flush(); expect(resources()).not.toHaveTextContent('99%');
    });
    it.each(['synthetic', 'sandbox', 'unauthenticated'] as const)('never polls %s views', async mode => {
        if (mode === 'synthetic') { latest.synthetic = true; latest.source = 'synthetic'; }
        if (mode === 'sandbox') latest.source = 'sandbox';
        if (mode === 'unauthenticated') vi.mocked(useOperator).mockReturnValue({ ...operator, authenticated: false });
        await start(); await advance(180000); expect(reads()).toHaveLength(1);
    });
});
