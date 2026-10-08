import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, APIError, AUTH_REQUIRED_EVENT, hasPendingAPIRequests, request } from './api';
import { useResourceHistory } from './resource-history-resource';
import { historyDevice, historyFixture, historyNow } from './resource-history-fixture';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), hasPendingAPIRequests: vi.fn(() => false) }));
const advance = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
const flush = () => act(async () => {});
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(ok => { resolve = ok; }); return { promise, resolve }; }
beforeEach(() => { vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date', 'performance'] }); vi.setSystemTime(historyNow); localStorage.clear(); sessionStorage.clear(); vi.mocked(request).mockReset().mockResolvedValue(historyFixture()); vi.mocked(hasPendingAPIRequests).mockReset().mockReturnValue(false); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });
describe('bounded resource-history reader', () => {
    it('loads authentic history with a response cap, then serializes visible polling', async () => {
        const h = renderHook(() => useResourceHistory(historyDevice, 'session', true)); await flush(); expect(h.result.current.view?.points).toHaveLength(4); expect(request).toHaveBeenCalledWith(`/devices/${historyDevice}/resource-history`, { signal: expect.any(AbortSignal) }, 1536 * 1024);
        vi.mocked(hasPendingAPIRequests).mockReturnValue(true); await advance(60000); expect(request).toHaveBeenCalledTimes(1); vi.mocked(hasPendingAPIRequests).mockReturnValue(false);
        const v = historyFixture(); v.serverNow = '2026-10-07T12:01:01Z'; v.windowStart = '2026-10-06T12:01:01Z'; vi.mocked(request).mockResolvedValue(v); await advance(500); expect(request).toHaveBeenCalledTimes(2); expect(h.result.current.error).toBe('');
        act(() => window.dispatchEvent(new Event('blur'))); expect(h.result.current.view).toBeNull(); await advance(120000); expect(request).toHaveBeenCalledTimes(2);
    });
    it('keeps initial history deferred while the browser clock is paused, then loads after its 500 ms yield', async () => {
        vi.mocked(hasPendingAPIRequests).mockReturnValue(true);
        const h = renderHook(() => useResourceHistory(historyDevice, 'session', true)); await flush();
        expect(request).not.toHaveBeenCalled(); expect(h.result.current.view).toBeNull(); expect(h.result.current.loading).toBe(true);
        // Finishing foreground inventory does not itself advance a paused clock.
        vi.mocked(hasPendingAPIRequests).mockReturnValue(false); await flush();
        expect(request).not.toHaveBeenCalled(); expect(h.result.current.view).toBeNull();
        await advance(499); expect(request).not.toHaveBeenCalled(); expect(h.result.current.view).toBeNull();
        await advance(1); expect(request).toHaveBeenCalledTimes(1); expect(h.result.current.view?.points).toHaveLength(4); expect(h.result.current.error).toBe('');
    });
    it('trims expired points once without redrawing unchanged history or renewing its age anchor', async () => {
        const full = historyFixture(Array.from({ length: 1441 }, (_, i) => (i - 1440) * 60));
        for (const point of full.points) { point.cpu.value = 35; point.memory.value = 48; }
        vi.mocked(request).mockResolvedValue(full); let renders = 0;
        const h = renderHook(() => { renders++; return useResourceHistory(historyDevice, 'session', true); }); await flush();
        expect(h.result.current.view?.points).toHaveLength(1441);
        await advance(1000); expect(h.result.current.view?.points).toHaveLength(1440); const afterRemoval = renders;
        for (let i = 0; i < 10; i++) await advance(1000);
        expect(renders).toBe(afterRemoval); expect(h.result.current.view?.points).toHaveLength(1440); expect(request).toHaveBeenCalledTimes(1);
        await advance(48000); expect(request).toHaveBeenCalledTimes(1);
    });
    it('clears data immediately when access changes and ignores delayed results', async () => {
        const held = deferred<ReturnType<typeof historyFixture>>(); vi.mocked(request).mockReturnValue(held.promise); const h = renderHook(() => useResourceHistory(historyDevice, 'session', true)); await flush();
        act(() => { abortProtectedRequests(); window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)); }); await act(async () => held.resolve(historyFixture())); expect(h.result.current.view).toBeNull(); expect(h.result.current.error).toBe('session');
    });
    it('does not publish an old device response after navigation', async () => {
        const held = deferred<ReturnType<typeof historyFixture>>(); vi.mocked(request).mockReturnValueOnce(held.promise); const other = 'agent_22222222222222222222222222222222'; const h = renderHook(({ id }) => useResourceHistory(id, 'session', true), { initialProps: { id: historyDevice } }); h.rerender({ id: other }); await flush(); await act(async () => held.resolve(historyFixture())); expect(h.result.current.view).toBeNull();
    });
    it('bounds a hung read at ten seconds and clears failed history', async () => {
        vi.mocked(request).mockReturnValue(new Promise(() => {})); const h = renderHook(() => useResourceHistory(historyDevice, 'session', true)); await advance(10000); expect(h.result.current.loading).toBe(false); expect(h.result.current.error).toBe('unavailable'); expect(h.result.current.view).toBeNull();
    });
    it('fails closed on invalid, frozen-clock, and revoked replies', async () => {
        const h = renderHook(() => useResourceHistory(historyDevice, 'session', true)); await flush(); await advance(60000); expect(h.result.current.view).toBeNull(); expect(h.result.current.error).toBe('invalid');
        cleanup(); vi.mocked(request).mockResolvedValue({ ...historyFixture([]), status: 'revoked' }); const revoked = renderHook(() => useResourceHistory(historyDevice, 'session', true)); await flush(); expect(revoked.result.current.view?.status).toBe('revoked'); const calls = vi.mocked(request).mock.calls.length; await advance(120000); expect(request).toHaveBeenCalledTimes(calls);
    });
    it('blocks a denied read without automatically retrying', async () => {
        vi.mocked(request).mockRejectedValue(new APIError('denied', 403)); const h = renderHook(() => useResourceHistory(historyDevice, 'session', true)); await flush(); expect(h.result.current.view).toBeNull(); await advance(120000); expect(request).toHaveBeenCalledTimes(1);
    });
});


describe('history delta reader transport', () => {
    it('uses a verified watermark, merges a minute, and bootstraps after suspension', async () => {
        const h = renderHook(() => useResourceHistory(historyDevice, 'session', true)); await flush();
        const point = { ...historyFixture([60]).points[0], sequence: '5' };
        const reply = { ...historyFixture(), schemaVersion: 'tracebolt.resource-history-delta.v1', serverNow: '2026-10-07T12:01:00Z', windowStart: '2026-10-06T12:01:00Z', points: [point], baseSequence: '4', lastSequence: '5', pointCount: 5 };
        vi.mocked(request).mockResolvedValue(reply); await advance(60000);
        expect(request).toHaveBeenLastCalledWith(`/devices/${historyDevice}/resource-history?afterSequence=4`, { signal: expect.any(AbortSignal) }, 1536 * 1024);
        expect(h.result.current.error).toBe(''); expect(h.result.current.view?.points.map(p => p.sequence)).toEqual(['1', '2', '3', '4', '5']);
        act(() => window.dispatchEvent(new Event('blur'))); expect(h.result.current.view).toBeNull();
        vi.mocked(request).mockResolvedValue({ ...historyFixture(), serverNow: reply.serverNow, windowStart: reply.windowStart });
        act(() => window.dispatchEvent(new Event('focus'))); await advance(0);
        expect(request).toHaveBeenLastCalledWith(`/devices/${historyDevice}/resource-history`, { signal: expect.any(AbortSignal) }, 1536 * 1024);
    });
    it('ignores a delayed delta after the protected request epoch changes', async () => {
        const h = renderHook(() => useResourceHistory(historyDevice, 'session', true)); await flush();
        const held = deferred<ReturnType<typeof historyFixture>>(); vi.mocked(request).mockReturnValueOnce(held.promise); await advance(60000);
        act(() => { abortProtectedRequests(); window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)); });
        await act(async () => held.resolve(historyFixture())); expect(h.result.current.view).toBeNull(); expect(h.result.current.error).toBe('session');
    });
});
