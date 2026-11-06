import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, AUTH_REQUIRED_EVENT, abortProtectedRequests, mutateRaw, request } from './api';
import type { OperatorSession } from './auth';
import type { UpdateJobHistory } from './windows-update-jobs-types';
import { useFleetUpdateHistory } from './windows-fleet-update-history-resource';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
const now = '2026-11-06T10:00:00Z', expiry = '2026-11-06T11:00:00Z', seconds = Date.parse(now) / 1000;
const actor = `operator_${'a'.repeat(32)}`, ids = Array.from({ length: 51 }, (_, i) => `agent_${(i + 1).toString(16).padStart(32, '0')}`);
const session = (): OperatorSession => ({ mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'fixture', serverNow: now, expiresAt: expiry, expiresInSeconds: 3600, loginMode: 'named', actorId: actor, capabilities: ['read', 'windows_update_install'] });
const history = (deviceId = ids[0]): UpdateJobHistory => ({ version: 'tracebolt.windows-selected-update-history.v1', deviceId, serverNow: seconds, available: true, reason: 'ready', remainingCapacity: 32, jobs: [] });
const flush = () => act(async () => {});
const hook = (targets = ids.slice(0, 2)) => renderHook(() => useFleetUpdateHistory(targets, actor, expiry, true));
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime(now);
    vi.mocked(request).mockReset().mockImplementation(async path => structuredClone(path === '/auth/session' ? session() : history(path.split('/')[2])) as never);
    vi.mocked(mutateRaw).mockReset();
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('bounded, explicit fleet saved-job reads', () => {
    it('starts without I/O and rechecks the named session before bounded history GETs only', async () => {
        const storage = vi.spyOn(Storage.prototype, 'setItem'), { result } = hook(); expect(request).not.toHaveBeenCalled();
        act(() => { result.current.read(); result.current.read(); }); await flush();
        expect(vi.mocked(request).mock.calls.map(([path]) => path)).toEqual(['/auth/session', ...ids.slice(0, 2).map(id => `/devices/${id}/windows-update-jobs?history=1`)]);
        expect(vi.mocked(request).mock.calls.map(([, , cap]) => cap)).toEqual([16384, 65536, 65536]);
        for (const [, options] of vi.mocked(request).mock.calls) expect(options?.method ?? 'GET').toBe('GET');
        expect(result.current.reports).toEqual(ids.slice(0, 2).map(deviceId => ({ deviceId, history: history(deviceId) })));
        expect(result.current.loading).toBe(false); expect(result.current.waiting).toBe(false);
        act(() => vi.advanceTimersByTime(15000)); expect(request).toHaveBeenCalledTimes(3);
        expect(mutateRaw).not.toHaveBeenCalled(); expect(storage).not.toHaveBeenCalled();
    });

    it.each([
        { actorId: `operator_${'b'.repeat(32)}` }, { capabilities: ['read'] }, { capabilities: ['read', 'windows_update_download'] },
        { expiresAt: '2026-11-06T11:01:00Z' }, { loginMode: 'shared', actorId: null }, { transport: 'http', insecureTestMode: true, transportWarning: 'unencrypted_lan_test' },
        { serverNow: expiry }, { mode: 'development' }, { authenticated: false },
    ])('rejects an incompatible session before any device read: %j', async patch => {
        vi.mocked(request).mockResolvedValue({ ...session(), ...patch } as never);
        const { result } = hook(); act(() => result.current.read()); await flush();
        expect(request).toHaveBeenCalledTimes(1); expect(result.current.reports).toEqual([]); expect(result.current.error).toBe(true);
        act(() => result.current.read()); expect(request).toHaveBeenCalledTimes(1);
    });

    it.each([[], ids, [ids[0], ids[0]], ['agent_bad']].map(targets => ({ targets })))('rejects invalid or excessive scopes without truncating: %j', async ({ targets }) => {
        const { result } = hook(targets); act(() => result.current.read()); await flush(); expect(request).not.toHaveBeenCalled();
    });

    it('reads at most four histories at a time across fifty exact devices', async () => {
        const queued: Array<() => void> = []; let live = 0, maximum = 0;
        vi.mocked(request).mockImplementation(path => {
            if (path === '/auth/session') return Promise.resolve(session()) as never;
            live++; maximum = Math.max(maximum, live);
            return new Promise(resolve => queued.push(() => { live--; resolve(history(path.split('/')[2])); })) as never;
        });
        const { result } = hook(ids.slice(0, 50)); act(() => result.current.read()); await flush(); expect(request).toHaveBeenCalledTimes(5);
        while (queued.length) { const batch = queued.splice(0); await act(async () => batch.forEach(resolve => resolve())); }
        expect(maximum).toBe(4); expect(request).toHaveBeenCalledTimes(51); expect(result.current.reports).toHaveLength(50); expect(result.current.loading).toBe(false);
    });

    it('keeps unavailable and unread devices separate from validated empty histories', async () => {
        vi.mocked(request).mockImplementation(async path => {
            if (path === '/auth/session') return session() as never;
            const id = path.split('/')[2]; if (id === ids[1]) throw new APIError('Denied', 403);
            return (id === ids[2] ? { ...history(id), deviceId: ids[0] } : history(id)) as never;
        });
        const { result } = hook(ids.slice(0, 4)); act(() => result.current.read()); await flush();
        expect(result.current.reports.filter(report => report.history).map(report => report.deviceId)).toEqual([ids[0], ids[3]]);
        expect(result.current.reports.filter(report => !report.history).map(report => report.deviceId)).toEqual([ids[1], ids[2]]);
    });

    it.each([{ extra: 'unexpected' }, { jobs: [{}] }, { serverNow: seconds - 1 }, { deviceId: ids[1] }])('rejects malformed or stale history before retaining its fields: %j', async patch => {
        vi.mocked(request).mockImplementation(async path => (path === '/auth/session' ? session() : { ...history(), ...patch }) as never);
        const { result } = hook([ids[0]]); act(() => result.current.read()); await flush();
        expect(result.current.reports).toEqual([{ deviceId: ids[0] }]); expect(mutateRaw).not.toHaveBeenCalled();
    });

    it('clears all rows when a history response reaches the original session expiry', async () => {
        vi.mocked(request).mockImplementation(async path => (path === '/auth/session' ? session() : { ...history(path.split('/')[2]), serverNow: Date.parse(expiry) / 1000 }) as never);
        const { result } = hook(); act(() => result.current.read()); await flush();
        expect(result.current.hasRead).toBe(false); expect(result.current.reports).toEqual([]); expect(result.current.blocked).toBe(true);
    });

    it.each([0, 1, 500, 999])('admits whole-second history time with an auth timestamp %i ms into that same second', async ms => {
        const auth = { ...session(), serverNow: new Date(Date.parse(now) + ms).toISOString() };
        vi.mocked(request).mockImplementation(async path => (path === '/auth/session' ? auth : history()) as never);
        const { result } = hook([ids[0]]); act(() => result.current.read()); await flush();
        expect(result.current.reports[0]?.history?.serverNow).toBe(seconds);
    });

    it.each([{ authMS: 999, historySeconds: seconds - 1 }, { authMS: 1000, historySeconds: seconds }])('rejects history from an actually earlier second: %j', async ({ authMS, historySeconds }) => {
        const auth = { ...session(), serverNow: new Date(Date.parse(now) + authMS).toISOString() };
        vi.mocked(request).mockImplementation(async path => (path === '/auth/session' ? auth : { ...history(), serverNow: historySeconds }) as never);
        const { result } = hook([ids[0]]); act(() => result.current.read()); await flush();
        expect(result.current.reports).toEqual([{ deviceId: ids[0] }]);
    });

    it('clears at the precise confirmed session deadline even with a slow browser clock', async () => {
        vi.setSystemTime(Date.parse(now) - 600000);
        const until = new Date(Date.parse(now) + 1500).toISOString(), auth = { ...session(), serverNow: new Date(Date.parse(now) + 500).toISOString(), expiresAt: until, expiresInSeconds: 1 };
        vi.mocked(request).mockImplementation(async path => (path === '/auth/session' ? auth : history()) as never);
        const { result } = renderHook(() => useFleetUpdateHistory([ids[0]], actor, until, true));
        act(() => result.current.read()); await flush(); expect(result.current.reports).toHaveLength(1);
        act(() => vi.advanceTimersByTime(999)); expect(result.current.reports).toHaveLength(1);
        act(() => vi.advanceTimersByTime(1)); expect(result.current.reports).toEqual([]); expect(result.current.blocked).toBe(true);
        act(() => result.current.read()); expect(request).toHaveBeenCalledTimes(2);
    });

    it('does not renew confirmed session time by waiting for a slow authentication response', async () => {
        vi.setSystemTime(Date.parse(now) - 600000);
        const until = new Date(Date.parse(now) + 1000).toISOString();
        vi.mocked(request).mockImplementation(() => new Promise(resolve => window.setTimeout(() => resolve({ ...session(), expiresAt: until, expiresInSeconds: 1 }), 1500)) as never);
        const { result } = renderHook(() => useFleetUpdateHistory([ids[0]], actor, until, true));
        act(() => result.current.read()); await act(async () => vi.advanceTimersByTimeAsync(1500));
        expect(result.current.reports).toEqual([]); expect(result.current.blocked).toBe(true); expect(request).toHaveBeenCalledTimes(1);
    });

    it('tightens but never extends the session deadline from a later history server time', async () => {
        vi.setSystemTime(Date.parse(now) - 600000);
        const until = new Date(Date.parse(now) + 10000).toISOString(), auth = { ...session(), expiresAt: until, expiresInSeconds: 10 };
        vi.mocked(request).mockImplementation(async path => (path === '/auth/session' ? auth : { ...history(path.split('/')[2]), serverNow: path.includes(ids[0]) ? seconds + 9 : seconds }) as never);
        const { result } = renderHook(() => useFleetUpdateHistory(ids.slice(0, 2), actor, until, true));
        act(() => result.current.read()); await flush(); expect(result.current.reports).toHaveLength(2);
        act(() => vi.advanceTimersByTime(1000)); expect(result.current.reports).toEqual([]); expect(result.current.blocked).toBe(true);
    });

    it('does not start histories from an interrupted or replaced session check', async () => {
        let resolve!: (value: unknown) => void;
        vi.mocked(request).mockImplementation(() => new Promise(done => { resolve = done; }) as never);
        const { result, rerender } = renderHook(({ current }) => useFleetUpdateHistory([ids[0]], current, expiry, true), { initialProps: { current: actor } });
        act(() => result.current.read()); expect(request).toHaveBeenCalledTimes(1);
        rerender({ current: `operator_${'b'.repeat(32)}` });
        await act(async () => resolve(session())); expect(result.current.reports).toEqual([]); expect(request).toHaveBeenCalledTimes(1);
    });

    it('locks and clears the whole batch on an unauthorized device response', async () => {
        vi.mocked(request).mockImplementation(async path => { if (path === '/auth/session') return session() as never; if (path.includes(ids[1])) throw new APIError('Unauthorized', 401); return history(path.split('/')[2]) as never; });
        const { result } = hook(ids.slice(0, 8)); act(() => result.current.read()); await flush();
        const count = vi.mocked(request).mock.calls.length; expect(result.current.blocked).toBe(true); expect(result.current.hasRead).toBe(false); expect(result.current.reports).toEqual([]);
        act(() => result.current.read()); expect(request).toHaveBeenCalledTimes(count);
    });

    it('does not replace canceled noncooperative reads or reuse their outstanding slots', async () => {
        const late: Array<() => void> = [];
        vi.mocked(request).mockImplementation(path => path === '/auth/session' ? Promise.resolve(session()) as never : new Promise(resolve => late.push(() => resolve(history(path.split('/')[2])))) as never);
        const { result } = hook(ids.slice(0, 8)); act(() => result.current.read()); await flush();
        await act(async () => vi.advanceTimersByTimeAsync(10000));
        expect(request).toHaveBeenCalledTimes(5); expect(result.current.loading).toBe(false); expect(result.current.waiting).toBe(true);
        expect(result.current.reports).toHaveLength(4); expect(result.current.reports.every(report => !report.history)).toBe(true);
        act(() => { result.current.clear(); result.current.read(); }); expect(request).toHaveBeenCalledTimes(5);
        await act(async () => late.forEach(resolve => resolve())); expect(result.current.waiting).toBe(false); expect(result.current.reports).toEqual([]);
        vi.mocked(request).mockImplementation(async path => (path === '/auth/session' ? session() : { ...history(path.split('/')[2]), serverNow: seconds + 10 }) as never);
        act(() => result.current.read()); await flush(); expect(result.current.reports).toHaveLength(8);
    });

    it.each([actor, `operator_${'b'.repeat(32)}`])('preserves the page-wide bound across full unmount and remount for %s', async nextActor => {
        const late: Array<() => void> = []; let live = 0, maximum = 0;
        vi.mocked(request).mockImplementation(path => {
            live++; maximum = Math.max(maximum, live);
            if (path === '/auth/session') return Promise.resolve(session()).finally(() => { live--; }) as never;
            return new Promise(resolve => late.push(() => { live--; resolve(history(path.split('/')[2])); })) as never;
        });
        const first = hook(ids.slice(0, 8)); act(() => first.result.current.read()); await flush();
        expect(live).toBe(4); expect(request).toHaveBeenCalledTimes(5); first.unmount();
        const next = renderHook(() => useFleetUpdateHistory(ids.slice(4, 8), nextActor, expiry, true));
        expect(next.result.current.waiting).toBe(true); act(() => next.result.current.read()); await flush(); expect(request).toHaveBeenCalledTimes(5);
        await act(async () => vi.advanceTimersByTimeAsync(300000));
        act(() => next.result.current.read()); expect(request).toHaveBeenCalledTimes(5); expect(next.result.current.waiting).toBe(true);
        await act(async () => late.splice(0, 3).forEach(resolve => resolve()));
        act(() => next.result.current.read()); expect(request).toHaveBeenCalledTimes(5); expect(next.result.current.reports).toEqual([]);
        await act(async () => late.splice(0).forEach(resolve => resolve()));
        expect(live).toBe(0); expect(maximum).toBe(4); expect(next.result.current.waiting).toBe(false); expect(next.result.current.hasRead).toBe(false);
        // Transport completion cannot start a new session or restore old rows.
        expect(request).toHaveBeenCalledTimes(5);
        vi.mocked(request).mockImplementation(async path => (path === '/auth/session' ? { ...session(), actorId: nextActor, serverNow: new Date(Date.now()).toISOString(), expiresInSeconds: 3300 } : { ...history(path.split('/')[2]), serverNow: seconds + 300 }) as never);
        act(() => next.result.current.read()); await flush();
        expect(vi.mocked(request).mock.calls[5][0]).toBe('/auth/session');
        expect(next.result.current.reports.map(report => report.deviceId)).toEqual(ids.slice(4, 8));
        expect(next.result.current.reports.every(report => !!report.history)).toBe(true); expect(next.result.current.waiting).toBe(false);
    });

    it('admits only one simultaneous reader, including an interrupted session check', async () => {
        let finish!: (value: unknown) => void;
        vi.mocked(request).mockImplementation(() => new Promise(resolve => { finish = resolve; }) as never);
        const first = hook(), second = hook();
        act(() => { first.result.current.read(); second.result.current.read(); }); expect(request).toHaveBeenCalledTimes(1);
        act(() => { first.result.current.clear(); second.result.current.read(); }); expect(request).toHaveBeenCalledTimes(1);
        await act(async () => finish(session())); expect(request).toHaveBeenCalledTimes(1); expect(second.result.current.waiting).toBe(false);
        vi.mocked(request).mockImplementation(async path => (path === '/auth/session' ? session() : history(path.split('/')[2])) as never);
        act(() => second.result.current.read()); await flush(); expect(second.result.current.reports).toHaveLength(2); expect(first.result.current.reports).toEqual([]);
    });

    it.each(['throw', 'reject'])('releases admission after a transport %s without an automatic retry', async kind => {
        vi.mocked(request).mockImplementationOnce(() => { if (kind === 'throw') throw new Error('Transport failed'); return Promise.reject(new Error('Transport failed')) as never; });
        const { result } = hook(); act(() => result.current.read()); await flush();
        expect(result.current.error).toBe(true); expect(result.current.waiting).toBe(false); expect(request).toHaveBeenCalledTimes(1);
        act(() => result.current.read()); await flush(); expect(result.current.reports).toHaveLength(2); expect(result.current.waiting).toBe(false);
    });

    it('ends a progressing batch after one minute without starting later reads', async () => {
        vi.mocked(request).mockImplementation(path => path === '/auth/session' ? Promise.resolve(session()) as never : new Promise(resolve => window.setTimeout(() => resolve({ ...history(path.split('/')[2]), serverNow: Date.now() / 1000 }), 9000)) as never);
        const { result } = hook(ids.slice(0, 50)); act(() => result.current.read()); await flush();
        await act(async () => vi.advanceTimersByTimeAsync(60000)); expect(result.current.hasRead).toBe(false); expect(result.current.reports).toEqual([]);
        const count = vi.mocked(request).mock.calls.length; await act(async () => vi.advanceTimersByTimeAsync(10000)); expect(request).toHaveBeenCalledTimes(count); expect(result.current.reports).toEqual([]);
    });
});

describe('private saved-history lifetime', () => {
    it.each(['blur', 'pagehide', 'popstate', 'hashchange', AUTH_REQUIRED_EVENT, 'visibilitychange', 'clear', 'unmount'])('clears accepted and late rows on %s', async event => {
        const pending: Array<() => void> = [];
        vi.mocked(request).mockImplementation(path => path === '/auth/session' ? Promise.resolve(session()) as never : path.includes(ids[0]) ? Promise.resolve(history(ids[0])) as never : new Promise(resolve => pending.push(() => resolve(history(path.split('/')[2])))) as never);
        const { result, unmount } = hook(ids.slice(0, 8)); act(() => result.current.read()); await flush(); expect(result.current.reports).toHaveLength(1);
        const count = vi.mocked(request).mock.calls.length;
        act(() => { if (event === 'unmount') unmount(); else if (event === 'clear') result.current.clear(); else if (event === 'visibilitychange') { vi.spyOn(document, 'hidden', 'get').mockReturnValue(true); document.dispatchEvent(new Event(event)); } else window.dispatchEvent(new Event(event)); });
        await act(async () => pending.forEach(resolve => resolve()));
        if (event !== 'unmount') { expect(result.current.reports).toEqual([]); expect(result.current.hasRead).toBe(false); }
        expect(request).toHaveBeenCalledTimes(count);
    });

    it('retains the original batch expiry even when histories arrive later', async () => {
        vi.mocked(request).mockImplementation(path => path === '/auth/session' ? Promise.resolve(session()) as never : new Promise(resolve => window.setTimeout(() => resolve(history(path.split('/')[2])), 9000)) as never);
        const { result } = hook(); act(() => result.current.read()); await flush(); await act(async () => vi.advanceTimersByTimeAsync(9000)); expect(result.current.reports).toHaveLength(2);
        act(() => vi.advanceTimersByTime(290999)); expect(result.current.reports).toHaveLength(2);
        act(() => vi.advanceTimersByTime(501)); expect(result.current.reports).toEqual([]); expect(request).toHaveBeenCalledTimes(3);
    });

    it('rejects replayed server time but keeps original recorded event times after a fresh read', async () => {
        const { result } = hook(); act(() => result.current.read()); await flush(); act(() => vi.advanceTimersByTime(2000));
        act(() => result.current.read()); await flush(); expect(result.current.reports.every(report => !report.history)).toBe(true);
        vi.mocked(request).mockImplementation(async path => (path === '/auth/session' ? session() : { ...history(path.split('/')[2]), serverNow: seconds + 2 }) as never);
        act(() => result.current.read()); await flush(); expect(result.current.reports.every(report => report.history?.serverNow === seconds + 2)).toBe(true);
    });

    it.each(['epoch', 'clock', 'expiry'])('clears private data on %s loss', async kind => {
        const { result } = hook(); act(() => result.current.read()); await flush();
        if (kind === 'epoch') act(() => abortProtectedRequests());
        else if (kind === 'clock') act(() => vi.setSystemTime(Date.now() - 5000));
        else act(() => vi.setSystemTime(expiry));
        act(() => vi.advanceTimersByTime(500)); expect(result.current.reports).toEqual([]);
        if (kind === 'epoch') { act(() => result.current.read()); expect(request).toHaveBeenCalledTimes(3); }
    });

    it('keeps reordering stable, but clears membership, operator and capability changes', async () => {
        const { result, rerender } = renderHook(props => useFleetUpdateHistory(props.ids, props.actor, expiry, props.enabled), { initialProps: { ids: ids.slice(0, 2), actor, enabled: true } });
        act(() => result.current.read()); await flush();
        rerender({ ids: [ids[1], ids[0]], actor, enabled: true }); expect(result.current.reports).toHaveLength(2);
        rerender({ ids: [ids[0]], actor, enabled: true }); expect(result.current.reports).toEqual([]);
        act(() => result.current.read()); await flush(); expect(result.current.reports).toHaveLength(1);
        rerender({ ids: [ids[0]], actor: `operator_${'b'.repeat(32)}`, enabled: true }); expect(result.current.reports).toEqual([]);
        rerender({ ids: [ids[0]], actor, enabled: false }); act(() => result.current.read()); expect(result.current.reports).toEqual([]);
    });
});
