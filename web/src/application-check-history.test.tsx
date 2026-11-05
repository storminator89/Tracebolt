import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, abortProtectedRequests, request } from './api';
import { ApplicationCheckHistory } from './application-check-history';
import { APPLICATION_HISTORY_BYTES, APPLICATION_HISTORY_MEDIA, validApplicationHistory } from './application-check-history-types';
import type { ApplicationHistory } from './application-check-history-types';
import { setLocale } from './i18n';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
const now = '2026-11-04T12:00:00Z';
function fixture(): ApplicationHistory {
    return { schemaVersion: 'tracebolt.application-check-history.v1', enabled: true, vantage: 'management_server', serverNow: now, retentionSeconds: 86400, perTargetLimit: 32, clockReliable: true, items: [
        { id: 'fixture-app', kind: 'http', targetScheme: 'https', earlierOmitted: true, samples: [
            { observedAt: '2026-11-04T11:55:00Z', completedAt: '2026-11-04T11:55:01Z', state: 'http_error', reason: 'http_status', httpStatus: 503, gapBefore: false },
            { observedAt: '2026-11-04T11:59:00Z', completedAt: '2026-11-04T11:59:01Z', state: 'ok', reason: 'http_2xx', httpStatus: 204, gapBefore: true },
        ] },
        { id: 'dns-fixture', kind: 'dns', targetScheme: '', earlierOmitted: false, samples: [{ observedAt: '2026-11-04T11:59:00Z', completedAt: '2026-11-04T11:59:01Z', state: 'ok', reason: 'dns_resolved', httpStatus: null, gapBefore: false }] },
    ] };
}
const flush = () => act(async () => {});
async function open() { const details = document.querySelector('details')!; details.open = true; fireEvent(details, new Event('toggle')); await flush(); return details; }
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(r => { resolve = r; }); return { promise, resolve }; }
beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(now); setLocale('en', false); localStorage.clear(); vi.spyOn(document, 'hasFocus').mockReturnValue(true); vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible'); vi.mocked(request).mockReset().mockResolvedValue(fixture()); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('strict bounded historical representation', () => {
    it('accepts mixed completed outcomes and explicit empty/clock-gap histories', () => {
        expect(validApplicationHistory(fixture())).toBe(true);
        const v = fixture(); v.clockReliable = false; v.items.forEach(t => { t.samples = []; t.earlierOmitted = true; }); expect(validApplicationHistory(v)).toBe(true);
        expect(validApplicationHistory({ ...fixture(), enabled: false, items: [] })).toBe(true);
    });
    it('rejects extra payload, ambiguous sources, malformed outcomes and nanosecond time violations', () => {
        const cases: ((v: ReturnType<typeof fixture>) => unknown)[] = [
            v => ({ ...v, url: 'https://private.example' }), v => ({ ...v, items: [...v.items, v.items[0]] }),
            v => ({ ...v, perTargetLimit: 33 }), v => ({ ...v, retentionSeconds: 86401 }),
            v => { v.items[0].samples[0].httpStatus = 204; return v; },
            v => { v.items[1].samples[0].httpStatus = 200; return v; },
            v => { v.items[0].samples[0].reason = '<script>private</script>'; return v; },
            v => { v.items[0].samples[1].completedAt = '2026-11-04T12:00:00.000000001Z'; return v; },
            v => { v.items[0].samples[1].observedAt = v.items[0].samples[0].completedAt; return v; },
            v => { v.items[0].samples[0].observedAt = '2026-11-03T11:59:59.999999999Z'; return v; },
            v => { v.items[0].samples[0].completedAt = '2026-11-04T11:54:59Z'; return v; },
            v => { v.items[0].samples = Array(33).fill(v.items[0].samples[0]); return v; },
        ];
        for (const mutate of cases) expect(validApplicationHistory(mutate(fixture()))).toBe(false);
    });
});
describe('deliberate private history reads', () => {
    it('does no work until expanded, requests only the saved representation and shows original outcomes', async () => {
        render(<ApplicationCheckHistory/>); expect(request).not.toHaveBeenCalled(); await open();
        expect(request).toHaveBeenCalledExactlyOnceWith('/application-checks/status', { signal: expect.any(AbortSignal), cache: 'no-store', redirect: 'error', headers: { Accept: APPLICATION_HISTORY_MEDIA } }, APPLICATION_HISTORY_BYTES);
        expect(screen.getByText('204 · Success observed')).toBeInTheDocument(); expect(screen.getByText('503 · Failure observed')).toBeInTheDocument(); expect(screen.getByText('Observation gap before this sample.')).toBeInTheDocument(); expect(screen.getByText('Earlier observations are not retained.')).toBeInTheDocument();
        expect(document.querySelector('li time')).toHaveAttribute('datetime', '2026-11-04T11:59:00Z'); expect(screen.queryByText(/recovered|uptime percentage|fully healthy/i)).not.toBeInTheDocument();
    });
    it('clears on close, blur and session loss and ignores an interrupted response', async () => {
        const held = deferred<unknown>(); vi.mocked(request).mockReturnValueOnce(held.promise); render(<ApplicationCheckHistory/>); const details = await open(); const signal = vi.mocked(request).mock.calls[0][1]!.signal!;
        fireEvent(window, new Event('blur')); await flush(); expect(details.open).toBe(false); expect(signal.aborted).toBe(true);
        await act(async () => held.resolve(fixture())); expect(screen.queryByText('204 · Success observed')).toBeNull();
        await open(); expect(screen.getByText('204 · Success observed')).toBeInTheDocument(); fireEvent(window, new Event(AUTH_REQUIRED_EVENT)); await flush(); expect(details.open).toBe(false); expect(screen.queryByText('204 · Success observed')).toBeNull();
    });
    it('expires without background polling and re-reads only on explicit reload', async () => {
        render(<ApplicationCheckHistory/>); await open(); await act(async () => { await vi.advanceTimersByTimeAsync(60000); }); expect(screen.queryByText('204 · Success observed')).toBeNull(); expect(screen.getByText('History view expired. Reload saved observations.')).toBeInTheDocument(); expect(request).toHaveBeenCalledTimes(1);
        fireEvent.click(screen.getByRole('button', { name: 'Reload history' })); await flush(); expect(request).toHaveBeenCalledTimes(2);
    });
    it('does not display samples past their original retention deadline', async () => {
        const v = fixture(); v.items = [v.items[0]]; v.items[0].samples = [{ ...v.items[0].samples[0], observedAt: '2026-11-03T12:00:00.500Z', completedAt: '2026-11-03T12:00:01Z' }]; vi.mocked(request).mockResolvedValue(v);
        render(<ApplicationCheckHistory/>); await open(); expect(screen.getByText('503 · Failure observed')).toBeInTheDocument(); await act(async () => { await vi.advanceTimersByTimeAsync(500); }); expect(screen.queryByText('503 · Failure observed')).toBeNull();
    });
    it('does not let a frozen server reply extend the original retention deadline', async () => {
        const v = fixture(); v.items = [v.items[0]]; v.items[0].samples = [{ ...v.items[0].samples[0], observedAt: '2026-11-03T12:01:00Z', completedAt: '2026-11-03T12:01:01Z' }]; vi.mocked(request).mockResolvedValue(v);
        render(<ApplicationCheckHistory/>); await open(); await act(async () => { await vi.advanceTimersByTimeAsync(30000); }); fireEvent.click(screen.getByRole('button', { name: 'Reload history' })); await flush(); expect(screen.getByText('503 · Failure observed')).toBeInTheDocument();
        await act(async () => { await vi.advanceTimersByTimeAsync(30000); }); expect(screen.queryByText('503 · Failure observed')).toBeNull(); expect(request).toHaveBeenCalledTimes(2);
    });
    it('preserves frozen-clock retention across navigation remounts', async () => {
        const v = fixture(); v.items = [v.items[0]]; v.items[0].samples = [{ ...v.items[0].samples[0], observedAt: '2026-11-03T12:01:00Z', completedAt: '2026-11-03T12:01:01Z' }]; vi.mocked(request).mockResolvedValue(v);
        const mounted = render(<ApplicationCheckHistory/>); await open(); await act(async () => { await vi.advanceTimersByTimeAsync(30000); }); mounted.unmount(); render(<ApplicationCheckHistory/>); await open(); expect(screen.getByText('503 · Failure observed')).toBeInTheDocument(); await act(async () => { await vi.advanceTimersByTimeAsync(30000); }); expect(screen.queryByText('503 · Failure observed')).toBeNull();
    });
    it('never installs an already expired replay after reopening', async () => {
        const v = fixture(); v.items = [v.items[0]]; v.items[0].samples = [{ ...v.items[0].samples[0], observedAt: '2026-11-03T12:00:01Z', completedAt: '2026-11-03T12:00:01Z' }]; vi.mocked(request).mockResolvedValue(v);
        const mounted = render(<ApplicationCheckHistory/>); await open(); mounted.unmount(); await act(async () => { await vi.advanceTimersByTimeAsync(2000); }); render(<ApplicationCheckHistory/>); await open(); expect(screen.queryByText('503 · Failure observed')).toBeNull(); expect(screen.getByText('History view expired. Reload saved observations.')).toBeInTheDocument();
    });
    it('bounds stalled reads, rejects malformed history and local clock jumps', async () => {
        vi.mocked(request).mockReturnValueOnce(new Promise(() => {})); render(<ApplicationCheckHistory/>); await open(); await act(async () => { await vi.advanceTimersByTimeAsync(10000); }); expect(screen.getByRole('alert')).toHaveTextContent('Observation history unavailable');
        vi.mocked(request).mockResolvedValue({ ...fixture(), url: 'https://not-allowed.example' }); fireEvent.click(screen.getByRole('button', { name: 'Reload history' })); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('Observation history unavailable');
        vi.mocked(request).mockResolvedValue(fixture()); fireEvent.click(screen.getByRole('button', { name: 'Reload history' })); await flush(); vi.setSystemTime('2026-11-04T11:00:00Z'); await act(async () => { await vi.advanceTimersByTimeAsync(1000); }); expect(document.querySelector('details')).not.toHaveAttribute('open'); expect(screen.queryByText('204 · Success observed')).toBeNull();
    });
    it('uses German captions and clears on unmount without a late render', async () => {
        setLocale('de', false); const held = deferred<unknown>(); vi.mocked(request).mockReturnValueOnce(held.promise); const mounted = render(<ApplicationCheckHistory/>); expect(screen.getByText('Letzte Prüfbeobachtungen')).toBeInTheDocument(); await open(); const signal = vi.mocked(request).mock.calls[0][1]!.signal!; mounted.unmount(); expect(signal.aborted).toBe(true); await act(async () => held.resolve(fixture())); expect(screen.queryByText('fixture-app')).toBeNull();
    });
});
