import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, APIError, AUTH_REQUIRED_EVENT, request } from './api';
import { LOGOUT_INTENT_KEY, useOperator } from './auth';
import { setLocale } from './i18n';
import { AlarmStatusPanel } from './alarm-status';
import { ALARM_STATUS_BYTES, validAlarmStatus } from './alarm-status-types';
import type { AlarmStatus } from './alarm-status-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: '2026-10-06T14:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
const empty = (): AlarmStatus => ({ schemaVersion: 'tracebolt.alarm-status.v1', enabled: false, queued: 0, inFlight: 0, providerAccepted: 0, failed: 0, uncertain: 0, suppressed: 0, dropped: 0 });
const populated = (): AlarmStatus => ({ ...empty(), enabled: true, queued: 2, inFlight: 1, providerAccepted: 7, failed: 4, uncertain: 5, suppressed: 9, dropped: 11 });
const flush = () => act(async () => {}), advance = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
const refresh = () => screen.getByRole('button', { name: 'Refresh alarm status' });
const panel = () => screen.getByRole('region', { name: 'Alarm delivery' });
const count = (name: string) => within(panel()).getAllByText(name, { selector: 'dt' })[0].parentElement!.querySelector('dd')!;
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { resolve, promise }; }
async function start(value: unknown = populated()) { vi.mocked(request).mockResolvedValue(value); const mounted = render(<AlarmStatusPanel/>); await flush(); return mounted; }
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime('2026-10-06T12:00:00Z'); localStorage.clear(); sessionStorage.clear(); setLocale('en', false);
    vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible'); vi.mocked(useOperator).mockReturnValue(operator); vi.mocked(request).mockReset();
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe('aggregate alarm response validation', () => {
    it('accepts disabled retained history and independent dropped counts', () => {
        expect(validAlarmStatus(empty())).toBe(true); expect(validAlarmStatus({ ...populated(), enabled: false, dropped: Number.MAX_SAFE_INTEGER })).toBe(true);
        expect(validAlarmStatus({ ...empty(), queued: 499, inFlight: 1, suppressed: 500 })).toBe(true);
    });
    it.each([null, [], {}, { ...empty(), enabled: 'false' }, { ...empty(), schemaVersion: 'tracebolt.alarm-status.v2' }, { ...empty(), endpoint: 'https://private.invalid/token' }, { ...empty(), queued: 500, inFlight: 1 }, { ...empty(), suppressed: 1001 }, { ...empty(), providerAccepted: 999, failed: 2 }])('rejects malformed or out-of-bounds status %j', value => expect(validAlarmStatus(value)).toBe(false));
    it.each(['queued', 'inFlight', 'providerAccepted', 'failed', 'uncertain', 'suppressed', 'dropped'] as const)('requires a bounded integer for %s', key => {
        for (const bad of [-1, 0.1, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, null, '0', undefined]) expect(validAlarmStatus({ ...empty(), [key]: bad })).toBe(false);
    });
});

describe('compact read-only status and meanings', () => {
    it('renders quiet disabled state with details closed and no fictitious zero history', async () => {
        await start(empty()); expect(panel()).toHaveTextContent('Off'); expect(panel().querySelector('.alarm-counts')).toBeNull();
        const details = panel().querySelector('details')!; expect(details.open).toBe(false);
        fireEvent.click(within(panel()).getByText('Details', { selector: 'summary' })); expect(details.open).toBe(true);
        expect(panel()).toHaveTextContent('Delivery is disabled in manager configuration'); expect(within(panel()).getAllByRole('button')).toHaveLength(1);
        expect(panel().querySelector('input,select,a')).toBeNull(); expect(panel()).not.toHaveTextContent('Test send');
    });
    it('separates retained states and durable dropped gaps without a total or success claim', async () => {
        await start();
        for (const [label, value] of [['Provider accepted', '7'], ['Pending', '3'], ['Failed', '4'], ['Uncertain', '5'], ['Queued', '2'], ['In flight', '1'], ['Suppressed', '9'], ['Dropped', '11']]) expect(count(label)).toHaveTextContent(new RegExp(`^${value}$`));
        expect(panel()).toHaveTextContent('Provider acceptance does not confirm receipt by a person.');
        expect(panel()).toHaveTextContent('Counts include opening/recovery events, previous destinations and synthetic tests;');
        expect(panel()).toHaveTextContent('not complete delivery history or per-event confirmation');
        expect(panel()).toHaveTextContent('not automatically replayed'); expect(panel()).toHaveTextContent('separate durable count');
        expect(panel()).not.toHaveTextContent('Delivered'); expect(panel().querySelector('time')).toHaveAttribute('datetime', '2026-10-06T12:00:00.000Z');
        expect(request).toHaveBeenCalledExactlyOnceWith('/alerts/status', { signal: expect.any(AbortSignal), cache: 'no-store' }, ALARM_STATUS_BYTES);
    });
    it('keeps retained failures and dropped gaps visible while delivery is off', async () => {
        await start({ ...populated(), enabled: false }); expect(panel().querySelector('.alarm-mode')).toHaveTextContent('Off');
        expect(count('Failed')).toHaveTextContent('4'); expect(count('Dropped')).toHaveTextContent('11'); expect(panel().querySelector('details')!.open).toBe(false);
    });
    it('shows no accepted events as zero counts rather than a healthy or delivered badge', async () => {
        await start({ ...empty(), enabled: true }); expect(count('Provider accepted')).toHaveTextContent(/^0$/); expect(panel()).not.toHaveTextContent('Healthy');
    });
    it('changes every status label to German without requesting another snapshot', async () => {
        await start(); act(() => setLocale('de', false)); const content = screen.getByRole('region', { name: 'Alarmversand' });
        for (const label of ['Vom Anbieter angenommen', 'Ausstehend', 'Fehlgeschlagen', 'Ungewiss', 'Verworfen', 'Warteschlange', 'In Übertragung', 'Unterdrückt']) expect(content).toHaveTextContent(label);
        expect(content).toHaveTextContent('keinen Empfang durch eine Person'); expect(screen.getByRole('button', { name: 'Alarmstatus aktualisieren' })).toBeInTheDocument(); expect(request).toHaveBeenCalledTimes(1);
    });
    it.each([null, { ...operator, mode: 'development' as const }, { ...operator, authenticated: false }])('does not render or fetch outside authenticated LAN access', async value => {
        vi.mocked(useOperator).mockReturnValue(value); await start(); expect(screen.queryByRole('region')).toBeNull(); expect(request).not.toHaveBeenCalled();
    });
    it('supports named read-only accounts without requesting new authority', async () => {
        vi.mocked(useOperator).mockReturnValue({ ...operator, loginMode: 'named', actorId: `operator_${'a'.repeat(32)}`, capabilities: ['read'] });
        await start(); expect(count('Provider accepted')).toHaveTextContent('7'); expect(within(panel()).getAllByRole('button')).toHaveLength(1);
    });
});

describe('snapshot and access lifecycle', () => {
    it('never polls, retries failure, or overlaps repeated manual refresh clicks', async () => {
        await start(); await advance(180000); expect(request).toHaveBeenCalledTimes(1);
        const held = deferred<AlarmStatus>(); vi.mocked(request).mockReturnValueOnce(held.promise); fireEvent.click(refresh()); fireEvent.click(refresh());
        expect(request).toHaveBeenCalledTimes(2); expect(refresh()).toBeDisabled(); expect(panel()).toHaveTextContent('Previous snapshot'); expect(panel().querySelector('.alarm-mode')).toHaveTextContent('Unknown');
        await act(async () => held.resolve(populated())); expect(refresh()).toBeEnabled();
        vi.mocked(request).mockRejectedValue(new APIError('PRIVATE RAW ERROR', 503)); fireEvent.click(refresh()); await flush(); await advance(180000);
        expect(request).toHaveBeenCalledTimes(3); expect(panel()).not.toHaveTextContent('PRIVATE RAW ERROR');
        expect(vi.mocked(request).mock.calls.every(([path, options]) => path === '/alerts/status' && options?.method === undefined && options?.body === undefined)).toBe(true);
    });
    it.each(['failure', 'invalid', 'timeout'] as const)('retains last-good counts and original loaded time as previous after %s', async kind => {
        await start(); const original = panel().querySelector('time')!.dateTime; await advance(60000);
        if (kind === 'failure') vi.mocked(request).mockRejectedValueOnce(new Error('private failure'));
        if (kind === 'invalid') vi.mocked(request).mockResolvedValueOnce({ ...populated(), providerAccepted: 'secret-invalid' });
        if (kind === 'timeout') vi.mocked(request).mockReturnValueOnce(new Promise(() => {}));
        fireEvent.click(refresh()); await flush(); if (kind === 'timeout') await advance(10000);
        expect(screen.getByRole('alert')).toBeInTheDocument(); expect(panel()).toHaveTextContent('Previous snapshot'); expect(panel().querySelector('time')).toHaveAttribute('datetime', original);
        expect(panel().querySelector('.alarm-mode')).toHaveTextContent('Unknown'); expect(count('Provider accepted')).toHaveTextContent('7'); expect(panel()).not.toHaveTextContent('secret-invalid');
        vi.mocked(request).mockResolvedValueOnce({ ...populated(), providerAccepted: 8 }); fireEvent.click(refresh()); await flush();
        expect(panel()).not.toHaveTextContent('Previous snapshot'); expect(count('Provider accepted')).toHaveTextContent('8'); expect(panel().querySelector('time')!.dateTime).not.toBe(original);
    });
    it('does not invent zero counts when the initial read fails', async () => {
        vi.mocked(request).mockRejectedValue(new Error('unavailable')); render(<AlarmStatusPanel/>); await flush();
        expect(panel().querySelector('time,dd,.alarm-counts')).toBeNull(); expect(panel().querySelector('.alarm-mode')).toHaveTextContent('Unknown');
    });
    it.each(['pagehide', 'visibility', 'navigation', 'unmount'] as const)('clears and cancels on %s; late replies cannot restore a snapshot', async kind => {
        const mounted = await start(); const held = deferred<AlarmStatus>(); vi.mocked(request).mockReturnValueOnce(held.promise); fireEvent.click(refresh()); const signal = vi.mocked(request).mock.calls[1][1]!.signal!;
        if (kind === 'unmount') mounted.unmount();
        else if (kind === 'visibility') { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); }
        else act(() => window.dispatchEvent(new Event(kind === 'navigation' ? 'hashchange' : 'pagehide')));
        expect(signal.aborted).toBe(true); await act(async () => held.resolve(populated())); expect(document.querySelector('.alarm-counts')).toBeNull();
        if (kind === 'pagehide' || kind === 'visibility') {
            vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible'); act(() => window.dispatchEvent(new Event('pageshow'))); await advance(30000);
            expect(request).toHaveBeenCalledTimes(2); fireEvent.click(refresh()); await flush(); expect(request).toHaveBeenCalledTimes(3); expect(count('Provider accepted')).toHaveTextContent('7');
        }
    });
    it.each(['event', 'epoch', 'storage', 'logout', '401', '403'] as const)('clears history and refuses more reads after %s access loss', async kind => {
        await start(); const held = deferred<AlarmStatus>();
        if (kind === '401' || kind === '403') vi.mocked(request).mockRejectedValueOnce(new APIError('private auth error', Number(kind)));
        else vi.mocked(request).mockReturnValueOnce(held.promise);
        fireEvent.click(refresh()); const signal = vi.mocked(request).mock.calls[1][1]!.signal!;
        act(() => {
            if (kind === 'event') window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT));
            if (kind === 'epoch') abortProtectedRequests();
            if (kind === 'storage' || kind === 'logout') { localStorage.setItem(LOGOUT_INTENT_KEY, '1'); if (kind === 'storage') window.dispatchEvent(new StorageEvent('storage', { key: LOGOUT_INTENT_KEY, newValue: '1' })); }
        });
        await advance(1000); await act(async () => held.resolve(populated()));
        expect(signal.aborted).toBe(true); expect(panel().querySelector('time,dd')).toBeNull(); expect(refresh()).toBeDisabled();
        fireEvent.click(refresh()); await advance(30000); expect(request).toHaveBeenCalledTimes(2);
    });
    it('allows explicit refresh after hash navigation that keeps Settings mounted', async () => {
        await start(); act(() => window.dispatchEvent(new Event('hashchange'))); expect(panel().querySelector('.alarm-counts')).toBeNull();
        fireEvent.click(refresh()); await flush(); expect(request).toHaveBeenCalledTimes(2); expect(count('Provider accepted')).toHaveTextContent('7');
    });
    it('rejects a response after a browser clock discontinuity without rewriting the snapshot time', async () => {
        await start(); const original = panel().querySelector('time')!.dateTime; const held = deferred<AlarmStatus>(); vi.mocked(request).mockReturnValueOnce(held.promise); fireEvent.click(refresh());
        vi.setSystemTime('2026-10-06T15:00:00Z'); await act(async () => held.resolve({ ...populated(), providerAccepted: 99 }));
        expect(screen.getByRole('alert')).toHaveTextContent('did not respond in time'); expect(count('Provider accepted')).toHaveTextContent(/^7$/); expect(panel().querySelector('time')).toHaveAttribute('datetime', original);
    });
    it('does not accept a late timed-out reply over a newer manually loaded snapshot', async () => {
        await start(); const held = deferred<AlarmStatus>(); vi.mocked(request).mockReturnValueOnce(held.promise); fireEvent.click(refresh()); await advance(10000);
        vi.mocked(request).mockResolvedValueOnce({ ...populated(), providerAccepted: 13 }); fireEvent.click(refresh()); await flush();
        await act(async () => held.resolve({ ...populated(), providerAccepted: 99 })); expect(count('Provider accepted')).toHaveTextContent(/^13$/);
    });
    it('rekeys on a different authenticated session and cancels its old read', async () => {
        const mounted = await start(); const held = deferred<AlarmStatus>(); vi.mocked(request).mockReturnValueOnce(held.promise); fireEvent.click(refresh()); const signal = vi.mocked(request).mock.calls[1][1]!.signal!;
        vi.mocked(useOperator).mockReturnValue({ ...operator, expiresAt: '2026-10-06T15:00:00Z' }); vi.mocked(request).mockResolvedValueOnce(empty()); mounted.rerender(<AlarmStatusPanel/>); await flush();
        expect(signal.aborted).toBe(true); await act(async () => held.resolve(populated())); expect(panel().querySelector('.alarm-counts')).toBeNull(); expect(panel().querySelector('.alarm-mode')).toHaveTextContent('Off');
    });
    it('rejects an oversized actual GET body without rendering any private error or fields', async () => {
        const real = await vi.importActual<typeof import('./api')>('./api'); vi.mocked(request).mockImplementation(real.request);
        const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ ...populated(), private: 'PRIVATE'.repeat(1000) }), { status: 200 })); vi.stubGlobal('fetch', fetch);
        render(<AlarmStatusPanel/>); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('could not be confirmed');
        expect(panel().querySelector('.alarm-counts')).toBeNull(); expect(panel()).not.toHaveTextContent('PRIVATE'); expect(fetch).toHaveBeenCalledTimes(1);
    });
    it('uses the real same-origin bounded GET wrapper without credentials or mutation requests', async () => {
        const real = await vi.importActual<typeof import('./api')>('./api'); vi.mocked(request).mockImplementation(real.request);
        const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(populated()), { status: 200, headers: { 'Content-Type': 'application/json' } })); vi.stubGlobal('fetch', fetch);
        render(<AlarmStatusPanel/>); await flush(); expect(count('Provider accepted')).toHaveTextContent('7');
        expect(fetch).toHaveBeenCalledExactlyOnceWith('/api/alerts/status', expect.objectContaining({ credentials: 'same-origin', cache: 'no-store', signal: expect.any(AbortSignal), headers: { Accept: 'application/json' } }));
        expect(fetch.mock.calls[0][1]).not.toHaveProperty('body'); expect(fetch.mock.calls[0][1]).not.toHaveProperty('method');
    });
});
