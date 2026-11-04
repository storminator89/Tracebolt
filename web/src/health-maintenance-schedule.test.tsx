import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, AUTH_REQUIRED_EVENT, abortProtectedRequests, mutate, request } from './api';
import { setLocale } from './i18n';
import { HealthMaintenanceSchedule } from './health-maintenance-schedule';
import { canRetainMaintenanceRequest } from './health-maintenance-schedule-resource';
import { maintenanceConfirmed, maintenanceDraft, maintenanceUTC, validMaintenanceSchedule } from './health-maintenance-schedule-types';
import type { MaintenanceRequest, MaintenanceScheduleView, MaintenanceWindow } from './health-maintenance-schedule-types';
import goFixture from './health-maintenance-schedule-go-fixture.json';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
const id = 'agent_schedule_fixture', at = '2026-11-04T12:00:00Z', session = '2026-11-04T13:00:00Z', windowId = `maintenance_${'1'.repeat(32)}`;
const initial = (deviceId = id): MaintenanceScheduleView => ({ schemaVersion: 'tracebolt.linux-maintenance-schedule-view.v1', deviceId, serverNow: at, revision: '0', canManage: true, remainingSlots: 64, legacyMaintenanceUntil: null, window: null, lastRequest: null });
function saved(state: MaintenanceWindow['state'] = 'pending'): MaintenanceScheduleView {
    const value = initial();
    value.revision = state === 'canceled' || state === 'ended' ? '2' : '1'; value.remainingSlots = 63;
    value.window = { id: windowId, createdAt: at, startsAt: '2026-11-04T12:05:00Z', endsAt: '2026-11-04T13:05:00Z', state, closedAt: null };
    value.lastRequest = { requestId: windowId, action: 'schedule', windowId };
    if (state === 'active' || state === 'ended') value.serverNow = '2026-11-04T12:10:00Z';
    if (state === 'expired') { value.serverNow = '2026-11-04T13:10:00Z'; value.window.closedAt = value.window.endsAt; }
    if (state === 'canceled' || state === 'ended') { value.window.closedAt = value.serverNow; value.lastRequest = { requestId: `maintenance_${'2'.repeat(32)}`, action: state === 'canceled' ? 'cancel' : 'end', windowId }; }
    return value;
}
function result(body: MaintenanceRequest, base = initial()): MaintenanceScheduleView {
    const value = structuredClone(base); value.revision = (BigInt(body.expectedRevision) + 1n).toString();
    value.lastRequest = { requestId: body.requestId, action: body.action, windowId: body.windowId };
    if (body.action === 'schedule') { value.remainingSlots--; value.window = { id: body.windowId, createdAt: value.serverNow, startsAt: body.startsAt!, endsAt: body.endsAt!, state: 'pending', closedAt: null }; }
    else { value.window!.state = body.action === 'cancel' ? 'canceled' : 'ended'; value.window!.closedAt = value.serverNow; }
    return value;
}
function deferred<T>() { let resolve!: (v: T) => void; const promise = new Promise<T>(r => { resolve = r; }); return { promise, resolve }; }
const draw = (props: Partial<Parameters<typeof HealthMaintenanceSchedule>[0]> = {}) => render(<HealthMaintenanceSchedule deviceId={id} sessionKey={session} enabled onChanged={vi.fn()} {...props}/>);
async function open() { fireEvent.click(screen.getByRole('button', { name: 'Plan a one-time maintenance window' })); await screen.findByText('No saved maintenance window.'); }
async function review() {
    fireEvent.change(screen.getByLabelText('Start (UTC)'), { target: { value: '2026-11-04T12:05' } });
    fireEvent.click(screen.getByRole('button', { name: 'Review fixed window' }));
    await screen.findByRole('heading', { name: 'Review exact maintenance change' });
}
function approve() { fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Save this one-time window' })); }
beforeEach(() => { abortProtectedRequests(); localStorage.clear(); sessionStorage.clear(); setLocale('en', false); vi.mocked(request).mockReset().mockResolvedValue(initial()); vi.mocked(mutate).mockReset().mockImplementation(async (_path, body) => result(body as MaintenanceRequest)); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('closed Linux maintenance schedule metadata', () => {
    it('bounds all retained requests across different keys without losing outcomes on transfer', () => {
        const body: MaintenanceRequest = { requestId: windowId, expectedRevision: '0', action: 'schedule', windowId, startsAt: '2026-11-04T12:05:00Z', endsAt: '2026-11-04T13:05:00Z' };
        const pending = new Map<string, MaintenanceRequest>([['live', body]]), history = new Map<string, MaintenanceRequest[]>();
        for (let index = 0; index < 126; index++) history.set(`other-device-session-${index}`, [body]);
        expect(canRetainMaintenanceRequest(pending, history)).toBe(true); history.set('another-key', [body]); expect(canRetainMaintenanceRequest(pending, history)).toBe(false);
        pending.delete('live'); history.set('verified-later-revision', [body]); expect(canRetainMaintenanceRequest(pending, history)).toBe(false); expect(history.size).toBe(128); expect(history.get('verified-later-revision')).toEqual([body]);
    });
    it('accepts the exact JSON emitted by the real TLS Go API fixture', () => { expect(validMaintenanceSchedule(goFixture, goFixture.deviceId)).toBe(true); expect(goFixture.window.startsAt).toBe('2026-11-04T14:32:56Z'); });
    it('accepts empty, pending, active and all terminal receipts, including full capacity', () => {
        expect(validMaintenanceSchedule(initial(), id)).toBe(true);
        for (const state of ['pending', 'active', 'canceled', 'ended', 'expired'] as const) { const value = saved(state); expect(validMaintenanceSchedule(value, id), state).toBe(true); value.remainingSlots = 0; expect(validMaintenanceSchedule(value, id)).toBe(true); }
    });
    it.each([
        (v: MaintenanceScheduleView) => { v.deviceId = 'agent_other'; },
        (v: MaintenanceScheduleView) => { v.revision = '01'; },
        (v: MaintenanceScheduleView) => { v.revision = '18446744073709551616'; },
        (v: MaintenanceScheduleView) => { v.remainingSlots = 65; },
        (v: MaintenanceScheduleView) => { v.remainingSlots = 1.5; },
        (v: MaintenanceScheduleView) => { v.remainingSlots = 64; },
        (v: MaintenanceScheduleView) => { v.window!.startsAt = '2026-11-04T12:05:00+00:00'; },
        (v: MaintenanceScheduleView) => { v.window!.startsAt = '2026-02-30T12:05:00Z'; },
        (v: MaintenanceScheduleView) => { v.window!.endsAt = '2026-11-04T12:06:00Z'; },
        (v: MaintenanceScheduleView) => { v.window!.state = 'active'; },
        (v: MaintenanceScheduleView) => { v.window!.closedAt = at; },
        (v: MaintenanceScheduleView) => { v.lastRequest!.windowId = `maintenance_${'3'.repeat(32)}`; },
        (v: MaintenanceScheduleView) => { v.legacyMaintenanceUntil = at; },
        (v: MaintenanceScheduleView) => { Object.assign(v, { telemetry: [] }); },
        (v: MaintenanceScheduleView) => { Object.assign(v.window!, { actor: 'unknown' }); },
    ])('rejects malformed, extended or contradictory projection %#', change => { const value = saved(); change(value); expect(validMaintenanceSchedule(value, id)).toBe(false); });
    it('treats the datetime input as UTC and rejects normalized dates and unsupported windows', () => {
        expect(maintenanceUTC('2026-11-04T12:05')).toBe('2026-11-04T12:05:00Z');
        for (const input of ['2026-02-30T12:05', '2026-11-04T25:00', '2026-11-04 12:05', '2026-11-04T12:05Z']) expect(maintenanceUTC(input)).toBeNull();
        expect(maintenanceDraft('2026-11-04T12:05', 240, Date.parse(at))).toEqual({ startsAt: '2026-11-04T12:05:00Z', endsAt: '2026-11-04T16:05:00Z' });
        for (const args of [['2026-11-04T12:00', 15], ['2026-11-12T12:00', 60], ['2026-11-04T12:05', 30]] as const) expect(maintenanceDraft(args[0], args[1], Date.parse(at))).toBeNull();
    });
    it('confirms only exact original creation bounds or the exact last-command receipt', () => {
        const body: MaintenanceRequest = { requestId: windowId, expectedRevision: '0', action: 'schedule', windowId, startsAt: '2026-11-04T12:05:00Z', endsAt: '2026-11-04T13:05:00Z' };
        expect(maintenanceConfirmed(result(body), body)).toBe(true);
        for (const value of [{ ...result(body), lastRequest: null }, { ...result(body), window: { ...result(body).window!, endsAt: '2026-11-04T16:05:00Z' } }]) expect(maintenanceConfirmed(value, body)).toBe(false);
        const later = result(body); later.revision = '2'; later.window!.state = 'canceled'; later.window!.closedAt = at; later.lastRequest = { requestId: `maintenance_${'2'.repeat(32)}`, action: 'cancel', windowId: body.windowId }; expect(maintenanceConfirmed(later, body)).toBe(true);
    });
});

describe('one-time maintenance review and reconciliation', () => {
    it('reads only on deliberate open and requires an unchecked exact UTC review before one write', async () => {
        const changed = vi.fn(); draw({ onChanged: changed }); expect(request).not.toHaveBeenCalled();
        await open(); expect(request).toHaveBeenCalledWith(`/devices/${id}/health/maintenance-schedule`, expect.objectContaining({ signal: expect.any(AbortSignal) }), 8192);
        await review(); expect(screen.getByRole('checkbox')).not.toBeChecked(); const save = screen.getByRole('button', { name: 'Save this one-time window' }); expect(save).toBeDisabled(); expect(mutate).not.toHaveBeenCalled();
        expect(screen.getByText(id)).toBeVisible(); expect(screen.getByText('2026-11-04 12:05:00 UTC')).toBeVisible();
        fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(save); fireEvent.click(save);
        await screen.findByText('The manager confirmed this exact change.'); expect(mutate).toHaveBeenCalledOnce(); expect(changed).toHaveBeenCalledOnce();
        const body = vi.mocked(mutate).mock.calls[0][1] as MaintenanceRequest;
        expect(body).toEqual({ requestId: expect.stringMatching(/^maintenance_[0-9a-f]{32}$/), expectedRevision: '0', action: 'schedule', windowId: body.requestId, startsAt: '2026-11-04T12:05:00Z', endsAt: '2026-11-04T13:05:00Z' });
        expect(vi.mocked(mutate).mock.calls[0][0]).toBe(`/devices/${id}/health/maintenance-schedule`);
    });
    it.each(['pending', 'active'] as const)('reviews the exact %s window before cancel or early end', async state => {
        const base = saved(state); vi.mocked(request).mockResolvedValue(base); vi.mocked(mutate).mockImplementation(async (_path, body) => result(body as MaintenanceRequest, base)); draw(); fireEvent.click(screen.getByRole('button', { name: 'Plan a one-time maintenance window' }));
        fireEvent.click(await screen.findByRole('button', { name: state === 'pending' ? 'Review cancellation' : 'Review early end' })); await act(async () => {}); expect(screen.getByRole('checkbox')).not.toBeChecked(); fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: state === 'pending' ? 'Cancel this exact schedule' : 'End this exact window now' }));
        await screen.findByText('The manager confirmed this exact change.'); const body = vi.mocked(mutate).mock.calls[0][1] as MaintenanceRequest;
        expect(body).toMatchObject({ action: state === 'pending' ? 'cancel' : 'end', windowId, startsAt: null, endsAt: null, expectedRevision: '1' }); expect(mutate).toHaveBeenCalledOnce();
    });
    it.each(['read-only', 'capacity', 'legacy'])('does not offer a new window for %s metadata', async mode => {
        const base = mode === 'capacity' ? saved('canceled') : initial(); if (mode === 'read-only') base.canManage = false; if (mode === 'capacity') base.remainingSlots = 0; if (mode === 'legacy') base.legacyMaintenanceUntil = '2026-11-04T12:15:00Z'; vi.mocked(request).mockResolvedValue(base);
        draw(); fireEvent.click(screen.getByRole('button', { name: 'Plan a one-time maintenance window' })); await screen.findByText(/Saved state read at/); expect(screen.queryByLabelText('Start (UTC)')).not.toBeInTheDocument(); expect(mutate).not.toHaveBeenCalled();
        expect(document.body).toHaveTextContent(mode === 'read-only' ? 'Read-only access' : mode === 'capacity' ? 'All 64 lifetime window slots' : 'Immediate maintenance is active');
    });
    it('keeps a lost response uncertain through close/reopen and resolves only the exact saved command', async () => {
        vi.mocked(mutate).mockRejectedValue(new APIError('lost', 503)); draw(); await open(); await review(); approve();
        await screen.findByText(/Change unconfirmed/); const body = vi.mocked(mutate).mock.calls[0][1] as MaintenanceRequest;
        fireEvent.click(screen.getByRole('button', { name: 'Close scheduled maintenance' })); fireEvent.click(screen.getByRole('button', { name: 'Plan a one-time maintenance window' })); await screen.findByText(/saved state does not confirm/); expect(screen.queryByLabelText('Start (UTC)')).not.toBeInTheDocument(); expect(mutate).toHaveBeenCalledOnce();
        vi.mocked(request).mockResolvedValue(result(body)); fireEvent.click(screen.getByRole('button', { name: 'Read saved schedule' })); await screen.findByText('The manager confirmed this exact change.'); expect(screen.queryByText(/Change unconfirmed/)).not.toBeInTheDocument(); expect(mutate).toHaveBeenCalledOnce();
    });
    it('requires a fresh read and review after a definite precommit conflict', async () => {
        vi.mocked(mutate).mockRejectedValue(new APIError('conflict', 409)); draw(); await open(); await review(); approve(); await screen.findByText(/schedule unavailable/); expect(screen.queryByText(/Change unconfirmed/)).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Read saved schedule' })); await screen.findByLabelText('Start (UTC)'); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); expect(mutate).toHaveBeenCalledOnce();
    });
    it('retains only the uncertain command through an actual parent unmount and same-session remount', async () => {
        vi.mocked(mutate).mockRejectedValue(new APIError('lost', 503)); const first = draw(); await open(); await review(); approve(); await screen.findByText(/Change unconfirmed/); const body = vi.mocked(mutate).mock.calls[0][1] as MaintenanceRequest; first.unmount();
        draw(); await open(); expect(screen.getByText(body.requestId)).toBeVisible(); expect(screen.queryByLabelText('Start (UTC)')).not.toBeInTheDocument(); expect(mutate).toHaveBeenCalledOnce();
    });
    it('keeps the unknown old outcome explicit while permitting a distinct review only after a verified later revision', async () => {
        vi.mocked(mutate).mockRejectedValue(new APIError('lost', 503)); draw(); await open(); await review(); approve(); await screen.findByText(/Change unconfirmed/); const original = vi.mocked(mutate).mock.calls[0][1] as MaintenanceRequest;
        const later = saved('canceled'); vi.mocked(request).mockResolvedValue(later); fireEvent.click(screen.getByRole('button', { name: 'Read saved schedule' })); await screen.findByLabelText('Start (UTC)'); expect(screen.getByText(/earlier change outcome remains unconfirmed/)).toBeVisible(); expect(screen.queryByText('The manager confirmed this exact change.')).not.toBeInTheDocument();
        // A new timestamp cannot revive a superseded lower revision, even after close.
        fireEvent.click(screen.getByRole('button', { name: 'Close scheduled maintenance' })); vi.mocked(request).mockResolvedValue({ ...initial(), serverNow: '2026-11-04T12:00:01Z' }); fireEvent.click(screen.getByRole('button', { name: 'Plan a one-time maintenance window' })); await screen.findByText(/schedule unavailable/); expect(screen.queryByLabelText('Start (UTC)')).not.toBeInTheDocument();
        vi.mocked(request).mockResolvedValue(later); fireEvent.click(screen.getByRole('button', { name: 'Read saved schedule' })); await screen.findByLabelText('Start (UTC)'); await review(); vi.mocked(mutate).mockImplementation(async (_path, body) => result(body as MaintenanceRequest, later)); approve(); await screen.findByText('The manager confirmed this exact change.');
        const next = vi.mocked(mutate).mock.calls[1][1] as MaintenanceRequest; expect(next.requestId).not.toBe(original.requestId); expect(next.expectedRevision).toBe('2'); expect(screen.getByText(/earlier change outcome remains unconfirmed/)).toBeVisible(); expect(mutate).toHaveBeenCalledTimes(2);
    });
    it('discards a review on refresh and never keeps its consent', async () => {
        draw(); await open(); await review(); fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Read saved schedule' })); await screen.findByLabelText('Start (UTC)'); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); expect(mutate).not.toHaveBeenCalled();
    });
    it('localizes the schedule and consent in German without changing exact UTC bytes', async () => {
        setLocale('de', false); draw(); fireEvent.click(screen.getByRole('button', { name: 'Einmaliges Wartungsfenster planen' })); await screen.findByLabelText('Beginn (UTC)'); fireEvent.change(screen.getByLabelText('Beginn (UTC)'), { target: { value: '2026-11-04T12:05' } }); fireEvent.click(screen.getByRole('button', { name: 'Festes Fenster prüfen' })); expect(screen.getByRole('checkbox')).toHaveAccessibleName(/genau dieses Gerät/); expect(screen.getByText('2026-11-04 12:05:00 UTC')).toBeVisible();
    });
});

describe('schedule read and write lifecycle isolation', () => {
    it.each(['blur', 'pagehide', 'hashchange', 'popstate', AUTH_REQUIRED_EVENT])('aborts a delayed read and ignores its answer after %s', async event => {
        const pending = deferred<MaintenanceScheduleView>(); vi.mocked(request).mockReturnValue(pending.promise); draw(); fireEvent.click(screen.getByRole('button', { name: 'Plan a one-time maintenance window' })); const signal = vi.mocked(request).mock.calls[0][1]!.signal as AbortSignal;
        act(() => window.dispatchEvent(new Event(event))); expect(signal.aborted).toBe(true); await act(async () => pending.resolve(saved())); expect(screen.queryByText('Scheduled · not active at this read')).not.toBeInTheDocument(); expect(mutate).not.toHaveBeenCalled();
    });
    it('clears an in-flight mutation on close, retains uncertainty, and never retries it on reopen', async () => {
        const pending = deferred<MaintenanceScheduleView>(); vi.mocked(mutate).mockReturnValue(pending.promise); draw(); await open(); await review(); approve(); const body = vi.mocked(mutate).mock.calls[0][1] as MaintenanceRequest, signal = vi.mocked(mutate).mock.calls[0][2]!;
        fireEvent.click(screen.getByRole('button', { name: 'Close scheduled maintenance' })); expect(signal.aborted).toBe(true); await act(async () => pending.resolve(result(body))); fireEvent.click(screen.getByRole('button', { name: 'Plan a one-time maintenance window' })); await screen.findByText(/saved state does not confirm/); expect(mutate).toHaveBeenCalledOnce();
    });
    it('does not publish an old device response after replacement', async () => {
        const pending = deferred<MaintenanceScheduleView>(); vi.mocked(request).mockReturnValueOnce(pending.promise); const rendered = draw(); fireEvent.click(screen.getByRole('button', { name: 'Plan a one-time maintenance window' })); rendered.rerender(<HealthMaintenanceSchedule deviceId="agent_other" sessionKey={session} enabled onChanged={vi.fn()}/>); await act(async () => pending.resolve(saved())); expect(screen.queryByText(windowId)).not.toBeInTheDocument(); expect(mutate).not.toHaveBeenCalled();
    });
    it('expires the bounded snapshot without polling or pretending a pending window started', async () => {
        vi.useFakeTimers(); vi.mocked(request).mockResolvedValue(saved()); draw(); fireEvent.click(screen.getByRole('button', { name: 'Plan a one-time maintenance window' })); await act(async () => {}); expect(screen.getByText('Scheduled · not active at this read')).toBeVisible();
        act(() => vi.advanceTimersByTime(60001)); expect(screen.queryByText('Scheduled · not active at this read')).not.toBeInTheDocument(); expect(screen.getByText(/snapshot expired/)).toBeVisible(); expect(request).toHaveBeenCalledOnce(); expect(mutate).not.toHaveBeenCalled();
    });
    it('does not restore a snapshot from a cumulatively stalled manager clock', async () => {
        vi.useFakeTimers(); draw(); fireEvent.click(screen.getByRole('button', { name: 'Plan a one-time maintenance window' })); await act(async () => {}); act(() => vi.advanceTimersByTime(2000)); fireEvent.click(screen.getByRole('button', { name: 'Read saved schedule' })); await act(async () => {}); expect(screen.queryByLabelText('Start (UTC)')).not.toBeInTheDocument(); expect(screen.getByText(/schedule unavailable/)).toBeVisible(); expect(mutate).not.toHaveBeenCalled();
    });
    it('removes review and consent on a wall-clock jump instead of using local time as manager time', async () => {
        vi.useFakeTimers(); draw(); fireEvent.click(screen.getByRole('button', { name: 'Plan a one-time maintenance window' })); await act(async () => {}); fireEvent.change(screen.getByLabelText('Start (UTC)'), { target: { value: '2026-11-04T12:05' } }); fireEvent.click(screen.getByRole('button', { name: 'Review fixed window' })); fireEvent.click(screen.getByRole('checkbox'));
        vi.setSystemTime(Date.now() + 30000); act(() => vi.advanceTimersByTime(251)); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); expect(screen.getByText(/Time reference changed/)).toBeVisible(); expect(mutate).not.toHaveBeenCalled();
    });
    it('expires at the original session deadline and does not publish a late answer', async () => {
        vi.useFakeTimers(); draw({ sessionKey: '2026-11-04T12:00:02Z' }); fireEvent.click(screen.getByRole('button', { name: 'Plan a one-time maintenance window' })); await act(async () => {}); expect(screen.getByLabelText('Start (UTC)')).toBeVisible(); act(() => vi.advanceTimersByTime(2001)); expect(screen.queryByLabelText('Start (UTC)')).not.toBeInTheDocument(); expect(request).toHaveBeenCalledOnce(); expect(mutate).not.toHaveBeenCalled();
    });
    it('times out a write as uncertain, aborts it, and ignores its late success', async () => {
        vi.useFakeTimers(); draw(); fireEvent.click(screen.getByRole('button', { name: 'Plan a one-time maintenance window' })); await act(async () => {}); fireEvent.change(screen.getByLabelText('Start (UTC)'), { target: { value: '2026-11-04T12:05' } }); fireEvent.click(screen.getByRole('button', { name: 'Review fixed window' }));
        const pending = deferred<MaintenanceScheduleView>(); vi.mocked(mutate).mockReturnValue(pending.promise); approve(); const body = vi.mocked(mutate).mock.calls[0][1] as MaintenanceRequest, signal = vi.mocked(mutate).mock.calls[0][2]!;
        act(() => vi.advanceTimersByTime(15001)); expect(signal.aborted).toBe(true); expect(screen.getByText(/Change unconfirmed/)).toBeVisible(); await act(async () => pending.resolve(result(body))); expect(screen.queryByText('The manager confirmed this exact change.')).not.toBeInTheDocument(); expect(mutate).toHaveBeenCalledOnce();
    });
});
