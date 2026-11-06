import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { request, mutateRaw, AUTH_REQUIRED_EVENT } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { useWindowsInventory } from './windows-inventory-resource';
import { windowsUpdatesView } from './windows-updates-fixture';
import { WindowsFleetUpdateWorklist } from './windows-fleet-update-worklist';
import { planFleetUpdateWindows } from './windows-fleet-update-window-plan';
import type { Device } from './types';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
vi.mock('./windows-inventory-resource', () => ({ useWindowsInventory: vi.fn() }));
const now = '2026-10-11T10:00:00Z', until = '2026-10-11T11:00:00Z', seconds = Date.parse(now) / 1000;
const devices = Array.from({ length: 3 }, (_, i) => ({ id: `agent_${String(i + 1).repeat(32)}`, name: `Workstation ${i + 1}`, platform: 'windows', source: 'lan', synthetic: false } as Device));
const ids = devices.map(device => device.id), window = { startAt: seconds + 120, endAt: seconds + 420 };
const selection = { updateId: '11111111-2222-3333-4444-555555555555', revision: 3 }, digest = `sha256:${'3'.repeat(64)}`;
let session: { mode: string; transport: string; insecureTestMode: boolean; transportWarning: null; authenticationRequired: boolean; authenticated: boolean; csrfToken: string; serverNow: string; expiresAt: string; expiresInSeconds: number; loginMode: string; actorId: string; capabilities: string[] };
const base = (deviceId: string) => ({ version: 'tracebolt.windows-selected-update-job.v1', deviceId, serverNow: seconds, available: true, reason: 'ready', schedulingAvailable: true, job: null });
const flush = () => act(async () => {});
const saved = new Map<string, unknown>();
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime(now); setLocale('en', false); saved.clear();
    session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'csrf', serverNow: now, expiresAt: until, expiresInSeconds: 3600, loginMode: 'named', actorId: `operator_${crypto.randomUUID().replaceAll('-', '')}`, capabilities: ['read', 'windows_update_install', 'windows_update_schedule'] };
    vi.mocked(useOperator).mockReturnValue({ ...session, theme: 'light', logout: vi.fn(), setTheme: vi.fn() } as never);
    vi.mocked(useWindowsInventory).mockReturnValue({ loading: false, updates: { rows: [{ ...selection, title: 'Exact cached revision' }] } } as never);
    vi.mocked(request).mockReset().mockImplementation(async path => structuredClone(path === '/auth/session' ? session : saved.get(path.split('/')[2]) ?? base(path.split('/')[2])) as never);
    vi.mocked(mutateRaw).mockReset().mockImplementation(async (path, raw, _headers, _signal, _cap, beforeSend) => {
        if (beforeSend && !beforeSend()) throw new Error('Canceled before send');
        const body = JSON.parse(raw), deviceId = path.split('/')[2];
        if (path.endsWith('/request')) return { ...base(deviceId), job: { id: body.requestId, selection, state: 'preview', reason: 'ready', result: null, preview: { id: body.requestId, actorId: session.actorId, binding: { managerId: `manager_${'4'.repeat(32)}`, deviceId, incarnationDigest: digest, executorId: `executor_${'5'.repeat(32)}`, executorKeyId: `sha256:${'8'.repeat(64)}`, grantId: `grant_${'6'.repeat(32)}`, keyId: digest }, readiness: { selection, capturedAt: seconds, software: 'yes', installed: 'no', hidden: 'no', downloaded: 'yes', eulaAccepted: 'yes', canRequestUserInput: 'no', canRequireSource: 'no', requiresNetwork: 'no', bundledCount: 0, installerBusy: 'no', rebootRequiredBefore: 'no', rebootBehavior: 'can', offlineVerified: 'yes' }, createdAt: seconds, expiresAt: seconds + 60, digest } } } as never;
        const value = { ...base(deviceId), available: false, reason: 'job_pending_or_intervention', job: { id: body.previewId, selection, state: 'scheduled', reason: 'schedule_waiting', preview: null, result: null, schedule: { version: 'tracebolt.windows-selected-update-schedule.v1', digest, approvedAt: seconds, startAt: body.startAt, endAt: body.endAt, permitIssuedAt: 0, revoked: false } } };
        saved.set(deviceId, value); return value as never;
    });
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });
const labels = (de = false) => ({ title: de ? 'Windows-Updatearbeitsliste' : 'Windows update worklist', scheduled: de ? 'Ein gemeinsames UTC-Zeitfenster verwenden' : 'Use one shared UTC window', start: de ? 'Gemeinsamer Beginn (UTC)' : 'Shared start (UTC)', end: de ? 'Gemeinsames Ende (UTC)' : 'Shared end (UTC)', stagger: de ? 'Geräte auf aufeinanderfolgende UTC-Zeitfenster verteilen' : 'Spread devices across successive UTC windows', size: de ? 'Geräte je Zeitfenster' : 'Devices per window', gap: de ? 'Abstand nach jedem Zeitfenster (Minuten)' : 'Gap after each window (minutes)', freeze: de ? 'Geräteauswahl festhalten' : 'Freeze device selection', preview: de ? 'Geplante Gerätezeitfenster prüfen' : 'Review planned device windows', frozen: de ? 'Festgehaltene Gerätezeitfenster' : 'Frozen device windows' });
function plan(de = false) {
    const c = labels(de); fireEvent.click(screen.getByRole('button', { name: c.title }));
    for (const device of devices) fireEvent.click(screen.getByRole('checkbox', { name: new RegExp(device.name) }));
    fireEvent.click(screen.getByRole('checkbox', { name: c.scheduled }));
    fireEvent.change(screen.getByLabelText(c.start), { target: { value: '2026-10-11T10:02' } }); fireEvent.change(screen.getByLabelText(c.end), { target: { value: '2026-10-11T10:07' } });
    fireEvent.click(screen.getByRole('checkbox', { name: c.stagger })); return c;
}
async function review(device: Device, de = false) {
    fireEvent.click(screen.getByRole('button', { name: `${de ? 'Gerät öffnen' : 'Open device'}: ${device.name}` })); await flush();
    fireEvent.change(screen.getByRole('combobox'), { target: { value: `${selection.updateId}:${selection.revision}` } }); fireEvent.click(screen.getByRole('button', { name: de ? 'Bereitschaft prüfen' : 'Check readiness' })); await flush();
}
it('plans deterministic bounded windows in frozen selection order without modifying inputs', () => {
    const input = [...ids], before = [...ids]; const value = planFleetUpdateWindows(input, window, '2', '5', seconds)!;
    expect(value.waveCount).toBe(2); expect(value.entries.map(entry => [entry.deviceId, entry.wave, entry.window])).toEqual([[ids[0], 1, window], [ids[1], 1, window], [ids[2], 2, { startAt: seconds + 720, endAt: seconds + 1020 }]]);
    expect(input).toEqual(before); expect(window).toEqual({ startAt: seconds + 120, endAt: seconds + 420 });
    expect(Object.isFrozen(value)).toBe(true); expect(Object.isFrozen(value.entries)).toBe(true); expect(value.entries.every(entry => Object.isFrozen(entry) && Object.isFrozen(entry.window))).toBe(true);
});
it('uses absolute UTC windows across midnight and daylight saving boundaries', () => {
    const startAt = Date.parse('2026-10-25T00:55:00Z') / 1000, result = planFleetUpdateWindows(ids, { startAt, endAt: startAt + 300 }, '1', '0', startAt - 60)!;
    expect(result.entries.map(entry => new Date(entry.window.startAt * 1000).toISOString())).toEqual(['2026-10-25T00:55:00.000Z', '2026-10-25T01:00:00.000Z', '2026-10-25T01:05:00.000Z']);
    const midnight = Date.parse('2026-10-31T23:55:00Z') / 1000, overnight = planFleetUpdateWindows(ids, { startAt: midnight, endAt: midnight + 300 }, '1', '0', midnight - 60)!;
    expect(overnight.entries.map(entry => new Date(entry.window.startAt * 1000).toISOString())).toEqual(['2026-10-31T23:55:00.000Z', '2026-11-01T00:00:00.000Z', '2026-11-01T00:05:00.000Z']);
});
it.each([['0', '5'], ['51', '5'], ['1.5', '5'], ['1', '-1'], ['1', '1441'], ['1', '1.5'], ['NaN', '0'], ['1', ''], ['9007199254740992', '0']])('rejects malformed or out-of-bound wave inputs %s / %s', (size, gap) => {
    expect(planFleetUpdateWindows(ids, window, size, gap, seconds)).toBeNull();
});
it('rejects the whole plan when any target, start or duration is invalid, without clamping', () => {
    expect(planFleetUpdateWindows([], window, '1', '5', seconds)).toBeNull();
    expect(planFleetUpdateWindows(Array.from({ length: 51 }, (_, i) => `agent_${i.toString(16).padStart(32, '0')}`), window, '1', '0', seconds)).toBeNull();
    expect(planFleetUpdateWindows([ids[0], ids[0]], window, '1', '5', seconds)).toBeNull();
    expect(planFleetUpdateWindows(['not-a-device'], window, '1', '5', seconds)).toBeNull();
    expect(planFleetUpdateWindows(ids, null, '1', '5', seconds)).toBeNull();
    expect(planFleetUpdateWindows(ids, { ...window, endAt: window.startAt + 59 }, '1', '5', seconds)).toBeNull();
    expect(planFleetUpdateWindows(ids, { ...window, endAt: window.startAt + 3601 }, '1', '5', seconds)).toBeNull();
    expect(planFleetUpdateWindows(ids, window, '1', '5', window.startAt)).toBeNull();
    expect(planFleetUpdateWindows(ids, window, '1', '5', NaN)).toBeNull();
    const last = { startAt: seconds + 86400, endAt: seconds + 86460 };
    expect(planFleetUpdateWindows([ids[0]], last, '1', '0', seconds)).not.toBeNull();
    expect(planFleetUpdateWindows(ids, last, '1', '0', seconds)).toBeNull();
});
it.each(['en', 'de'] as const)('reviews and freezes waves without requests, then independently approves their exact windows in %s', async locale => {
    const de = locale === 'de'; setLocale(locale, false); render(<WindowsFleetUpdateWorklist devices={devices}/>); const c = plan(de);
    const preview = screen.getByRole('region', { name: c.preview });
    expect(preview).toHaveTextContent('2026-10-11 10:02:00 UTC'); expect(preview).toHaveTextContent('2026-10-11 10:12:00 UTC'); expect(preview).toHaveTextContent('2026-10-11 10:22:00 UTC');
    expect(preview).toHaveTextContent(de ? 'keine Parallelitätsgrenze' : 'not a concurrency limit');
    expect(request).not.toHaveBeenCalled(); expect(mutateRaw).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: c.freeze })); await flush();
    expect(screen.getByRole('region', { name: c.frozen })).toHaveTextContent('2026-10-11 10:22:00 UTC'); expect(screen.queryByLabelText(c.size)).toBeNull();
    for (const [index, device] of devices.entries()) {
        await review(device, de);
        const ack = screen.getByRole('checkbox', { name: de ? /vorausschauend für dieses UTC/ : /prospectively for this UTC/ }), approve = screen.getByRole('button', { name: de ? 'Geplantes Update einmal freigeben' : 'Approve scheduled update once' });
        expect(ack).not.toBeChecked(); expect(approve).toBeDisabled(); expect(screen.queryByLabelText(de ? 'Beginn (UTC)' : 'Start (UTC)')).toBeNull();
        fireEvent.click(ack); fireEvent.click(approve); fireEvent.click(approve); await flush();
        expect(mutateRaw).toHaveBeenCalledTimes((index + 1) * 2);
        const requests = vi.mocked(mutateRaw).mock.calls, requestBody = JSON.parse(requests[index * 2][1]), approval = JSON.parse(requests[index * 2 + 1][1]);
        expect(approval).toEqual({ previewId: requestBody.requestId, previewDigest: digest, acknowledged: true, startAt: seconds + 120 + index * 600, endAt: seconds + 420 + index * 600 });
        expect(requests[index * 2 + 1][0]).toBe(`/devices/${device.id}/windows-update-jobs/schedule`);
        for (const later of devices.slice(index + 1)) expect(vi.mocked(request).mock.calls.some(([path]) => path.includes(later.id))).toBe(false);
    }
});
it('keeps membership and windows fixed after a view reorder and does not compact them when a target disappears', async () => {
    const ui = render(<WindowsFleetUpdateWorklist devices={devices}/>), c = plan();
    fireEvent.change(screen.getByLabelText(c.size), { target: { value: '2' } }); fireEvent.click(screen.getByRole('button', { name: c.freeze }));
    ui.rerender(<WindowsFleetUpdateWorklist devices={[devices[2], devices[0], { ...devices[1], id: `agent_${'4'.repeat(32)}`, name: 'New target' }]}/>);
    const frozen = screen.getByRole('region', { name: c.frozen }); expect(frozen).not.toHaveTextContent('New target'); expect(frozen).toHaveTextContent('Workstation 2');
    expect(screen.getByRole('button', { name: 'Open device: Workstation 2' })).toBeDisabled();
    await review(devices[2]); fireEvent.click(screen.getByRole('checkbox', { name: /prospectively for this UTC/ })); fireEvent.click(screen.getByRole('button', { name: 'Approve scheduled update once' })); await flush();
    expect(JSON.parse(vi.mocked(mutateRaw).mock.calls[1][1])).toMatchObject({ startAt: seconds + 720, endAt: seconds + 1020 });
});
it('keeps a device in its original wave when cache triage selects only that reporting device', async () => {
    const firstPair = { updateId: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', revision: 1 }, original = vi.mocked(request).getMockImplementation()!;
    vi.mocked(request).mockImplementation((path, ...args) => {
        if (!path.endsWith('/windows-inventory')) return original(path, ...args);
        const value = windowsUpdatesView(1); value.deviceId = path.split('/')[2]; value.serverNow = now; value.receivedAt = now; value.snapshot!.collectedAt = now; value.updates.collectedAt = now;
        Object.assign(value.updates.rows[0], value.deviceId === ids[2] ? selection : firstPair);
        return Promise.resolve(value) as never;
    });
    render(<WindowsFleetUpdateWorklist devices={devices}/>); const c = plan(); fireEvent.click(screen.getByRole('button', { name: c.freeze }));
    fireEvent.click(screen.getByRole('button', { name: 'Read cached updates' })); await flush();
    fireEvent.click(screen.getByRole('button', { name: `Review reporting devices: ${selection.updateId} · rev. ${selection.revision}` }));
    expect(screen.queryByRole('button', { name: 'Open device: Workstation 1' })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Open device: Workstation 3' })); await flush();
    fireEvent.click(screen.getByRole('button', { name: 'Check readiness' })); await flush();
    expect(document.querySelector('.windows-update-fixed-window')).toHaveTextContent('2026-10-11 10:22:00 UTC');
    fireEvent.click(screen.getByRole('checkbox', { name: /prospectively for this UTC/ })); fireEvent.click(screen.getByRole('button', { name: 'Approve scheduled update once' })); await flush();
    expect(JSON.parse(vi.mocked(mutateRaw).mock.calls[1][1])).toMatchObject({ startAt: seconds + 1320, endAt: seconds + 1620 });
});
it('blocks an invalid last wave and rechecks current time when freezing', () => {
    render(<WindowsFleetUpdateWorklist devices={devices}/>); const c = plan(), freeze = screen.getByRole('button', { name: c.freeze });
    fireEvent.change(screen.getByLabelText(c.gap), { target: { value: '1440' } }); expect(freeze).toBeDisabled(); expect(screen.getByRole('status')).toHaveTextContent('All window starts');
    fireEvent.change(screen.getByLabelText(c.gap), { target: { value: '5' } }); expect(freeze).toBeEnabled();
    vi.setSystemTime('2026-10-11T10:03:00Z'); fireEvent.click(freeze); expect(screen.queryByRole('region', { name: c.frozen })).toBeNull(); expect(mutateRaw).not.toHaveBeenCalled();
});
it('does not expose planning without the separate scheduling capability', () => {
    vi.mocked(useOperator).mockReturnValue({ ...session, capabilities: ['read', 'windows_update_install'] } as never);
    render(<WindowsFleetUpdateWorklist devices={devices}/>); fireEvent.click(screen.getByRole('button', { name: labels().title })); expect(screen.queryByRole('checkbox', { name: labels().scheduled })).toBeNull(); expect(screen.queryByLabelText(labels().stagger)).toBeNull();
});
it('retains later windows unchanged after an earlier window starts, without dispatching anything', () => {
    render(<WindowsFleetUpdateWorklist devices={devices}/>); const c = plan(); fireEvent.click(screen.getByRole('button', { name: c.freeze }));
    act(() => { vi.setSystemTime('2026-10-11T10:03:00Z'); vi.advanceTimersByTime(1000); });
    const frozen = screen.getByRole('region', { name: c.frozen });
    expect(frozen).toHaveTextContent('This window has started'); expect(frozen).toHaveTextContent('2026-10-11 10:12:00 UTC'); expect(frozen).toHaveTextContent('2026-10-11 10:22:00 UTC');
    expect(request).not.toHaveBeenCalled(); expect(mutateRaw).not.toHaveBeenCalled();
});
it('keeps a revoked device schedule read-only and never falls back to immediate approval', async () => {
    render(<WindowsFleetUpdateWorklist devices={devices}/>); const c = plan(); fireEvent.click(screen.getByRole('button', { name: c.freeze }));
    vi.mocked(request).mockImplementation(async path => structuredClone(path === '/auth/session' ? session : { ...base(path.split('/')[2]), schedulingAvailable: false, schedulingRevoked: true }) as never);
    fireEvent.click(screen.getByRole('button', { name: 'Open device: Workstation 2' })); await flush();
    expect(screen.getByText('Scheduling is unavailable for this device or operator. Saved jobs remain readable.')).toBeVisible();
    expect(screen.queryByRole('combobox')).toBeNull(); expect(screen.queryByRole('button', { name: 'Approve this update once' })).toBeNull(); expect(mutateRaw).not.toHaveBeenCalled();
});
it('removes approval when the operator loses scheduling capability after freezing', async () => {
    const ui = render(<WindowsFleetUpdateWorklist devices={devices}/>), c = plan(); fireEvent.click(screen.getByRole('button', { name: c.freeze }));
    session.capabilities = ['read', 'windows_update_install']; vi.mocked(useOperator).mockReturnValue({ ...session } as never); ui.rerender(<WindowsFleetUpdateWorklist devices={devices}/>);
    fireEvent.click(screen.getByRole('button', { name: 'Open device: Workstation 1' })); await flush();
    fireEvent.change(screen.getByRole('combobox'), { target: { value: `${selection.updateId}:${selection.revision}` } }); fireEvent.click(screen.getByRole('button', { name: 'Check readiness' })); await flush();
    expect(screen.getByRole('alert')).toHaveTextContent('Update job unavailable or changed. Read saved status.'); expect(screen.queryByRole('button', { name: 'Approve scheduled update once' })).toBeNull(); expect(screen.queryByRole('button', { name: 'Approve this update once' })).toBeNull(); expect(mutateRaw).not.toHaveBeenCalled();
});
it.each(['blur', 'pagehide', 'popstate', 'hashchange', AUTH_REQUIRED_EVENT])('stops pending wave approval on %s without advancing another device', async event => {
    render(<WindowsFleetUpdateWorklist devices={devices}/>); const c = plan(); fireEvent.click(screen.getByRole('button', { name: c.freeze })); await review(devices[0]);
    fireEvent.click(screen.getByRole('checkbox', { name: /prospectively for this UTC/ }));
    let resolve!: (value: unknown) => void; vi.mocked(request).mockImplementationOnce(() => new Promise(done => { resolve = done; }) as never);
    fireEvent.click(screen.getByRole('button', { name: 'Approve scheduled update once' })); act(() => globalThis.window.dispatchEvent(new Event(event))); await act(async () => resolve(session));
    expect(mutateRaw).toHaveBeenCalledTimes(1); expect(screen.queryByRole('button', { name: 'Approve scheduled update once' })).toBeNull(); expect(vi.mocked(request).mock.calls.some(([path]) => path.includes(ids[1]))).toBe(false);
});
it('retains an uncertain exact wave as GET-only after switching devices, never rescheduling it', async () => {
    render(<WindowsFleetUpdateWorklist devices={devices}/>); const c = plan(); fireEvent.click(screen.getByRole('button', { name: c.freeze })); await review(devices[1]);
    const requestId = JSON.parse(vi.mocked(mutateRaw).mock.calls[0][1]).requestId;
    vi.mocked(mutateRaw).mockRejectedValueOnce(new Error('lost schedule')); fireEvent.click(screen.getByRole('checkbox', { name: /prospectively for this UTC/ })); fireEvent.click(screen.getByRole('button', { name: 'Approve scheduled update once' })); await flush();
    expect(JSON.parse(vi.mocked(mutateRaw).mock.calls[1][1])).toMatchObject({ startAt: seconds + 720, endAt: seconds + 1020 });
    fireEvent.click(screen.getByRole('button', { name: 'Open device: Workstation 3' })); await flush(); fireEvent.click(screen.getByRole('button', { name: 'Open device: Workstation 2' })); await flush();
    expect(request).toHaveBeenCalledWith(`/devices/${ids[1]}/windows-update-jobs?jobId=${requestId}`, expect.anything(), 16384); expect(screen.getByText('Write unconfirmed; read saved status only')).toBeVisible(); expect(mutateRaw).toHaveBeenCalledTimes(2);
});
it('clears wave drafts on a new selection and operator replacement', () => {
    const ui = render(<WindowsFleetUpdateWorklist devices={devices}/>), c = plan(); fireEvent.change(screen.getByLabelText(c.size), { target: { value: '2' } }); fireEvent.click(screen.getByRole('button', { name: c.freeze }));
    fireEvent.click(screen.getByRole('button', { name: 'New selection' })); expect(screen.getByRole('checkbox', { name: c.scheduled })).not.toBeChecked();
    fireEvent.click(screen.getByRole('checkbox', { name: c.scheduled })); expect(screen.getByRole('checkbox', { name: c.stagger })).not.toBeChecked(); fireEvent.click(screen.getByRole('checkbox', { name: c.stagger })); expect(screen.getByLabelText(c.size)).toHaveValue(1); expect(screen.getByLabelText(c.gap)).toHaveValue(5);
    vi.mocked(useOperator).mockReturnValue({ ...session, actorId: `operator_${'a'.repeat(32)}` } as never); ui.rerender(<WindowsFleetUpdateWorklist devices={devices}/>); expect(screen.getByRole('checkbox', { name: c.scheduled })).not.toBeChecked(); expect(screen.queryByLabelText(c.size)).toBeNull(); expect(mutateRaw).not.toHaveBeenCalled();
});
