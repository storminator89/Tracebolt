import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, APIError, AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { useOperator } from './auth';
import { DeviceInventoryWorkspace } from './device-inventory';
import { setLocale } from './i18n';
import { LinuxProcessWatches, parseProcessWatchNames } from './linux-process-watches';
import { processWatchCapacity } from './linux-process-watches-resource';
import { PROCESS_WATCH_BYTES, processWatchCondition, processWatchConfirmed, processWatchTime, validProcessWatchName, validProcessWatches } from './linux-process-watches-types';
import type { ProcessWatchRequest, ProcessWatchesView } from './linux-process-watches-types';
import { processCommand, processConfirmed, processDevice, processEnabled, processNow, processObservation, processToken, processView } from './linux-process-watches-fixtures';
import goFixtures from './linux-process-watches-go-fixture.json';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
vi.mock('./complete-overview', () => ({ CompleteOverviewPanel: ({ section }: { section: string }) => <p>Complete overview {section}</p> }));
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: '2026-11-04T14:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
const flush = () => act(async () => {});
const advance = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
function toggle(open: boolean) { const details = document.querySelector('details.linux-process-watches') as HTMLDetailsElement; details.open = open; fireEvent(details, new Event('toggle')); }
async function start(v = processView()) { vi.mocked(request).mockResolvedValue(v); const mounted = render(<LinuxProcessWatches deviceId={processDevice}/>); toggle(true); await flush(); return mounted; }
function prepare(names = 'worker') { fireEvent.change(screen.getByLabelText('Exact process names, one per line'), { target: { value: names } }); fireEvent.click(screen.getByRole('button', { name: 'Review process monitoring' })); }
function apply(name = 'Enable this reviewed policy') { fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name })); }
function captureRequest(): ProcessWatchRequest { const [path, json] = vi.mocked(mutateRaw).mock.calls[0]; return path.endsWith('/acknowledge') ? { operation: 'acknowledge', body: JSON.parse(json) } : { operation: 'policy', body: JSON.parse(json) }; }
function deferred<T>() { let resolve!: (v: T) => void; const promise = new Promise<T>(a => { resolve = a; }); return { promise, resolve }; }
beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(processNow); localStorage.clear(); sessionStorage.clear(); setLocale('en', false); vi.spyOn(document, 'hasFocus').mockReturnValue(true); vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible'); vi.mocked(useOperator).mockReturnValue(operator); vi.mocked(request).mockReset().mockResolvedValue(processView()); vi.mocked(mutateRaw).mockReset(); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('Linux process-watch wire contract', () => {
    it('validates every unchanged real Go API lifecycle fixture', () => {
        for (const [stage, view] of Object.entries(goFixtures)) expect(validProcessWatches(view, view.deviceId), stage).toBe(true);
    });
    it('rejects opening and recovery proofs that skip source generations', () => {
        const opening = processEnabled(); opening.incidents[0].opening.first.generation.sequence = '1'; expect(validProcessWatches(opening, processDevice)).toBe(false);
        const recovery = structuredClone(goFixtures.recovered); recovery.incidents[0].recovery!.last.generation.sequence = String(BigInt(recovery.incidents[0].recovery!.last.generation.sequence) + 1n);
        expect(validProcessWatches(recovery, recovery.deviceId)).toBe(false);
    });
    it('accepts the default-off source and actual evaluator zero counters for present and open incidents', () => {
        expect(validProcessWatches(processView(), processDevice)).toBe(true);
        const open = processEnabled(); expect(validProcessWatches(open, processDevice)).toBe(true);
        const present = processEnabled(); present.incidents = []; present.checks[0] = { ...present.checks[0], condition: 'present', activeCount: 1 };
        expect(validProcessWatches(present, processDevice)).toBe(true);
        const recovering = processEnabled(); recovering.checks[0].activeCount = 1; recovering.checks[0].successCount = 1;
        expect(validProcessWatches(recovering, processDevice)).toBe(true);
    });
    it('accepts recovered and monitoring-stopped history without fabricating recovery', () => {
        const v = processEnabled(); const i = v.incidents[0]; i.state = 'recovered'; i.closedAt = processNow;
        i.recovery = { first: processObservation(4), last: processObservation(5), samples: 2 };
        i.recovery.first.activeCount = 1; i.recovery.last.activeCount = 1;
        i.recovery.first.generation.captureStartedAt = '2026-11-04T11:59:45Z'; i.recovery.first.generation.captureFinishedAt = '2026-11-04T11:59:46Z'; i.recovery.first.generation.receivedAt = '2026-11-04T11:59:47Z';
        i.recovery.last.generation.captureStartedAt = '2026-11-04T11:59:55Z'; i.recovery.last.generation.captureFinishedAt = '2026-11-04T11:59:56Z'; i.recovery.last.generation.receivedAt = '2026-11-04T11:59:57Z';
        i.lastObservedAt = i.recovery.last.generation.captureFinishedAt; v.source.generation = i.recovery.last.generation; v.checks[0].condition = 'present'; v.checks[0].activeCount = 1;
        expect(validProcessWatches(v, processDevice)).toBe(true);
        i.state = 'monitoring_stopped'; i.recovery = null; expect(validProcessWatches(v, processDevice)).toBe(true);
    });
    it('accepts a pure GET after identity replacement without treating old open history as current evidence', () => {
        const v = processEnabled(); v.policy.sourceMatches = false; v.incidents[0].sourceCurrent = false;
        v.checks[0] = { ...v.checks[0], condition: 'unknown', activeCount: null, nonRunningCount: null, failureCount: 0, successCount: 0 };
        expect(validProcessWatches(v, processDevice)).toBe(true);
        v.checks[0] = { ...v.checks[0], condition: 'incident', activeCount: 0, nonRunningCount: 0 };
        expect(validProcessWatches(v, processDevice)).toBe(false);
    });
    it('rejects contradictory counters, unidentified absence, unbound data, unknown fields and oversized revisions', () => {
        const bad = processEnabled(); bad.checks[0].failureCount = 2; expect(validProcessWatches(bad, processDevice)).toBe(false);
        const badRecovery = processEnabled(); badRecovery.checks[0].activeCount = 1; expect(validProcessWatches(badRecovery, processDevice)).toBe(false);
        const pending = processEnabled(); pending.incidents = []; pending.checks[0].condition = 'pending'; expect(validProcessWatches(pending, processDevice)).toBe(false); pending.checks[0].failureCount = 1; expect(validProcessWatches(pending, processDevice)).toBe(true);
        pending.source.generation!.unidentifiedRows = 1; expect(validProcessWatches(pending, processDevice)).toBe(false);
        expect(validProcessWatches(processView(), `agent_${'f'.repeat(32)}`)).toBe(false);
        expect(validProcessWatches({ ...processView(), revision: '9223372036854775808' }, processDevice)).toBe(false);
        expect(validProcessWatches({ ...processView(), commandLine: 'private' }, processDevice)).toBe(false);
    });
    it('preserves exact name bytes and rejects unsupported names consistently with Go', () => {
        expect(parseProcessWatchNames('worker\n Alpha \nworker2')).toEqual([' Alpha ', 'worker', 'worker2']);
        expect(parseProcessWatchNames('worker\nworker')).toEqual(['worker']); expect(parseProcessWatchNames(Array.from({ length: 9 }, (_, i) => `p${i}`).join('\n'))).toBeNull();
        expect(validProcessWatchName('é'.repeat(32))).toBe(true); expect(validProcessWatchName('é'.repeat(33))).toBe(false);
        for (const name of ['', 'a\u0000', 'a\u2028', 'a\u2029', 'a\ufffd', 'a\u200b', '\ud800']) expect(validProcessWatchName(name)).toBe(false);
        expect(validProcessWatchName('worker*')).toBe(true); // The asterisk is literal, never interpreted.
    });
    it('uses exact nanoseconds, stale boundaries and bounded unconfirmed capacity', () => {
        expect(processWatchTime('2026-02-30T00:00:00Z')).toBeNull(); expect(processWatchTime('2026-11-04T12:00:00.000000001Z')! - processWatchTime(processNow)!).toBe(1n);
        const v = processEnabled(); expect(processWatchCondition(v, v.checks[0], 99999)).toBe('incident'); expect(processWatchCondition(v, v.checks[0], 100000)).toBe('unknown');
        expect(processWatchCondition(v, v.checks[0], Infinity)).toBe('unknown');
        const b = processCommand(); expect(processWatchConfirmed(processConfirmed(processView(), b), b)).toBe(true); const wrong = processConfirmed(processView(), b); wrong.lastRequest!.requestId = `processrequest_${'f'.repeat(32)}`; expect(processWatchConfirmed(wrong, b)).toBe(false);
        expect(processWatchCapacity(new Map(), new Map([['a', Array.from({ length: 128 }, () => b)]]))).toBe(false);
    });
});

describe('Linux process-watch private lifecycle and reviewed changes', () => {
    it('is closed and request-free until opened, then uses the exact bounded GET without polling', async () => {
        render(<LinuxProcessWatches deviceId={processDevice}/>); expect(request).not.toHaveBeenCalled(); expect(screen.queryByRole('button')).toBeNull();
        toggle(true); await flush(); expect(request).toHaveBeenCalledExactlyOnceWith(`/devices/${processDevice}/linux-process-watches`, { signal: expect.any(AbortSignal), cache: 'no-store', redirect: 'error' }, PROCESS_WATCH_BYTES);
        expect(screen.getByText('Local process monitoring is disabled.')).toBeVisible(); await advance(30000); expect(request).toHaveBeenCalledTimes(1); expect(screen.queryByText('No retained process incidents.')).toBeNull();
    });
    it('sends sorted exact names only after unchecked explicit review and confirms the matching policy', async () => {
        await start(); prepare('worker\n Alpha '); const review = screen.getByRole('region', { name: 'Review this exact local change' });
        expect(review).toHaveTextContent('Any existing monitoring period ends'); expect(screen.getByRole('checkbox')).not.toBeChecked(); expect(screen.getByRole('button', { name: 'Enable this reviewed policy' })).toBeDisabled(); expect(mutateRaw).not.toHaveBeenCalled();
        vi.mocked(mutateRaw).mockImplementation(async (_path, raw) => processConfirmed(processView(), { operation: 'policy', body: JSON.parse(raw) })); apply(); await flush();
        expect(captureRequest()).toMatchObject({ operation: 'policy', body: { expectedRevision: '0', sourceToken: processToken, enabled: true, names: [' Alpha ', 'worker'], consecutiveFailures: 2, retentionAcknowledged: true } });
        expect(vi.mocked(mutateRaw).mock.calls[0][0]).toBe(`/devices/${processDevice}/linux-process-watches/policy`); expect(screen.getByText('The manager confirmed this exact request.')).toBeVisible();
    });
    it('combines duplicate exact names and requires a new review after cancellation', async () => {
        await start(); prepare('worker\nworker'); expect(screen.getByRole('region', { name: 'Review this exact local change' }).querySelectorAll('li')).toHaveLength(1);
        fireEvent.click(screen.getByRole('button', { name: 'Discard review' })); prepare(); fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Discard review' })); prepare(); expect(screen.getByRole('checkbox')).not.toBeChecked(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('keeps named read-only accounts and unavailable sources read-only without collecting', async () => {
        const v = processEnabled(); v.canManage = false; await start(v); expect(screen.getByText(/^Read only\./)).toBeVisible(); expect(screen.getAllByRole('button')).toHaveLength(1); expect(screen.queryByRole('textbox')).toBeNull();
        cleanup(); abortProtectedRequests(); const unknown = processView(); unknown.source = { ...unknown.source, status: 'unknown', reason: 'no_generation', generation: null }; await start(unknown); expect(screen.getByText('No complete process snapshot is available.')).toBeVisible(); expect(screen.queryByRole('textbox')).toBeNull(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('marks only the reviewed incident as seen without closing it', async () => {
        const v = processEnabled(); await start(v); fireEvent.click(screen.getByRole('button', { name: /^Review marking as seen/ }));
        expect(screen.getByRole('region', { name: 'Review this exact local change' })).toHaveTextContent(v.incidents[0].id);
        vi.mocked(mutateRaw).mockImplementation(async (_path, raw) => processConfirmed(v, { operation: 'acknowledge', body: JSON.parse(raw) })); apply('Mark as seen'); await flush();
        expect(captureRequest()).toMatchObject({ operation: 'acknowledge', body: { expectedRevision: '1', sourceToken: processToken, incidentId: v.incidents[0].id } });
        expect(screen.getByRole('heading', { name: 'worker · Open' })).toBeVisible(); expect(screen.queryByRole('button', { name: /^Review marking as seen/ })).toBeNull();
    });
    it('labels old identity history honestly and withholds acknowledgement until the current binding is reconciled', async () => {
        const v = processEnabled(); v.policy.sourceMatches = false; v.incidents[0].sourceCurrent = false;
        v.checks[0] = { ...v.checks[0], condition: 'unknown', activeCount: null, nonRunningCount: null, failureCount: 0, successCount: 0 };
        await start(v); expect(screen.getByText(/^The saved policy belongs to a previous source identity/)).toBeVisible(); expect(screen.getByRole('heading', { name: 'worker · Open' })).toBeVisible();
        expect(document.querySelector('.process-watch-checks')).toHaveTextContent('Current evidence unknown'); expect(screen.queryByRole('button', { name: /^Review marking as seen/ })).toBeNull(); expect(screen.getByRole('button', { name: 'Review disabling monitoring' })).toBeVisible();
    });
    it('disables only after review and displays monitoring stopped rather than recovered', async () => {
        const v = processEnabled(); await start(v); fireEvent.click(screen.getByRole('button', { name: 'Review disabling monitoring' }));
        vi.mocked(mutateRaw).mockImplementation(async (_path, raw) => processConfirmed(v, { operation: 'policy', body: JSON.parse(raw) })); apply('Disable this policy'); await flush();
        expect(captureRequest()).toMatchObject({ operation: 'policy', body: { enabled: false, names: [], consecutiveFailures: 0, retentionAcknowledged: false } }); expect(screen.getByRole('heading', { name: 'worker · Monitoring stopped' })).toBeVisible();
    });
    it('retains ambiguous writes and reconciles only through GET, without retrying a possibly accepted mutation', async () => {
        await start(); prepare(); vi.mocked(mutateRaw).mockRejectedValue(new Error('private raw error')); apply(); await flush(); const b = captureRequest();
        expect(screen.getByText(/^Outcome unconfirmed/)).toBeVisible(); expect(document.body).not.toHaveTextContent('private raw error');
        fireEvent.click(screen.getByRole('button', { name: 'Reload process watches' })); await flush(); expect(screen.getByText(/^This read does not confirm/)).toBeVisible(); expect(screen.queryByRole('textbox')).toBeNull();
        vi.mocked(request).mockResolvedValue(processConfirmed(processView(), b)); fireEvent.click(screen.getByRole('button', { name: 'Reload process watches' })); await flush(); expect(screen.getByText('The manager confirmed this exact request.')).toBeVisible(); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
    it('retains unresolved write uncertainty across close and reopen without reusing consent', async () => {
        await start(); prepare(); vi.mocked(mutateRaw).mockRejectedValue(new Error('lost')); apply(); await flush();
        toggle(false); await flush(); expect(screen.queryByText(/^Outcome unconfirmed/)).toBeNull(); toggle(true); await flush();
        expect(screen.getByText(/^Outcome unconfirmed/)).toBeVisible(); expect(screen.queryByRole('checkbox')).toBeNull(); expect(screen.queryByRole('textbox')).toBeNull(); expect(mutateRaw).toHaveBeenCalledTimes(1); expect(request).toHaveBeenCalledTimes(2);
    });
    it.each(['revision', 'source'] as const)('allows an independent review after a verified changed %s while retaining the prior uncertainty', async fence => {
        await start(); prepare(); vi.mocked(mutateRaw).mockRejectedValue(new Error('lost')); apply(); await flush(); const next = processView(); if (fence === 'revision') next.revision = '1'; else next.source.token = `processsource_${'f'.repeat(32)}`;
        vi.mocked(request).mockResolvedValue(next); fireEvent.click(screen.getByRole('button', { name: 'Reload process watches' })); await flush(); expect(screen.getByText(/^An earlier outcome remains unconfirmed/)).toBeVisible(); expect(screen.getByRole('textbox')).toHaveValue(''); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
    it.each([400, 403])('treats a definite HTTP %s rejection as failed without automatic retry', async status => {
        await start(); prepare(); vi.mocked(mutateRaw).mockRejectedValue(new APIError('private', status)); apply(); await flush(); expect(screen.queryByText(/^Outcome unconfirmed/)).toBeNull(); fireEvent.click(screen.getByRole('button', { name: 'Reload process watches' })); await flush(); expect(screen.getByRole('textbox')).toBeVisible(); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
    it.each(['policy', 'acknowledge'] as const)('retains HTTP 409 uncertainty after a possible %s commit and confirms only the exact saved request', async operation => {
        const v = operation === 'policy' ? processView() : processEnabled(); await start(v);
        if (operation === 'policy') prepare(); else fireEvent.click(screen.getByRole('button', { name: /^Review marking as seen/ }));
        vi.mocked(mutateRaw).mockRejectedValue(new APIError('Clock or source changed after commit', 409)); apply(operation === 'policy' ? 'Enable this reviewed policy' : 'Mark as seen'); await flush();
        const b = captureRequest(); expect(screen.getByText(/^Outcome unconfirmed/)).toBeVisible(); expect(screen.queryByText('The manager confirmed this exact request.')).toBeNull();
        fireEvent.click(screen.getByRole('button', { name: 'Reload process watches' })); await flush();
        expect(screen.getByText(/^This read does not confirm/)).toBeVisible(); expect(screen.queryByRole('textbox')).toBeNull(); expect(screen.queryByRole('button', { name: /^Review marking as seen/ })).toBeNull();
        vi.mocked(request).mockResolvedValue(processConfirmed(v, b)); fireEvent.click(screen.getByRole('button', { name: 'Reload process watches' })); await flush();
        expect(screen.getByText('The manager confirmed this exact request.')).toBeVisible(); expect(screen.queryByText(/^Outcome unconfirmed/)).toBeNull(); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
    it.each(['blur', 'pagehide', 'hashchange', 'popstate'])('clears private data, names and consent on %s without automatically refreshing', async event => {
        await start(); prepare(); fireEvent.click(screen.getByRole('checkbox')); act(() => window.dispatchEvent(new Event(event))); expect(screen.queryByRole('region', { name: 'Review this exact local change' })).toBeNull(); expect(screen.queryByRole('textbox')).toBeNull();
        act(() => window.dispatchEvent(new Event('focus'))); await flush(); expect(request).toHaveBeenCalledTimes(1); fireEvent.click(screen.getByRole('button', { name: 'Reload process watches' })); await flush(); expect(screen.getByRole('textbox')).toHaveValue(''); prepare(); expect(screen.getByRole('checkbox')).not.toBeChecked();
    });
    it('aborts reads on closing and never renders late evidence', async () => {
        const held = deferred<ProcessWatchesView>(); vi.mocked(request).mockReturnValue(held.promise); render(<LinuxProcessWatches deviceId={processDevice}/>); toggle(true); await flush(); const signal = vi.mocked(request).mock.calls[0][1]?.signal;
        toggle(false); await flush(); expect(signal?.aborted).toBe(true); await act(async () => held.resolve(processEnabled())); expect(screen.queryByRole('heading', { name: 'worker · Open' })).toBeNull(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('rechecks lifecycle at POST send time, rejects late completion after blur, and retains uncertainty', async () => {
        const held = deferred<unknown>(); await start(); prepare(); let gate: (() => boolean) | undefined;
        vi.mocked(mutateRaw).mockImplementation((_path, _json, _headers, _signal, _cap, beforeSend) => { gate = beforeSend; expect(gate?.()).toBe(true); return held.promise; });
        apply(); const b = captureRequest(); act(() => window.dispatchEvent(new Event('blur'))); expect(gate?.()).toBe(false); expect(vi.mocked(mutateRaw).mock.calls[0][3]?.aborted).toBe(true);
        await act(async () => held.resolve(processConfirmed(processView(), b))); expect(screen.queryByText('The manager confirmed this exact request.')).toBeNull(); expect(screen.getByText(/^Outcome unconfirmed/)).toBeVisible(); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
    it('rejects regressed revisions, even under a changed source token', async () => {
        const v = processView(); v.revision = '3'; await start(v); const next = processView(); next.revision = '2'; next.source.token = `processsource_${'f'.repeat(32)}`; vi.mocked(request).mockResolvedValue(next);
        fireEvent.click(screen.getByRole('button', { name: 'Reload process watches' })); await flush(); expect(screen.getByText('Process watches unavailable. Reload to verify saved state.')).toBeVisible(); expect(screen.queryByRole('textbox')).toBeNull();
    });
    it('permits only reviewed disable during manager clock rollback and retains original history times', async () => {
        const v = processEnabled(); v.clockReliable = false; v.serverNow = '2026-11-04T10:00:00Z'; v.validUntil = '2026-11-04T10:00:30Z'; v.source = { ...v.source, status: 'unknown', reason: 'stale', generation: null }; v.checks[0] = { ...v.checks[0], condition: 'unknown', activeCount: null, nonRunningCount: null, failureCount: 0, successCount: 0 };
        await start(v); expect(screen.getByText(/^Manager clock is unreliable/)).toBeVisible(); expect(screen.queryByRole('textbox')).toBeNull(); expect(screen.queryByRole('button', { name: /^Review marking as seen/ })).toBeNull(); expect(screen.getByRole('button', { name: 'Review disabling monitoring' })).toBeVisible(); expect(document.querySelector('.process-watch-history time')).toHaveAttribute('datetime', '2026-11-04T11:58:40Z');
    });
    it('isolates device and actor scopes, closes on switching, and does not read for signed-out or invalid IDs', async () => {
        const mounted = await start(); prepare(); vi.mocked(useOperator).mockReturnValue({ ...operator, loginMode: 'named', actorId: 'other', capabilities: ['read'] }); mounted.rerender(<LinuxProcessWatches deviceId={processDevice}/>); await flush();
        expect(document.querySelector('details.linux-process-watches')).not.toHaveAttribute('open'); expect(screen.queryByRole('textbox')).toBeNull(); expect(request).toHaveBeenCalledTimes(1);
        mounted.rerender(<LinuxProcessWatches deviceId="../invalid"/>); expect(document.querySelector('details.linux-process-watches')).toBeNull();
        vi.mocked(useOperator).mockReturnValue({ ...operator, authenticated: false }); mounted.rerender(<LinuxProcessWatches deviceId={processDevice}/>); expect(document.querySelector('details.linux-process-watches')).toBeNull();
    });
    it('clears on authentication expiry and never opens a replacement session automatically', async () => {
        await start(processEnabled()); act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); expect(screen.getByText('Session ended. Sign in again.')).toBeVisible(); expect(screen.queryByRole('heading', { name: 'worker · Open' })).toBeNull(); expect(screen.getByRole('button', { name: 'Reload process watches' })).toBeDisabled();
    });
    it('switches language without another read and keeps nested evidence details from closing the watch', async () => {
        await start(processEnabled()); act(() => setLocale('de', false)); expect(screen.getByText('Lokale Linux-Prozessüberwachung')).toBeVisible(); expect(screen.getByRole('heading', { name: 'worker · Offen' })).toBeVisible(); expect(request).toHaveBeenCalledTimes(1);
        const nested = document.querySelector('.process-watch-incident details') as HTMLDetailsElement; nested.open = true; fireEvent(nested, new Event('toggle', { bubbles: true })); expect(document.querySelector('details.linux-process-watches')).toHaveAttribute('open'); expect(request).toHaveBeenCalledTimes(1);
    });
    it('mounts only in Processes and resets on leaving the inventory source', async () => {
        render(<DeviceInventoryWorkspace deviceId={processDevice} initialSource="processes"/>); expect(screen.getByText('Local Linux process watches')).toBeVisible(); expect(request).not.toHaveBeenCalled(); toggle(true); await flush();
        const tabs = screen.getByRole('tablist', { name: 'Inventory source' }); fireEvent.click(within(tabs).getByRole('tab', { name: 'Mounts' })); expect(screen.queryByText('Local Linux process watches')).toBeNull(); fireEvent.click(within(tabs).getByRole('tab', { name: 'Processes' })); expect(document.querySelector('details.linux-process-watches')).not.toHaveAttribute('open'); expect(request).toHaveBeenCalledTimes(1);
    });
});

describe('discarding an unsaved Linux process-watch draft', () => {
    it('does not renew the original display lease when discarding and reopening an edit', async () => {
        await start(processEnabled()); fireEvent.click(screen.getByRole('button', { name: 'Edit monitored processes' }));
        fireEvent.change(screen.getByRole('textbox'), { target: { value: 'unsaved-worker' } }); await advance(29000);
        fireEvent.click(screen.getByRole('button', { name: 'Discard unsaved changes' }));
        fireEvent.click(screen.getByRole('button', { name: 'Edit monitored processes' })); expect(screen.getByRole('textbox')).toBeEnabled();
        await advance(1001); expect(screen.getByRole('textbox')).toBeDisabled();
        expect(screen.getByRole('button', { name: 'Review process monitoring' })).toBeDisabled();
        expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('never offers local discard as cancellation of an uncertain submitted write', async () => {
        await start(); prepare(); vi.mocked(mutateRaw).mockRejectedValueOnce(new TypeError('lost reply')); apply(); await flush();
        expect(screen.getByText(/^Outcome unconfirmed/)).toBeVisible();
        expect(screen.queryByRole('button', { name: 'Discard unsaved changes' })).toBeNull();
        expect(screen.queryByRole('textbox')).toBeNull(); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
    it.each(['en', 'de'] as const)('cancels saved-policy editing locally and restores the saved values on the next edit in %s', async locale => {
        const v = processEnabled(); await start(v); act(() => setLocale(locale, false));
        const edit = locale === 'de' ? 'Überwachte Prozesse bearbeiten' : 'Edit monitored processes';
        const discard = locale === 'de' ? 'Ungespeicherte Änderungen verwerfen' : 'Discard unsaved changes';
        fireEvent.click(screen.getByRole('button', { name: edit }));
        fireEvent.change(screen.getByRole('textbox'), { target: { value: 'different-worker' } });
        fireEvent.change(screen.getByRole('combobox'), { target: { value: '3' } });
        const button = screen.getByRole('button', { name: discard }); expect(button).toHaveAttribute('type', 'button');
        fireEvent.click(button);
        expect(screen.queryByRole('textbox')).toBeNull(); expect(screen.getByRole('button', { name: edit })).toBeVisible();
        const panel = document.querySelector('details.linux-process-watches')!;
        expect(panel).toHaveAttribute('open'); expect(panel.querySelector('summary')).toHaveFocus();
        expect(screen.getByRole('heading', { name: locale === 'de' ? 'worker · Offen' : 'worker · Open' })).toBeVisible();
        fireEvent.click(screen.getByRole('button', { name: edit }));
        expect(screen.getByRole('textbox')).toHaveValue(v.policy.names.join('\n')); expect(screen.getByRole('combobox')).toHaveValue(String(v.policy.consecutiveFailures));
        expect(screen.queryByRole('checkbox')).toBeNull(); expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it.each(['en', 'de'] as const)('lets an expired draft be discarded without renewing evidence or review in %s', async locale => {
        await start(processEnabled()); act(() => setLocale(locale, false));
        fireEvent.click(screen.getByRole('button', { name: locale === 'de' ? 'Überwachte Prozesse bearbeiten' : 'Edit monitored processes' }));
        fireEvent.change(screen.getByRole('textbox'), { target: { value: 'unconfirmed-worker' } });
        await advance(30001);
        expect(screen.getByRole('textbox')).toBeDisabled();
        const button = screen.getByRole('button', { name: locale === 'de' ? 'Ungespeicherte Änderungen verwerfen' : 'Discard unsaved changes' });
        expect(button).toBeEnabled(); fireEvent.click(button);
        expect(screen.queryByRole('textbox')).toBeNull(); expect(screen.queryByRole('checkbox')).toBeNull();
        expect(document.querySelector('details.linux-process-watches > summary')).toHaveFocus();
        expect(screen.getByRole('button', { name: locale === 'de' ? 'Prozessüberwachung neu laden' : 'Reload process watches' })).toBeVisible();
        expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('clears a new unsaved selection without changing the default-off saved policy', async () => {
        await start(); fireEvent.change(screen.getByRole('textbox'), { target: { value: 'unsaved-worker' } });
        fireEvent.change(screen.getByRole('combobox'), { target: { value: '3' } });
        fireEvent.click(screen.getByRole('button', { name: 'Discard unsaved changes' }));
        expect(screen.getByRole('textbox')).toHaveValue(''); expect(screen.getByRole('combobox')).toHaveValue('2');
        expect(screen.getByText('Local process monitoring is disabled.')).toBeVisible();
        expect(screen.getByRole('button', { name: 'Review process monitoring' })).toBeDisabled();
        expect(screen.queryByRole('button', { name: 'Discard unsaved changes' })).toBeNull();
        expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).not.toHaveBeenCalled();
    });
});
