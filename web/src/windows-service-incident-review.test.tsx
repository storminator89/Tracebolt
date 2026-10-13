import goldenReview from '../../tests/fixtures/windows-service-incident-review.json';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, mutateRaw, request } from './api';
import { LOGOUT_INTENT_KEY, useOperator } from './auth';
import { acceptWindowsHealthClock } from './windows-health-clock';
import { setLocale } from './i18n';
import { windowsIncidentItem, windowsIncidentView } from './windows-incident-inbox-fixture';
import { windowsCapacityDevice, windowsCapacitySession } from './windows-capacity-fixture';
import { windowsDeviceId, windowsNow } from './windows-inventory-fixture';
import { WindowsIncidentInbox } from './windows-incident-inbox';
import { WindowsServiceIncidentReview } from './windows-service-incident-review';
import { WindowsServiceActionsPanel } from './windows-service-actions';
import { validWindowsServiceIncidentReview, windowsServiceReviewCurrent, windowsServiceReviewObservation, windowsServiceReviewClockKey, WINDOWS_SERVICE_REVIEW_HEADER } from './windows-service-incident-review-types';
import type { WindowsServiceIncidentReviewContext, WindowsServiceIncidentReviewView } from './windows-service-incident-review-types';
import type { WindowsActionBinding, WindowsActionView, WindowsServiceOperation } from './windows-service-action-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const digest = `sha256:${'a'.repeat(64)}`, actor = `operator_${'2'.repeat(32)}`;
const binding: WindowsActionBinding = { managerId: `manager_${'3'.repeat(32)}`, keyId: digest, endpointId: windowsDeviceId, incarnationDigest: digest, installationId: `broker_${'4'.repeat(32)}`, grantDigest: digest, target: 'FixtureService', targetDigest: digest };
const incident = () => windowsIncidentItem({ domain: 'service', incidentId: 'wservice_0000000000000001', serviceName: binding.target, status: 'attention' });
const reviewView = (): WindowsServiceIncidentReviewView => ({ schemaVersion: 'tracebolt.windows-service-incident-review.v1', serverNow: windowsNow, authorityExpiresAt: '2026-10-07T12:02:10Z', incident: incident(), observation: { name: binding.target, displayName: 'Fixture Service', state: 'stopped', collectedAt: '2026-10-07T12:00:00Z', receivedAt: '2026-10-07T12:00:01Z', sequence: 9, quality: 'healthy', complete: true, truncated: false, countExact: true, observedCount: 1 }, control: { status: 'matched', binding, bindingDigest: digest } });
const context = (): WindowsServiceIncidentReviewContext => { const value = { view: reviewView(), sessionKey: windowsCapacitySession, anchor: { mono: performance.now(), wall: Date.now(), epoch: getProtectedRequestEpoch() } }; acceptWindowsHealthClock(windowsServiceReviewClockKey(value.sessionKey),value.anchor.epoch,value.view.serverNow,0); return value; };
const actionView = (): WindowsActionView => ({ schemaVersion: 'tracebolt.windows-service-action-view.v1', deviceId: windowsDeviceId, serverNow: windowsNow, configured: true, available: true, reason: 'ready', target: binding.target, preview: null, job: null });
const preview = (operation: WindowsServiceOperation = 'start'): WindowsActionView => ({ ...actionView(), preview: { version: 'tracebolt.windows-service-action-preview.v1', id: `action_${'5'.repeat(32)}`, binding, operation, actorId: actor, sequence: '1', createdAt: windowsNow, expiresAt: '2026-10-07T12:01:10Z', digest } });
const session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'csrf', serverNow: windowsNow, expiresAt: windowsCapacitySession, expiresInSeconds: 3590, loginMode: 'named', actorId: actor, capabilities: ['read', 'windows_service_control'] };
const flush = () => act(async () => {});
const reviewPath = `/fleet/windows-incidents/${incident().key}/service-review`;
function renderReview() { return render(<WindowsServiceIncidentReview incidentKey={incident().key} deviceId={windowsDeviceId} serviceName={binding.target} sessionKey={windowsCapacitySession} onClose={vi.fn()}/>); }
async function choose(op: WindowsServiceOperation = 'start') { fireEvent.click(screen.getByRole('button', { name: /Select service:/ })); fireEvent.change(screen.getByRole('combobox'), { target: { value: op } }); fireEvent.click(screen.getByRole('button', { name: 'Review action' })); await flush(); }
let response: WindowsServiceIncidentReviewView;
beforeEach(() => {
    abortProtectedRequests(); vi.useFakeTimers(); vi.setSystemTime(windowsNow); setLocale('en', false); response = reviewView();
    vi.mocked(useOperator).mockReturnValue({ ...session, mode: 'lan', theme: 'light', loginMode: 'named', capabilities: ['read', 'windows_service_control'], logout: vi.fn(), setTheme: vi.fn() });
    vi.mocked(request).mockReset().mockImplementation(async path => structuredClone(path === '/auth/session' ? session : path === reviewPath ? response : path.startsWith('/fleet/windows-incidents?') ? windowsIncidentView([incident()]) : actionView()) as never);
    vi.mocked(mutateRaw).mockReset().mockImplementation(async (_path, body) => preview(JSON.parse(body).operation) as never);
});
afterEach(() => { cleanup(); abortProtectedRequests(); localStorage.removeItem(LOGOUT_INTENT_KEY); sessionStorage.removeItem(LOGOUT_INTENT_KEY); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('closed service-incident review contract', () => {
    it('validates the exact incident and rejects unrelated or overbroad pairing', () => {
        const valid = (value: unknown) => validWindowsServiceIncidentReview(value, incident().key, windowsDeviceId, binding.target);
        expect(valid(response)).toBe(true);
        for (const bad of [
            { ...response, grant: true }, { ...response, incident: { ...response.incident, domain: 'cpu' } },
            { ...response, incident: { ...response.incident, key: '2'.repeat(64) } },
            { ...response, observation: { ...response.observation, name: 'fixtureservice' } },
            { ...response, observation: { ...response.observation, collectedAt: '2026-10-07T11:50:00Z' } },
            { ...response, observation: { ...response.observation, state: 'absent' } },
            { ...response, control: { ...response.control, binding: { ...binding, target: 'OtherService' } } },
            { ...response, control: { ...response.control, status: 'unavailable' } },
            { ...response, authorityExpiresAt: '2026-10-07T12:30:00Z' },
        ]) expect(valid(bad)).toBe(false);
        expect(valid({ ...response, observation: null, control: { status: 'unavailable', binding: null, bindingDigest: null } })).toBe(true);
    });
    it('ages current observations without changing incident lifecycle or timestamps', async () => {
        const review = context(), original = structuredClone(review.view.incident);
        expect(windowsServiceReviewObservation(review)).not.toBeNull();
        await act(async () => vi.advanceTimersByTime(111000));
        expect(windowsServiceReviewCurrent(review)).toBe(true); expect(windowsServiceReviewObservation(review)).toBeNull();
        expect(review.view.incident).toEqual(original);
        await act(async () => vi.advanceTimersByTime(9000)); expect(windowsServiceReviewCurrent(review)).toBe(false);
    });
});

describe('compact incident-to-exact-service handoff', () => {
    it.each(['en', 'de'] as const)('opens only the chosen row through GET and carries its original times in %s', async locale => {
        setLocale(locale, false); render(<WindowsIncidentInbox devices={[windowsCapacityDevice()]} sessionKey={windowsCapacitySession} admin={false}/>);
        fireEvent.click(screen.getByRole('button', { name: locale === 'de' ? 'Windows-Vorfälle' : 'Windows incidents' })); await flush();
        expect(vi.mocked(request).mock.calls.some(([path]) => path === reviewPath)).toBe(false);
        fireEvent.click(screen.getByRole('button', { name: new RegExp(locale === 'de' ? '^Dienst prüfen:' : '^Review service:') })); await flush();
        const region = screen.getByRole('region', { name: locale === 'de' ? 'Vorfallsdienst prüfen' : 'Review incident service' });
        expect(within(region).getByText('Fixture Service')).toBeInTheDocument();
        expect(region.querySelector('time')).toHaveAttribute('datetime', incident().openedAt);
        expect(mutateRaw).not.toHaveBeenCalled(); expect(within(region).queryByRole('combobox')).toBeNull(); expect(within(region).queryByRole('checkbox')).toBeNull();
        const guarded = vi.mocked(request).mock.calls.find(([path]) => path.endsWith('/windows-service-actions'))!;
        expect(guarded[1]?.headers).toEqual({ [WINDOWS_SERVICE_REVIEW_HEADER]: digest });
        fireEvent.click(within(region).getByRole('button', { name: locale === 'de' ? 'Dienstprüfung schließen' : 'Close service review' }));
        expect(screen.queryByRole('region', { name: locale === 'de' ? 'Vorfallsdienst prüfen' : 'Review incident service' })).toBeNull();
    });
    it.each(['en', 'de'] as const)('keeps current state visible and reveals original evidence without requesting an action in %s', async locale => {
        setLocale(locale, false); renderReview(); await flush(); const de = locale === 'de';
        expect(screen.getByText('Fixture Service')).toBeVisible();
        const scope = screen.getByText(de ? 'Belege & Steuerung' : 'Evidence & control', { selector: 'summary' });
        const limit = screen.getByText(de ? /kein Nachweis derselben Dienstinstanz/ : /not proof that the same service instance/);
        expect(scope.closest('details')).not.toHaveAttribute('open'); expect(limit).not.toBeVisible();
        expect(screen.getByText(de ? /Nur das ursprüngliche Gerät/ : /Only this incident’s original device/)).toBeVisible();
        const reads = vi.mocked(request).mock.calls.length;
        fireEvent.click(scope); expect(limit).toBeVisible();
        const times = scope.closest('details')!.querySelectorAll('time'); expect(times).toHaveLength(2);
        expect(times[0]).toHaveAttribute('datetime', response.observation!.collectedAt); expect(times[1]).toHaveAttribute('datetime', response.observation!.receivedAt);
        fireEvent.click(scope); expect(limit).not.toBeVisible(); expect(request).toHaveBeenCalledTimes(reads); expect(mutateRaw).not.toHaveBeenCalled();
        expect(screen.queryByRole('combobox')).toBeNull(); expect(screen.queryByRole('checkbox')).toBeNull();
    });
    it('keeps partial coverage visible and retains evidence when service control is blocked', async () => {
        response.observation = { ...response.observation!, quality: 'partial', complete: false, truncated: true, countExact: false };
        response.control = { status: 'not_configured', binding: null, bindingDigest: null };
        renderReview(); await flush();
        expect(screen.getAllByText('Caller-visible, partial source coverage').some(node => !node.closest('details'))).toBe(true);
        expect(screen.getByText('No separate service-control grant is configured.')).toBeVisible();
        const evidence = screen.getByText('Evidence & limits', { selector: 'summary' }); expect(evidence.closest('details')).not.toHaveAttribute('open');
        fireEvent.click(evidence); expect(screen.getByText(/not proof that the same service instance/)).toBeVisible(); expect(evidence.closest('details')!.querySelectorAll('time')).toHaveLength(2);
        expect(screen.queryByRole('button', { name: /Select service:/ })).toBeNull(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('requires a deliberate operation and preserves the original guard through every status/preview', async () => {
        renderReview(); await flush();
        fireEvent.click(screen.getByRole('button', { name: /Select service:/ }));
        expect(screen.getByRole('combobox')).toHaveValue(''); expect(screen.getByRole('button', { name: 'Review action' })).toBeDisabled();
        fireEvent.click(screen.getByRole('button', { name: 'Review action' })); expect(mutateRaw).not.toHaveBeenCalled();
        fireEvent.change(screen.getByRole('combobox'), { target: { value: 'restart' } }); fireEvent.click(screen.getByRole('button', { name: 'Review action' })); await flush();
        expect(vi.mocked(mutateRaw).mock.calls[0].slice(0, 3)).toEqual([`/devices/${windowsDeviceId}/windows-service-actions/preview`, JSON.stringify({ target: binding.target, operation: 'restart' }), { [WINDOWS_SERVICE_REVIEW_HEADER]: digest }]);
        expect(screen.getByRole('button', { name: 'Approve this action once' })).toBeDisabled();
        fireEvent.click(screen.getByRole('button', { name: 'Dismiss preview' })); fireEvent.click(screen.getByRole('button', { name: 'Read saved status' })); await flush();
        expect(vi.mocked(request).mock.calls.filter(([path]) => path.endsWith('/windows-service-actions')).every(([, options]) => (options?.headers as Record<string,string>)?.[WINDOWS_SERVICE_REVIEW_HEADER] === digest)).toBe(true);
        fireEvent.click(screen.getByRole('button', { name: /Select service:/ })); expect(screen.getByRole('combobox')).toHaveValue(''); expect(mutateRaw).toHaveBeenCalledOnce();
    });
    it('rejects a replacement-incarnation preview even when the exact device and service name match', async () => {
        renderReview(); await flush(); vi.mocked(mutateRaw).mockResolvedValueOnce({ ...preview(), preview: { ...preview().preview!, binding: { ...binding, incarnationDigest: `sha256:${'b'.repeat(64)}` } } });
        await choose(); expect(screen.queryByRole('checkbox')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('unavailable or changed'); expect(mutateRaw).toHaveBeenCalledOnce();
    });
    it.each(['not_configured', 'unavailable', 'target_mismatch', 'operator_capability_required'] as const)('keeps %s clearly blocked and never reads generic replacement controls', async status => {
        response.control = { status, binding: null, bindingDigest: null }; renderReview(); await flush();
        expect(screen.getByRole('status')).toBeInTheDocument(); expect(screen.queryByRole('button', { name: /Select service:/ })).toBeNull();
        expect(vi.mocked(request).mock.calls.map(([path]) => path)).toEqual([reviewPath]); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('does not infer stopped from missing observation and preserves policy closure rather than recovery', async () => {
        response.observation = null; Object.assign(response.incident, { resolvedAt: '2026-10-07T11:59:00Z', closedReason: 'policy-changed', status: 'disabled', statusValidUntil: null }); renderReview(); await flush();
        expect(screen.getByText(/Current service state is unknown/)).toBeInTheDocument(); expect(screen.getByText('Closed after a policy change; recovery not established')).toBeInTheDocument(); expect(screen.queryByText('Incident recovered')).toBeNull();
    });
    it.each(['blur', 'pagehide', 'hashchange', 'popstate', AUTH_REQUIRED_EVENT])('discards private context and late reads after %s', async event => {
        let finish!: (v: unknown) => void; vi.mocked(request).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }) as never); renderReview();
        act(() => window.dispatchEvent(new Event(event))); await act(async () => finish(response));
        expect(screen.queryByText('Fixture Service')).toBeNull(); expect(screen.queryByRole('button', { name: /Select service:/ })).toBeNull(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('does not renew the original review lifetime through status reads', async () => {
        renderReview(); await flush(); await act(async () => vi.advanceTimersByTime(60000)); fireEvent.click(screen.getByRole('button', { name: 'Read saved status' })); await flush();
        await act(async () => vi.advanceTimersByTime(60000)); expect(screen.queryByRole('button', { name: /Select service:/ })).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('expired'); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('rechecks expiry before a manual preview leaves the session read', async () => {
        const review = context(); render(<WindowsServiceActionsPanel deviceId={windowsDeviceId} sessionKey={windowsCapacitySession} review={review}/>); await flush();
        let finish!: (v: unknown) => void; vi.mocked(request).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }) as never);
        await choose(); await act(async () => vi.advanceTimersByTime(120000)); await act(async () => finish(session)); expect(mutateRaw).not.toHaveBeenCalled();
    });
});


it('approval stays a separate exact-preview action and cannot be inferred from the incident', async () => {
    renderReview(); await flush(); await choose('stop');
    const p = preview('stop').preview!;
    vi.mocked(mutateRaw).mockResolvedValueOnce({ ...actionView(), available: false, reason: 'job_pending', job: { identity: { jobId: p.id, sequence: p.sequence, envelopeDigest: digest }, target: binding.target, operation: 'stop', actorId: actor, approvedAt: windowsNow, startDeadline: p.expiresAt, state: 'approved', result: null } });
    const approval = screen.getByRole('button', { name: 'Approve this action once' }); expect(approval).toBeDisabled();
    fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(approval); fireEvent.click(approval); await flush();
    expect(mutateRaw).toHaveBeenCalledTimes(2); expect(vi.mocked(mutateRaw).mock.calls[1].slice(0,3)).toEqual([`/devices/${windowsDeviceId}/windows-service-actions/approve`,JSON.stringify({previewId:p.id,previewDigest:p.digest}),{}]);
    expect(screen.queryByRole('checkbox')).toBeNull();
});

it('drops a late action preview when the selected incident disclosure is closed', async () => {
    const ui=renderReview();await flush();let finish!:(value:unknown)=>void;vi.mocked(mutateRaw).mockImplementationOnce(()=>new Promise(resolve=>{finish=resolve}) as never);await choose();ui.unmount();await act(async()=>finish(preview()));expect(screen.queryByRole('checkbox')).toBeNull();expect(mutateRaw).toHaveBeenCalledOnce();
});

it('discards old review bytes on a session change without exposing them during a pending read', async () => {
    const ui=renderReview();await flush();expect(screen.getByText('Fixture Service')).toBeInTheDocument();vi.mocked(request).mockImplementationOnce(()=>new Promise(()=>{}) as never);
    ui.rerender(<WindowsServiceIncidentReview incidentKey={incident().key} deviceId={windowsDeviceId} serviceName={binding.target} sessionKey="2026-10-07T14:00:00Z" onClose={vi.fn()}/>);
    expect(screen.queryByText('Fixture Service')).toBeNull();expect(screen.queryByRole('button',{name:/Select service:/})).toBeNull();expect(mutateRaw).not.toHaveBeenCalled();
});


it('validates every exact Go-generated API review fixture and renders its original evidence', async () => {
    for (const value of Object.values(goldenReview)) expect(validWindowsServiceIncidentReview(value,value.incident.key,value.incident.deviceId,value.incident.serviceName)).toBe(true);
    const value=goldenReview.matched;vi.setSystemTime(value.serverNow);
    vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?{...session,serverNow:value.serverNow}:path.endsWith('/service-review')?value:{...actionView(),deviceId:value.incident.deviceId,serverNow:value.serverNow}) as never);
    render(<WindowsServiceIncidentReview incidentKey={value.incident.key} deviceId={value.incident.deviceId} serviceName={value.incident.serviceName} sessionKey={windowsCapacitySession} onClose={vi.fn()}/>);await flush();
    expect(screen.getByText('Fixture service')).toBeInTheDocument();expect(document.querySelector('.windows-service-incident-review time')).toHaveAttribute('datetime',value.incident.openedAt);expect(screen.getByRole('button',{name:/Select service:/})).toBeInTheDocument();
    expect(vi.mocked(request).mock.calls.find(([path])=>path.endsWith('/windows-service-actions'))?.[1]?.headers).toEqual({[WINDOWS_SERVICE_REVIEW_HEADER]:value.control.bindingDigest});expect(mutateRaw).not.toHaveBeenCalled();
});

it.each(['2026-10-07T12:00:09Z','2026-10-07T12:02:10Z'])('rejects contextual status outside the original trusted review time range: %s', async serverNow => {
    vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?session:path===reviewPath?response:{...actionView(),serverNow}) as never);renderReview();await flush();expect(screen.queryByRole('button',{name:/Select service:/})).toBeNull();expect(screen.getByRole('alert')).toHaveTextContent('unavailable or changed');expect(mutateRaw).not.toHaveBeenCalled();
});


it('does not reset an original review lifetime by reopening an unchanged server timestamp', async () => {
    const ui=renderReview();await flush();expect(screen.getByRole('button',{name:/Select service:/})).toBeInTheDocument();ui.unmount();await act(async()=>vi.advanceTimersByTime(120000));renderReview();await flush();expect(screen.queryByRole('button',{name:/Select service:/})).toBeNull();expect(screen.getByRole('alert')).toHaveTextContent('expired');expect(mutateRaw).not.toHaveBeenCalled();
});

it.each(['blur','hidden'] as const)('restoring the inbox after %s requires a new explicit service review click', async loss => {
    render(<WindowsIncidentInbox devices={[windowsCapacityDevice()]} sessionKey={windowsCapacitySession} admin={false}/>);fireEvent.click(screen.getByRole('button',{name:'Windows incidents'}));await flush();fireEvent.click(screen.getByRole('button',{name:/^Review service:/}));await flush();
    const visibility=vi.spyOn(document,'visibilityState','get');
    act(()=>{if(loss==='hidden'){visibility.mockReturnValue('hidden');document.dispatchEvent(new Event('visibilitychange'));}else window.dispatchEvent(new Event('blur'));});
    expect(screen.queryByRole('region',{name:'Review incident service'})).toBeNull();
    act(()=>{if(loss==='hidden'){visibility.mockReturnValue('visible');document.dispatchEvent(new Event('visibilitychange'));}else window.dispatchEvent(new Event('focus'));});await flush();
    expect(screen.getByRole('button',{name:/^Review service:/})).toBeInTheDocument();expect(screen.queryByRole('region',{name:'Review incident service'})).toBeNull();expect(vi.mocked(request).mock.calls.filter(([path])=>path===reviewPath)).toHaveLength(1);expect(mutateRaw).not.toHaveBeenCalled();
});
