import { act, cleanup, fireEvent, render, renderHook, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, APIError, AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { AuthBoundary, useOperator } from './auth';
import { ApplicationIncidentWorkspace } from './application-incidents';
import { useApplicationIncidents } from './application-incidents-resource';
import { APPLICATION_INCIDENT_BYTES, validApplicationIncidents } from './application-incidents-types';
import type { ApplicationIncidentsView, IncidentRequest } from './application-incidents-types';
import { IncidentWorkQueue } from './incident-work-queue';
import type { InvestigationsResource } from './investigations-resource';
import { useWindowsIncidentInbox } from './windows-incident-inbox-resource';
import { setLocale } from './i18n';
import goFixture from './application-incidents-go-fixture.json';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
vi.mock('./windows-incident-inbox-resource', () => ({ useWindowsIncidentInbox: vi.fn() }));
vi.mock('./manager-readiness-panel', () => ({ ManagerReadinessPanel: () => null }));
const now = '2026-11-04T16:00:00Z';
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: '2026-11-04T18:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
const flush = () => act(async () => {});
const advance = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
function fixture(): ApplicationIncidentsView {
    const view = structuredClone(goFixture) as ApplicationIncidentsView;
    view.serverNow = now;
    view.checks[0].observedAt = '2026-11-04T15:59:59Z';
    view.checks[0].completedAt = '2026-11-04T15:59:59.5Z';
    return view;
}
function history(): ApplicationIncidentsView {
    const view = fixture(), original = view.incidents[0];
    view.earlierOmitted = true;
    view.incidents.push({ ...structuredClone(original), id: 'appincident_0000000000000002', kind: 'http', targetScheme: 'http', acknowledgedAt: '2026-11-04T15:56:00.000000001Z' });
    // A same-named retired target must never join the current selected check.
    view.incidents.push({ ...structuredClone(original), id: 'appincident_0000000000000003', kind: 'dns', targetScheme: null, state: 'recovered', sourceCurrent: false,
        opening: { ...original.opening, reason: 'dns_failed', httpStatus: null },
        lastObservedAt: '2026-11-04T15:57:00Z', lastCompletedAt: '2026-11-04T15:57:01Z', closedAt: '2026-11-04T15:57:01Z',
        recovery: { firstObservedAt: '2026-11-04T15:56:00Z', observedAt: '2026-11-04T15:57:00Z', completedAt: '2026-11-04T15:57:01Z', samples: 2 } });
    view.incidents.push({ ...structuredClone(original), id: 'appincident_0000000000000004', kind: 'tcp', targetScheme: null, state: 'monitoring_stopped', sourceCurrent: false,
        opening: { ...original.opening, reason: 'tcp_failed', httpStatus: null } });
    if (!validApplicationIncidents(view)) throw new Error('Invalid history fixture');
    return view;
}
const panel = () => screen.getByRole('region', { name: 'Manager application incidents' });
const reload = () => fireEvent.click(within(panel()).getByRole('button', { name: 'Reload local incidents' }));
async function start(view = fixture()) { vi.mocked(request).mockResolvedValue(view); const mounted = render(<ApplicationIncidentWorkspace/>); await flush(); return mounted; }
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime(now); localStorage.clear(); sessionStorage.clear(); setLocale('en', false);
    vi.spyOn(document, 'hasFocus').mockReturnValue(true); vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
    vi.mocked(useOperator).mockReturnValue(operator); vi.mocked(request).mockReset().mockResolvedValue(fixture()); vi.mocked(mutateRaw).mockReset();
    vi.mocked(useWindowsIncidentInbox).mockReturnValue({ view: null, loading: false, error: false, age: 0, refresh: vi.fn() } as unknown as ReturnType<typeof useWindowsIncidentInbox>);
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('independent application incident workspace', () => {
    it('reuses the bounded Go DTO and exact UTC evidence without controls even for administrators', async () => {
        vi.setSystemTime(goFixture.serverNow); await start(structuredClone(goFixture) as ApplicationIncidentsView);
        expect(within(panel()).getByText('fixture · HTTPS · Open')).toBeVisible();
        for (const timestamp of [goFixture.serverNow, goFixture.incidents[0].opening.firstObservedAt, goFixture.incidents[0].opening.completedAt]) {
            expect(panel().querySelector(`time[datetime="${timestamp}"]`)).not.toBeNull();
        }
        expect(panel().querySelector('form, input, select')).toBeNull();
        expect(within(panel()).getAllByRole('button')).toHaveLength(1);
        expect(request).toHaveBeenCalledWith('/application-checks/incidents', expect.objectContaining({ cache: 'no-store', redirect: 'error', signal: expect.any(AbortSignal) }), APPLICATION_INCIDENT_BYTES);
        expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('preserves HTTP/HTTPS/DNS/TCP identities, seen and recovery versus stopped history including unknown close time', async () => {
        const view = history(), before = JSON.stringify(view); await start(view);
        const rows = panel().querySelectorAll('.application-incident-card'); expect(rows).toHaveLength(4);
        expect(rows[0]).toHaveTextContent('fixture · HTTPS · Open'); expect(rows[0]).toHaveTextContent('Not seen');
        expect(rows[1]).toHaveTextContent('fixture · HTTP · Open'); expect(rows[1].querySelector('time[datetime="2026-11-04T15:56:00.000000001Z"]')).not.toBeNull();
        expect(rows[2]).toHaveTextContent('fixture · DNS · Recovery confirmed'); expect(rows[2]).toHaveTextContent('Previous configuration');
        expect(rows[3]).toHaveTextContent('fixture · TCP · Monitoring stopped'); expect(rows[3]).toHaveTextContent('Close time unknown after clock change.');
        expect(rows[3]).not.toHaveTextContent('Recovery confirmed');
        view.incidents.forEach((incident, index) => expect(rows[index]).toHaveTextContent(incident.id));
        expect(panel()).toHaveTextContent('Retained application incidents: 4'); expect(panel()).toHaveTextContent('Earlier closed incidents were omitted');
        expect(JSON.stringify(view)).toBe(before); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('renders in the real central workspace independently of device rows, filters, comparisons and queue refresh', async () => {
        const linux: InvestigationsResource = { view: null, counts: null, readiness: 'unknown', pending: false, failure: null, locked: false, refresh: vi.fn() };
        const props = { devices: [], sessionKey: operator.expiresAt, linux, scope: 'active' as const, onScope: vi.fn(), linuxOffset: 0, onLinuxPage: vi.fn() };
        const mounted = render(<IncidentWorkQueue {...props}/>); await flush();
        expect(panel()).toHaveTextContent('fixture · HTTPS · Open');
        expect(screen.getByRole('region', { name: 'Incident work queue' })).not.toHaveTextContent('appincident_');
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'no-device-match' } });
        fireEvent.change(screen.getByLabelText('Platform on loaded pages'), { target: { value: 'windows' } });
        fireEvent.change(screen.getByLabelText('Seen on loaded pages'), { target: { value: 'seen' } });
        mounted.rerender(<IncidentWorkQueue {...props} scope="all" linuxOffset={50}/>);
        expect(panel()).toHaveTextContent('fixture · HTTPS · Open'); expect(request).toHaveBeenCalledTimes(1);
        fireEvent.click(screen.getByRole('button', { name: 'Refresh work queue' })); await flush();
        expect(request).toHaveBeenCalledTimes(1);
        reload(); await flush(); expect(request).toHaveBeenCalledTimes(2); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it.each([true, false])('keeps disabled external history visible with canManage=%s and no mutation path', async canManage => {
        const view = history(); view.canManage = canManage; view.currentSource = { ...view.currentSource, mode: 'external', checksEnabled: false, intervalSeconds: 0, maxAgeSeconds: 0, targets: [] };
        view.policy = { enabled: false, sourceMatches: false, targetIds: [], enabledAt: null, consecutiveFailures: 2 }; view.checks = [];
        await start(view); expect(panel()).toHaveTextContent('External startup configuration'); expect(panel()).toHaveTextContent('Checks disabled.');
        expect(panel().querySelectorAll('.application-incident-card')).toHaveLength(4); expect(within(panel()).getAllByRole('button')).toHaveLength(1);
        reload(); await flush(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('translates into German without another read or altering the evidence', async () => {
        await start(history()); act(() => setLocale('de', false));
        const german = screen.getByRole('region', { name: 'Anwendungsvorfälle des Managers' });
        expect(german).toHaveTextContent('Gespeicherte Anwendungsvorfälle: 4'); expect(german).toHaveTextContent('fixture · TCP · Überwachung beendet');
        expect(german).toHaveTextContent('fixture · DNS · Erholung bestätigt'); expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('clears the entire expired snapshot without polling or inventing an empty history', async () => {
        await start(history()); expect(panel().querySelector('.application-incident-checks')).toHaveTextContent('Open incident retained');
        // A fresh snapshot still expires after one minute, before this source's 70-second age limit.
        await advance(60000);
        expect(panel().querySelector('.application-incident-checks')).toBeNull(); expect(panel().querySelector('.application-incident-list')).toBeNull();
        expect(panel()).not.toHaveTextContent('Retained application incidents:'); expect(panel()).not.toHaveTextContent('No retained incidents.');
        expect(panel()).toHaveTextContent('Private view cleared.'); expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('preserves history while an older selected check becomes unknown before snapshot expiry', async () => {
        const view = history(); view.checks[0].observedAt = '2026-11-04T15:59:00Z'; view.checks[0].completedAt = '2026-11-04T15:59:01Z';
        await start(view); await advance(10000);
        expect(panel().querySelector('.application-incident-checks')).toHaveTextContent('Current outcome unknown');
        expect(panel().querySelector('.application-incident-checks')).not.toHaveTextContent('503');
        expect(panel().querySelector('.application-incident-list')).toHaveTextContent('503');
        expect(panel().querySelectorAll('.application-incident-open')).toHaveLength(2); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it.each(['blur', 'pagehide', 'hashchange', 'popstate'])('clears private evidence on %s and requires an explicit reload after returning', async event => {
        await start(); act(() => window.dispatchEvent(new Event(event))); expect(panel()).not.toHaveTextContent('fixture · HTTPS · Open');
        act(() => { window.dispatchEvent(new Event('focus')); window.dispatchEvent(new Event('pageshow')); }); await flush();
        expect(request).toHaveBeenCalledTimes(1); reload(); await flush(); expect(request).toHaveBeenCalledTimes(2);
        expect(panel()).toHaveTextContent('fixture · HTTPS · Open'); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('aborts a hidden in-flight read and rejects its late completion without background refresh', async () => {
        const held = deferred<ApplicationIncidentsView>(); vi.mocked(request).mockReturnValue(held.promise); render(<ApplicationIncidentWorkspace/>); await flush();
        const signal = vi.mocked(request).mock.calls[0][1]?.signal;
        vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange')));
        expect(signal?.aborted).toBe(true); await act(async () => held.resolve(fixture())); expect(panel()).not.toHaveTextContent('fixture');
        vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible'); act(() => document.dispatchEvent(new Event('visibilitychange'))); await flush();
        expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('clears an expired session earlier than the one-minute snapshot limit', async () => {
        vi.mocked(useOperator).mockReturnValue({ ...operator, expiresAt: '2026-11-04T16:00:05Z' }); await start(); await advance(5000);
        expect(panel()).not.toHaveTextContent('fixture · HTTPS · Open'); expect(request).toHaveBeenCalledTimes(1);
    });
    it.each(['actor', 'session'] as const)('rejects old pending evidence after an authenticated %s change', async change => {
        const held = deferred<ApplicationIncidentsView>(); vi.mocked(request).mockReturnValueOnce(held.promise).mockResolvedValueOnce({ ...fixture(), incidents: [] });
        const mounted = render(<ApplicationIncidentWorkspace/>); await flush(); const signal = vi.mocked(request).mock.calls[0][1]?.signal;
        vi.mocked(useOperator).mockReturnValue({ ...operator, ...(change === 'actor' ? { loginMode: 'named' as const, actorId: 'replacement', capabilities: ['read' as const] } : { expiresAt: '2026-11-04T18:01:00Z' }) });
        mounted.rerender(<ApplicationIncidentWorkspace/>); await flush(); expect(signal?.aborted).toBe(true);
        await act(async () => held.resolve(history())); expect(panel()).not.toHaveTextContent('appincident_'); expect(panel()).toHaveTextContent('No retained incidents.'); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('locks and clears a rejected session without retrying reads or exposing raw errors', async () => {
        await start(); vi.mocked(request).mockRejectedValue(new APIError('private backend message', 401)); reload(); await flush();
        expect(panel()).toHaveTextContent('Session ended.'); expect(panel()).not.toHaveTextContent('private backend message'); expect(panel()).not.toHaveTextContent('appincident_');
        expect(within(panel()).getByRole('button')).toBeDisabled(); expect(request).toHaveBeenCalledTimes(2); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('rejects pending completion after authentication invalidation and unmount', async () => {
        const held = deferred<ApplicationIncidentsView>(); vi.mocked(request).mockReturnValue(held.promise); const mounted = render(<ApplicationIncidentWorkspace/>); await flush();
        act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); expect(vi.mocked(request).mock.calls[0][1]?.signal?.aborted).toBe(true);
        await act(async () => held.resolve(history())); expect(panel()).not.toHaveTextContent('appincident_'); mounted.unmount(); await advance(60000);
        expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it.each(['failure', 'malformed'] as const)('never presents unavailable %s as an empty or zero-count success', async failure => {
        if (failure === 'failure') vi.mocked(request).mockRejectedValue(new Error('private endpoint detail'));
        else vi.mocked(request).mockResolvedValue({ ...fixture(), incidents: [{ ...fixture().incidents[0], state: 'healthy' }] });
        render(<ApplicationIncidentWorkspace/>); await flush(); expect(panel()).toHaveTextContent('Local incidents unavailable.');
        expect(panel()).not.toHaveTextContent('private endpoint detail'); expect(panel()).not.toHaveTextContent('No retained incidents.'); expect(panel()).not.toHaveTextContent('Retained application incidents:');
        expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('keeps original times with an unreliable manager clock and never infers recovery', async () => {
        const view = history(); view.clockReliable = false; view.serverNow = '2026-11-04T15:00:00Z';
        view.checks = view.checks.map(check => ({ ...check, condition: 'unknown', observedAt: null, completedAt: null, reason: null, httpStatus: null, failureCount: 0, successCount: 0 }));
        await start(view); expect(panel()).toHaveTextContent('Manager clock is unreliable.'); expect(panel().querySelectorAll('.application-incident-open')).toHaveLength(2);
        expect(panel().querySelector(`time[datetime="${view.incidents[0].opening.firstObservedAt}"]`)).not.toBeNull(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it.each(['signed-out', 'development'] as const)('does not mount or read for %s', state => {
        vi.mocked(useOperator).mockReturnValue({ ...operator, ...(state === 'signed-out' ? { authenticated: false } : { mode: 'development' as const }) });
        render(<ApplicationIncidentWorkspace/>); expect(screen.queryByRole('region', { name: 'Manager application incidents' })).toBeNull(); expect(request).not.toHaveBeenCalled();
    });
    it('rejects writes at the shared resource boundary in read-only mode even if canManage is true', async () => {
        const view = fixture(); const { result } = renderHook(() => useApplicationIncidents(true, 'read-only-resource', operator.expiresAt, true)); await flush();
        expect(result.current.view?.canManage).toBe(true);
        const body: IncidentRequest = { requestId: `apprequest_${'a'.repeat(32)}`, operation: 'acknowledge', expectedRevision: view.revision, sourceToken: view.currentSource.token, incidentId: view.incidents[0].id, targetIds: [], consecutiveFailures: 0, retentionAcknowledged: false };
        await act(async () => { expect(await result.current.write(body)).toBe(false); });
        expect(mutateRaw).not.toHaveBeenCalled(); expect(result.current.view).toEqual(view); expect(result.current.uncertain).toBeNull();
    });
    it('leaves an earlier unconfirmed administration request for its original controls to reconcile', async () => {
        const view = fixture();
        const { result, rerender } = renderHook(({ readOnly }) => useApplicationIncidents(true, 'shared-reconciliation-scope', operator.expiresAt, readOnly), { initialProps: { readOnly: false } });
        await flush();
        const body: IncidentRequest = { requestId: `apprequest_${'b'.repeat(32)}`, operation: 'acknowledge', expectedRevision: view.revision, sourceToken: view.currentSource.token, incidentId: view.incidents[0].id, targetIds: [], consecutiveFailures: 0, retentionAcknowledged: false };
        vi.mocked(mutateRaw).mockRejectedValue(new Error('Lost response'));
        await act(async () => { expect(await result.current.write(body)).toBe(false); });
        expect(result.current.uncertain).toEqual(body);
        const saved = structuredClone(view); saved.revision = String(BigInt(view.revision) + 1n);
        saved.lastRequest = { requestId: body.requestId, operation: body.operation, sourceToken: body.sourceToken, incidentId: body.incidentId };
        saved.incidents[0].acknowledgedAt = now; vi.mocked(request).mockResolvedValue(saved);
        rerender({ readOnly: true }); await flush();
        expect(result.current.view).toEqual(saved); expect(result.current.uncertain).toEqual(body); expect(result.current.confirmed).toBe(false);
        rerender({ readOnly: false }); await flush();
        expect(result.current.uncertain).toBeNull(); expect(result.current.confirmed).toBe(true); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });

    it('waits for explicit reload after a first mount during access revalidation', async () => {
        vi.mocked(useOperator).mockReturnValue({ ...operator, checkingAccess: true });
        const mounted = render(<ApplicationIncidentWorkspace/>); await flush();
        expect(request).not.toHaveBeenCalled(); expect(within(panel()).getByRole('button')).toBeDisabled();
        vi.mocked(useOperator).mockReturnValue({ ...operator, checkingAccess: false });
        mounted.rerender(<ApplicationIncidentWorkspace/>); await flush(); expect(request).not.toHaveBeenCalled();
        reload(); await flush(); expect(request).toHaveBeenCalledTimes(1); expect(panel()).toHaveTextContent('fixture · HTTPS · Open');
    });
    it('aborts and ignores an in-flight read across access revalidation without automatic resumption', async () => {
        const held = deferred<ApplicationIncidentsView>(); vi.mocked(request).mockReturnValueOnce(held.promise).mockResolvedValue(fixture());
        const mounted = render(<ApplicationIncidentWorkspace/>); await flush(); const signal = vi.mocked(request).mock.calls[0][1]?.signal;
        vi.mocked(useOperator).mockReturnValue({ ...operator, checkingAccess: true }); mounted.rerender(<ApplicationIncidentWorkspace/>); await flush();
        expect(signal?.aborted).toBe(true); await act(async () => held.resolve(fixture())); expect(panel()).not.toHaveTextContent('appincident_');
        vi.mocked(useOperator).mockReturnValue({ ...operator, checkingAccess: false }); mounted.rerender(<ApplicationIncidentWorkspace/>); await flush();
        expect(request).toHaveBeenCalledTimes(1); expect(panel()).not.toHaveTextContent('appincident_');
        reload(); await flush(); expect(request).toHaveBeenCalledTimes(2); expect(panel()).toHaveTextContent('fixture · HTTPS · Open');
    });
    it('keeps the real AuthBoundary hide/revalidate/return flow cleared until explicit reload', async () => {
        const originalAuth = await vi.importActual<typeof import('./auth')>('./auth');
        vi.mocked(useOperator).mockImplementation(originalAuth.useOperator);
        const session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'fixture-only', serverNow: now, expiresAt: operator.expiresAt, expiresInSeconds: 7200, loginMode: 'shared', actorId: null, capabilities: ['read'] };
        const revalidation = deferred<typeof session>(); let sessionReads = 0, incidentReads = 0;
        vi.mocked(request).mockImplementation(async path => {
            if (path === '/auth/session') return ++sessionReads === 1 ? session : revalidation.promise;
            if (path === '/application-checks/incidents') { incidentReads++; return fixture(); }
            throw new Error('Unexpected request');
        });
        render(<AuthBoundary><ApplicationIncidentWorkspace/></AuthBoundary>); await flush(); expect(incidentReads).toBe(1); expect(panel()).toHaveTextContent('fixture · HTTPS · Open');
        vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); await flush();
        expect(document.querySelector('.application-incidents-workspace')).not.toHaveTextContent('appincident_');
        vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible'); act(() => document.dispatchEvent(new Event('visibilitychange'))); await flush();
        expect(sessionReads).toBe(2); expect(incidentReads).toBe(1);
        await act(async () => revalidation.resolve(session)); await flush();
        expect(panel()).not.toHaveTextContent('appincident_'); expect(incidentReads).toBe(1);
        reload(); await flush(); expect(incidentReads).toBe(2); expect(panel()).toHaveTextContent('fixture · HTTPS · Open'); expect(mutateRaw).not.toHaveBeenCalled();
    });

});
