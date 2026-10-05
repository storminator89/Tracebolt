import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, AUTH_REQUIRED_EVENT, abortProtectedRequests, mutate, request } from './api';
import { HealthPanel } from './health';
import { DeviceDetail } from './details';
import { useOperator } from './auth';
import type { Device } from './types';
import { parseHealthServices, validHealthView } from './health-types';
import type { HealthView } from './health-types';
import { setLocale } from './i18n';
import goFixture from './health-go-fixture.json';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
// Keep health request/lifecycle assertions independent of the separately tested inventory reader.
vi.mock('./system-inventory-resource', () => ({ useSystemInventory: () => ({
    view: { status: 'not_configured', lastComplete: { services: null }, latest: null }, page: null,
    loading: false, error: null, search: '', elapsed: 0, scanned: 0, matches: 0,
    refresh: vi.fn(), changeSearch: vi.fn(), startSearch: vi.fn(), next: vi.fn(),
}) }));
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: null, insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
const id = 'agent_health_fixture', now = '2026-10-05T00:05:00Z';
function fixture(deviceId = id): HealthView {
    return {
        schemaVersion: 'tracebolt.health-view.v1', deviceId, serverNow: now, evaluatedAt: now, status: 'attention', maintenanceUntil: null,
        monitoredServices: ['sshd.service'],
        checks: [
            { key: 'offline:contact', kind: 'offline', target: 'agent', state: 'ok', observedAt: now, value: 0 },
            { key: 'filesystem:root', kind: 'filesystem', target: '/', state: 'open', observedAt: now, value: 94 },
            { key: 'service:sshd.service', kind: 'service', target: 'sshd.service', state: 'unknown', observedAt: null, value: null },
        ],
        incidents: [{ id: 'health_fixture_1', key: 'filesystem:root', kind: 'filesystem', target: '/', openedAt: '2026-10-05T00:01:00Z', lastObservedAt: now, resolvedAt: null, acknowledgedAt: null }],
    };
}
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(r => { resolve = r; }); return { resolve, promise }; }
beforeEach(() => {
    setLocale('en', false); localStorage.clear(); sessionStorage.clear(); vi.mocked(useOperator).mockReturnValue(operator);
    vi.mocked(request).mockReset().mockResolvedValue(fixture()); vi.mocked(mutate).mockReset().mockResolvedValue(fixture());
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('health response boundaries', () => {
    it('accepts and renders the exact Go evaluator fixture including delayed source times', async () => {
        expect(validHealthView(goFixture, goFixture.deviceId)).toBe(true);
        const incident = goFixture.incidents[0]; expect(Date.parse(incident.lastObservedAt)).toBeLessThan(Date.parse(incident.openedAt));
        vi.mocked(request).mockResolvedValue(goFixture); render(<HealthPanel deviceId={goFixture.deviceId}/>);
        expect(await screen.findByRole('list', { name: 'Alert history' })).toHaveTextContent('Alert open');
        expect(screen.getByRole('list', { name: 'Current checks' })).toHaveTextContent('Root filesystem /');
    });
    it('accepts selected checks and bounded history with explicitly stopped monitoring', () => {
        const view = fixture(); view.incidents[0].resolvedAt = now; view.incidents[0].closedReason = 'monitoring_stopped'; expect(validHealthView(view, id)).toBe(true);
    });
    it.each([
        (v: HealthView) => { v.deviceId = 'agent_other'; },
        (v: HealthView) => { v.checks[1].target = '/home'; },
        (v: HealthView) => { v.checks[1].value = Infinity; },
        (v: HealthView) => { v.checks[1].value = 101; },
        (v: HealthView) => { v.evaluatedAt = '2026-10-05T00:00:00Z'; },
        (v: HealthView) => { v.evaluatedAt = null; },
        (v: HealthView) => { v.checks[1].observedAt = '2026-10-05T00:00:00Z'; },
        (v: HealthView) => { v.status = 'clear'; },
        (v: HealthView) => { v.checks[1].observedAt = '2026-10-06T00:05:00Z'; },
        (v: HealthView) => { v.checks[1].observedAt = '2026-02-31T00:05:00Z'; },
        (v: HealthView) => { v.checks.pop(); },
        (v: HealthView) => { v.checks[1] = v.checks[0]; },
        (v: HealthView) => { v.monitoredServices = ['sshd.service', 'sshd.service']; },
        (v: HealthView) => { v.incidents.push(v.incidents[0]); },
        (v: HealthView) => { v.incidents[0].closedReason = 'recovered'; },
    ])('rejects inconsistent or unbounded data %#', change => { const view = fixture(); change(view); expect(validHealthView(view, id)).toBe(false); });
    it('preserves original observation timestamps when transport delay predates incident opening', () => {
        const view = fixture(); view.incidents[0].lastObservedAt = '2026-10-05T00:00:59Z'; expect(validHealthView(view, id)).toBe(true);
    });
    it('validates explicit service names, rejects duplicates and wildcards, and permits clearing selection', () => {
        expect(parseHealthServices('z.service, a@b.service\nsshd.service')).toEqual(['a@b.service', 'sshd.service', 'z.service']);
        expect(parseHealthServices('')).toEqual([]);
        for (const value of ['*.service', '../sshd.service', 'sshd', 'x.service x.service', Array.from({ length: 9 }, (_, i) => `a${i}.service`).join('\n'), `${'a'.repeat(120)}.service`]) expect(parseHealthServices(value)).toBeNull();
    });
});

describe('selected health checks and controls', () => {
    it('shows limited check scope, unknown service, source times and incident history without an overall-health claim', async () => {
        render(<HealthPanel deviceId={id}/>); await screen.findByText('Selected checks need attention.');
        const checks = screen.getByRole('list', { name: 'Current checks' });
        expect(checks).toHaveTextContent('Unknown'); expect(checks).toHaveTextContent('94.0% used'); expect(checks).toHaveTextContent('Time unknown');
        expect(screen.getByText(/manager must be running/)).not.toBeVisible(); expect(screen.getByText('Agent contact · root filesystem / · selected services')).toBeVisible(); expect(document.body).not.toHaveTextContent('Device is healthy');
        expect(screen.getByRole('list', { name: 'Alert history' })).toHaveTextContent('Opened'); expect(document.querySelector(`time[datetime="${now}"]`)).not.toBeNull();
        expect(request).toHaveBeenCalledWith(`/devices/${id}/health`, expect.objectContaining({ signal: expect.any(AbortSignal) }), 131072);
    });
    it('opens scope details through native disclosure without changing the service draft or saving', async () => {
        render(<HealthPanel deviceId={id}/>);
        const editor = await screen.findByRole('textbox', { name: 'Add an exact systemd service manually' });
        fireEvent.change(editor, { target: { value: 'edited.service' } });
        fireEvent.click(screen.getByRole('button', { name: 'Add service' }));
        const summary = screen.getByText('Check scope & limits', { selector: 'summary' });
        expect(summary.parentElement).not.toHaveAttribute('open');
        expect(screen.getByText('Selected checks need attention.')).toBeVisible();
        expect(within(screen.getByRole('list', { name: 'Current checks' })).getByText('Unknown')).toBeVisible();
        summary.focus();
        fireEvent.click(summary);
        expect(summary.parentElement).toHaveAttribute('open');
        expect(screen.getByText(/manager must be running/)).toBeVisible();
        fireEvent.click(summary);
        expect(summary.parentElement).not.toHaveAttribute('open');
        expect(summary).toHaveFocus();
        expect(screen.getByRole('list', { name: 'Selected services' })).toHaveTextContent('edited.service');
        expect(screen.getByRole('button', { name: 'Save service selection' })).toBeEnabled();
        expect(request).toHaveBeenCalledTimes(1);
        expect(mutate).not.toHaveBeenCalled();
        act(() => setLocale('de', false));
        expect(screen.getByText('Prüfumfang & Grenzen', { selector: 'summary' })).toBe(summary);
        expect(screen.getByRole('list', { name: 'Ausgewählte Dienste' })).toHaveTextContent('edited.service');
    });
    it('acknowledges exactly one incident and does not locally resolve it', async () => {
        const result = fixture(); result.incidents[0].acknowledgedAt = now; vi.mocked(mutate).mockResolvedValue(result);
        render(<HealthPanel deviceId={id}/>); fireEvent.click(await screen.findByRole('button', { name: 'Acknowledge alert: Root filesystem /' }));
        await screen.findByText('Acknowledged'); expect(mutate).toHaveBeenCalledWith(`/devices/${id}/health/acknowledge`, { incidentId: 'health_fixture_1' }, expect.any(AbortSignal));
        expect(screen.getByRole('list', { name: 'Alert history' })).toHaveTextContent('Alert open'); expect(screen.queryByRole('button', { name: /Acknowledge alert:/ })).not.toBeInTheDocument();
    });
    it('distinguishes monitoring stopped from recovered', async () => {
        const view = fixture(); view.incidents[0].resolvedAt = now; view.incidents[0].closedReason = 'monitoring_stopped'; vi.mocked(request).mockResolvedValue(view);
        render(<HealthPanel deviceId={id}/>); await screen.findByText('Monitoring stopped'); expect(screen.queryByText('Recovered')).not.toBeInTheDocument();
    });
    it('submits only bounded maintenance durations', async () => {
        const view = fixture(); view.status = 'maintenance'; view.maintenanceUntil = '2026-10-05T04:05:00Z'; vi.mocked(mutate).mockResolvedValue(view);
        render(<HealthPanel deviceId={id}/>); const select = await screen.findByRole('combobox', { name: 'Duration from now' });
        expect(within(select).getAllByRole('option').map(x => (x as HTMLOptionElement).value)).toEqual(['15', '60', '240', '0']);
        fireEvent.change(select, { target: { value: '240' } }); fireEvent.click(screen.getByRole('button', { name: 'Apply maintenance' })); await screen.findByText('Maintenance window active.');
        expect(mutate).toHaveBeenCalledWith(`/devices/${id}/health/maintenance`, { minutes: 240 }, expect.any(AbortSignal));
    });
    it('validates service edits and submits the explicit sorted selection', async () => {
        const view = fixture(); view.monitoredServices = ['nginx.service', 'sshd.service']; view.checks.push({ key: 'service:nginx.service', kind: 'service', target: 'nginx.service', state: 'unknown', observedAt: null, value: null }); vi.mocked(mutate).mockResolvedValue(view);
        render(<HealthPanel deviceId={id}/>); const editor = await screen.findByRole('textbox', { name: 'Add an exact systemd service manually' });
        fireEvent.change(editor, { target: { value: '*.service' } }); expect(screen.getByRole('button', { name: 'Add service' })).toBeDisabled(); expect(screen.getByRole('button', { name: 'Save service selection' })).toBeDisabled(); expect(mutate).not.toHaveBeenCalled();
        fireEvent.change(editor, { target: { value: 'nginx.service' } }); fireEvent.click(screen.getByRole('button', { name: 'Add service' })); expect(mutate).not.toHaveBeenCalled(); fireEvent.click(screen.getByRole('button', { name: 'Save service selection' }));
        await waitFor(() => expect(within(screen.getByRole('list', { name: 'Selected services' })).getAllByRole('listitem').map(row => row.querySelector('span')!.textContent)).toEqual(['nginx.service', 'sshd.service']));
        expect(mutate).toHaveBeenCalledWith(`/devices/${id}/health/services`, { services: ['nginx.service', 'sshd.service'] }, expect.any(AbortSignal));
    });
    it('reports mutation failures without displaying raw server text and requires a new read before retry', async () => {
        vi.mocked(mutate).mockRejectedValue(new APIError('raw secret from server', 503)); render(<HealthPanel deviceId={id}/>);
        fireEvent.click(await screen.findByRole('button', { name: /Acknowledge alert:/ })); await screen.findByRole('alert');
        expect(screen.getByRole('alert')).toHaveTextContent('Change not confirmed'); expect(document.body).not.toHaveTextContent('raw secret'); expect(screen.queryByRole('button', { name: /Acknowledge alert:/ })).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Refresh health' })); await screen.findByRole('button', { name: /Acknowledge alert:/ }); expect(request).toHaveBeenCalledTimes(2); expect(mutate).toHaveBeenCalledTimes(1);
    });
    it('suppresses repeated mutation clicks and ignores an unmounted reply', async () => {
        const d = deferred<HealthView>(); vi.mocked(mutate).mockReturnValue(d.promise); const { unmount } = render(<HealthPanel deviceId={id}/>);
        const button = await screen.findByRole('button', { name: /Acknowledge alert:/ }); fireEvent.click(button); fireEvent.click(button); expect(mutate).toHaveBeenCalledTimes(1);
        const signal = vi.mocked(mutate).mock.calls[0][2]!; unmount(); expect(signal.aborted).toBe(true); await act(async () => d.resolve(fixture())); expect(screen.queryByText('Alert history')).not.toBeInTheDocument();
    });
    it('renders German controls and localized error messages', async () => {
        setLocale('de', false); vi.mocked(request).mockRejectedValue(new Error('raw failure')); render(<HealthPanel deviceId={id}/>);
        expect(screen.getByRole('heading', { name: 'Health & Verlauf' })).toBeVisible(); expect(await screen.findByRole('alert')).toHaveTextContent('Health-Daten konnten nicht gelesen werden');
    });
});

describe('health lifecycle and freshness', () => {
    it('rejects malformed responses instead of preserving previous current checks', async () => {
        vi.mocked(request).mockResolvedValueOnce(fixture()).mockResolvedValue({ ...fixture(), extra: 'sensitive value' }); render(<HealthPanel deviceId={id}/>); await screen.findByText(/94\.0% used/);
        fireEvent.click(screen.getByRole('button', { name: 'Refresh health' })); await screen.findByRole('alert'); expect(screen.queryByRole('list', { name: 'Current checks' })).not.toBeInTheDocument(); expect(document.body).not.toHaveTextContent('sensitive value');
    });
    it('discards late reads after device or session changes and aborts on unmount', async () => {
        const d = deferred<HealthView>(); vi.mocked(request).mockReturnValueOnce(d.promise); const { rerender, unmount } = render(<HealthPanel deviceId={id} sessionKey="first"/>);
        const signal = vi.mocked(request).mock.calls[0][1]!.signal!;
        const second = fixture('agent_second'); second.checks[1].value = 55; vi.mocked(request).mockResolvedValue(second); rerender(<HealthPanel deviceId="agent_second" sessionKey="first"/>);
        await screen.findByText(/55\.0% used/); expect(signal.aborted).toBe(true); await act(async () => d.resolve(fixture())); expect(screen.queryByText(/94\.0% used/)).not.toBeInTheDocument();
        const last = deferred<HealthView>(); vi.mocked(request).mockReturnValue(last.promise); rerender(<HealthPanel deviceId="agent_second" sessionKey="second"/>); const lastSignal = vi.mocked(request).mock.calls.at(-1)![1]!.signal!;
        unmount(); expect(lastSignal.aborted).toBe(true); await act(async () => last.resolve(second));
    });
    it('discards a mutation reply from the previous device', async () => {
        const d = deferred<HealthView>(); vi.mocked(mutate).mockReturnValue(d.promise); const { rerender } = render(<HealthPanel deviceId={id}/>);
        fireEvent.click(await screen.findByRole('button', { name: /Acknowledge alert:/ })); const signal = vi.mocked(mutate).mock.calls[0][2]!;
        const second = fixture('agent_second'); second.checks[1].value = 42; vi.mocked(request).mockResolvedValue(second); rerender(<HealthPanel deviceId="agent_second"/>);
        await screen.findByText(/42\.0% used/); expect(signal.aborted).toBe(true); await act(async () => d.resolve(fixture())); expect(screen.queryByText(/94\.0% used/)).not.toBeInTheDocument();
    });
    it('locks and conceals values on auth loss, without polling or focus restoring access', async () => {
        render(<HealthPanel deviceId={id}/>); await screen.findByText('Selected checks need attention.'); act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));
        expect(screen.queryByRole('list', { name: 'Current checks' })).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Refresh health' })).toBeDisabled();
        act(() => window.dispatchEvent(new Event('focus'))); expect(request).toHaveBeenCalledTimes(1);
    });
    it('rejects a response after the protected request epoch changes without a window event', async () => {
        const d = deferred<HealthView>(); vi.mocked(request).mockReturnValue(d.promise); render(<HealthPanel deviceId={id}/>);
        act(() => abortProtectedRequests()); await act(async () => d.resolve(fixture())); expect(screen.getByRole('alert')).toHaveTextContent('session expired'); expect(screen.queryByRole('list', { name: 'Current checks' })).not.toBeInTheDocument();
    });
    it('aborts on pagehide and reloads on return without repeating a mutation', async () => {
        const d = deferred<HealthView>(); vi.mocked(mutate).mockReturnValue(d.promise); render(<HealthPanel deviceId={id}/>); fireEvent.click(await screen.findByRole('button', { name: /Acknowledge alert:/ }));
        act(() => window.dispatchEvent(new Event('pagehide'))); expect(vi.mocked(mutate).mock.calls[0][2]!.aborted).toBe(true); await act(async () => d.resolve(fixture()));
        expect(screen.queryByRole('list', { name: 'Current checks' })).not.toBeInTheDocument(); act(() => window.dispatchEvent(new Event('pageshow'))); await screen.findByRole('list', { name: 'Current checks' }); expect(mutate).toHaveBeenCalledTimes(1);
    });
    it('refreshes every30s, preserves a dirty service draft, and clears values after a read timeout', async () => {
        vi.useFakeTimers(); const wall = Date.now(); vi.spyOn(performance, 'now').mockImplementation(() => Date.now() - wall);
        render(<HealthPanel deviceId={id}/>); await act(async () => {}); fireEvent.change(screen.getByRole('textbox'), { target: { value: 'edited.service' } }); fireEvent.click(screen.getByRole('button', { name: 'Add service' }));
        const summary = screen.getByText('Check scope & limits', { selector: 'summary' }); fireEvent.click(summary);
        const editor = screen.getByRole('textbox'); editor.focus();
        await act(async () => { vi.advanceTimersByTime(30000); }); expect(summary.parentElement).toHaveAttribute('open'); expect(editor).toHaveFocus(); expect(request).toHaveBeenCalledTimes(2); expect(screen.getByRole('list', { name: 'Selected services' })).toHaveTextContent('edited.service');
        vi.mocked(request).mockReturnValue(new Promise(() => {})); await act(async () => { vi.advanceTimersByTime(30000); }); await act(async () => { vi.advanceTimersByTime(10000); });
        expect(screen.getByRole('alert')).toHaveTextContent('not responding'); expect(screen.queryByRole('list', { name: 'Current checks' })).not.toBeInTheDocument();
    });
    it('ages original source timestamps to unknown between polls without resolving incidents', async () => {
        vi.useFakeTimers(); const wall = Date.now(); vi.spyOn(performance, 'now').mockImplementation(() => Date.now() - wall);
        const view = fixture(); view.checks[1].observedAt = '2026-10-05T00:03:01Z'; vi.mocked(request).mockResolvedValue(view);
        render(<HealthPanel deviceId={id}/>); await act(async () => {}); expect(screen.getByRole('list', { name: 'Current checks' })).toHaveTextContent('94.0% used');
        await act(async () => { vi.advanceTimersByTime(2000); });
        expect(screen.getByRole('list', { name: 'Current checks' })).not.toHaveTextContent('94.0% used');
        expect(screen.getByRole('list', { name: 'Alert history' })).toHaveTextContent('Alert open'); expect(request).toHaveBeenCalledTimes(1);
    });
    it('fails closed on manager clock rollback', async () => {
        vi.mocked(request).mockResolvedValueOnce(fixture()).mockResolvedValue({ ...fixture(), serverNow: '2026-10-04T00:00:00Z', evaluatedAt: null }); render(<HealthPanel deviceId={id}/>);
        await screen.findByText('Selected checks need attention.'); fireEvent.click(screen.getByRole('button', { name: 'Refresh health' })); await screen.findByRole('alert'); expect(screen.queryByRole('list', { name: 'Current checks' })).not.toBeInTheDocument();
    });
    it('does not write health snapshots or controls to browser storage', async () => {
        const spy = vi.spyOn(Storage.prototype, 'setItem'); render(<HealthPanel deviceId={id}/>); await screen.findByText('Selected checks need attention.'); expect(spy).not.toHaveBeenCalled();
    });
});


describe('health tab integration', () => {
    function device(): Device {
        const metric = { value: null, unit: '%', quality: 'unknown' as const, source: 'fixture', collectedAt: '0001-01-01T00:00:00Z' };
        return { id, name: 'Linux health fixture', platform: 'linux', os: 'Linux', source: 'lan', synthetic: false, status: 'unknown', site: '', group: '', ip: null, lastSeen: now, agentVersion: 'fixture', cpu: metric, memory: metric, disk: metric, uptime: '', tags: [], capabilities: [], evidence: [], trend: [], caseIds: [] };
    }
    it('loads only when its dedicated tab opens and aborts when switching away', async () => {
        const d = deferred<HealthView>(); vi.mocked(request).mockImplementation(async path => path.endsWith('/health') ? d.promise : device());
        render(<DeviceDetail id={id} onClose={() => {}} onCase={() => {}}/>); const tab = await screen.findByRole('tab', { name: 'Health & history' });
        expect(vi.mocked(request).mock.calls.some(([path]) => path.endsWith('/health'))).toBe(false);
        fireEvent.click(tab); const call = vi.mocked(request).mock.calls.find(([path]) => path.endsWith('/health'))!; expect(call).toBeDefined();
        fireEvent.click(screen.getByRole('tab', { name: 'Overview' })); expect(call[1]!.signal!.aborted).toBe(true); await act(async () => d.resolve(fixture()));
        expect(screen.queryByRole('heading', { name: 'Health & history' })).not.toBeInTheDocument();
    });
    it.each(['unknown', 'windows', 'macos', 'synthetic', 'local', 'signed-out'] as const)('does not expose health for %s', async kind => {
        const value = device();
        if (kind === 'synthetic') value.synthetic = true;
        else if (kind === 'local') value.source = 'local';
        else if (kind === 'signed-out') vi.mocked(useOperator).mockReturnValue({ ...operator, authenticated: false });
        else value.platform = kind;
        vi.mocked(request).mockResolvedValue(value); render(<DeviceDetail id={id} onClose={() => {}} onCase={() => {}}/>); await screen.findByRole('heading', { name: value.name });
        expect(screen.queryByRole('tab', { name: 'Health & history' })).not.toBeInTheDocument(); expect(vi.mocked(request).mock.calls.some(([path]) => path.endsWith('/health'))).toBe(false);
    });
});
