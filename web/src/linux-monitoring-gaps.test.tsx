import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import healthWire from './health-go-fixture.json';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT, mutate, request } from './api';
import { setLocale } from './i18n';
import { ageInvestigations, validInvestigationsView } from './investigations-types';
import type { InvestigationsView } from './investigations-types';
import { useInvestigations } from './investigations-resource';
import type { InvestigationsResource } from './investigations-resource';
import type { HealthView } from './health-types';
import type { Device } from './types';
import { useWindowsIncidentInbox } from './windows-incident-inbox-resource';
import { IncidentWorkQueue } from './incident-work-queue';
import { LinuxMonitoringGaps } from './linux-monitoring-gaps';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
vi.mock('./windows-incident-inbox-resource', () => ({ useWindowsIncidentInbox: vi.fn() }));
const id = healthWire.deviceId, second = `agent_${'b'.repeat(32)}`, now = healthWire.serverNow;
function source(): InvestigationsView {
    const health = structuredClone(healthWire) as HealthView;
    health.incidents = []; health.status = 'unknown';
    health.checks = health.checks.map(check => ({ ...check, state: check.kind === 'offline' ? 'ok' : 'unknown', value: null }));
    const other: HealthView = { ...structuredClone(health), deviceId: second, checks: health.checks.map(check => ({ ...check, state: check.kind === 'offline' ? 'unknown' : 'ok', value: check.kind === 'filesystem' ? 10 : null })) };
    const view: InvestigationsView = { schemaVersion: 'tracebolt.investigations.v1', serverNow: now, scope: 'open', offset: 0, total: 0, counts: { open: 0, recovered: 0, closed: 0, all: 0 }, devices: [other, health], items: [] };
    if (!validInvestigationsView(view, 'open', 0)) throw new Error('Invalid gap fixture');
    return view;
}
function device(deviceId: string, name: string, options: Partial<Device> = {}): Device {
    const metric = { value: null, unit: '%', quality: 'unknown' as const, source: 'fixture', collectedAt: now };
    return { id: deviceId, name, platform: 'linux', source: 'lan', synthetic: false, os: 'Linux', site: '', group: '', ip: null, status: 'unknown', lastSeen: now, agentVersion: '', cpu: metric, memory: metric, disk: metric, uptime: '', tags: [], capabilities: [], evidence: [], trend: [], caseIds: [], ...options };
}
function resource(view: InvestigationsView | null, locked = false): InvestigationsResource { return { view, counts: view?.counts ?? null, readiness: view ? 'ready' : 'unknown', pending: false, failure: null, locked, refresh: vi.fn() }; }
const queue = (view: InvestigationsView | null, sessionKey = 'session-a', locked = false) => <IncidentWorkQueue devices={[device(id, 'North'), device(second, 'South')]} sessionKey={sessionKey} linux={resource(view, locked)} scope="active" onScope={vi.fn()} linuxOffset={0} onLinuxPage={vi.fn()}/>;
const expand = (de = false) => fireEvent.click(screen.getByText(de ? /^Linux-Prüfungen ohne aktuelle Belege:/ : /^Linux checks without current evidence:/));
const flush = () => act(async () => {});
beforeEach(() => {
    localStorage.clear(); sessionStorage.clear(); setLocale('en', false);
    vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
    vi.mocked(request).mockReset(); vi.mocked(mutate).mockReset();
    vi.mocked(useWindowsIncidentInbox).mockReturnValue({ view: null, age: 0, loading: false, writing: false, error: false, notice: null, refresh: vi.fn(), acknowledge: vi.fn(), isUncertain: () => false });
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('find Linux monitoring gaps without an incident', () => {
    it.each(['en', 'de'] as const)('lists exact current unknown checks and Health links in %s', locale => {
        setLocale(locale, false); const view = source(), before = JSON.stringify(view);
        render(<LinuxMonitoringGaps view={view} devices={[device(id, 'Shared'), device(second, 'Shared')]}/>); expand(locale === 'de');
        const links = screen.getAllByRole('link'); expect(links).toHaveLength(2);
        expect(links.map(link => link.getAttribute('href'))).toEqual([`#/devices/${id}/health`, `#/devices/${second}/health`]);
        expect(links[0]).toHaveAccessibleName(new RegExp(id)); expect(links[1]).toHaveAccessibleName(new RegExp(second));
        expect(screen.getByRole('status')).toHaveTextContent(locale === 'de' ? 'Passende Geräte: 2 / 2 · unbekannte Prüfungen: 3 / 3' : 'Matching devices: 2 / 2 · unknown checks: 3 / 3');
        expect(screen.getByText('sshd.service', { exact: false })).toBeInTheDocument();
        expect(screen.getByText(locale === 'de' ? /^Ursprünglicher Eingang des akzeptierten Berichts:/ : /^Original accepted-report receipt:/)).toHaveTextContent(now);
        expect(document.querySelector(`time[datetime="${now}"]`)).toHaveTextContent(now);
        expect(JSON.stringify(view)).toBe(before); expect(request).not.toHaveBeenCalled(); expect(mutate).not.toHaveBeenCalled();
    });
    it('filters literal names, identities and check targets locally, intersects kind, and resets', () => {
        render(<LinuxMonitoringGaps view={source()} devices={[device(id, 'North [.*]'), device(second, 'South')]}/>); expand();
        const search = screen.getByRole('searchbox', { name: 'Find a Linux monitoring gap' });
        fireEvent.change(search, { target: { value: '[.*]' } }); expect(screen.getAllByRole('link')).toHaveLength(1);
        fireEvent.change(search, { target: { value: 'SSHD.SERVICE' } }); expect(screen.getByRole('status')).toHaveTextContent('unknown checks: 1 / 3');
        fireEvent.change(screen.getByRole('combobox', { name: 'Check type' }), { target: { value: 'offline' } });
        expect(screen.queryByRole('link')).toBeNull(); expect(screen.getByText(/No matching unknown checks/)).toBeInTheDocument();
        fireEvent.change(search, { target: { value: second } }); expect(screen.getAllByRole('link')).toHaveLength(1);
        expect(screen.getByRole('link')).toHaveAttribute('href', `#/devices/${second}/health`);
        fireEvent.change(search, { target: { value: 'x'.repeat(500) } }); expect(search).toHaveValue('x'.repeat(160));
        fireEvent.click(screen.getByRole('button', { name: 'Clear coverage filters' })); expect(search).toHaveValue('');
        expect(screen.getByRole('combobox', { name: 'Check type' })).toHaveValue('all'); expect(screen.getAllByRole('link')).toHaveLength(2);
        expect(request).not.toHaveBeenCalled(); expect(mutate).not.toHaveBeenCalled(); expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0);
    });
    it('never joins Windows, synthetic, local or unauthorized metadata into the source', () => {
        const unknownId = `agent_${'c'.repeat(32)}`;
        render(<LinuxMonitoringGaps view={source()} devices={[device(id, 'Wrong Windows', { platform: 'windows' }), device(id, 'Wrong synthetic', { synthetic: true }), device(second, 'Wrong local', { source: 'local' }), device(unknownId, 'Not authorized')]}/>); expand();
        expect(screen.queryByText(/Wrong|Not authorized/)).toBeNull(); expect(screen.getAllByRole('link')).toHaveLength(2);
        expect(screen.getByRole('link', { name: new RegExp(id) })).toHaveAttribute('href', `#/devices/${id}/health`);
    });
    it('renders names as inert text and does not create controls for delivery, settings or acknowledgement', () => {
        render(<LinuxMonitoringGaps view={source()} devices={[device(id, '<img src=x onerror=alert(1)>')]}/>); expand();
        expect(screen.getByRole('heading', { name: '<img src=x onerror=alert(1)>' })).toBeInTheDocument();
        expect(document.querySelector('img,script')).toBeNull(); expect(screen.getAllByRole('button')).toHaveLength(1);
        expect(screen.getAllByRole('link').every(link => link.getAttribute('href')?.endsWith('/health'))).toBe(true);
    });
    it('keeps unknown checks during maintenance and absent evaluation, with original timestamps', () => {
        const view = source(), until = '2026-10-05T00:10:00Z';
        view.devices[0] = { ...view.devices[0], evaluatedAt: null, status: 'maintenance', maintenanceUntil: until, checks: view.devices[0].checks.map(check => ({ ...check, state: 'unknown', value: null })) };
        expect(validInvestigationsView(view, 'open', 0)).toBe(true);
        render(<LinuxMonitoringGaps view={view} devices={[]}/>); expand();
        expect(screen.getByText('No manager evaluation is available for this device.')).toBeInTheDocument();
        expect(screen.getByText(/^Maintenance until:/)).toHaveTextContent(until); expect(screen.getByRole('status')).toHaveTextContent('unknown checks: 5 / 5');
        expect(document.querySelector(`time[datetime="${until}"]`)).toHaveTextContent(until);
    });
    it('uses the source aging result without relabeling observations or creating incidents', () => {
        const fresh = source(); fresh.devices.forEach(device => { device.status = 'clear'; device.checks.forEach(check => { check.state = 'ok'; check.value = check.kind === 'filesystem' ? 10 : null; }); });
        const mounted = render(queue(fresh)); expect(screen.queryByText(/^Linux checks without current evidence:/)).toBeNull();
        const aged = ageInvestigations(fresh, 121000); mounted.rerender(queue(aged)); expand();
        expect(within(document.querySelector('.linux-monitoring-gaps')! as HTMLElement).getByRole('status')).toHaveTextContent('unknown checks: 6 / 6');
        expect(document.querySelector(`time[datetime="${now}"]`)).toHaveTextContent(now);
        expect(aged.items).toEqual([]); expect(aged.counts.open).toBe(0); expect(mutate).not.toHaveBeenCalled();
    });
    it('integrates independently of incident page filters and finds gaps with no open incident', () => {
        render(queue(source())); expand();
        const panel = document.querySelector('.linux-monitoring-gaps')!;
        fireEvent.change(screen.getByRole('combobox', { name: 'Platform on loaded pages' }), { target: { value: 'windows' } });
        fireEvent.change(screen.getByRole('searchbox', { name: 'Search loaded incidents' }), { target: { value: 'unrelated' } });
        expect(within(panel as HTMLElement).getAllByRole('link')).toHaveLength(2);
        fireEvent.change(screen.getByRole('searchbox', { name: 'Find a Linux monitoring gap' }), { target: { value: 'north' } });
        expect(within(panel as HTMLElement).getAllByRole('link')).toHaveLength(1);
        expect(screen.getByRole('searchbox', { name: 'Search loaded incidents' })).toHaveValue('unrelated');
        expect(request).not.toHaveBeenCalled(); expect(mutate).not.toHaveBeenCalled();
    });
    it('drops all private content and local filters on source loss, lock, session or authority-set change', () => {
        const view = source(), mounted = render(queue(view)); expand();
        fireEvent.change(screen.getByRole('searchbox', { name: 'Find a Linux monitoring gap' }), { target: { value: 'North' } });
        mounted.rerender(queue(null)); expect(document.querySelector('.linux-monitoring-gaps')).toBeNull();
        mounted.rerender(queue(view)); expand(); expect(screen.getByRole('searchbox', { name: 'Find a Linux monitoring gap' })).toHaveValue('');
        fireEvent.change(screen.getByRole('searchbox', { name: 'Find a Linux monitoring gap' }), { target: { value: 'North' } });
        mounted.rerender(queue(view, 'session-b')); expand(); expect(screen.getByRole('searchbox', { name: 'Find a Linux monitoring gap' })).toHaveValue('');
        fireEvent.change(screen.getByRole('searchbox', { name: 'Find a Linux monitoring gap' }), { target: { value: 'South' } });
        mounted.rerender(queue({ ...view, devices: view.devices.filter(device => device.deviceId === id) }, 'session-b')); expand();
        expect(screen.getByRole('searchbox', { name: 'Find a Linux monitoring gap' })).toHaveValue(''); expect(screen.queryByRole('link', { name: /South/ })).toBeNull();
        mounted.rerender(queue(view, 'session-b', true)); expect(document.querySelector('.linux-monitoring-gaps')).toBeNull();
    });
    it.each(['pagehide', 'blur', AUTH_REQUIRED_EVENT])('the real guarded reader removes the panel on %s without a new request', async event => {
        vi.mocked(request).mockResolvedValue(source());
        function Harness() { const linux = useInvestigations(true, 'session-a', 'cases', 'open', 0, true); return <IncidentWorkQueue devices={[]} sessionKey="session-a" linux={linux} scope="active" onScope={vi.fn()} linuxOffset={0} onLinuxPage={vi.fn()}/>; }
        render(<Harness/>); await flush(); expand(); expect(screen.getAllByRole('link')).toHaveLength(2);
        expect(request).toHaveBeenCalledTimes(1); expect(vi.mocked(request).mock.calls[0][0]).toBe('/investigations?scope=open&offset=0');
        act(() => window.dispatchEvent(new Event(event))); expect(document.querySelector('.linux-monitoring-gaps')).toBeNull();
        expect(request).toHaveBeenCalledTimes(1); expect(mutate).not.toHaveBeenCalled();
    });
});
