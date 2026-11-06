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
import { LinuxConfirmingChecks } from './linux-confirming-checks';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
vi.mock('./windows-incident-inbox-resource', () => ({ useWindowsIncidentInbox: vi.fn() }));
const id = healthWire.deviceId, second = `agent_${'b'.repeat(32)}`, now = healthWire.serverNow;
function source(): InvestigationsView {
    const health = structuredClone(healthWire) as HealthView;
    health.incidents = []; health.status = 'attention';
    health.checks = health.checks.map(check => ({ ...check, state: check.kind === 'offline' ? 'ok' : 'pending' }));
    const other: HealthView = { ...structuredClone(health), deviceId: second, checks: health.checks.map(check => ({ ...check, state: check.kind === 'offline' ? 'pending' : 'ok', value: check.kind === 'filesystem' ? 10 : null })) };
    other.checks[0].observedAt = '2026-10-05T00:00:00Z';
    const view: InvestigationsView = { schemaVersion: 'tracebolt.investigations.v1', serverNow: now, scope: 'open', offset: 0, total: 0, counts: { open: 0, recovered: 0, closed: 0, all: 0 }, devices: [other, health], items: [] };
    if (!validInvestigationsView(view, 'open', 0)) throw new Error('Invalid confirming-check fixture');
    return view;
}
function device(deviceId: string, name: string, options: Partial<Device> = {}): Device {
    const metric = { value: null, unit: '%', quality: 'unknown' as const, source: 'fixture', collectedAt: now };
    return { id: deviceId, name, platform: 'linux', source: 'lan', synthetic: false, os: 'Linux', site: '', group: '', ip: null, status: 'unknown', lastSeen: now, agentVersion: '', cpu: metric, memory: metric, disk: metric, uptime: '', tags: [], capabilities: [], evidence: [], trend: [], caseIds: [], ...options };
}
function resource(view: InvestigationsView | null, locked = false): InvestigationsResource { return { view, counts: view?.counts ?? null, readiness: view ? 'ready' : 'unknown', pending: false, failure: null, locked, refresh: vi.fn() }; }
const queue = (view: InvestigationsView | null, sessionKey = 'session-a', locked = false) => <IncidentWorkQueue devices={[device(id, 'North'), device(second, 'South')]} sessionKey={sessionKey} linux={resource(view, locked)} scope="active" onScope={vi.fn()} linuxOffset={0} onLinuxPage={vi.fn()}/>;
const panel = () => document.querySelector('.linux-confirming-checks') as HTMLElement;
const expand = () => fireEvent.click(panel().querySelector('summary')!);
beforeEach(() => {
    localStorage.clear(); sessionStorage.clear(); setLocale('en', false);
    vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
    vi.mocked(request).mockReset(); vi.mocked(mutate).mockReset();
    vi.mocked(useWindowsIncidentInbox).mockReturnValue({ view: null, age: 0, loading: false, writing: false, error: false, notice: null, refresh: vi.fn(), acknowledge: vi.fn(), isUncertain: () => false });
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('inspect Linux checks before an incident opens', () => {
    it.each(['en', 'de'] as const)('shows confirming checks, exact identity routes and original evidence in %s', locale => {
        setLocale(locale, false); const view = source(), before = JSON.stringify(view);
        render(<LinuxConfirmingChecks view={view} devices={[device(id, 'Shared'), device(second, 'Shared')]}/>);
        expect(panel()).not.toHaveAttribute('open'); expand();
        const links = screen.getAllByRole('link'); expect(links).toHaveLength(2);
        expect(links.map(link => link.getAttribute('href'))).toEqual([`#/devices/${id}/health`, `#/devices/${second}/health`]);
        expect(links[0]).toHaveAccessibleName(new RegExp(id)); expect(links[1]).toHaveAccessibleName(new RegExp(second));
        expect(screen.getByRole('status')).toHaveTextContent(locale === 'de' ? 'Angezeigt: 3 / 3 ausstehende Prüfungen · 2 / 2 Geräte' : 'Shown: 3 / 3 confirming checks · 2 / 2 devices');
        expect(screen.getByText(locale === 'de' ? /Diese Bedingungen haben noch keinen Vorfall/ : /These conditions have not opened an incident/)).toBeVisible();
        expect(screen.getByText(locale === 'de' ? 'Root-Belegung: 95%' : 'Root allocation: 95%')).toBeVisible();
        const details = panel().querySelectorAll('.linux-confirming-evidence');
        details.forEach(detail => { expect(detail.querySelector('time')).not.toBeVisible(); fireEvent.click(detail.querySelector('summary')!); });
        expect(screen.getByText(locale === 'de' ? /^Eingang des akzeptierten Berichts:/ : /^Accepted-report receipt:/)).toHaveTextContent('2026-10-05T00:00:00Z');
        expect(panel().querySelector(`time[datetime="${now}"]`)).toHaveTextContent(now);
        const sourceDetails = panel().querySelector('.linux-confirming-source')!;
        fireEvent.click(sourceDetails.querySelector('summary')!);
        expect(sourceDetails).toHaveTextContent(locale === 'de' ? 'weder Bestätigungsbeginn noch Restdauer' : 'no confirmation start or remaining duration');
        expect(sourceDetails).toHaveTextContent(locale === 'de' ? 'bestätigt keinen Vorfall' : 'acknowledges no incidents');
        expect(JSON.stringify(view)).toBe(before); expect(request).not.toHaveBeenCalled(); expect(mutate).not.toHaveBeenCalled();
    });
    it('filters literal target, device and translated check names, intersects kind, bounds input and restores focus', () => {
        render(<LinuxConfirmingChecks view={source()} devices={[device(id, 'North [.*]'), device(second, 'South')]}/>); expand();
        const search = screen.getByRole('searchbox', { name: 'Find a confirming check' });
        const kind = screen.getByRole('combobox', { name: 'Confirming check type' });
        fireEvent.change(search, { target: { value: '[.*]' } }); expect(screen.getByRole('status')).toHaveTextContent('2 / 3');
        fireEvent.change(search, { target: { value: ' SSHD.SERVICE ' } }); expect(screen.getByRole('status')).toHaveTextContent('1 / 3');
        fireEvent.change(kind, { target: { value: 'offline' } }); expect(screen.queryByRole('link')).toBeNull();
        expect(screen.getByText('No matching confirming checks.')).toBeVisible();
        fireEvent.change(search, { target: { value: second } }); expect(screen.getByRole('link')).toHaveAttribute('href', `#/devices/${second}/health`);
        fireEvent.change(search, { target: { value: 'AGENT CONTACT' } }); expect(screen.getAllByRole('link')).toHaveLength(1);
        fireEvent.change(search, { target: { value: 'x'.repeat(500) } }); expect(search).toHaveValue('x'.repeat(160));
        fireEvent.click(screen.getByRole('button', { name: 'Clear confirming-check filters' }));
        expect(search).toHaveValue(''); expect(search).toHaveFocus(); expect(kind).toHaveValue('all'); expect(screen.getAllByRole('link')).toHaveLength(2);
        expect(screen.getByRole('button')).toBeDisabled(); expect(request).not.toHaveBeenCalled(); expect(mutate).not.toHaveBeenCalled();
        expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0);
    });
    it('has labeled native controls, semantic markerless lists and noninteractive decorative icons', () => {
        const { container } = render(<LinuxConfirmingChecks view={source()} devices={[]}/>); expand();
        expect(screen.getByRole('searchbox')).toHaveAccessibleName('Find a confirming check');
        expect(screen.getByRole('combobox')).toHaveAccessibleName('Confirming check type');
        container.querySelectorAll('.linux-confirming-devices, .linux-confirming-targets').forEach(list => expect(list).toHaveAttribute('role', 'list'));
        expect(container.querySelectorAll('svg').length).toBeGreaterThan(5);
        container.querySelectorAll('svg').forEach(icon => { expect(icon).toHaveAttribute('aria-hidden', 'true'); expect(icon).toHaveAttribute('focusable', 'false'); expect(icon).not.toHaveAttribute('tabindex'); });
        const details = container.querySelector('.linux-confirming-evidence')!;
        for (let i = 0; i < 3; i++) { fireEvent.click(details.querySelector('summary')!); expect(details).toHaveAttribute('open'); fireEvent.click(details.querySelector('summary')!); expect(details).not.toHaveAttribute('open'); }
        expect(screen.queryByRole('progressbar')).toBeNull(); expect(screen.queryByRole('timer')).toBeNull();
    });
    it('uses only authorized source rows and safe Linux display names, with hostile names inert', () => {
        const notAuthorized = `agent_${'c'.repeat(32)}`;
        const mounted = render(<LinuxConfirmingChecks view={source()} devices={[device(id, 'Wrong Windows', { platform: 'windows' }), device(id, 'Wrong synthetic', { synthetic: true }), device(second, 'Wrong local', { source: 'local' }), device(notAuthorized, 'Not authorized')]}/>); expand();
        expect(screen.queryByText(/Wrong|Not authorized/)).toBeNull(); expect(screen.getAllByRole('link')).toHaveLength(2);
        mounted.rerender(<LinuxConfirmingChecks view={source()} devices={[device(id, '<img src=x onerror=alert(1)>')]}/>);
        expect(screen.getByRole('heading', { name: '<img src=x onerror=alert(1)>' })).toBeVisible(); expect(document.querySelector('img,script')).toBeNull();
        expect(screen.getAllByRole('button')).toHaveLength(1); expect(screen.getAllByRole('link').every(link => link.getAttribute('href')?.endsWith('/health'))).toBe(true);
    });
    it('excludes clear, open and unknown checks, and distinguishes the component-only zero fallback', () => {
        const view = source(), mounted = render(<LinuxConfirmingChecks view={view} devices={[]}/>); expand();
        const changed = structuredClone(view);
        changed.devices[0].checks[0].state = 'unknown'; changed.devices[1].checks[1].state = 'open'; changed.devices[1].checks[2].state = 'ok';
        expect(validInvestigationsView(changed, 'open', 0)).toBe(true);
        mounted.rerender(<LinuxConfirmingChecks view={changed} devices={[]}/>);
        expect(screen.getByText('No confirming checks in this source view.')).toBeVisible(); expect(screen.getByText('This is not a whole-device health verdict.')).toBeVisible();
        expect(screen.queryByRole('link')).toBeNull(); expect(screen.getByRole('status')).toHaveTextContent('0 / 0');
        expect(changed.items).toEqual([]); expect(changed.counts.open).toBe(0);
    });
    it('does not invent contact age limits or advance confirmation; original source aging removes pending rows', () => {
        const fresh = source(), mounted = render(queue(fresh)); expand();
        const aged = ageInvestigations(fresh, 10000); mounted.rerender(queue(aged));
        expect(within(panel()).getByRole('status')).toHaveTextContent('3 / 3');
        expect(within(panel()).getByRole('link', { name: /South/ })).toBeInTheDocument();
        mounted.rerender(queue(ageInvestigations(fresh, 121000))); expect(panel()).toBeNull();
        expect(screen.queryByText('No confirming checks in this source view.')).toBeNull();
        mounted.rerender(queue(fresh)); expect(panel()).not.toHaveAttribute('open');
        expect(fresh.items).toEqual([]); expect(fresh.counts.open).toBe(0); expect(request).not.toHaveBeenCalled(); expect(mutate).not.toHaveBeenCalled();
    });
    it('integrates with no open incident and keeps its filters independent of incident-page filters', () => {
        render(queue(source())); expand();
        fireEvent.change(screen.getByRole('combobox', { name: 'Platform on loaded pages' }), { target: { value: 'windows' } });
        fireEvent.change(screen.getByRole('searchbox', { name: 'Search loaded incidents' }), { target: { value: 'unrelated' } });
        expect(within(panel()).getAllByRole('link')).toHaveLength(2);
        fireEvent.change(screen.getByRole('searchbox', { name: 'Find a confirming check' }), { target: { value: 'north' } });
        expect(within(panel()).getAllByRole('link')).toHaveLength(1); expect(screen.getByRole('searchbox', { name: 'Search loaded incidents' })).toHaveValue('unrelated');
        expect(request).not.toHaveBeenCalled(); expect(mutate).not.toHaveBeenCalled();
    });
    it('reconciles new check state immediately without keeping selected private rows', () => {
        const view = source(), mounted = render(queue(view)); expand();
        fireEvent.change(screen.getByRole('searchbox', { name: 'Find a confirming check' }), { target: { value: 'sshd' } });
        const changed = structuredClone(view); changed.devices[1].checks[2].state = 'open';
        expect(validInvestigationsView(changed, 'open', 0)).toBe(true); mounted.rerender(queue(changed));
        expect(within(panel()).queryByRole('link')).toBeNull(); expect(screen.getByText('No matching confirming checks.')).toBeVisible();
        expect(within(panel()).getByRole('status')).toHaveTextContent('0 / 2');
        expect(screen.queryByText('Selected service: sshd.service')).toBeNull();
    });
    it.each(['source', 'session', 'authority', 'lock'] as const)('drops private content and resets filters/disclosures after %s changes', change => {
        const view = source(), mounted = render(queue(view)); expand();
        fireEvent.change(screen.getByRole('searchbox', { name: 'Find a confirming check' }), { target: { value: 'North' } });
        fireEvent.click(screen.getByText('Original evidence times')); fireEvent.click(screen.getByText('How confirmation works'));
        if (change === 'source') { mounted.rerender(queue(null)); expect(panel()).toBeNull(); mounted.rerender(queue(view)); }
        if (change === 'lock') { mounted.rerender(queue(view, 'session-a', true)); expect(panel()).toBeNull(); mounted.rerender(queue(view)); }
        if (change === 'session') mounted.rerender(queue(view, 'session-b'));
        if (change === 'authority') mounted.rerender(queue({ ...view, devices: [view.devices[0]] }));
        expect(panel()).not.toHaveAttribute('open'); expand();
        expect(screen.getByRole('searchbox', { name: 'Find a confirming check' })).toHaveValue('');
        expect(panel().querySelectorAll('details[open]')).toHaveLength(0);
        if (change === 'authority') expect(within(panel()).queryByRole('link', { name: /North/ })).toBeNull();
        expect(request).not.toHaveBeenCalled(); expect(mutate).not.toHaveBeenCalled();
    });
    it.each(['pagehide', 'blur', AUTH_REQUIRED_EVENT])('the unchanged real source reader removes the panel on %s', async event => {
        vi.mocked(request).mockResolvedValue(source());
        function Harness() { const linux = useInvestigations(true, 'session-a', 'cases', 'open', 0, true); return <IncidentWorkQueue devices={[]} sessionKey="session-a" linux={linux} scope="active" onScope={vi.fn()} linuxOffset={0} onLinuxPage={vi.fn()}/>; }
        render(<Harness/>); await act(async () => {}); expand(); expect(within(panel()).getAllByRole('link')).toHaveLength(2);
        expect(request).toHaveBeenCalledTimes(1); expect(vi.mocked(request).mock.calls[0][0]).toBe('/investigations?scope=open&offset=0');
        act(() => window.dispatchEvent(new Event(event))); expect(panel()).toBeNull();
        expect(request).toHaveBeenCalledTimes(1); expect(mutate).not.toHaveBeenCalled();
    });
});
