import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, APIError, AUTH_REQUIRED_EVENT, request } from './api';
import { FleetGroupsControls, useFleetGroups } from './fleet-groups';
import type { FleetGroupsView } from './fleet-groups-types';
import { groupMonitoringMetrics, validGroupMonitoringView } from './fleet-group-monitoring-types';
import type { GroupMonitoringView, GroupMonitoringWrite } from './fleet-group-monitoring-types';
import { reviewGroupMonitoring } from './fleet-group-monitoring-workflow';
import { setLocale } from './i18n';
import { windowsCapacitySession } from './windows-capacity-fixture';
import { windowsDeviceId, windowsNow } from './windows-inventory-fixture';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
const second = `agent_${'2'.repeat(32)}`, linux = `agent_${'3'.repeat(32)}`, groupId = `group_${'4'.repeat(32)}`, path = `/fleet/groups/${groupId}/monitoring`;
let groups: FleetGroupsView, monitoring: GroupMonitoringView;
const session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'fixture-csrf', serverNow: windowsNow, expiresAt: windowsCapacitySession, expiresInSeconds: 3590, loginMode: 'shared', actorId: null, capabilities: ['read'] };
const posts = () => vi.mocked(request).mock.calls.filter(([, options]) => options?.method === 'POST');
const reads = () => vi.mocked(request).mock.calls.filter(([url, options]) => url === path && options?.method !== 'POST');
const flush = () => act(async () => {});
const expandStatus = () => { const details = screen.getByRole('region').querySelector<HTMLDetailsElement>('.fleet-inheritance-status')!; if (!details.open) fireEvent.click(details.querySelector('summary')!); };
function Harness({ admin = true }: { admin?: boolean } = {}) { const resource = useFleetGroups(true, windowsCapacitySession, admin); return <FleetGroupsControls key={resource.generation} resource={resource}/>; }
async function open() { fireEvent.click(screen.getByRole('button', { name: 'Fleet groups' })); await flush(); fireEvent.change(screen.getByRole('combobox'), { target: { value: groupId } }); fireEvent.click(screen.getByRole('button', { name: 'Group monitoring' })); await flush(); }
async function prepare() { await open(); fireEvent.click(screen.getByRole('checkbox', { name: 'Include CPU percentage' })); fireEvent.click(screen.getByRole('checkbox', { name: 'Enable policy · CPU percentage' })); fireEvent.change(screen.getByRole('spinbutton', { name: 'Threshold (%) · CPU percentage' }), { target: { value: '91' } }); fireEvent.click(screen.getByRole('checkbox', { name: `Desk One ${windowsDeviceId}` })); fireEvent.click(screen.getByRole('checkbox', { name: /Keep these reviewed/ })); fireEvent.click(screen.getByRole('button', { name: 'Review inheritance' })); await flush(); }
function apply(body: GroupMonitoringWrite) {
    monitoring.revision += body.definitions.length ? 1 : 0;
    for (const definition of body.definitions) monitoring.definitions = [...monitoring.definitions.filter(d => d.metric !== definition.metric), definition];
    for (const assignment of body.assignments) {
        const target = monitoring.targets.find(t => t.deviceId === assignment.deviceId && t.metric === assignment.metric)!;
        target.assignmentRevision++; target.owned = assignment.inherit; target.status = assignment.inherit ? 'pending' : 'stopped';
        const definition = monitoring.definitions.find(d => d.metric === target.metric);
        target.desired = assignment.inherit && definition ? { enabled: definition.enabled, thresholdPercent: definition.thresholdPercent } : null;
    }
    return structuredClone(monitoring);
}
beforeEach(() => {
    abortProtectedRequests(); vi.useFakeTimers(); vi.setSystemTime(windowsNow); setLocale('en', false); vi.mocked(request).mockReset();
    groups = { schemaVersion: 'tracebolt.fleet-groups.v1', serverNow: windowsNow, groups: [{ id: groupId, name: 'Office', revision: 2, memberIds: [windowsDeviceId, second, linux], unavailableMembers: 1 }], devices: [{ id: windowsDeviceId, name: 'Desk One', platform: 'windows' }, { id: second, name: 'Desk Two', platform: 'windows' }, { id: linux, name: 'Server', platform: 'linux' }] };
    monitoring = { schemaVersion: 'tracebolt.fleet-group-monitoring.v1', groupId, serverNow: windowsNow, groupRevision: 2, revision: 0, definitions: [], unavailableAssignments: 0, targets: groups.devices.filter(d => d.platform === 'windows').flatMap(d => groupMonitoringMetrics.map(metric => ({ deviceId: d.id, name: d.name, metric, assignmentRevision: 0, policy: { enabled: false, thresholdPercent: 90, revision: 0 }, desired: null, status: 'manual' as const, owned: false, certificateExpiresAt: windowsCapacitySession }))) };
    vi.mocked(request).mockImplementation(async (url, options) => { if (url === '/auth/session') return structuredClone(session); if (url === path) return options?.method === 'POST' ? apply(JSON.parse(options.body as string)) : structuredClone(monitoring); if (url === '/fleet/groups') return structuredClone(groups); throw new Error(`Unexpected request: ${url}`); });
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('explicit group monitoring inheritance', () => {
    it.each(['en', 'de'] as const)('starts collapsed with no metric, member or ongoing consent selected in %s', async locale => {
        setLocale(locale, false); render(<Harness/>); fireEvent.click(screen.getByRole('button', { name: locale === 'en' ? 'Fleet groups' : 'Flottengruppen' })); await flush();
        expect(reads()).toHaveLength(0); expect(screen.queryByRole('button', { name: 'Group monitoring' })).toBeNull(); fireEvent.change(screen.getByRole('combobox'), { target: { value: groupId } });
        const button = screen.getByRole('button', { name: locale === 'en' ? 'Group monitoring' : 'Gruppen-Monitoring' }); expect(button).toHaveAttribute('aria-expanded', 'false'); expect(screen.queryByRole('region')).toBeNull(); expect(reads()).toHaveLength(0);
        fireEvent.click(button); await flush(); expect(button).toHaveAttribute('aria-expanded', 'true'); expect(reads()).toHaveLength(1);
        const region = screen.getByRole('region'); expect(within(region).getAllByRole('checkbox')).toHaveLength(9); for (const checkbox of within(region).getAllByRole('checkbox')) expect(checkbox).not.toBeChecked();
        expect(within(region).getByRole('button', { name: locale === 'en' ? 'Review inheritance' : 'Vererbung prüfen' })).toBeDisabled(); expect(region).not.toHaveTextContent('Server'); expect(region).toHaveTextContent(locale === 'en' ? 'New members are never included automatically' : 'Neue Mitglieder werden nie automatisch einbezogen'); expect(posts()).toHaveLength(0);
    });
    it('freezes exact settings and all revisions, posts once with CSRF, and preserves Apply once', async () => {
        render(<Harness/>); await prepare(); expect(posts()).toHaveLength(0); const region = screen.getByRole('region'); expect(region).toHaveTextContent('Group revision: 2'); expect(region).toHaveTextContent('Definition revision: 0'); expect(region).toHaveTextContent('Policy revision: 0'); expect(region).not.toHaveTextContent('Desk Two'); expect(region).toHaveTextContent('Enabled · 91%');
        const save = screen.getByRole('button', { name: 'Save reviewed inheritance' }); fireEvent.click(save); fireEvent.click(save); await flush(); expect(posts()).toHaveLength(1);
        expect(JSON.parse(posts()[0][1]!.body as string)).toEqual({ expectedGroupRevision: 2, expectedRevision: 0, consent: true, definitions: [{ metric: 'cpu', enabled: true, thresholdPercent: 91 }], assignments: [{ deviceId: windowsDeviceId, metric: 'cpu', expectedRevision: 0, expectedPolicyRevision: 0, inherit: true }] });
        expect(posts()[0][1]!.headers).toMatchObject({ 'X-CSRF-Token': 'fixture-csrf' }); expect(screen.getByText(/Inheritance saved/)).toBeVisible(); expandStatus(); expect(screen.getByText('CPU percentage · Pending')).toBeVisible(); expect(screen.queryByRole('button', { name: 'Save reviewed inheritance' })).toBeNull(); expect(screen.getByRole('button', { name: 'Apply monitoring policies' })).toBeVisible();
        fireEvent.click(screen.getByRole('button', { name: 'Start new review' })); await flush(); expect(screen.getByRole('checkbox', { name: 'Include CPU percentage' })).not.toBeChecked(); expect(screen.getByRole('checkbox', { name: /Keep these reviewed/ })).not.toBeChecked(); expect(screen.getByRole('checkbox', { name: `Desk One ${windowsDeviceId}` })).not.toBeChecked();
    });
    it('reviews existing active definition targets without enrolling unchecked manual overrides or new members', () => {
        const owned = monitoring.targets.find(t => t.deviceId === second && t.metric === 'cpu')!; owned.owned = true; owned.status = 'inherited'; owned.assignmentRevision = 3; owned.policy.revision = 5;
        const override = monitoring.targets.find(t => t.deviceId === windowsDeviceId && t.metric === 'cpu')!; override.status = 'manual-override'; override.assignmentRevision = 2;
        const review = reviewGroupMonitoring(monitoring, [{ metric: 'cpu', enabled: false, thresholdPercent: 88 }], [], true);
        expect(review.targets.map(t => t.deviceId)).toEqual([second]); expect(review.body.assignments).toEqual([{ deviceId: second, metric: 'cpu', expectedRevision: 3, expectedPolicyRevision: 5, inherit: true }]);
        monitoring.targets[0].name = 'Changed'; monitoring.revision++; expect(review.view.revision).toBe(0); expect(review.view.targets[0].name).toBe('Desk One');
    });
    it('requires unchecked ongoing consent again after changing a draft', async () => {
        render(<Harness/>); await open(); fireEvent.click(screen.getByRole('checkbox', { name: /Keep these reviewed/ })); fireEvent.click(screen.getByRole('checkbox', { name: 'Include CPU percentage' })); expect(screen.getByRole('checkbox', { name: /Keep these reviewed/ })).not.toBeChecked(); fireEvent.click(screen.getByRole('checkbox', { name: /Keep these reviewed/ })); fireEvent.click(screen.getByRole('checkbox', { name: `Desk One ${windowsDeviceId}` })); expect(screen.getByRole('checkbox', { name: /Keep these reviewed/ })).not.toBeChecked(); expect(posts()).toHaveLength(0);
    });
    it('stops one exact assignment after review and leaves its last policy unchanged', async () => {
        const target = monitoring.targets.find(t => t.metric === 'disk')!; target.status = 'inherited'; target.owned = true; target.assignmentRevision = 4; target.policy = { enabled: true, thresholdPercent: 82, revision: 7 }; monitoring.revision = 3;
        render(<Harness/>); await open(); expandStatus(); fireEvent.click(screen.getByRole('button', { name: 'Stop inheriting · Desk One · System-volume capacity' })); await flush(); expect(posts()).toHaveLength(0); expect(screen.getByText(/The last device policy stays in place/)).toBeVisible();
        fireEvent.click(screen.getByRole('button', { name: 'Stop reviewed inheritance' })); await flush(); expect(posts()).toHaveLength(1); expect(JSON.parse(posts()[0][1]!.body as string)).toEqual({ expectedGroupRevision: 2, expectedRevision: 3, consent: false, definitions: [], assignments: [{ deviceId: windowsDeviceId, metric: 'disk', expectedRevision: 4, expectedPolicyRevision: 7, inherit: false }] }); expect(target.policy).toEqual({ enabled: true, thresholdPercent: 82, revision: 7 }); expect(screen.getByText(/Inheritance stopped/)).toBeVisible();
    });
    it('shows compact inherited, manual-override, pending, conflict and unavailable truth', async () => {
        monitoring.targets[0].status = 'inherited'; monitoring.targets[1].status = 'manual-override'; monitoring.targets[2].status = 'pending'; monitoring.targets[3].status = 'conflict'; monitoring.unavailableAssignments = 2;
        render(<Harness/>); await open(); expandStatus(); expect(screen.getByText('System-volume capacity · Inherited')).toBeVisible(); expect(screen.getByText('CPU percentage · Manual override')).toBeVisible(); expect(screen.getByText('Physical RAM percentage · Pending')).toBeVisible(); expect(screen.getByText('System-volume capacity · Another group owns this metric')).toBeVisible(); expect(screen.getByText(/Unavailable assignments: 2/)).toHaveTextContent('Previously opted-in unavailable assignments may become pending');
    });
    it('reconciles an uncertain write by GET only and never retries or claims readback proved the write', async () => {
        render(<Harness/>); await prepare(); const original = vi.mocked(request).getMockImplementation()!;
        vi.mocked(request).mockImplementation(async (url, options, cap) => { if (options?.method === 'POST') { apply(JSON.parse(options.body as string)); throw new Error('response lost'); } return original(url, options, cap); });
        fireEvent.click(screen.getByRole('button', { name: 'Save reviewed inheritance' })); await flush(); expect(posts()).toHaveLength(1); expect(reads()).toHaveLength(3); expect(screen.getByText(/Save is unconfirmed/)).toHaveTextContent('does not prove this save succeeded'); expandStatus(); expect(screen.getByText('CPU percentage · Pending')).toBeVisible(); await act(async () => vi.advanceTimersByTimeAsync(15000)); expect(posts()).toHaveLength(1);
    });
    it('requires a new review after a stale revision conflict without re-posting', async () => {
        render(<Harness/>); await prepare(); const original = vi.mocked(request).getMockImplementation()!; vi.mocked(request).mockImplementation(async (url, options, cap) => options?.method === 'POST' ? Promise.reject(new APIError('conflict', 409)) : original(url, options, cap));
        fireEvent.click(screen.getByRole('button', { name: 'Save reviewed inheritance' })); await flush(); expect(posts()).toHaveLength(1); expect(screen.getByText('Conflict. Refresh and review again.')).toBeVisible(); expect(screen.queryByRole('button', { name: 'Save reviewed inheritance' })).toBeNull();
    });
    it.each(['blur', 'hashchange', 'pagehide', AUTH_REQUIRED_EVENT])('clears private inheritance and aborts a pending write on %s', async event => {
        render(<Harness/>); await prepare(); const original = vi.mocked(request).getMockImplementation()!; let finish!: (value: unknown) => void;
        vi.mocked(request).mockImplementation(async (url, options, cap) => options?.method === 'POST' ? new Promise(resolve => { finish = resolve; }) : original(url, options, cap));
        fireEvent.click(screen.getByRole('button', { name: 'Save reviewed inheritance' })); await flush(); act(() => window.dispatchEvent(new Event(event))); expect(posts()[0][1]!.signal!.aborted).toBe(true); expect(screen.queryByRole('region')).toBeNull(); await act(async () => finish(structuredClone(monitoring))); expect(posts()).toHaveLength(1); expect(screen.queryByText(/Inheritance saved/)).toBeNull();
    });
    it('rechecks certificate expiry while waiting for CSRF and withholds the POST', async () => {
        monitoring.targets.forEach(t => { t.certificateExpiresAt = new Date(Date.parse(windowsNow) + 1000).toISOString(); }); render(<Harness/>); await prepare();
        const original = vi.mocked(request).getMockImplementation()!; let finish!: (value: unknown) => void; vi.mocked(request).mockImplementation(async (url, options, cap) => url === '/auth/session' ? new Promise(resolve => { finish = resolve; }) : original(url, options, cap));
        fireEvent.click(screen.getByRole('button', { name: 'Save reviewed inheritance' })); await flush(); await act(async () => vi.advanceTimersByTimeAsync(1000)); await act(async () => finish(structuredClone(session))); expect(posts()).toHaveLength(0); expect(screen.queryByRole('region')).toBeNull();
    });
    it('clears selection on Close and reopening and allows named read-only status without writes', async () => {
        const rendered = render(<Harness/>); await open(); fireEvent.click(screen.getByRole('checkbox', { name: 'Include CPU percentage' })); fireEvent.click(screen.getByRole('checkbox', { name: /Keep these reviewed/ })); fireEvent.click(screen.getByRole('button', { name: 'Close inheritance' })); expect(screen.queryByRole('region')).toBeNull(); fireEvent.click(screen.getByRole('button', { name: 'Group monitoring' })); await flush(); for (const checkbox of screen.getAllByRole('checkbox')) expect(checkbox).not.toBeChecked();
        rendered.unmount(); render(<Harness admin={false}/>); await open(); expect(screen.getByText('Read-only access.')).toBeVisible(); expect(screen.queryByRole('checkbox')).toBeNull(); expect(screen.queryByRole('button', { name: 'Review inheritance' })).toBeNull(); expect(posts()).toHaveLength(0);
    });
    it('does not cancel a newer group refresh when closing the inheritance panel', async () => {
        render(<Harness/>); await open(); fireEvent.click(screen.getByRole('button', { name: 'Refresh groups' })); await flush(); expect(screen.queryByRole('region')).toBeNull(); expect(screen.getByRole('option', { name: 'Office (3)' })).toBeInTheDocument(); expect(screen.queryByText(/Group membership is unavailable/)).toBeNull(); fireEvent.click(screen.getByRole('button', { name: 'Group monitoring' })); await flush(); expect(screen.getByRole('checkbox', { name: 'Include CPU percentage' })).not.toBeChecked(); expect(posts()).toHaveLength(0);
    });
    it('discards private state when hidden', async () => {
        render(<Harness/>); await open(); vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); expect(screen.queryByRole('region')).toBeNull(); expect(posts()).toHaveLength(0);
    });
    it('rejects unknown data, incomplete metric rosters, expired identities and oversize projections', () => {
        expect(validGroupMonitoringView(monitoring, groupId)).toBe(true); expect(validGroupMonitoringView({ ...monitoring, privateIdentity: 'hidden' }, groupId)).toBe(false);
        expect(validGroupMonitoringView({ ...monitoring, targets: monitoring.targets.slice(1) }, groupId)).toBe(false); expect(validGroupMonitoringView({ ...monitoring, targets: Array(76).fill(monitoring.targets[0]) }, groupId)).toBe(false);
        monitoring.targets[0].certificateExpiresAt = windowsNow; expect(validGroupMonitoringView(monitoring, groupId)).toBe(false);
    });
    it('keeps withheld whole devices unavailable and never selects them or accepts partial metric rows', async () => {
        monitoring.targets = monitoring.targets.filter(t => t.deviceId !== second); render(<Harness/>); await open(); expect(screen.getByText('Unavailable Windows members: 1')).toBeVisible(); expect(screen.queryByRole('checkbox', { name: `Desk Two ${second}` })).toBeNull(); expect(screen.getByRole('checkbox', { name: `Desk One ${windowsDeviceId}` })).not.toBeChecked(); expect(posts()).toHaveLength(0);
    });
    it('shows current and desired settings and limits Stop to active owned assignments', async () => {
        const target = monitoring.targets[0]; target.status = 'manual-override'; target.desired = { enabled: true, thresholdPercent: 85 }; render(<Harness/>); await open(); expandStatus(); expect(screen.getByText('Current policy: Disabled · 90% · Desired policy: Enabled · 85%')).toBeVisible(); expect(screen.queryByRole('button', { name: 'Stop inheriting · Desk One · System-volume capacity' })).toBeNull();
    });
    it('allows disclosed edits to an existing definition with only unavailable prior assignments', async () => {
        monitoring.definitions = [{ metric: 'cpu', enabled: true, thresholdPercent: 90 }]; monitoring.unavailableAssignments = 1; monitoring.targets = [];
        render(<Harness/>); await open(); fireEvent.click(screen.getByRole('checkbox', { name: 'Include CPU percentage' })); fireEvent.click(screen.getByRole('checkbox', { name: /Keep these reviewed/ })); fireEvent.click(screen.getByRole('button', { name: 'Review inheritance' })); await flush(); expect(screen.getByText(/Unavailable assignments: 1/)).toBeVisible(); fireEvent.click(screen.getByRole('button', { name: 'Save reviewed inheritance' })); await flush(); expect(posts()).toHaveLength(1); expect(JSON.parse(posts()[0][1]!.body as string).assignments).toEqual([]); expect(screen.getByText(/Inheritance saved/)).toBeVisible();
    });
    it('keeps technical scope and exact identities collapsed, with threshold guidance only when useful', async () => {
        render(<Harness/>); await open(); const region = screen.getByRole('region'); const technical = region.querySelector<HTMLDetailsElement>('.fleet-inheritance-details')!; expect(technical).not.toHaveAttribute('open'); expect(region.querySelector('.fleet-inheritance-status')).not.toHaveAttribute('open'); expect(region.querySelector('.fleet-inheritance-status > summary')).toHaveTextContent('Manual: 6'); expect(within(technical).getByText(windowsDeviceId)).not.toBeVisible(); expect(within(technical).getByText(/No collection, notifications/)).not.toBeVisible(); expect(screen.queryByRole('alert')).toBeNull();
        fireEvent.click(screen.getByRole('checkbox', { name: 'Include CPU percentage' })); fireEvent.change(screen.getByRole('spinbutton', { name: 'Threshold (%) · CPU percentage' }), { target: { value: '49' } }); expect(screen.getByRole('alert')).toHaveTextContent('Use a whole-number threshold from 50 to 99.'); fireEvent.change(screen.getByRole('spinbutton', { name: 'Threshold (%) · CPU percentage' }), { target: { value: '91' } }); expect(screen.queryByRole('alert')).toBeNull(); fireEvent.click(technical.querySelector('summary')!); expect(within(technical).getByText(windowsDeviceId)).toBeVisible(); expect(technical).toHaveTextContent('Group revision: 2'); expect(technical).toHaveTextContent('Assignment revision: 0');
    });
    it('does not accept a changed group roster as current inheritance', async () => {
        monitoring.groupRevision++; render(<Harness/>); await open(); expect(screen.getByText(/Inheritance is unavailable/)).toBeVisible(); expect(screen.queryByRole('checkbox')).toBeNull(); expect(posts()).toHaveLength(0);
    });
});
