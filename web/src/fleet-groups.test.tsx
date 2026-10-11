import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, APIError, AUTH_REQUIRED_EVENT, request } from './api';
import { setLocale } from './i18n';
import { FleetGroupsControls, useFleetGroups } from './fleet-groups';
import type { FleetGroupsView } from './fleet-groups-types';
import { windowsCapacityDevice, windowsCapacitySession, windowsCapacityView } from './windows-capacity-fixture';
import { windowsResourceView } from './windows-resource-fixture';
import { windowsDeviceId, windowsNow } from './windows-inventory-fixture';
import type { WindowsPercentageMetric } from './windows-capacity-types';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
const second = `agent_${'2'.repeat(32)}`, linux = `agent_${'3'.repeat(32)}`, groupId = `group_${'4'.repeat(32)}`;
const session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'fixture-csrf', serverNow: windowsNow, expiresAt: windowsCapacitySession, expiresInSeconds: 3590, loginMode: 'shared', actorId: null, capabilities: ['read'] };
let groups: FleetGroupsView;
const posts = () => vi.mocked(request).mock.calls.filter(([, options]) => options?.method === 'POST');
function Harness({ enabled = true, admin = true, sessionKey = windowsCapacitySession }: { enabled?: boolean; admin?: boolean; sessionKey?: string | null } = {}) {
    const resource = useFleetGroups(enabled, sessionKey, admin);
    return <><output data-testid="filter">{resource.memberIds ? [...resource.memberIds].join(',') : 'all'}</output><FleetGroupsControls key={resource.generation} resource={resource}/></>;
}
const flush = () => act(async () => {});
const advance = (ms: number) => act(async () => vi.advanceTimersByTimeAsync(ms));
async function load() { fireEvent.click(screen.getByRole('button', { name: 'Fleet groups' })); await flush(); }
const select = () => fireEvent.change(screen.getByRole('combobox', { name: 'Fleet groups' }), { target: { value: groupId } });
async function draft(metric: WindowsPercentageMetric = 'disk', both = false) {
    await load(); select(); fireEvent.click(screen.getByRole('button', { name: 'Review health setting' }));
    fireEvent.change(screen.getByRole('combobox', { name: 'One setting' }), { target: { value: metric } });
    fireEvent.click(screen.getByRole('checkbox', { name: 'Enable this policy' }));
    fireEvent.click(screen.getByRole('checkbox', { name: new RegExp(`^Desk One ${windowsDeviceId}`) }));
    if (both) fireEvent.click(screen.getByRole('checkbox', { name: new RegExp(`^Desk Two ${second}`) }));
}
async function review(metric: WindowsPercentageMetric = 'disk', both = false) { await draft(metric, both); fireEvent.click(screen.getByRole('button', { name: 'Review exact changes' })); await flush(); }
const policy = (id: string, metric: WindowsPercentageMetric = 'disk', enabled = false) => ({ ...(metric === 'disk' ? windowsCapacityView(enabled ? 'unknown' : 'disabled') : windowsResourceView(metric, enabled ? 'unknown' : 'disabled')), deviceId: id });
function setup() {
    vi.mocked(request).mockImplementation(async (path, options) => {
        if (path === '/auth/session') return structuredClone(session);
        if (path.startsWith('/fleet/groups')) return structuredClone(groups);
        const id = path.split('/')[2], metric = path.includes('/windows-resource/cpu') ? 'cpu' : path.includes('/windows-resource/memory') ? 'memory' : 'disk';
        if (path === `/devices/${id}`) return { ...windowsCapacityDevice(), id, name: id === second ? 'Desk Two' : 'Desk One' };
        return policy(id, metric, options?.method === 'POST');
    });
}
beforeEach(() => {
    abortProtectedRequests(); vi.useFakeTimers(); vi.setSystemTime(windowsNow); setLocale('en', false); vi.mocked(request).mockReset();
    groups = { schemaVersion: 'tracebolt.fleet-groups.v1', serverNow: windowsNow, groups: [{ id: groupId, name: 'Office', revision: 2, memberIds: [windowsDeviceId, second, linux], unavailableMembers: 1 }], devices: [{ id: windowsDeviceId, name: 'Desk One', platform: 'windows' }, { id: second, name: 'Desk Two', platform: 'windows' }, { id: linux, name: 'Server', platform: 'linux' }] };
    setup();
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('compact manual fleet groups', () => {
    it('does no read until deliberately opened and clears selected membership while refreshing or unavailable', async () => {
        render(<Harness/>); await flush(); expect(request).not.toHaveBeenCalled(); await load(); select(); expect(screen.getByTestId('filter')).toHaveTextContent(windowsDeviceId);
        let finish!: (value: unknown) => void; vi.mocked(request).mockReturnValueOnce(new Promise(resolve => { finish = resolve; }));
        fireEvent.click(screen.getByRole('button', { name: 'Refresh groups' })); expect(screen.getByTestId('filter')).toBeEmptyDOMElement();
        await act(async () => finish({ ...groups, secret: 'reject' })); expect(screen.getByTestId('filter')).toBeEmptyDOMElement(); expect(screen.getByText(/Group membership is unavailable/)).toBeVisible();
    });
    it('named access reads membership but cannot edit groups or policy settings', async () => {
        render(<Harness admin={false}/>); await load(); select(); expect(screen.queryByRole('button', { name: 'Review health setting' })).toBeNull();
        fireEvent.click(screen.getByRole('button', { name: 'Manage groups' })); expect(screen.getByText(/Your access is read-only/)).toBeVisible(); expect(screen.queryByRole('button', { name: 'Create group' })).toBeNull();
        fireEvent.click(screen.getByRole('button', { name: 'Office' })); expect(screen.getByRole('textbox', { name: 'Group name' })).toBeDisabled(); expect(screen.queryByRole('button', { name: 'Review group changes' })).toBeNull(); expect(posts()).toHaveLength(0);
    });
    it.each([false, true])('reviews exact edits and explicitly chooses unavailable removal=%s', async remove => {
        render(<Harness/>); await load(); fireEvent.click(screen.getByRole('button', { name: 'Manage groups' })); fireEvent.click(screen.getByRole('button', { name: 'Office' }));
        const checkbox = screen.getByRole('checkbox', { name: 'Remove unavailable members (1)' }); expect(checkbox).not.toBeChecked(); if (remove) fireEvent.click(checkbox);
        fireEvent.change(screen.getByRole('textbox', { name: 'Group name' }), { target: { value: 'Lab' } }); fireEvent.click(screen.getByRole('button', { name: 'Review group changes' }));
        expect(posts()).toHaveLength(0); expect(screen.getByText(remove ? /Unavailable members will be removed/ : /Unavailable members will be retained/)).toBeVisible();
        fireEvent.click(screen.getByRole('button', { name: 'Save reviewed group' })); await flush();
        expect(posts()).toHaveLength(1); expect(posts()[0][0]).toBe(`/fleet/groups/${groupId}`); expect(JSON.parse(posts()[0][1]!.body as string)).toEqual({ name: 'Lab', memberIds: [windowsDeviceId, second, linux], expectedRevision: 2, removeUnavailableMembers: remove });
    });
    it('requires separate review before creating and deleting a group', async () => {
        render(<Harness/>); await load(); fireEvent.click(screen.getByRole('button', { name: 'Manage groups' })); fireEvent.click(screen.getByRole('button', { name: 'Create group' }));
        fireEvent.change(screen.getByRole('textbox', { name: 'Group name' }), { target: { value: 'Lab' } }); fireEvent.click(screen.getByRole('checkbox', { name: new RegExp(`Desk One Windows · ${windowsDeviceId}`) }));
        fireEvent.click(screen.getByRole('button', { name: 'Review group changes' })); expect(posts()).toHaveLength(0); fireEvent.click(screen.getByRole('button', { name: 'Save reviewed group' })); await flush();
        expect(JSON.parse(posts()[0][1]!.body as string)).toEqual({ name: 'Lab', memberIds: [windowsDeviceId], expectedRevision: 0 });
        fireEvent.click(screen.getByRole('button', { name: 'Manage groups' })); fireEvent.click(screen.getByRole('button', { name: 'Office' })); fireEvent.click(screen.getByRole('button', { name: 'Delete group' })); expect(posts()).toHaveLength(1); fireEvent.click(screen.getByRole('button', { name: 'Confirm group deletion' })); await flush(); expect(posts()[1][0]).toBe(`/fleet/groups/${groupId}/delete`);
    });
    it('never retries an uncertain group mutation and requires a new review', async () => {
        render(<Harness/>); await load(); fireEvent.click(screen.getByRole('button', { name: 'Manage groups' })); fireEvent.click(screen.getByRole('button', { name: 'Office' })); fireEvent.click(screen.getByRole('button', { name: 'Review group changes' }));
        const defaultRequest = vi.mocked(request).getMockImplementation()!; vi.mocked(request).mockImplementation(async (path, options, cap) => options?.method === 'POST' ? Promise.reject(new Error('lost')) : defaultRequest(path, options, cap));
        fireEvent.click(screen.getByRole('button', { name: 'Save reviewed group' })); await flush(); expect(screen.getByText(/group write could not be confirmed/)).toBeVisible(); expect(screen.queryByRole('dialog')).toBeNull(); await advance(30000); expect(posts()).toHaveLength(1);
    });
    it('supports German labels without translating names', async () => {
        setLocale('de', false); render(<Harness/>); fireEvent.click(screen.getByRole('button', { name: 'Flottengruppen' })); await flush(); expect(screen.getByRole('option', { name: 'Office (3)' })).toBeInTheDocument(); fireEvent.click(screen.getByRole('button', { name: 'Gruppen verwalten' })); expect(screen.getByText(/Manuelle Gruppen ordnen nur Geräte/)).toBeVisible();
    });
});

describe('explicit one-setting Windows group health review', () => {
    it.each(['disk', 'cpu', 'memory'] as const)('freezes exact %s review before a single explicit write', async metric => {
        render(<Harness/>); await review(metric); expect(posts()).toHaveLength(0); expect(screen.getByRole('table')).toHaveTextContent(windowsDeviceId); expect(screen.getByRole('table')).toHaveTextContent('Policy revision: 0'); expect(screen.getByRole('table')).not.toHaveTextContent(second); expect(screen.queryByText(/^Server$/)).toBeNull();
        fireEvent.click(screen.getByRole('button', { name: 'Apply reviewed setting' })); await flush(); expect(posts()).toHaveLength(1); expect(posts()[0][0]).toBe(`/devices/${windowsDeviceId}/${metric === 'disk' ? 'windows-capacity' : `windows-resource/${metric}`}/policy`); expect(JSON.parse(posts()[0][1]!.body as string)).toEqual({ enabled: true, thresholdPercent: 90, expectedRevision: 0 }); expect(screen.getByText('Changed · confirmed response')).toBeVisible(); expect(screen.queryByRole('button', { name: 'Apply reviewed setting' })).toBeNull();
    });
    it('starts off with no selected members and never includes Linux or unavailable members', async () => {
        render(<Harness/>); await load(); select(); fireEvent.click(screen.getByRole('button', { name: 'Review health setting' })); expect(screen.getByRole('checkbox', { name: 'Enable this policy' })).not.toBeChecked(); expect(screen.getByRole('button', { name: 'Review exact changes' })).toBeDisabled(); expect(screen.getAllByRole('checkbox')).toHaveLength(3); expect(screen.getByRole('combobox', { name: 'One setting' }).querySelectorAll('option')).toHaveLength(3); expect(request).toHaveBeenCalledTimes(1);
    });
    it('stops before writes if group membership or revision changed after review', async () => {
        render(<Harness/>); await review('disk', true); groups.groups[0].revision++; fireEvent.click(screen.getByRole('button', { name: 'Apply reviewed setting' })); await flush(); expect(posts()).toHaveLength(0); expect(screen.getByText('Conflict · review again')).toBeVisible(); expect(screen.getByText('Not attempted')).toBeVisible();
    });
    it.each(['disk', 'memory'] as const)('does not attribute matching %s readback after an uncertain POST to our write and stops remaining devices', async metric => {
        render(<Harness/>); await review(metric, true); const defaultRequest = vi.mocked(request).getMockImplementation()!; let attempted = false;
        vi.mocked(request).mockImplementation(async (path, options, cap) => { if (options?.method === 'POST') { attempted = true; throw new Error('lost response'); } if (attempted && path.endsWith(metric === 'disk' ? '/windows-capacity' : '/windows-resource/memory')) return policy(windowsDeviceId, metric, true); return defaultRequest(path, options, cap); });
        fireEvent.click(screen.getByRole('button', { name: 'Apply reviewed setting' })); await flush(); expect(posts()).toHaveLength(1); expect(screen.getByText('Unconfirmed · write may have happened')).toBeVisible(); expect(screen.getByText(/does not prove our write succeeded/)).toBeVisible(); expect(screen.getByText('Not attempted')).toBeVisible();
        const outcome = screen.getByText(windowsDeviceId).closest('tr')!.querySelector('td:last-child')!;
        expect(outcome.textContent).toBe('Unconfirmed · write may have happenedCurrent policy matches, but this does not prove our write succeeded.');
        await advance(15000); expect(posts()).toHaveLength(1);
    });
    it('stops after policy conflict and does not retry', async () => {
        render(<Harness/>); await review('disk', true); const defaultRequest = vi.mocked(request).getMockImplementation()!; vi.mocked(request).mockImplementation(async (path, options, cap) => options?.method === 'POST' ? Promise.reject(new APIError('conflict', 409)) : defaultRequest(path, options, cap));
        fireEvent.click(screen.getByRole('button', { name: 'Apply reviewed setting' })); await flush(); expect(posts()).toHaveLength(1); expect(screen.getByText('Conflict · review again')).toBeVisible(); expect(screen.getByText('Not attempted')).toBeVisible();
    });
    it('retains earlier confirmed outcomes on Stop and marks the interrupted POST unconfirmed', async () => {
        render(<Harness/>); await review('disk', true); const defaultRequest = vi.mocked(request).getMockImplementation()!; let finish!: (value: unknown) => void;
        vi.mocked(request).mockImplementation(async (path, options, cap) => options?.method === 'POST' && path.includes(second) ? new Promise(resolve => { finish = resolve; }) : defaultRequest(path, options, cap));
        fireEvent.click(screen.getByRole('button', { name: 'Apply reviewed setting' })); await flush(); expect(screen.getByText('Changed · confirmed response')).toBeVisible(); expect(posts()).toHaveLength(2);
        fireEvent.click(screen.getByRole('button', { name: 'Stop remaining writes' })); expect(posts()[1][1]?.signal?.aborted).toBe(true); await act(async () => finish(policy(second, 'disk', true))); expect(screen.getByText('Changed · confirmed response')).toBeVisible(); expect(screen.getByText('Unconfirmed · write may have happened')).toBeVisible(); expect(screen.getByText(/^Stopped\./)).toBeVisible(); expect(screen.queryByRole('button', { name: 'Apply reviewed setting' })).toBeNull();
    });
    it.each(['blur', 'hashchange', 'pagehide', AUTH_REQUIRED_EVENT])('clears private review and aborts a write on %s', async event => {
        render(<Harness/>); await review('disk', true); const defaultRequest = vi.mocked(request).getMockImplementation()!; let finish!: (value: unknown) => void;
        vi.mocked(request).mockImplementation(async (path, options, cap) => options?.method === 'POST' ? new Promise(resolve => { finish = resolve; }) : defaultRequest(path, options, cap));
        fireEvent.click(screen.getByRole('button', { name: 'Apply reviewed setting' })); await flush(); act(() => window.dispatchEvent(new Event(event))); expect(posts()[0][1]?.signal?.aborted).toBe(true); expect(screen.queryByRole('dialog')).toBeNull(); await act(async () => finish(policy(windowsDeviceId, 'disk', true))); expect(posts()).toHaveLength(1); expect(screen.queryByText('Changed · confirmed response')).toBeNull();
    });
    it('clears private review and aborts a pending write when the document becomes hidden', async () => {
        render(<Harness/>); await review('disk', true); const defaultRequest = vi.mocked(request).getMockImplementation()!;
        vi.mocked(request).mockImplementation(async (path, options, cap) => options?.method === 'POST' ? new Promise(() => {}) : defaultRequest(path, options, cap));
        fireEvent.click(screen.getByRole('button', { name: 'Apply reviewed setting' })); await flush(); vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); expect(posts()[0][1]?.signal?.aborted).toBe(true); expect(screen.queryByRole('dialog')).toBeNull(); expect(screen.getByTestId('filter')).toBeEmptyDOMElement();
    });
    it('expires original device metadata while a write is pending and stops remaining members', async () => {
        const original = vi.mocked(request).getMockImplementation()!;
        vi.mocked(request).mockImplementation(async (path, options, cap) => { const value = await original(path, options, cap); if (path === `/devices/${windowsDeviceId}`) return { ...(value as object), agentCertificate: { ...windowsCapacityDevice().agentCertificate, checkedAt: '2026-10-07T11:58:11Z' } }; return value; });
        render(<Harness/>); await review('disk', true); const defaultRequest = vi.mocked(request).getMockImplementation()!;
        vi.mocked(request).mockImplementation(async (path, options, cap) => options?.method === 'POST' ? new Promise(() => {}) : defaultRequest(path, options, cap));
        fireEvent.click(screen.getByRole('button', { name: 'Apply reviewed setting' })); await flush(); await advance(2000); expect(posts()).toHaveLength(1); expect(posts()[0][1]?.signal?.aborted).toBe(true); expect(screen.queryByRole('dialog')).toBeNull();
    });
    it('expires the operator lease while a write is pending', async () => {
        const expiry = '2026-10-07T12:00:11Z', original = vi.mocked(request).getMockImplementation()!;
        vi.mocked(request).mockImplementation(async (path, options, cap) => path === '/auth/session' ? { ...session, expiresAt: expiry, expiresInSeconds: 1 } : original(path, options, cap));
        render(<Harness sessionKey={expiry}/>); await review(); const defaultRequest = vi.mocked(request).getMockImplementation()!;
        vi.mocked(request).mockImplementation(async (path, options, cap) => options?.method === 'POST' ? new Promise(() => {}) : defaultRequest(path, options, cap));
        fireEvent.click(screen.getByRole('button', { name: 'Apply reviewed setting' })); await flush(); await advance(1000); expect(posts()).toHaveLength(1); expect(posts()[0][1]?.signal?.aborted).toBe(true); expect(screen.queryByRole('dialog')).toBeNull();
    });
    it('rejects a stale rendered Apply synchronously before the expiry timer renders', async () => {
        render(<Harness/>); await review(); vi.spyOn(performance, 'now').mockReturnValue(performance.now() + 121000); vi.setSystemTime(Date.parse(windowsNow) + 121000); fireEvent.click(screen.getByRole('button', { name: 'Apply reviewed setting' })); await flush(); expect(posts()).toHaveLength(0);
    });
    it('rechecks session and metadata authority after an in-flight CSRF read', async () => {
        render(<Harness/>); await review(); const defaultRequest = vi.mocked(request).getMockImplementation()!; let finish!: (value: unknown) => void;
        vi.mocked(request).mockImplementation(async (path, options, cap) => path === '/auth/session' ? new Promise(resolve => { finish = resolve; }) : defaultRequest(path, options, cap));
        fireEvent.click(screen.getByRole('button', { name: 'Apply reviewed setting' })); await flush(); act(() => abortProtectedRequests()); await act(async () => finish(session)); expect(posts()).toHaveLength(0);
    });
    it('rejects a named or changed session returned at the final write boundary', async () => {
        render(<Harness/>); await review(); const defaultRequest = vi.mocked(request).getMockImplementation()!;
        vi.mocked(request).mockImplementation(async (path, options, cap) => path === '/auth/session' ? { ...session, loginMode: 'named', actorId: `operator_${'7'.repeat(32)}` } : defaultRequest(path, options, cap));
        fireEvent.click(screen.getByRole('button', { name: 'Apply reviewed setting' })); await flush(); expect(posts()).toHaveLength(0); expect(screen.getByText('Unconfirmed · write may have happened')).toBeVisible();
    });
    it('clears review when component loses shared-admin/session or enabled state', async () => {
        const wrapper = render(<Harness/>); await review(); wrapper.rerender(<Harness admin={false}/>); expect(screen.queryByRole('dialog')).toBeNull(); expect(posts()).toHaveLength(0);
    });
    it('rejects malformed/mismatched policy and failed device metadata before showing Apply', async () => {
        render(<Harness/>); await draft('cpu'); const defaultRequest = vi.mocked(request).getMockImplementation()!; vi.mocked(request).mockImplementation(async (path, options, cap) => path.endsWith('/windows-resource/cpu') ? policy(windowsDeviceId, 'memory') : defaultRequest(path, options, cap));
        fireEvent.click(screen.getByRole('button', { name: 'Review exact changes' })); await flush(); expect(screen.queryByRole('button', { name: 'Apply reviewed setting' })).toBeNull(); expect(screen.getByText(/Review could not be verified/)).toBeVisible(); expect(posts()).toHaveLength(0);
    });
});
