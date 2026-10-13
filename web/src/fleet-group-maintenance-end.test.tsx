import { StrictMode } from 'react';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, request, AUTH_REQUIRED_EVENT } from './api';
import { FleetGroupsControls, useFleetGroups } from './fleet-groups';
import { groupMaintenanceEndFixture, maintenanceGroupId } from './fleet-group-maintenance-fixture';
import type { GroupMaintenanceView } from './fleet-group-maintenance-workflow';
import { setLocale } from './i18n';
import { windowsCapacitySession } from './windows-capacity-fixture';
import { windowsNow } from './windows-inventory-fixture';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
let view: GroupMaintenanceView;
const session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'fixture-csrf', serverNow: windowsNow, expiresAt: windowsCapacitySession, expiresInSeconds: 3590, loginMode: 'shared', actorId: null, capabilities: ['read'] };
const flush = () => act(async () => {});
const posts = () => vi.mocked(request).mock.calls.filter(([, options]) => options?.method === 'POST');
function Harness({ admin = true, sessionKey = windowsCapacitySession }: { admin?: boolean; sessionKey?: string } = {}) {
    const resource = useFleetGroups(true, sessionKey, admin);
    return <FleetGroupsControls key={resource.generation} resource={resource}/>;
}
const labels = (de = false) => de ? { groups: 'Flottengruppen', open: 'Gruppenwartung beenden', review: 'Vorzeitige Enden prüfen', apply: 'Geprüfte Fenster beenden', consent: 'Nur diese exakten aktiven Fenster jetzt beenden. Jedes ursprüngliche Ende bleibt im Verlauf.', results: 'Wartungsergebnisse je Fenster' } : { groups: 'Fleet groups', open: 'End group maintenance', review: 'Review early ends', apply: 'End reviewed windows', consent: 'End only these exact active windows now. Keep each original end in history.', results: 'Per-window maintenance results' };
async function open(de = false) {
    const c = labels(de); fireEvent.click(screen.getByRole('button', { name: c.groups })); await flush();
    fireEvent.change(screen.getByRole('combobox', { name: c.groups }), { target: { value: maintenanceGroupId } });
    fireEvent.click(screen.getByRole('button', { name: c.open })); await flush();
}
async function review(de = false) { await open(de); for (const checkbox of screen.getAllByRole('checkbox')) fireEvent.click(checkbox); fireEvent.click(screen.getByRole('button', { name: labels(de).review })); await flush(); }
async function apply() { fireEvent.click(screen.getByRole('checkbox', { name: labels().consent })); fireEvent.click(screen.getByRole('button', { name: labels().apply })); await flush(); }
beforeEach(() => {
    abortProtectedRequests(); vi.useFakeTimers(); vi.setSystemTime(windowsNow); setLocale('en', false); vi.mocked(request).mockReset(); view = groupMaintenanceEndFixture();
    vi.mocked(request).mockImplementation(async (path, options) => {
        if (path === '/auth/session') return structuredClone(session);
        if (path === '/fleet/groups') return { schemaVersion: 'tracebolt.fleet-groups.v1', serverNow: windowsNow, groups: [{ id: maintenanceGroupId, name: 'Office', revision: 2, memberIds: view.members.map(m => m.deviceId), unavailableMembers: 1 }], devices: view.members.map(m => ({ id: m.deviceId, name: m.name, platform: 'windows' })) };
        if (path.endsWith('/maintenance/end')) { const body = JSON.parse(options!.body as string), target = view.members.flatMap(m => m.targets).find(t => t.key === body.key)!; target.revision++; target.changedAt = view.serverNow; target.windows[0].endedAt = view.serverNow; }
        if (path.includes('/maintenance')) return structuredClone(view);
        throw new Error('Unexpected route');
    });
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });
describe('explicit group early-end controls', () => {
    it.each([false, true])('requires active-window selection, exact review and unchecked consent in DE=%s', async de => {
        setLocale(de ? 'de' : 'en', false); render(<Harness/>); await open(de); const c = labels(de);
        expect(screen.getAllByRole('checkbox')).toHaveLength(3); expect(screen.getAllByRole('checkbox').every(el => !(el as HTMLInputElement).checked)).toBe(true); expect(screen.getByRole('button', { name: c.review })).toBeDisabled();
        for (const checkbox of screen.getAllByRole('checkbox')) fireEvent.click(checkbox);
        fireEvent.click(screen.getByRole('button', { name: c.review })); await flush();
        expect(posts()).toHaveLength(0); expect(screen.getByRole('checkbox', { name: c.consent })).not.toBeChecked(); expect(screen.getByRole('button', { name: c.apply })).toBeDisabled();
        const table = screen.getByRole('table', { name: c.review }); expect(within(table).getAllByRole('row')).toHaveLength(4);
        const details = screen.getByRole('dialog').querySelector('details')!; expect(details).not.toHaveAttribute('open');
        const targets = view.members.flatMap(m => m.targets).filter(t => t.windows.length), ends = targets.map(t => t.windows[0].endsAt);
        for (const target of targets) { expect(details).toHaveTextContent(target.key); expect(details).toHaveTextContent(target.windows[0].endsAt); }
        fireEvent.click(screen.getByRole('checkbox', { name: c.consent })); const applyButton = screen.getByRole('button', { name: c.apply }); fireEvent.click(applyButton); fireEvent.click(applyButton); await flush();
        expect(posts()).toHaveLength(3); expect(posts().map(([path]) => path)).toEqual(Array(3).fill(`/fleet/groups/${maintenanceGroupId}/maintenance/end`)); expect(posts().map(([, options]) => JSON.parse(options!.body as string))).toEqual(targets.map(t => ({ groupRevision: 2, key: t.key, revision: 1, windowId: 1 })));
        expect(targets.map(t => t.windows[0].endsAt)).toEqual(ends); expect(within(screen.getByRole('table', { name: c.results })).getAllByRole('row')).toHaveLength(4); expect(screen.queryByRole('button', { name: c.apply })).toBeNull();
    });
    it('offers the entry only to shared administrators with a selected group', async () => {
        render(<Harness admin={false}/>); fireEvent.click(screen.getByRole('button', { name: 'Fleet groups' })); await flush(); fireEvent.change(screen.getByRole('combobox', { name: 'Fleet groups' }), { target: { value: maintenanceGroupId } }); expect(screen.queryByRole('button', { name: 'End group maintenance' })).toBeNull(); expect(posts()).toHaveLength(0);
    });
    it('keeps selection clear through strict effect setup and filters ended or expired windows', async () => {
        const targets = view.members[0].targets.filter(t => t.windows.length); targets[0].revision++; targets[0].windows[0].endedAt = view.serverNow;
        targets[1].windows[0].startedAt = '2026-10-07T09:00:00Z'; targets[1].windows[0].endsAt = '2026-10-07T09:30:00Z'; targets[1].changedAt = targets[1].windows[0].startedAt;
        render(<StrictMode><Harness/></StrictMode>); await open(); expect(screen.getAllByRole('checkbox')).toHaveLength(1); expect(screen.getByRole('checkbox')).not.toBeChecked(); expect(posts()).toHaveLength(0);
    });
    it('blocks a newer window between selection and review without substituting it', async () => {
        render(<Harness/>); await open(); fireEvent.click(screen.getAllByRole('checkbox')[0]); const target = view.members[0].targets.find(t => t.windows.length)!; target.revision += 2; target.windows[0].id += 2;
        fireEvent.click(screen.getByRole('button', { name: labels().review })); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('changed or expired'); expect(posts()).toHaveLength(0);
    });
    it('preserves confirmed and uncertain rows on Stop with remaining work unattempted', async () => {
        render(<Harness/>); await review(); const original = vi.mocked(request).getMockImplementation()!; let reject!: (error: Error) => void, count = 0;
        vi.mocked(request).mockImplementation(async (path, options, cap) => { if (options?.method === 'POST' && ++count === 2) return new Promise((_, fail) => { reject = fail; }); return original(path, options, cap); });
        await apply(); expect(screen.getByText('Ended · confirmed response')).toBeVisible(); fireEvent.click(screen.getByRole('button', { name: 'Stop remaining ends' })); await act(async () => reject(new Error('interrupted')));
        expect(screen.getByText('Ended · confirmed response')).toBeVisible(); expect(screen.getByText('Unconfirmed · end may have happened')).toBeVisible(); expect(screen.getByText('Not attempted')).toBeVisible(); expect(posts()).toHaveLength(2);
        await act(async () => vi.advanceTimersByTimeAsync(10000)); expect(posts()).toHaveLength(2);
        fireEvent.click(screen.getByRole('button', { name: 'Start fresh review' })); await flush(); expect(screen.getAllByRole('checkbox').every(el => !(el as HTMLInputElement).checked)).toBe(true); expect(screen.getByRole('button', { name: labels().review })).toBeDisabled();
    });
    it('reconciles a lost committed response by GET only and never promotes it to confirmed', async () => {
        render(<Harness/>); await review(); const original = vi.mocked(request).getMockImplementation()!;
        vi.mocked(request).mockImplementation(async (path, options, cap) => { const value = await original(path, options, cap); if (options?.method === 'POST') throw new Error('lost response'); return value; });
        await apply(); expect(screen.getByText('Unconfirmed · end may have happened')).toBeVisible(); expect(screen.getByText('Current state matches; this does not prove this attempt ended it.')).toBeVisible(); expect(posts()).toHaveLength(1); expect(screen.queryByText('Ended · confirmed response')).toBeNull();
    });
    it('keeps a stopped pending review stopped after rejection; a fresh selection is required', async () => {
        render(<Harness/>); await open(); fireEvent.click(screen.getAllByRole('checkbox')[0]); let reject!: (error: Error) => void; vi.mocked(request).mockReturnValueOnce(new Promise((_, fail) => { reject = fail; }));
        fireEvent.click(screen.getByRole('button', { name: labels().review })); await flush(); fireEvent.click(screen.getByRole('button', { name: 'Stop remaining ends' })); expect(screen.getByRole('button', { name: 'Start fresh review' })).toBeDisabled(); await act(async () => reject(new Error('stopped read')));
        expect(screen.getByText(/Stopped. Earlier outcomes are retained/)).toBeVisible(); expect(screen.queryByRole('alert')).toBeNull(); expect(posts()).toHaveLength(0);
    });
    it.each(['blur', 'hashchange', AUTH_REQUIRED_EVENT, 'pagehide'])('clears private review on %s and never sends stale work', async event => {
        render(<Harness/>); await review(); act(() => window.dispatchEvent(new Event(event))); await flush(); expect(screen.queryByRole('dialog')).toBeNull(); expect(posts()).toHaveLength(0);
    });
    it('clears private review when original authority expires', async () => {
        render(<Harness/>); await review(); await act(async () => vi.advanceTimersByTimeAsync(120001)); expect(screen.queryByRole('dialog')).toBeNull(); expect(posts()).toHaveLength(0);
    });
    it('rechecks the live shared session after CSRF wait and sends no end on lost access', async () => {
        render(<Harness/>); await review(); const original = vi.mocked(request).getMockImplementation()!; vi.mocked(request).mockImplementation(async (path, options, cap) => path === '/auth/session' ? { ...session, loginMode: 'named' } : original(path, options, cap));
        await apply(); expect(posts()).toHaveLength(0); expect(screen.getByText('Unconfirmed · end may have happened')).toBeVisible();
    });
});
