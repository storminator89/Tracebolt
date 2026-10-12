import { StrictMode } from 'react';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, request, AUTH_REQUIRED_EVENT } from './api';
import { FleetGroupsControls, useFleetGroups } from './fleet-groups';
import { groupMaintenanceFixture, maintenanceGroupId } from './fleet-group-maintenance-fixture';
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
const labels = (de: boolean) => de ? { groups: 'Flottengruppen', open: 'Gruppenwartung starten', intent: 'Absicht des Operators', review: 'Gruppenwartung prüfen', apply: 'Geprüfte Wartung starten', consent: 'Diesen exakten Wartungsumfang für diese gewählten Mitglieder bis zum oben angezeigten festen Ende starten.', results: 'Wartungsergebnisse je Gerät' } : { groups: 'Fleet groups', open: 'Start group maintenance', intent: 'Operator intent', review: 'Review group maintenance', apply: 'Start reviewed maintenance', consent: 'Start this exact maintenance scope for these selected members until the fixed end shown above.', results: 'Per-device maintenance results' };
async function open(de = false) {
    const c = labels(de); fireEvent.click(screen.getByRole('button', { name: c.groups })); await flush();
    fireEvent.change(screen.getByRole('combobox', { name: c.groups }), { target: { value: maintenanceGroupId } });
    fireEvent.click(screen.getByRole('button', { name: c.open })); await flush();
}
async function review(de = false) {
    await open(de); for (const m of view.members) fireEvent.click(screen.getByRole('checkbox', { name: `${m.name} ${m.deviceId}` }));
    fireEvent.change(screen.getByRole('combobox', { name: labels(de).intent }), { target: { value: 'planned-work' } });
    fireEvent.click(screen.getByRole('button', { name: labels(de).review })); await flush();
}
beforeEach(() => {
    abortProtectedRequests(); vi.useFakeTimers(); vi.setSystemTime(windowsNow); setLocale('en', false); vi.mocked(request).mockReset(); view = groupMaintenanceFixture();
    vi.mocked(request).mockImplementation(async (path, options) => {
        if (path === '/auth/session') return structuredClone(session);
        if (path === '/fleet/groups') return { schemaVersion: 'tracebolt.fleet-groups.v1', serverNow: windowsNow, groups: [{ id: maintenanceGroupId, name: 'Office', revision: 2, memberIds: view.members.map(m => m.deviceId), unavailableMembers: 1 }], devices: view.members.map(m => ({ id: m.deviceId, name: m.name, platform: 'windows' })) };
        if (path.endsWith('/maintenance/start')) { const body = JSON.parse(options!.body as string); const target = view.members.flatMap(m => m.targets).find(t => t.key === body.key)!; target.revision++; target.changedAt = view.serverNow; target.windows = [{ id: target.revision, startedAt: view.serverNow, endsAt: body.endsAt, endedAt: null, intent: body.intent }]; }
        if (path.includes('/maintenance')) return structuredClone(view);
        throw new Error('Unexpected route');
    });
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });
describe('deliberate group maintenance controls', () => {
    it.each([false, true])('requires selected members, purpose, exact common-end review and unchecked consent in DE=%s', async de => {
        setLocale(de ? 'de' : 'en', false); render(<Harness/>); await open(de); const c = labels(de);
        expect(screen.getAllByRole('checkbox').every(el => !(el as HTMLInputElement).checked)).toBe(true);
        expect(screen.getByRole('button', { name: c.review })).toBeDisabled(); expect(screen.getByRole('dialog')).toHaveTextContent(`${de ? 'Ausgeschlossene Linux-Mitglieder' : 'Excluded Linux members'}: 1`);
        for (const m of view.members) fireEvent.click(screen.getByRole('checkbox', { name: `${m.name} ${m.deviceId}` }));
        fireEvent.change(screen.getByRole('combobox', { name: c.intent }), { target: { value: 'planned-work' } });
        fireEvent.click(screen.getByRole('button', { name: c.review })); await flush();
        expect(posts()).toHaveLength(0); expect(screen.getByRole('checkbox', { name: c.consent })).not.toBeChecked(); expect(screen.getByRole('button', { name: c.apply })).toBeDisabled();
        const table = screen.getByRole('table', { name: c.review }); for (const m of view.members) expect(table).toHaveTextContent(m.deviceId);
        const exact = screen.getByRole('dialog').querySelector('details')!; expect(exact).not.toHaveAttribute('open'); for (const m of view.members) expect(exact).toHaveTextContent(m.targets[0].key);
        fireEvent.click(screen.getByRole('checkbox', { name: c.consent })); fireEvent.click(screen.getByRole('button', { name: c.apply })); await flush();
        expect(posts()).toHaveLength(2); const bodies = posts().map(([, options]) => JSON.parse(options!.body as string)); expect(bodies[0].endsAt).toBe(bodies[1].endsAt); expect(bodies.every(b => b.groupRevision === 2 && b.revision === 0 && b.intent === 'planned-work')).toBe(true);
        const results = screen.getByRole('table', { name: c.results }); expect(within(results).getAllByRole('row')).toHaveLength(3); expect(screen.queryByRole('button', { name: c.apply })).toBeNull();
    });
    it('survives repeated effect setup without retaining an abandoned load', async () => { render(<StrictMode><Harness/></StrictMode>); await open(); expect(screen.getByRole('button', { name: 'Review group maintenance' })).toBeDisabled(); expect(screen.getAllByRole('checkbox')).toHaveLength(2); expect(posts()).toHaveLength(0); });
    it('offers the entry only for a selected group and shared administrator', async () => {
        render(<Harness admin={false}/>); fireEvent.click(screen.getByRole('button', { name: 'Fleet groups' })); await flush(); fireEvent.change(screen.getByRole('combobox', { name: 'Fleet groups' }), { target: { value: maintenanceGroupId } }); expect(screen.queryByRole('button', { name: 'Start group maintenance' })).toBeNull(); expect(posts()).toHaveLength(0);
    });
    it('fails the review when original target identity changes between selection and reread', async () => {
        render(<Harness/>); await open(); fireEvent.click(screen.getByRole('checkbox', { name: `${view.members[0].name} ${view.members[0].deviceId}` })); fireEvent.change(screen.getByRole('combobox', { name: 'Operator intent' }), { target: { value: 'other' } }); view.members[0].targets[0].key = 'f'.repeat(64); fireEvent.click(screen.getByRole('button', { name: 'Review group maintenance' })); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('changed or expired'); expect(posts()).toHaveLength(0);
    });
    it('preserves confirmed rows on Stop during a later uncertain write; no replacement or retry', async () => {
        render(<Harness/>); await review(); const original = vi.mocked(request).getMockImplementation()!; let reject!: (error: Error) => void; let count = 0;
        vi.mocked(request).mockImplementation(async (path, options, cap) => { if (options?.method === 'POST' && ++count === 2) return new Promise((_, fail) => { reject = fail; }); return original(path, options, cap); });
        fireEvent.click(screen.getByRole('checkbox', { name: labels(false).consent })); fireEvent.click(screen.getByRole('button', { name: labels(false).apply })); await flush();
        expect(screen.getByText('Started · confirmed response')).toBeVisible(); fireEvent.click(screen.getByRole('button', { name: 'Stop remaining starts' })); await act(async () => reject(new Error('interrupted')));
        expect(screen.getByText('Started · confirmed response')).toBeVisible(); expect(screen.getByText('Unconfirmed · start may have happened')).toBeVisible(); expect(posts()).toHaveLength(2); await act(async () => vi.advanceTimersByTimeAsync(10000)); expect(posts()).toHaveLength(2);
    });
    it('keeps Stop visible when an interrupted review GET later rejects and permits an explicit fresh review', async () => {
        render(<Harness/>); await open(); fireEvent.click(screen.getByRole('checkbox', { name: `${view.members[0].name} ${view.members[0].deviceId}` })); fireEvent.change(screen.getByRole('combobox', { name: 'Operator intent' }), { target: { value: 'other' } });
        let reject!: (error: Error) => void; vi.mocked(request).mockReturnValueOnce(new Promise((_, fail) => { reject = fail; }));
        fireEvent.click(screen.getByRole('button', { name: 'Review group maintenance' })); await flush(); fireEvent.click(screen.getByRole('button', { name: 'Stop remaining starts' }));
        expect(screen.getByRole('button', { name: 'Start fresh review' })).toBeDisabled(); await act(async () => reject(new Error('interrupted read')));
        expect(screen.getByText(/Stopped. Earlier outcomes are retained/)).toBeVisible(); expect(screen.queryByRole('alert')).toBeNull(); expect(screen.getByRole('button', { name: 'Start fresh review' })).toBeEnabled(); expect(posts()).toHaveLength(0);
        fireEvent.click(screen.getByRole('button', { name: 'Start fresh review' })); await flush(); expect(screen.getByRole('button', { name: 'Review group maintenance' })).toBeDisabled(); expect(screen.getAllByRole('checkbox').every(el => !(el as HTMLInputElement).checked)).toBe(true);
    });
    it.each(['blur', 'hashchange', AUTH_REQUIRED_EVENT])('clears private review and selection on %s', async event => {
        render(<Harness/>); await review(); act(() => window.dispatchEvent(new Event(event))); await flush(); expect(screen.queryByRole('dialog')).toBeNull(); expect(posts()).toHaveLength(0);
    });
    it('rechecks live administrator session after CSRF wait before sending the start', async () => {
        render(<Harness/>); await review(); const original = vi.mocked(request).getMockImplementation()!;
        vi.mocked(request).mockImplementation(async (path, options, cap) => path === '/auth/session' ? { ...session, expiresAt: '2026-10-11T00:00:00Z' } : original(path, options, cap));
        fireEvent.click(screen.getByRole('checkbox', { name: labels(false).consent })); fireEvent.click(screen.getByRole('button', { name: labels(false).apply })); await flush(); expect(posts()).toHaveLength(0); expect(screen.getByText(/Unconfirmed · start may have happened/)).toBeVisible();
    });
});
