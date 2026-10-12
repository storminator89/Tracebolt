import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT, request } from './api';
import { LOGOUT_INTENT_KEY } from './auth';
import { setLocale } from './i18n';
import { windowsCapacityDevice, windowsCapacitySession } from './windows-capacity-fixture';
import { WindowsIncidentInbox } from './windows-incident-inbox';
import { windowsIncidentView } from './windows-incident-inbox-fixture';
import { windowsDeviceId, windowsNow } from './windows-inventory-fixture';
import { WindowsMaintenance } from './windows-maintenance';
import { windowsMaintenanceTarget, windowsMaintenanceView, windowsMaintenanceWindow } from './windows-maintenance-fixture';
import type { WindowsMaintenanceDomain, WindowsMaintenanceView, WindowsMaintenanceWindow } from './windows-maintenance-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
const session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'fixture-csrf', serverNow: windowsNow, expiresAt: windowsCapacitySession, expiresInSeconds: 3590, loginMode: 'shared', actorId: null, capabilities: ['read'] };
const devices = [{ ...windowsCapacityDevice(), name: 'Desk One' }];
let view: WindowsMaintenanceView;
const posts = () => vi.mocked(request).mock.calls.filter(([, options]) => options?.method === 'POST');
const reads = () => vi.mocked(request).mock.calls.filter(([path]) => path === '/fleet/windows-maintenance');
const flush = () => act(async () => {});
const advance = (ms: number) => act(async () => vi.advanceTimersByTimeAsync(ms));
function Harness({ admin = true, sessionKey = windowsCapacitySession }: { admin?: boolean; sessionKey?: string | null } = {}) {
    return <WindowsMaintenance devices={devices} sessionKey={sessionKey} admin={admin}/>;
}
async function open() { fireEvent.click(screen.getByRole('button', { name: 'Windows maintenance' })); await flush(); }
function select(domain: WindowsMaintenanceDomain = 'disk') {
    fireEvent.change(screen.getByRole('combobox', { name: 'Exact Windows device' }), { target: { value: view.targets[0].key } });
    fireEvent.change(screen.getByRole('combobox', { name: 'Maintenance scope' }), { target: { value: domain } });
}
function review() {
    select(); fireEvent.change(screen.getByRole('combobox', { name: 'Operator intent' }), { target: { value: 'planned-work' } }); fireEvent.click(screen.getByRole('button', { name: 'Review maintenance start' }));
}
function setWindow(domain: WindowsMaintenanceDomain, window: WindowsMaintenanceWindow) { view.targets = view.targets.map(target => target.domain === domain ? windowsMaintenanceTarget(domain, [window]) : target); }
beforeEach(() => {
    abortProtectedRequests(); vi.useFakeTimers(); vi.setSystemTime(windowsNow); setLocale('en', false); vi.mocked(request).mockReset(); view = windowsMaintenanceView();
    vi.mocked(request).mockImplementation(async (path, options) => {
        if (path === '/auth/session') return structuredClone(session);
        if (path.startsWith('/fleet/windows-incidents?')) return windowsIncidentView();
        if (options?.method === 'POST') {
            const body = JSON.parse(options.body as string);
            view.targets = view.targets.map(target => target.key !== body.key ? target : {
                ...target, revision: target.revision + 1, changedAt: view.serverNow,
                windows: path.endsWith('/start') ? [{ id: target.revision + 1, startedAt: view.serverNow, endsAt: body.endsAt, endedAt: null, intent: body.intent }, ...target.windows].slice(0, 4) : target.windows.map((window, index) => index === 0 ? { ...window, endedAt: view.serverNow } : window),
            });
        }
        return structuredClone(view);
    });
});
afterEach(() => { cleanup(); abortProtectedRequests(); localStorage.removeItem(LOGOUT_INTENT_KEY); sessionStorage.removeItem(LOGOUT_INTENT_KEY); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('compact Windows maintenance metadata panel', () => {
    it('starts collapsed, reads once on demand and discloses metadata-only effects', async () => {
        render(<Harness/>); await flush(); expect(request).not.toHaveBeenCalled(); await open();
        expect(reads()).toHaveLength(1); expect(reads()[0][2]).toBe(256 * 1024); expect(screen.getByText(/Checks and incidents continue; external alarms aren’t suppressed/)).toBeVisible();
        expect(screen.getByRole('combobox', { name: 'Exact Windows device' })).toHaveValue(''); expect(screen.queryByRole('button', { name: 'Start maintenance' })).toBeNull();
        fireEvent.click(screen.getByRole('button', { name: 'Windows maintenance' })); expect(screen.queryByRole('combobox')).toBeNull();
    });
    it('requires an exact identity, scope and explicit intent before a frozen visible UTC-end review', async () => {
        render(<Harness/>); await open(); select(); expect(screen.getByRole('button', { name: 'Review maintenance start' })).toBeDisabled();
        expect(screen.getByRole('combobox', { name: 'Operator intent' })).toHaveValue('');
        fireEvent.change(screen.getByRole('combobox', { name: 'Operator intent' }), { target: { value: 'investigation' } }); fireEvent.change(screen.getByRole('combobox', { name: 'Duration' }), { target: { value: '15' } }); fireEvent.click(screen.getByRole('button', { name: 'Review maintenance start' }));
        const region = screen.getByRole('region', { name: 'Review exact maintenance change' }); expect(within(region).getByText(new RegExp(windowsDeviceId))).toBeVisible(); expect(within(region).getByText('2026-10-07T12:15:10Z')).toBeVisible(); expect(posts()).toHaveLength(0);
        await advance(1000); expect(within(region).getByText('2026-10-07T12:15:10Z')).toBeVisible(); fireEvent.click(screen.getByRole('button', { name: 'Cancel review' })); expect(screen.queryByRole('region', { name: 'Review exact maintenance change' })).toBeNull(); expect(posts()).toHaveLength(0);
    });
    it('starts exactly the reviewed key/revision/end/intent with CSRF, then reconciles by GET', async () => {
        render(<Harness/>); await open(); review(); fireEvent.click(screen.getByRole('button', { name: 'Start maintenance' })); fireEvent.click(screen.getByRole('button', { name: 'Review maintenance start' })); await flush();
        expect(posts()).toHaveLength(1); expect(posts()[0][0]).toBe('/fleet/windows-maintenance/start'); expect(posts()[0][2]).toBe(256 * 1024);
        expect(JSON.parse(posts()[0][1]!.body as string)).toEqual({ key: windowsMaintenanceTarget('disk').key, revision: 0, endsAt: '2026-10-07T12:30:10Z', intent: 'planned-work' });
        expect(posts()[0][1]!.headers).toEqual({ 'Content-Type': 'application/json', 'X-CSRF-Token': 'fixture-csrf' }); expect(reads()).toHaveLength(2); expect(screen.getByText(/Maintenance started/)).toBeVisible();
        expect(screen.getByRole('list', { name: 'Current maintenance labels' })).toHaveTextContent('Maintenance now · until'); expect(screen.getByRole('button', { name: 'Review early end' })).toBeVisible();
    });
    it('reviews and ends only the selected latest active window, preserving its scheduled end', async () => {
        setWindow('disk', windowsMaintenanceWindow()); const endsAt = view.targets[3].windows[0].endsAt; render(<Harness/>); await open(); select();
        fireEvent.click(screen.getByRole('button', { name: 'Review early end' })); expect(posts()).toHaveLength(0); fireEvent.click(screen.getByRole('button', { name: 'End maintenance now' })); await flush();
        expect(posts()).toHaveLength(1); expect(posts()[0][0]).toBe('/fleet/windows-maintenance/end'); expect(JSON.parse(posts()[0][1]!.body as string)).toEqual({ key: view.targets[3].key, revision: 1, windowId: 1 });
        expect(view.targets[3].windows[0].endsAt).toBe(endsAt); fireEvent.click(screen.getByText(/^Latest maintenance windows ·/)); expect(screen.getByText('Ended early')).toBeVisible(); expect(screen.getByText(/No recovery is implied/)).toBeVisible();
    });
    it('uses GET only after uncertainty and keeps the same revision blocked across refresh and collapse', async () => {
        const normal = vi.mocked(request).getMockImplementation()!; vi.mocked(request).mockImplementation(async (path, options, cap) => options?.method === 'POST' ? Promise.reject(new Error('lost response')) : normal(path, options, cap));
        render(<Harness/>); await open(); review(); fireEvent.click(screen.getByRole('button', { name: 'Start maintenance' })); await flush(); expect(posts()).toHaveLength(1); expect(reads()).toHaveLength(2);
        expect(screen.getByText(/The change could not be confirmed/)).toBeVisible(); expect(screen.getByRole('button', { name: 'Review maintenance start' })).toBeDisabled();
        fireEvent.click(screen.getByRole('button', { name: 'Refresh maintenance' })); await flush(); fireEvent.click(screen.getByRole('button', { name: 'Windows maintenance' })); await open(); expect(posts()).toHaveLength(1); expect(screen.getByRole('button', { name: 'Review maintenance start' })).toBeDisabled();
    });
    it('allows a new deliberate review only after a later revision reconciles an uncertain change', async () => {
        const normal = vi.mocked(request).getMockImplementation()!; vi.mocked(request).mockImplementation(async (path, options, cap) => options?.method === 'POST' ? Promise.reject(new Error('lost response')) : normal(path, options, cap));
        render(<Harness/>); await open(); review(); fireEvent.click(screen.getByRole('button', { name: 'Start maintenance' })); await flush(); setWindow('disk', windowsMaintenanceWindow());
        fireEvent.click(screen.getByRole('button', { name: 'Refresh maintenance' })); await flush(); expect(screen.getByRole('button', { name: 'Review early end' })).toBeEnabled(); expect(posts()).toHaveLength(1);
    });
    it('treats a mismatched success response as uncertain and never replays it', async () => {
        const normal = vi.mocked(request).getMockImplementation()!; vi.mocked(request).mockImplementation(async (path, options, cap) => options?.method === 'POST' ? structuredClone(view) : normal(path, options, cap));
        render(<Harness/>); await open(); review(); fireEvent.click(screen.getByRole('button', { name: 'Start maintenance' })); await flush(); expect(screen.getByText(/The change could not be confirmed/)).toBeVisible(); expect(posts()).toHaveLength(1); expect(reads()).toHaveLength(2);
    });
    it('does not hide or acknowledge incident rows or change source/count text after a start', async () => {
        render(<><WindowsIncidentInbox devices={devices} sessionKey={windowsCapacitySession} admin/><Harness/></>); fireEvent.click(screen.getByRole('button', { name: 'Windows incidents' })); await flush();
        const inbox = screen.getByRole('region', { name: 'Windows incidents' }), before = inbox.textContent; await open(); review(); fireEvent.click(screen.getByRole('button', { name: 'Start maintenance' })); await flush();
        expect(inbox.textContent).toBe(before); expect(within(inbox).getByRole('button', { name: /^Mark seen:/ })).toBeVisible(); expect(within(inbox).getByText('Source status: Above threshold')).toBeVisible(); expect(posts().every(([path]) => path === '/fleet/windows-maintenance/start')).toBe(true);
    });
    it('gives named operators read-only current labels and retained history', async () => {
        setWindow('disk', windowsMaintenanceWindow()); render(<Harness admin={false}/>); await open(); select(); expect(screen.getByText(/Your access is read-only/)).toBeVisible();
        expect(screen.queryByRole('button', { name: 'Review early end' })).toBeNull(); expect(screen.queryByRole('combobox', { name: 'Operator intent' })).toBeNull(); fireEvent.click(screen.getByText(/^Latest maintenance windows ·/)); expect(screen.getByText(/Latest four windows/)).toBeVisible(); expect(posts()).toHaveLength(0);
    });
    it('prevents all/domain overlap while permitting an independent sibling domain', async () => {
        setWindow('disk', windowsMaintenanceWindow()); render(<Harness/>); await open(); select('all'); expect(screen.getByText(/overlaps this selection/)).toBeVisible(); expect(screen.queryByRole('button', { name: 'Review maintenance start' })).toBeNull();
        fireEvent.change(screen.getByRole('combobox', { name: 'Maintenance scope' }), { target: { value: 'cpu' } }); expect(screen.getByRole('button', { name: 'Review maintenance start' })).toBeDisabled();
    });
    it('ages active into expired at the original end without a write or a recovery claim', async () => {
        setWindow('disk', windowsMaintenanceWindow({ startedAt: '2026-10-07T11:59:11Z', endsAt: '2026-10-07T12:00:11Z' })); render(<Harness/>); await open(); select(); fireEvent.click(screen.getByRole('button', { name: 'Review early end' })); await advance(1000);
        fireEvent.click(screen.getByText(/^Latest maintenance windows ·/)); expect(screen.getByText('Expired')).toBeVisible(); expect(screen.queryByRole('list', { name: 'Current maintenance labels' })).toBeNull(); expect(screen.getByRole('button', { name: 'End maintenance now' })).toBeDisabled(); expect(posts()).toHaveLength(0); expect(reads()).toHaveLength(1);
    });
    it('keeps an explicit early-end state after scheduled expiry', async () => {
        setWindow('disk', windowsMaintenanceWindow({ startedAt: '2026-10-07T11:59:11Z', endsAt: '2026-10-07T12:00:11Z', endedAt: windowsNow })); render(<Harness/>); await open(); select(); fireEvent.click(screen.getByText(/^Latest maintenance windows ·/)); await advance(1000);
        expect(screen.getByText('Ended early')).toBeVisible(); expect(screen.queryByText('Expired')).toBeNull(); expect(posts()).toHaveLength(0);
    });
    it('clears review when selection, scope, intent, duration or refresh changes', async () => {
        render(<Harness/>); await open(); review(); fireEvent.change(screen.getByRole('combobox', { name: 'Duration' }), { target: { value: '60' } }); expect(screen.queryByRole('button', { name: 'Start maintenance' })).toBeNull();
        fireEvent.click(screen.getByRole('button', { name: 'Review maintenance start' })); fireEvent.change(screen.getByRole('combobox', { name: 'Operator intent' }), { target: { value: 'other' } }); expect(screen.queryByRole('button', { name: 'Start maintenance' })).toBeNull();
        fireEvent.click(screen.getByRole('button', { name: 'Review maintenance start' })); fireEvent.change(screen.getByRole('combobox', { name: 'Maintenance scope' }), { target: { value: 'cpu' } }); expect(screen.getByRole('combobox', { name: 'Operator intent' })).toHaveValue(''); expect(screen.queryByRole('button', { name: 'Start maintenance' })).toBeNull();
        review(); fireEvent.click(screen.getByRole('button', { name: 'Refresh maintenance' })); await flush(); expect(screen.queryByRole('button', { name: 'Start maintenance' })).toBeNull(); expect(posts()).toHaveLength(0);
    });
    it('does not carry a same-device-ID selection onto replacement identity keys', async () => {
        render(<Harness/>); await open(); review(); view.targets = view.targets.map((target, index) => ({ ...target, key: (index + 20).toString(16).padStart(64, '0') }));
        fireEvent.click(screen.getByRole('button', { name: 'Refresh maintenance' })); await flush(); expect(screen.getByRole('combobox', { name: 'Exact Windows device' })).toHaveValue(''); expect(screen.queryByRole('button', { name: 'Start maintenance' })).toBeNull(); expect(screen.queryByRole('combobox', { name: 'Operator intent' })).toBeNull();
    });
    it.each(['blur', 'hashchange', 'popstate', 'pagehide', AUTH_REQUIRED_EVENT])('clears private review/history and aborts delayed reads on %s', async event => {
        render(<Harness/>); await open(); review(); let finish!: (value: unknown) => void; vi.mocked(request).mockReturnValueOnce(new Promise(resolve => { finish = resolve; })); fireEvent.click(screen.getByRole('button', { name: 'Refresh maintenance' })); const old = reads().at(-1)!;
        act(() => window.dispatchEvent(new Event(event))); expect(old[1]?.signal?.aborted).toBe(true); await act(async () => finish(structuredClone(view))); expect(screen.queryByRole('combobox', { name: 'Exact Windows device' })).toBeNull(); expect(screen.queryByRole('button', { name: 'Start maintenance' })).toBeNull();
    });
    it('clears hidden private data and only reads again on visibility restoration', async () => {
        render(<Harness/>); await open(); review(); const visibility = vi.spyOn(document, 'visibilityState', 'get'); visibility.mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); expect(screen.queryByRole('combobox')).toBeNull();
        visibility.mockReturnValue('visible'); act(() => document.dispatchEvent(new Event('visibilitychange'))); await flush(); expect(screen.getByRole('combobox', { name: 'Exact Windows device' })).toBeVisible(); expect(screen.queryByRole('button', { name: 'Start maintenance' })).toBeNull(); expect(posts()).toHaveLength(0);
    });
    it('never replays an interrupted POST after focus restoration', async () => {
        const normal = vi.mocked(request).getMockImplementation()!; let finish!: (value: unknown) => void; vi.mocked(request).mockImplementation(async (path, options, cap) => options?.method === 'POST' ? new Promise(resolve => { finish = resolve; }) : normal(path, options, cap));
        render(<Harness/>); await open(); review(); fireEvent.click(screen.getByRole('button', { name: 'Start maintenance' })); await flush(); act(() => window.dispatchEvent(new Event('blur'))); expect(posts()[0][1]?.signal?.aborted).toBe(true);
        act(() => window.dispatchEvent(new Event('focus'))); await flush(); expect(screen.getByRole('button', { name: 'Review maintenance start' })).toBeDisabled(); await act(async () => finish(structuredClone(view))); expect(posts()).toHaveLength(1); expect(screen.getByText(/The change could not be confirmed/)).toBeVisible();
    });
    it.each(['epoch', 'logout'])('withholds private rows after %s', async reason => {
        setWindow('disk', windowsMaintenanceWindow()); render(<Harness/>); await open(); act(() => { if (reason === 'epoch') abortProtectedRequests(); else localStorage.setItem(LOGOUT_INTENT_KEY, '1'); }); await advance(250);
        expect(screen.queryByRole('list', { name: 'Current maintenance labels' })).toBeNull(); expect(posts()).toHaveLength(0);
    });
    it('withholds a frozen manager clock after the two-minute lease and after refresh', async () => {
        render(<Harness/>); await open(); review(); await advance(120000); expect(screen.queryByRole('combobox')).toBeNull(); fireEvent.click(screen.getByRole('button', { name: 'Refresh maintenance' })); await flush(); expect(screen.queryByRole('combobox')).toBeNull(); expect(screen.getByText(/unavailable or expired/)).toBeVisible();
    });
    it.each(['authority', 'session'])('withholds data and review at exact %s expiry', async expiry => {
        const at = '2026-10-07T12:00:11Z'; if (expiry === 'authority') view.authorityExpiresAt = at; render(<Harness sessionKey={expiry === 'session' ? at : windowsCapacitySession}/>); await open(); review(); await advance(1000); expect(screen.queryByRole('combobox')).toBeNull(); expect(screen.queryByRole('button', { name: 'Start maintenance' })).toBeNull(); expect(posts()).toHaveLength(0);
    });
    it('rechecks administrator/session/CSRF after review and before POST', async () => {
        render(<Harness/>); await open(); review(); vi.mocked(request).mockResolvedValueOnce({ ...session, loginMode: 'named', actorId: 'operator_fixture' }); fireEvent.click(screen.getByRole('button', { name: 'Start maintenance' })); await flush(); expect(posts()).toHaveLength(0);
    });
    it('rejects an older target revision even when the manager time advances', async () => {
        setWindow('disk', windowsMaintenanceWindow({ endedAt: windowsNow })); render(<Harness/>); await open(); view = windowsMaintenanceView(undefined, { serverNow: '2026-10-07T12:00:11Z' }); fireEvent.click(screen.getByRole('button', { name: 'Refresh maintenance' })); await flush(); expect(screen.queryByRole('combobox')).toBeNull(); expect(screen.getByText(/unavailable or expired/)).toBeVisible();
    });
    it('has German intent, UTC review and honest lifecycle labels', async () => {
        setLocale('de', false); render(<Harness/>); fireEvent.click(screen.getByRole('button', { name: 'Windows-Wartung' })); await flush(); fireEvent.change(screen.getByRole('combobox', { name: 'Exaktes Windows-Gerät' }), { target: { value: view.targets[0].key } });
        fireEvent.change(screen.getByRole('combobox', { name: 'Absicht des Operators' }), { target: { value: 'planned-work' } }); fireEvent.click(screen.getByRole('button', { name: 'Wartungsstart prüfen' })); expect(screen.getByText(/Geplantes Ende \(UTC\)/)).toBeVisible(); fireEvent.click(screen.getByRole('button', { name: 'Wartung starten' })); await flush();
        expect(screen.getByRole('list', { name: 'Aktuelle Wartungsmarkierungen' })).toHaveTextContent('Wartung jetzt · bis'); expect(screen.getByText(/Prüfungen und Vorfälle laufen weiter/)).toBeVisible();
    });
});
