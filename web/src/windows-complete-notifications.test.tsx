import wire from '../../tests/fixtures/windows-complete-notifications-view.json';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT, request } from './api';
import { setLocale } from './i18n';
import { windowsCapacityDevice, windowsCapacitySession } from './windows-capacity-fixture';
import { windowsNow } from './windows-inventory-fixture';
import { windowsNotificationView } from './windows-notifications-fixture';
import { windowsCompleteNotificationView } from './windows-complete-notifications-fixture';
import { validWindowsNotificationView } from './windows-notifications-types';
import { validWindowsCompleteNotificationView } from './windows-complete-notifications-types';
import { WindowsNotifications } from './windows-notifications';
import type { WindowsCompleteNotificationView } from './windows-complete-notifications-types';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
const session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'fixture-csrf', serverNow: windowsNow, expiresAt: windowsCapacitySession, expiresInSeconds: 3590, loginMode: 'shared', actorId: null, capabilities: ['read'] };
let view: WindowsCompleteNotificationView;
const flush = () => act(async () => {});
const posts = () => vi.mocked(request).mock.calls.filter(([, options]) => options?.method === 'POST');
const reads = () => vi.mocked(request).mock.calls.filter(([path]) => path === '/fleet/windows-notifications/complete');
function Harness({ admin = true, sessionKey = windowsCapacitySession }: { admin?: boolean; sessionKey?: string | null }) { return <WindowsNotifications devices={[{ ...windowsCapacityDevice(), name: 'Desk One' }]} sessionKey={sessionKey} admin={admin}/>; }
async function open(locale = 'en') {
    fireEvent.click(screen.getByRole('button', { name: locale === 'de' ? 'Windows-Benachrichtigungen' : 'Windows notifications' })); await flush();
    fireEvent.click(screen.getByRole('button', { name: locale === 'de' ? 'Vollständig' : 'Complete' })); await flush();
}
function select(locale = 'en') { fireEvent.change(screen.getByRole('combobox', { name: locale === 'de' ? 'Gerät und vollständige Prüfung' : 'Device and complete check' }), { target: { value: view.targets[0].key } }); }
function review(locale = 'en') { select(locale); fireEvent.click(screen.getByRole('button', { name: locale === 'de' ? 'Aktivierung prüfen' : 'Review enablement' })); }
async function approve() { fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Confirm change' })); await flush(); }
beforeEach(() => {
    abortProtectedRequests(); vi.useFakeTimers(); vi.setSystemTime(windowsNow); setLocale('en', false); vi.mocked(request).mockReset(); view = windowsCompleteNotificationView();
    vi.mocked(request).mockImplementation(async (path, options) => {
        if (path === '/auth/session') return structuredClone(session);
        if (path === '/fleet/windows-notifications') return windowsNotificationView();
        if (options?.method === 'POST') { const body = JSON.parse(options.body as string); view.targets = view.targets.map(target => target.key === body.key ? { ...target, revision: target.revision + 1, enabled: body.enabled, effective: body.enabled, changedAt: view.serverNow } : target); }
        return structuredClone(view);
    });
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('complete-source notifications in the collapsed production panel', () => {
    it.each(['en', 'de'])('requires independent exact-name, recipient and unchecked consent in %s', async locale => {
        setLocale(locale as 'en' | 'de', false); render(<Harness/>); await flush(); expect(request).not.toHaveBeenCalled(); await open(locale); expect(reads()).toHaveLength(1); expect(posts()).toHaveLength(0); review(locale);
        const box = document.querySelector('.windows-maintenance-review') as HTMLElement;
        expect(within(box).getByText(`${locale === 'de' ? 'Ziel' : 'Destination'}: receiver.example.test`)).toBeVisible();
        for (const name of view.targets[0].services) expect(within(box).getByText(name, { exact: true })).toBeVisible();
        expect(screen.getByRole('checkbox', { name: locale === 'de' ? /vollständigen Quelle/ : /complete-source/ })).not.toBeChecked();
        const confirm = screen.getByRole('button', { name: locale === 'de' ? 'Änderung bestätigen' : 'Confirm change' }); expect(confirm).toBeDisabled();
        fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(confirm); await flush();
        expect(posts()).toHaveLength(1); expect(posts()[0][0]).toBe('/fleet/windows-notifications/complete/policy');
        expect(JSON.parse(posts()[0][1]!.body as string)).toEqual({ key: view.targets[0].key, revision: 0, enabled: true, destinationBinding: view.destinationBinding, payloadAcknowledged: true });
        expect(posts()[0][1]!.headers).toEqual({ 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrfToken }); expect(reads()).toHaveLength(2);
    });
    it('does not transfer preview approval or pending review on source switches', async () => {
        render(<Harness/>); await open(); review(); fireEvent.click(screen.getByRole('checkbox'));
        fireEvent.click(screen.getByRole('button', { name: 'Preview' })); await flush(); expect(screen.queryByRole('checkbox')).toBeNull(); expect(screen.queryByText('Source: Complete service inventory')).toBeNull();
        fireEvent.change(screen.getByRole('combobox', { name: 'Device and check' }), { target: { value: windowsNotificationView().targets[4].key } }); expect(screen.getByText('Off', { selector: 'strong' })).toBeVisible();
        fireEvent.click(screen.getByRole('button', { name: 'Complete' })); await flush(); review(); expect(screen.getByRole('checkbox')).not.toBeChecked(); expect(posts()).toHaveLength(0);
    });
    it('keeps named operators read-only, including named alarm administrators', async () => {
        render(<Harness admin={false}/>); await open(); select(); expect(screen.getByText(/Shared administrator required/)).toBeVisible(); expect(screen.queryByRole('button', { name: 'Review enablement' })).toBeNull(); expect(screen.queryByRole('checkbox')).toBeNull(); expect(posts()).toHaveLength(0);
    });
    it('rechecks shared administrator authority before a POST', async () => {
        const implementation = vi.mocked(request).getMockImplementation()!;
        vi.mocked(request).mockImplementation(async (path, options, bytes) => path === '/auth/session' ? { ...session, loginMode: 'named', actorId: `operator_${'6'.repeat(32)}`, capabilities: ['read', 'alarm_admin'] } : implementation(path, options, bytes));
        render(<Harness/>); await open(); review(); await approve(); expect(posts()).toHaveLength(0); expect(screen.getByText(/Change unconfirmed/)).toBeVisible();
    });
    it('blocks unknown evidence while allowing a retained approval to be disabled', async () => {
        Object.assign(view.targets[0], { actionable: false, enabled: true, effective: false, revision: 2, changedAt: windowsNow });
        render(<Harness/>); await open(); select(); expect(screen.getByRole('button', { name: 'Review enablement' })).toBeDisabled(); expect(screen.getByText(/Current complete-source evidence is unavailable or unknown/)).toBeVisible();
        expect(screen.getByRole('link', { name: 'Review complete service checks' })).toHaveAttribute('href', `#/devices/${view.targets[0].deviceId}/health`);
        fireEvent.click(screen.getByRole('button', { name: 'Review disablement' })); expect(screen.queryByRole('checkbox')).toBeNull(); fireEvent.click(screen.getByRole('button', { name: 'Confirm change' })); await flush();
        expect(JSON.parse(posts()[0][1]!.body as string)).toEqual({ key: view.targets[0].key, revision: 2, enabled: false, destinationBinding: '', payloadAcknowledged: false });
    });
    it('requires fresh explicit approval after a destination or health revision changes', async () => {
        Object.assign(view.targets[0], { enabled: true, effective: false, revision: 3, healthPolicyRevision: 4, changedAt: windowsNow });
        view.destinationHost = 'new.receiver.test'; view.destinationBinding = 'd'.repeat(64); render(<Harness/>); await open(); review(); expect(screen.getByRole('checkbox')).not.toBeChecked(); expect(screen.getAllByText('Destination: new.receiver.test').some(node => !node.closest('details'))).toBe(true); await approve();
        expect(JSON.parse(posts()[0][1]!.body as string)).toMatchObject({ revision: 3, destinationBinding: 'd'.repeat(64) });
    });
    it('requires destination setup separately and never falls back to preview on failure', async () => {
        view.deliveryEnabled = false; view.counts.enabled = false; render(<Harness/>); await open(); select(); expect(screen.getByRole('button', { name: 'Review enablement' })).toBeDisabled(); expect(screen.getByText(/Configure and enable the destination/)).toBeVisible();
        const before = vi.mocked(request).mock.calls.filter(([path]) => path === '/fleet/windows-notifications').length;
        vi.mocked(request).mockRejectedValue(new Error('unavailable')); fireEvent.click(screen.getByRole('button', { name: 'Refresh' })); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('Complete notifications are unavailable');
        expect(vi.mocked(request).mock.calls.filter(([path]) => path === '/fleet/windows-notifications')).toHaveLength(before); expect(posts()).toHaveLength(0);
    });
    it('uses GET-only uncertainty reconciliation with no replay across source switches', async () => {
        const implementation = vi.mocked(request).getMockImplementation()!;
        vi.mocked(request).mockImplementation(async (path, options, bytes) => { if (options?.method === 'POST') throw new Error('lost response'); return implementation(path, options, bytes); });
        render(<Harness/>); await open(); review(); await approve(); expect(posts()).toHaveLength(1); expect(screen.getByText(/Change unconfirmed/)).toBeVisible(); expect(screen.getByRole('button', { name: 'Review enablement' })).toBeDisabled();
        fireEvent.click(screen.getByRole('button', { name: 'Refresh' })); await flush(); fireEvent.click(screen.getByRole('button', { name: 'Preview' })); await flush(); fireEvent.click(screen.getByRole('button', { name: 'Complete' })); await flush(); select(); expect(screen.getByRole('button', { name: 'Review enablement' })).toBeDisabled(); expect(posts()).toHaveLength(1);
        Object.assign(view.targets[0], { revision: 1, enabled: true, effective: true, changedAt: windowsNow }); fireEvent.click(screen.getByRole('button', { name: 'Refresh' })); await flush(); expect(screen.getByRole('button', { name: 'Review disablement' })).toBeEnabled(); expect(posts()).toHaveLength(1);
    });
    it.each(['blur', 'pagehide', 'popstate', 'hashchange', AUTH_REQUIRED_EVENT])('clears private names, destination and consent on %s', async event => {
        render(<Harness/>); await open(); review(); fireEvent.click(screen.getByRole('checkbox')); act(() => window.dispatchEvent(new Event(event))); await flush(); expect(screen.queryByRole('checkbox')).toBeNull(); expect(screen.queryAllByText('Destination: receiver.example.test')).toHaveLength(0); expect(screen.queryAllByText(view.targets[0].services[0])).toHaveLength(0); expect(posts()).toHaveLength(0);
    });
    it('clears approval on Cancel, collapse, refresh and session change', async () => {
        const rendered = render(<Harness/>); await open(); review(); fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Cancel' })); review(); expect(screen.getByRole('checkbox')).not.toBeChecked();
        fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Windows notifications' })); await flush(); expect(screen.queryByRole('checkbox')).toBeNull(); fireEvent.click(screen.getByRole('button', { name: 'Windows notifications' })); await flush(); review(); expect(screen.getByRole('checkbox')).not.toBeChecked();
        fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Refresh' })); await flush(); expect(screen.queryByRole('checkbox')).toBeNull(); review(); fireEvent.click(screen.getByRole('checkbox')); rendered.rerender(<Harness sessionKey={null}/>); await flush(); expect(screen.queryByRole('checkbox')).toBeNull(); expect(posts()).toHaveLength(0);
    });
    it('withholds a late GET after navigation', async () => {
        let resolveRead: (value: unknown) => void = () => {};
        vi.mocked(request).mockImplementation(async path => path === '/fleet/windows-notifications' ? windowsNotificationView() : new Promise(resolve => { resolveRead = resolve; }));
        render(<Harness/>); await open(); act(() => window.dispatchEvent(new Event('hashchange'))); resolveRead(view); await flush(); expect(screen.queryByRole('combobox', { name: 'Device and complete check' })).toBeNull(); expect(posts()).toHaveLength(0);
    });

    it('consumes the actual Go-exported long-name projection in the mounted panel', async () => {
        view = structuredClone(wire) as WindowsCompleteNotificationView; view.serverNow = windowsNow; view.authorityExpiresAt = '2026-10-07T12:02:10Z'; view.targets[0].effective = false;
        render(<Harness/>); await open(); review(); const box = document.querySelector('.windows-maintenance-review')!;
        expect(box.querySelector('.windows-notifications-names li')!.textContent).toBe(wire.targets[0].services[0]); expect(screen.getByRole('checkbox')).not.toBeChecked(); expect(posts()).toHaveLength(0);
    });
    it('keeps the uncertain fence after an interrupted POST and ignores late success', async () => {
        const implementation = vi.mocked(request).getMockImplementation()!; let resolvePost: (value: unknown) => void = () => {};
        vi.mocked(request).mockImplementation(async (path, options, bytes) => options?.method === 'POST' ? new Promise(resolve => { resolvePost = resolve; }) : implementation(path, options, bytes));
        render(<Harness/>); await open(); review(); await approve(); expect(posts()).toHaveLength(1); fireEvent.click(screen.getByRole('button', { name: 'Preview' })); await flush();
        const late = structuredClone(view); Object.assign(late.targets[0], { enabled: true, effective: true, revision: 1, changedAt: windowsNow }); resolvePost(late); await flush();
        fireEvent.click(screen.getByRole('button', { name: 'Complete' })); await flush(); select(); expect(screen.getByRole('button', { name: 'Review enablement' })).toBeDisabled(); expect(screen.queryByText('Policy saved.')).toBeNull(); expect(posts()).toHaveLength(1);
    });
    it('does not POST after authority expires during the fresh-session read', async () => {
        const implementation = vi.mocked(request).getMockImplementation()!; let resolveSession: (value: unknown) => void = () => {};
        vi.mocked(request).mockImplementation(async (path, options, bytes) => path === '/auth/session' ? new Promise(resolve => { resolveSession = resolve; }) : implementation(path, options, bytes));
        view.authorityExpiresAt = '2026-10-07T12:00:11Z'; render(<Harness/>); await open(); review(); await approve(); await act(async () => vi.advanceTimersByTimeAsync(1250)); resolveSession(session); await flush(); expect(posts()).toHaveLength(0); expect(screen.queryByRole('checkbox')).toBeNull();
    });
    it('rejects a regressed notification revision on refresh', async () => {
        Object.assign(view.targets[0], { enabled: true, effective: true, revision: 3, changedAt: windowsNow }); render(<Harness/>); await open(); select(); view.targets[0].revision = 2;
        fireEvent.click(screen.getByRole('button', { name: 'Refresh' })); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('Complete notifications are unavailable'); expect(screen.queryByRole('combobox', { name: 'Device and complete check' })).toBeNull();
    });
    it('resets consent when the local grant and reviewed health scope change', async () => {
        render(<Harness/>); await open(); review(); fireEvent.click(screen.getByRole('checkbox')); Object.assign(view.targets[0], { key: 'e'.repeat(64), healthPolicyRevision: 2, grantId: 'f'.repeat(32), grantRevision: 2, services: ['New exact service'] });
        fireEvent.click(screen.getByRole('button', { name: 'Refresh' })); await flush(); expect(screen.queryByRole('checkbox')).toBeNull(); review(); expect(screen.getByRole('checkbox')).not.toBeChecked(); expect(document.querySelector('.windows-maintenance-review .windows-notifications-names')!.textContent).toBe('New exact service'); expect(posts()).toHaveLength(0);
    });
    it('rejects a successful-looking POST response with altered reviewed scope', async () => {
        const implementation = vi.mocked(request).getMockImplementation()!;
        vi.mocked(request).mockImplementation(async (path, options, bytes) => { if (options?.method === 'POST') { const result = structuredClone(view); Object.assign(result.targets[0], { enabled: true, effective: true, revision: 1, changedAt: windowsNow, services: ['Unreviewed name'] }); return result; } return implementation(path, options, bytes); });
        render(<Harness/>); await open(); review(); await approve(); expect(screen.getByText(/Change unconfirmed/)).toBeVisible(); expect(screen.queryByText('Policy saved.')).toBeNull(); expect(screen.getByRole('button', { name: 'Review enablement' })).toBeDisabled(); expect(posts()).toHaveLength(1);
    });
    it('expires authority and preserves exact 256-unit non-normalized native names', async () => {
        view.targets[0].services = ['  Native  ', 'e\u0301', 'é', '😀'.repeat(128)]; view.authorityExpiresAt = '2026-10-07T12:00:11Z'; render(<Harness/>); await open(); review();
        const rows = document.querySelector('.windows-maintenance-review .windows-notifications-names')!; expect([...rows.children].map(node => node.textContent)).toEqual(view.targets[0].services); fireEvent.click(screen.getByRole('checkbox')); await act(async () => vi.advanceTimersByTimeAsync(1250)); expect(screen.queryByRole('checkbox')).toBeNull(); expect(posts()).toHaveLength(0);
    });
});
describe('closed complete-notification projection', () => {
    it('separates v1 preview and complete envelopes', () => { expect(validWindowsCompleteNotificationView(wire)).toBe(true); expect(validWindowsCompleteNotificationView(view)).toBe(true); expect(validWindowsCompleteNotificationView(windowsNotificationView())).toBe(false); expect(validWindowsNotificationView(view)).toBe(false); });
    it('rejects malformed, duplicate and unqualified complete projections', () => {
        const target = view.targets[0];
        const invalid = [{ ...view, endpoint: 'private' }, { ...view, destinationHost: 'https://private/path' }, { ...view, authorityExpiresAt: '2026-10-07T12:10:10Z' }, { ...view, targets: [target, target] }, ...[{ extra: true }, { domain: 'service' }, { healthPolicyRevision: 0 }, { grantRevision: '1' }, { grantId: '' }, { effective: true }, { revision: 1, enabled: true, effective: true, changedAt: windowsNow, actionable: false }].map(change => ({ ...view, targets: [{ ...target, ...change }] })), ...[[''], [], ['a', 'a'], ['z', 'a'], ['a'.repeat(257)], ['\ud800'], ['a\0b'], Array.from({ length: 9 }, (_, index) => `a${index}`)].map(services => ({ ...view, targets: [{ ...target, services }] }))];
        for (const value of invalid) expect(validWindowsCompleteNotificationView(value)).toBe(false);
        expect(validWindowsCompleteNotificationView({ ...view, targets: [{ ...target, services: [], actionable: false }] })).toBe(true);
        expect(validWindowsCompleteNotificationView({ ...view, targets: [{ ...target, services: ['😀'.repeat(128)] }] })).toBe(true);
    });
});
