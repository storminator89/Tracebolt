import wire from '../../tests/fixtures/windows-notifications-view.json';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT, request } from './api';
import { setLocale } from './i18n';
import { windowsCapacityDevice, windowsCapacitySession } from './windows-capacity-fixture';
import { windowsNow } from './windows-inventory-fixture';
import { windowsNotificationView } from './windows-notifications-fixture';
import { validWindowsNotificationView } from './windows-notifications-types';
import { WindowsNotifications } from './windows-notifications';
import type { WindowsNotificationView } from './windows-notifications-types';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
const session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'fixture-csrf', serverNow: windowsNow, expiresAt: windowsCapacitySession, expiresInSeconds: 3590, loginMode: 'shared', actorId: null, capabilities: ['read'] };
let view: WindowsNotificationView;
const flush = () => act(async () => {});
const posts = () => vi.mocked(request).mock.calls.filter(([, options]) => options?.method === 'POST');
const reads = () => vi.mocked(request).mock.calls.filter(([path]) => path === '/fleet/windows-notifications');
function Harness({ admin = true }: { admin?: boolean }) { return <WindowsNotifications devices={[{ ...windowsCapacityDevice(), name: 'Desk One' }]} sessionKey={windowsCapacitySession} admin={admin}/>; }
async function open() { fireEvent.click(screen.getByRole('button', { name: 'Windows notifications' })); await flush(); }
function review() { fireEvent.change(screen.getByRole('combobox', { name: 'Device and check' }), { target: { value: view.targets[2].key } }); fireEvent.click(screen.getByRole('button', { name: 'Review enablement' })); }
beforeEach(() => {
    abortProtectedRequests(); vi.useFakeTimers(); vi.setSystemTime(windowsNow); setLocale('en', false); vi.mocked(request).mockReset(); view = windowsNotificationView();
    vi.mocked(request).mockImplementation(async (path, options) => {
        if (path === '/auth/session') return structuredClone(session);
        if (options?.method === 'POST') { const body = JSON.parse(options.body as string); view.targets = view.targets.map(t => t.key === body.key ? { ...t, revision: t.revision + 1, enabled: body.enabled, effective: body.enabled, changedAt: view.serverNow } : t); }
        return structuredClone(view);
    });
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });
describe('Windows notification source policy', () => {
    it('requires a visible destination, exact source and unchecked payload approval', async () => {
        render(<Harness/>); await flush(); expect(request).not.toHaveBeenCalled(); await open(); expect(reads()).toHaveLength(1); expect(posts()).toHaveLength(0); review();
        expect(screen.getAllByText('Destination: receiver.example.test').some(node => !node.closest('details'))).toBe(true); expect(screen.getByText(/device and incident IDs, check and selected service name/)).toBeVisible(); expect(screen.getByRole('checkbox')).not.toBeChecked(); expect(screen.getByRole('button', { name: 'Confirm change' })).toBeDisabled();
        fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Confirm change' })); await flush(); expect(posts()).toHaveLength(1); expect(JSON.parse(posts()[0][1]!.body as string)).toEqual({ key: view.targets[2].key, revision: 0, enabled: true, destinationBinding: view.destinationBinding, payloadAcknowledged: true }); expect(screen.getByText('On', { selector: 'strong' })).toBeVisible();
    });
    it('keeps named readers and destination setup separate', async () => {
        view.deliveryEnabled = false; view.counts.enabled = false; render(<Harness admin={false}/>); await open(); fireEvent.change(screen.getByRole('combobox'), { target: { value: view.targets[2].key } }); expect(screen.getByText(/Shared administrator required/)).toBeVisible(); expect(screen.getByText(/Configure and enable the destination/)).toBeVisible(); expect(screen.queryByRole('button', { name: 'Review enablement' })).toBeNull(); expect(posts()).toHaveLength(0);
    });
    it('expires the maintenance label while preserving source-on and retained suppression counts', async () => {
        view.targets[2] = { ...view.targets[2], enabled: true, effective: true, revision: 1, changedAt: windowsNow, maintenanceUntil: '2026-10-07T12:00:11Z' }; view.counts.suppressed = 2; render(<Harness/>); await open(); fireEvent.change(screen.getByRole('combobox'), { target: { value: view.targets[2].key } }); expect(screen.getByText(/Muted for maintenance until/)).toBeVisible(); expect(screen.getByLabelText('Retained Windows delivery counts')).toHaveTextContent('Suppressed: 2'); await act(async () => vi.advanceTimersByTimeAsync(1250)); expect(screen.queryByText(/Muted for maintenance until/)).toBeNull(); expect(screen.getByText('On', { selector: 'strong' })).toBeVisible(); expect(posts()).toHaveLength(0);
    });
    it('reconciles an uncertain save without retrying it', async () => {
        vi.mocked(request).mockImplementation(async (path, options) => { if (path === '/auth/session') return structuredClone(session); if (options?.method === 'POST') throw new Error('lost response'); return structuredClone(view); }); render(<Harness/>); await open(); review(); fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Confirm change' })); await flush(); expect(posts()).toHaveLength(1); expect(screen.getByText(/Change unconfirmed/)).toBeVisible(); expect(screen.getByRole('button', { name: 'Review enablement' })).toBeDisabled(); fireEvent.click(screen.getByRole('button', { name: 'Refresh' })); await flush(); expect(posts()).toHaveLength(1);
    });
    it.each(['blur', 'pagehide', 'popstate', 'hashchange', AUTH_REQUIRED_EVENT])('clears private state and approval on %s', async event => {
        render(<Harness/>); await open(); review(); fireEvent.click(screen.getByRole('checkbox')); act(() => window.dispatchEvent(new Event(event))); await flush(); expect(screen.queryByRole('checkbox')).toBeNull(); expect(screen.queryAllByText('Destination: receiver.example.test')).toHaveLength(0); expect(posts()).toHaveLength(0);
    });
    it('renders German approval and status', async () => {
        setLocale('de', false); render(<Harness/>); fireEvent.click(screen.getByRole('button', { name: 'Windows-Benachrichtigungen' })); await flush(); fireEvent.change(screen.getByRole('combobox', { name: 'Gerät und Prüfung' }), { target: { value: view.targets[2].key } }); fireEvent.click(screen.getByRole('button', { name: 'Aktivierung prüfen' })); expect(screen.getAllByText('Ziel: receiver.example.test').length).toBeGreaterThan(0); expect(screen.getByRole('checkbox', { name: /Ich erlaube/ })).not.toBeChecked(); expect(posts()).toHaveLength(0);
    });
    it('rejects unknown fields, impossible counts and incomplete domains', () => {
        expect(validWindowsNotificationView(wire)).toBe(true); expect(validWindowsNotificationView(view)).toBe(true); for (const value of [{ ...view, endpoint: 'private' }, { ...view, destinationHost: 'https://secret.invalid/path' }, { ...view, targets: [view.targets[0]] }, { ...view, targets: view.targets.map(t => ({ ...t, effective: true })) }, { ...view, counts: { ...view.counts, queued: 501 } }]) expect(validWindowsNotificationView(value)).toBe(false);
    });
});
