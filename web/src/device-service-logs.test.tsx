import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, mutate, mutateRaw, request } from './api';
import { useOperator } from './auth';
import { DeviceDetail } from './details';
import { setLocale } from './i18n';
import { emptyEndpointView } from './endpoint-identity-fixtures';
import { completePage, completeRows, completeView } from './complete-packages-fixtures';
import { journalDevice as id, journalNow, journalSession, journalSessionExpiry, journalView } from './journal-fixtures';
import { serviceRows, systemPage, systemView } from './system-inventory-fixtures';
import type { HealthView } from './health-types';
import type { Device, Metric } from './types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: journalSessionExpiry, insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
const services = serviceRows(2), system = { ...systemView(2, 0), deviceId: id }, packages = { ...completeView(), deviceId: id };
function device(deviceId = id): Device {
    const metric: Metric = { value: null, unit: '%', quality: 'unknown', source: 'Synthetic fixture', collectedAt: '0001-01-01T00:00:00Z' };
    return { id: deviceId, name: 'Synthetic service diagnosis', platform: 'linux', os: 'Linux fixture', site: 'Fixture', group: 'Fixture', ip: null, status: 'unknown', source: 'lan', synthetic: false, lastSeen: '0001-01-01T00:00:00Z', agentVersion: 'fixture', cpu: metric, memory: metric, disk: metric, uptime: '', tags: [], capabilities: [], evidence: [], trend: [], caseIds: [] };
}
const health: HealthView = {
    schemaVersion: 'tracebolt.health-view.v1', deviceId: id, serverNow: journalNow, evaluatedAt: journalNow, status: 'unknown', maintenanceUntil: null,
    monitoredServices: [services[0].name], incidents: [], checks: [
        { key: 'offline:contact', kind: 'offline', target: 'agent', state: 'ok', observedAt: journalNow, value: 0 },
        { key: 'filesystem:root', kind: 'filesystem', target: '/', state: 'ok', observedAt: journalNow, value: 30 },
        { key: `service:${services[0].name}`, kind: 'service', target: services[0].name, state: 'unknown', observedAt: null, value: null },
    ],
};
function answer(path: string): unknown {
    if (path === '/auth/session') return journalSession;
    if (path.endsWith('/inventory/endpoint-identity')) return { ...emptyEndpointView(), deviceId: id };
    if (path.endsWith('/inventory/packages')) return packages;
    if (path.endsWith('/inventory/system')) return system;
    if (path.endsWith('/health')) return health;
    if (path.endsWith('/journal')) return journalView('awaiting');
    if (path === `/devices/${id}`) return device();
    throw new Error('Unconfigured synthetic fixture path');
}
const flush = () => act(async () => {});
function assertNoCapture() {
    expect(mutate).not.toHaveBeenCalled();
    // Both are bounded read-only inventory queries; journal creation/cancel remains forbidden.
    expect(vi.mocked(mutateRaw).mock.calls.every(([path]) => [`/devices/${id}/inventory/system/query`, `/devices/${id}/inventory/packages/query`].includes(path))).toBe(true);
}
async function openServices() {
    fireEvent.click(screen.getByRole('tab', { name: 'Inventory' })); await flush();
    fireEvent.click(screen.getByRole('tab', { name: 'Services' })); await flush();
}
async function start() {
    const onClose = vi.fn(), result = render(<main><DeviceDetail id={id} onClose={onClose} onCase={vi.fn()}/></main>); await flush();
    return { ...result, onClose };
}
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime(journalNow); localStorage.clear(); sessionStorage.clear(); setLocale('en', false);
    vi.mocked(useOperator).mockReturnValue(operator);
    vi.mocked(request).mockReset().mockImplementation(async path => answer(path));
    vi.mocked(mutate).mockReset(); vi.mocked(mutateRaw).mockReset().mockImplementation(async (path, raw) => {
        if (path === `/devices/${id}/inventory/packages/query`) return completePage(packages, completeRows(), raw);
        if (path !== `/devices/${id}/inventory/system/query`) throw new Error('Unexpected mutation');
        return systemPage(system, services, [], raw);
    });
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('explicit service to Logs navigation', () => {
    it('opens the failed service as an unapproved draft and repeated Logs clicks preserve it', async () => {
        await start(); await openServices();
        const row = screen.getByRole('rowheader', { name: services[0].name }).closest('tr')!;
        expect(row).toHaveTextContent('failed');
        const open = within(row).getByRole('button', { name: `Open logs: ${services[0].name}` });
        expect(open).toHaveAttribute('type', 'button'); fireEvent.click(open); await flush();
        openAdvanced(); const tab = screen.getByRole('tab', { name: 'Logs' }), input = screen.getByLabelText('Exact service unit');
        expect(tab).toHaveAttribute('aria-selected', 'true'); expect(tab).toHaveFocus(); expect(input).toHaveValue(services[0].name);
        expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); fireEvent.click(screen.getByRole('button', { name: 'Fetch logs' })); expect(screen.getByRole('checkbox')).not.toBeChecked(); expect(screen.getByRole('button', { name: 'Capture logs' })).toBeDisabled(); fireEvent.click(screen.getByRole('button', { name: 'Back' }));
        fireEvent.change(input, { target: { value: 'draft.service' } }); const calls = vi.mocked(request).mock.calls.length;
        fireEvent.click(tab); fireEvent.click(tab); await flush();
        expect(screen.getByLabelText('Exact service unit')).toBe(input); expect(input).toHaveValue('draft.service'); expect(request).toHaveBeenCalledTimes(calls); assertNoCapture();
    });
    it('preserves service selection, draft, focus and scroll through a metadata refresh', async () => {
        await start(); await openServices();
        fireEvent.click(screen.getByRole('button', { name: `Open logs: ${services[0].name}` })); await flush();
        openAdvanced(); const input = screen.getByLabelText('Exact service unit'), main = screen.getByRole('main');
        fireEvent.change(input, { target: { value: 'draft.service' } }); input.focus(); main.scrollTop = 321;
        let finish!: (value: Device) => void;
        vi.mocked(request).mockImplementation(async path => path === `/devices/${id}` ? new Promise<Device>(resolve => { finish = resolve; }) : answer(path));
        fireEvent.click(screen.getByRole('button', { name: 'Refresh device metadata' })); await flush();
        await act(async () => finish({ ...device(), os: 'Updated metadata' }));
        expect(screen.getByLabelText('Exact service unit')).toBe(input); expect(input).toHaveValue('draft.service'); expect(input).toHaveFocus(); expect(main.scrollTop).toBe(321);
        expect(screen.getByRole('tab', { name: 'Logs' })).toHaveAttribute('aria-selected', 'true'); assertNoCapture();
    });
    it('discards the handoff on normal tab navigation and replaces it only for the next explicit service', async () => {
        await start(); await openServices(); fireEvent.click(screen.getByRole('button', { name: `Open logs: ${services[0].name}` })); await flush();
        fireEvent.click(screen.getByRole('tab', { name: 'Overview' })); await flush(); fireEvent.click(screen.getByRole('tab', { name: 'Logs' })); await flush();
        expect(screen.getByLabelText('Exact service unit')).toHaveValue('');
        await openServices(); fireEvent.click(screen.getByRole('button', { name: `Open logs: ${services[1].name}` })); await flush();
        expect(screen.getByLabelText('Exact service unit')).toHaveValue(services[1].name); assertNoCapture();
    });
    it('keeps an unknown health check honest while offering the same explicit log shortcut', async () => {
        await start(); fireEvent.click(screen.getByRole('tab', { name: 'Health & history' })); await flush();
        const checks = screen.getByRole('list', { name: 'Current checks' }); expect(checks).toHaveTextContent('Unknown'); expect(checks).toHaveTextContent('Time unknown');
        expect(within(checks).getAllByRole('button', { name: /^Open logs:/ })).toHaveLength(1);
        fireEvent.click(within(checks).getByRole('button', { name: `Open logs: ${services[0].name}` })); await flush();
        expect(screen.getByLabelText('Exact service unit')).toHaveValue(services[0].name); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); fireEvent.click(screen.getByRole('button', { name: 'Fetch logs' })); expect(screen.getByRole('checkbox')).not.toBeChecked(); expect(screen.getByRole('button', { name: 'Capture logs' })).toBeDisabled(); assertNoCapture();
    });
    it('aborts a delayed log read on Back and does not revive its service draft after reopening', async () => {
        const mounted = await start(); await openServices(); let finish!: (value: unknown) => void, signal: AbortSignal | undefined;
        vi.mocked(request).mockImplementation(async (path, options) => path.endsWith('/journal') ? new Promise(resolve => { finish = resolve; signal = options?.signal as AbortSignal; }) : answer(path));
        fireEvent.click(screen.getByRole('button', { name: `Open logs: ${services[0].name}` })); await flush();
        expect(signal).toBeDefined(); fireEvent.click(screen.getByRole('button', { name: 'Back to devices' })); expect(mounted.onClose).toHaveBeenCalledOnce();
        mounted.unmount(); expect(signal!.aborted).toBe(true); await act(async () => finish(journalView('awaiting')));
        vi.mocked(request).mockImplementation(async path => answer(path)); await start();
        expect(screen.getByRole('tab', { name: 'Overview' })).toHaveAttribute('aria-selected', 'true');
        fireEvent.click(screen.getByRole('tab', { name: 'Logs' })); await flush(); expect(screen.getByLabelText('Exact service unit')).toHaveValue(''); assertNoCapture();
    });
});

function openAdvanced() {
    const summary = screen.getByText(/^(Advanced|Erweitert)$/, { selector: 'summary' });
    if (!summary.closest('details')!.open) fireEvent.click(summary);
}
