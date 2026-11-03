import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mutateRaw, request } from './api';
import { useOperator } from './auth';
import { DeviceDetail } from './details';
import { setLocale } from './i18n';
import { emptyEndpointView } from './endpoint-identity-fixtures';
import { updatePage, updateRows, updateView } from './complete-updates-fixtures';
import { windowsDevice, windowsDeviceId } from './windows-inventory-fixture';
import { windowsPatchContextView } from './windows-patch-context-fixture';
import { windowsUpdates } from './windows-updates-fixture';
import { unavailablePackageUpdates } from './package-update-fixtures';
import type { Device } from './types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const id = windowsDeviceId, expiresAt = '2026-10-07T12:30:00Z';
const operator = { mode: 'lan' as const, authenticated: true, expiresAt, insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
let device: Device;
const complete = () => ({ ...updateView(4), deviceId: id });
const flush = () => act(async () => {});
beforeEach(() => {
    setLocale('en', false); sessionStorage.clear(); localStorage.clear(); device = { ...windowsDevice(), platform: 'linux', name: 'Synthetic patch navigation', os: 'Linux fixture', agentCertificate: undefined };
    vi.mocked(useOperator).mockReturnValue(operator);
    vi.mocked(request).mockReset().mockImplementation(async path => {
        if (path === `/devices/${id}`) return device;
        if (path.endsWith('/inventory/endpoint-identity')) return { ...emptyEndpointView(), deviceId: id };
        if (path.endsWith('/inventory/complete-updates')) return complete();
        if (path.endsWith('/windows-inventory')) return { ...windowsPatchContextView(), updates: windowsUpdates() };
        if (path.endsWith('/package-updates')) return { ...unavailablePackageUpdates(), deviceId: id };
        throw new Error(`Unconfigured synthetic route: ${path}`);
    });
    vi.mocked(mutateRaw).mockReset().mockImplementation(async (_path, raw) => updatePage(complete(), updateRows(4), raw));
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });
async function open() { render(<DeviceDetail id={id} onClose={vi.fn()} onCase={vi.fn()}/>); await flush(); }

describe('patch evidence in the existing device page', () => {
    it('opens only metadata on Linux, then deliberately reaches the complete candidate source view', async () => {
        await open();
        const before = vi.mocked(request).mock.calls.filter(([path]) => path.endsWith('/inventory/complete-updates')).length;
        fireEvent.click(screen.getByRole('tab', { name: 'Patch evidence' })); await flush();
        expect(screen.getByRole('tab', { name: 'Patch evidence' })).toHaveAttribute('aria-selected', 'true');
        expect(screen.getByRole('region', { name: 'Patch evidence' })).toBeVisible(); expect(screen.queryByRole('table')).toBeNull();
        expect(vi.mocked(request).mock.calls.filter(([path]) => path.endsWith('/inventory/complete-updates'))).toHaveLength(before + 1);
        expect(mutateRaw).not.toHaveBeenCalled();
        fireEvent.click(screen.getByRole('button', { name: 'Open source view' })); await flush();
        expect(screen.getByRole('tab', { name: 'Inventory' })).toHaveAttribute('aria-selected', 'true'); expect(screen.getByRole('tab', { name: 'Updates' })).toHaveAttribute('aria-selected', 'true');
        expect(screen.getByLabelText('Update view')).toHaveValue('complete'); expect(screen.getByRole('rowheader', { name: 'fixture-update-000000' })).toBeVisible();
        expect(vi.mocked(mutateRaw).mock.calls.map(([path]) => path)).toEqual([`/devices/${id}/inventory/complete-updates/query`]);
    });
    it('reuses the admitted Windows resource and opens Updates rather than Processes', async () => {
        device = { ...windowsDevice(), name: 'Synthetic patch navigation' }; await open();
        const reads = vi.mocked(request).mock.calls.filter(([path]) => path.endsWith('/windows-inventory')).length;
        fireEvent.click(screen.getByRole('tab', { name: 'Patch evidence' })); await flush();
        expect(screen.getByText('Cached results observed')).toBeVisible(); expect(screen.getByText('Retained events', { selector: 'dt' })).toBeVisible();
        expect(vi.mocked(request).mock.calls.filter(([path]) => path.endsWith('/windows-inventory'))).toHaveLength(reads); expect(mutateRaw).not.toHaveBeenCalled();
        fireEvent.click(screen.getByRole('button', { name: 'Open source view' })); await flush();
        expect(screen.getByRole('tab', { name: 'Updates' })).toHaveAttribute('aria-selected', 'true'); expect(screen.getByRole('tab', { name: 'Processes' })).toHaveAttribute('aria-selected', 'false');
        expect(screen.getByRole('region', { name: 'Cached Windows Updates' })).toBeVisible(); expect(screen.getByText('Synthetic cached update 001')).toBeVisible(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it.each(['macos', 'unknown'] as const)('does not advertise Windows/Linux patch scope for %s devices', async platform => {
        device = { ...device, platform }; await open(); expect(screen.queryByRole('tab', { name: 'Patch evidence' })).toBeNull();
    });
    it('does not expose the tab to synthetic or unauthenticated devices', async () => {
        device.synthetic = true; await open(); expect(screen.queryByRole('tab', { name: 'Patch evidence' })).toBeNull(); cleanup();
        device.synthetic = false; vi.mocked(useOperator).mockReturnValue({ ...operator, authenticated: false }); await open(); expect(screen.queryByRole('tab', { name: 'Patch evidence' })).toBeNull();
    });
    it('unmounts the Linux reader on navigation and keeps a late response out of the next tab', async () => {
        await open(); let finish!: (value: unknown) => void; let signal: AbortSignal | null = null;
        vi.mocked(request).mockImplementation(async (path, init) => {
            if (path.endsWith('/inventory/complete-updates')) { signal = init?.signal as AbortSignal; return new Promise(done => { finish = done; }); }
            return device;
        });
        fireEvent.click(screen.getByRole('tab', { name: 'Patch evidence' })); await flush(); fireEvent.click(screen.getByRole('tab', { name: 'Evidence' })); await flush();
        expect((signal as AbortSignal | null)?.aborted).toBe(true); await act(async () => finish(complete())); expect(screen.queryByRole('region', { name: 'Patch evidence' })).toBeNull(); expect(screen.queryByText('Known newer candidates')).toBeNull();
    });
});
