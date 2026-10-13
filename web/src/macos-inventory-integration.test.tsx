import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mutateRaw, request } from './api';
import { DeviceDetail } from './details';
import { setLocale } from './i18n';
import { macInventoryDevice, macInventoryDeviceId, macInventoryFixtureClock } from './macos-inventory-fixture';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: () => ({ mode: 'lan', authenticated: true, insecureTestMode: false, expiresAt: '2026-10-13T10:30:00Z' }) }));
let macInventoryFixture: ReturnType<typeof macInventoryFixtureClock>;
beforeEach(() => { macInventoryFixture = macInventoryFixtureClock(); setLocale('en', false); vi.mocked(request).mockReset().mockImplementation(async path => { if (path === `/devices/${macInventoryDeviceId}`) return macInventoryDevice(); throw new Error(`Unexpected route ${path}`); }); vi.mocked(mutateRaw).mockReset().mockImplementation(async (_path, raw) => macInventoryFixture(JSON.parse(raw))); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); });
describe('Mac DeviceDetail integration', () => {
 it('adds the inventory workspace in the shared device page without Linux-only overview cards or reads', async () => {
  render(<DeviceDetail id={macInventoryDeviceId} onClose={() => {}} onCase={() => {}}/>); await screen.findByRole('heading', { name: 'Synthetic Mac' }); expect(screen.queryByText('Updates', { exact: true })).not.toBeInTheDocument(); expect(screen.queryByText('cached candidates')).not.toBeInTheDocument(); expect(mutateRaw).not.toHaveBeenCalled(); fireEvent.click(screen.getByRole('tab', { name: 'Inventory' })); await screen.findByText('Mac14,12'); fireEvent.click(screen.getByRole('tab', { name: 'Package receipts' })); await screen.findByText('com.example.fixture.editor'); fireEvent.click(screen.getByRole('button', { name: 'Refresh device metadata' })); await waitFor(() => expect(screen.getByRole('button', { name: 'Refresh device metadata' })).toBeEnabled()); expect(screen.getByRole('tab', { name: 'Package receipts' })).toHaveAttribute('aria-selected', 'true'); expect(screen.getByText('com.example.fixture.editor')).toBeVisible(); fireEvent.click(screen.getByRole('tab', { name: 'Details' })); expect(screen.queryByText('com.example.fixture.editor')).not.toBeInTheDocument(); expect(screen.queryByText(/existing APT cache/)).not.toBeInTheDocument(); expect(vi.mocked(request).mock.calls.every(([path]) => path === `/devices/${macInventoryDeviceId}`)).toBe(true);
 });
 it('shows explicit basic-Mac unavailability without querying the expanded route', async () => {
  vi.mocked(request).mockResolvedValue(macInventoryDevice(false)); render(<DeviceDetail id={macInventoryDeviceId} onClose={() => {}} onCase={() => {}}/>); fireEvent.click(await screen.findByRole('tab', { name: 'Inventory' })); expect(await screen.findByText(/This Mac has basic read-only scope/)).toBeVisible(); expect(mutateRaw).not.toHaveBeenCalled();
 });
});
