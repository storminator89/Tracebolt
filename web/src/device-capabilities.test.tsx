import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DeviceCapabilities } from './device-capabilities';
import { APIError, AUTH_REQUIRED_EVENT, request } from './api';
import { setLocale } from './i18n';
import { systemDevice, systemView } from './system-inventory-fixtures';
import type { Device } from './types';
import type { SystemView } from './system-inventory-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
const authFixture = vi.hoisted(() => ({ expiresAt: '2026-10-05T00:00:00Z' }));
vi.mock('./auth', () => ({ hasLogoutIntent: () => false, useOperator: () => ({ mode: 'lan', authenticated: true, expiresAt: authFixture.expiresAt, insecureTestMode: false }) }));
const device = (): Device => ({ id: systemDevice, name: 'Synthetic fixture', platform: 'linux', os: 'Debian fixture', source: 'lan', synthetic: false, status: 'unknown', lastSeen: '2026-10-04T00:00:00Z', capabilities: [
    { id: 'host_inventory', name: 'Host attribution', status: 'limited', detail: 'Static scope is not a failed read.' },
    { id: 'systemd', name: 'Service inventory', status: 'scope', detail: 'Source data must establish this result.' },
    { id: 'socket_inventory', name: 'Connections', status: 'scope', detail: 'Owner fields are separate.' },
    { id: 'remote_actions', name: 'Remote control', status: 'unsupported', detail: 'Not part of this read profile.' },
] } as Device);
const row = (id: string) => document.querySelector(`[data-capability="${id}"]`)!;
beforeEach(() => { authFixture.expiresAt = '2026-10-05T00:00:00Z'; setLocale('en', false); vi.mocked(request).mockReset().mockImplementation(async () => systemView()); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('compact capability collection status', () => {
    it('replaces static orange scope badges with actual bounded source status', async () => {
        render(<DeviceCapabilities device={device()}/>);
        await waitFor(() => expect(row('systemd')).toHaveAttribute('data-state', 'available'));
        expect(row('systemd')).toHaveTextContent('Collected');
        expect(row('host_inventory')).toHaveAttribute('data-state', 'scope');
        expect(row('remote_actions')).toHaveAttribute('data-state', 'unsupported');
        expect(document.querySelectorAll('.capability-row.attention')).toHaveLength(0);
        expect(row('systemd').querySelector('details')).not.toHaveAttribute('open');
        expect(screen.getByText('Source data must establish this result.')).not.toBeVisible();
        fireEvent.click(row('systemd').querySelector('summary')!);
        expect(screen.getByText('Source data must establish this result.')).toBeVisible();
        expect(request).toHaveBeenCalledTimes(1);
        expect(vi.mocked(request).mock.calls[0][0]).toBe(`/devices/${systemDevice}/inventory/system`);
        expect(row('socket_inventory')).toHaveAttribute('data-state', 'available');
    });
    it('keeps permission failure visible but treats unsupported source as neutral', async () => {
        const v = systemView();
        v.latest!.services = { ...v.latest!.services, coverage: 'failed', reason: 'permission_denied', observedCount: null, countExact: false };
        v.latest!.sockets = { ...v.latest!.sockets, coverage: 'failed', reason: 'not_supported', observedCount: null, countExact: false };
        vi.mocked(request).mockResolvedValue(v);
        render(<DeviceCapabilities device={device()}/>);
        await waitFor(() => expect(row('systemd')).toHaveAttribute('data-state', 'denied'));
        expect(row('systemd')).toHaveClass('attention');
        expect(row('systemd')).toHaveTextContent('Permission denied');
        expect(row('socket_inventory')).toHaveAttribute('data-state', 'unsupported');
        expect(row('socket_inventory')).not.toHaveClass('attention');
    });
    it('does not display success for malformed, wrong-device or unreadable status', async () => {
        vi.mocked(request).mockResolvedValue({ ...systemView(), deviceId: 'agent_other' });
        render(<DeviceCapabilities device={device()}/>);
        await waitFor(() => expect(screen.getByRole('button', { name: 'Check status' })).toBeEnabled());
        expect(row('systemd')).toHaveAttribute('data-state', 'unknown');
        vi.mocked(request).mockRejectedValue(new APIError('Denied', 403));
        fireEvent.click(screen.getByRole('button', { name: 'Check status' }));
        await waitFor(() => expect(row('systemd')).toHaveAttribute('data-state', 'denied'));
        expect(row('systemd')).toHaveTextContent('operator_access_denied');
    });
    it('aborts on suspension and discards late results before a fresh resume read', async () => {
        let resolve!: (value: SystemView) => void, signal: AbortSignal | undefined;
        vi.mocked(request).mockImplementation(async (_, options) => { signal = options?.signal as AbortSignal; return new Promise<SystemView>(r => { resolve = r; }); });
        render(<DeviceCapabilities device={device()}/>);
        await waitFor(() => expect(signal).toBeDefined());
        fireEvent.blur(window); expect(signal!.aborted).toBe(true);
        await act(async () => resolve(systemView()));
        expect(row('systemd')).toHaveAttribute('data-state', 'unknown');
        vi.mocked(request).mockResolvedValue(systemView()); fireEvent.focus(window);
        await waitFor(() => expect(row('systemd')).toHaveAttribute('data-state', 'available'));
        act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));
        expect(row('systemd')).toHaveAttribute('data-state', 'unknown');
        expect(screen.getByRole('button', { name: 'Check status' })).toBeDisabled();
        fireEvent.focus(window); expect(request).toHaveBeenCalledTimes(2);
    });
    it('does not renew the age of an unchanged source when server time stalls', async () => {
        vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'performance', 'Date'] });
        render(<DeviceCapabilities device={device()}/>);
        await act(async () => { await Promise.resolve(); });
        expect(row('systemd')).toHaveAttribute('data-state', 'available');
        await act(async () => { await vi.advanceTimersByTimeAsync(111000); });
        expect(request).toHaveBeenCalledTimes(8);
        expect(row('systemd')).toHaveAttribute('data-state', 'stale');
        expect(row('systemd')).toHaveTextContent('Stale');
    });
    it('manual refresh preserves stale age under unchanged server time and resets only for a different device', async () => {
        vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'performance', 'Date'] });
        const rendered = render(<DeviceCapabilities device={device()}/>);
        await act(async () => { await Promise.resolve(); });
        await act(async () => { await vi.advanceTimersByTimeAsync(111000); });
        expect(row('systemd')).toHaveAttribute('data-state', 'stale');
        for (let attempt = 0; attempt < 3; attempt++) {
            fireEvent.click(screen.getByRole('button', { name: 'Check status' }));
            await act(async () => { await Promise.resolve(); });
            expect(row('systemd')).toHaveAttribute('data-state', 'stale');
        }
        const next = { ...device(), id: 'agent_new_capability_fixture' };
        vi.mocked(request).mockResolvedValue({ ...systemView(), deviceId: next.id });
        rendered.rerender(<DeviceCapabilities device={next}/>);
        await act(async () => { await Promise.resolve(); });
        expect(row('systemd')).toHaveAttribute('data-state', 'available');
    });
    it('manual refresh cannot extend the original session deadline', async () => {
        vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'performance', 'Date'] });
        authFixture.expiresAt = '2026-10-04T00:00:40Z';
        render(<DeviceCapabilities device={device()}/>);
        await act(async () => { await Promise.resolve(); });
        await act(async () => { await vi.advanceTimersByTimeAsync(20000); });
        fireEvent.click(screen.getByRole('button', { name: 'Check status' }));
        await act(async () => { await Promise.resolve(); });
        await act(async () => { await vi.advanceTimersByTimeAsync(10000); });
        expect(screen.getByRole('button', { name: 'Check status' })).toBeDisabled();
        expect(row('systemd')).toHaveAttribute('data-state', 'unknown');
        expect(screen.getByRole('alert')).toHaveTextContent('Session ended');
    });
    it('keeps older managed service profiles informational without a v3 status request', async () => {
        const v = device(); v.capabilities = [{ id: 'systemd', name: 'Services', status: 'scope', detail: 'Managed operational preview.' }];
        render(<DeviceCapabilities device={v}/>);
        await act(async () => { await Promise.resolve(); });
        expect(row('systemd')).toHaveAttribute('data-state', 'scope');
        expect(request).not.toHaveBeenCalled();
    });
    it('does not issue source requests for a basic profile or a synthetic device', async () => {
        const v = device(); v.capabilities = v.capabilities.filter(c => c.status !== 'scope');
        const rendered = render(<DeviceCapabilities device={v}/>);
        await act(async () => { await Promise.resolve(); }); expect(request).not.toHaveBeenCalled();
        rendered.rerender(<DeviceCapabilities device={{ ...device(), synthetic: true }}/>);
        await act(async () => { await Promise.resolve(); }); expect(request).not.toHaveBeenCalled();
    });
});
