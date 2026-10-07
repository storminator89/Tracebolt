import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DeviceTable } from './components';
import { FleetIdentityName } from './fleet-identity';
import { FleetCopyValue } from './fleet-copy';
import { fleetIdentityProjection } from './fleet-identity-types';
import { endpointDevice, endpointView } from './endpoint-identity-fixtures';
import type { Device } from './types';
import { setLocale } from './i18n';
const clip = Object.getOwnPropertyDescriptor(navigator, 'clipboard'), exec = Object.getOwnPropertyDescriptor(document, 'execCommand');
function setClipboard(writeText: (value: string) => Promise<void>) { Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } }); }
function setLegacy(copy: () => boolean) { Object.defineProperty(document, 'execCommand', { configurable: true, value: copy }); }
const identities = () => fleetIdentityProjection({ schemaVersion: 'tracebolt.fleet-endpoint-identity.v1', serverNow: endpointView().serverNow, items: [endpointView()] }, 0);
function device(): Device { const metric = { value: null, unit: '%', quality: 'unknown' as const, source: 'fixture', collectedAt: '0001-01-01T00:00:00Z' }; return { id: endpointDevice, name: endpointDevice, platform: 'linux', os: 'Linux', source: 'lan', synthetic: false, status: 'unknown', site: '', group: 'Managed devices', ip: '198.51.100.250', lastSeen: '0001-01-01T00:00:00Z', agentVersion: 'fixture', cpu: metric, memory: metric, disk: metric, uptime: '', tags: [], capabilities: [], evidence: [], trend: [], caseIds: [] }; }
const nameButton = () => screen.getByRole('button', { name: 'Copy hostname: fixture-linux' });
const ipButton = () => screen.getByRole('button', { name: 'Copy IP address: 192.0.2.19 (eth0)' });
beforeEach(() => { setLocale('en', false); vi.stubGlobal('isSecureContext', true); });
afterEach(() => { cleanup(); window.getSelection()?.removeAllRanges(); vi.unstubAllGlobals(); vi.restoreAllMocks(); if (clip) Object.defineProperty(navigator, 'clipboard', clip); else delete (navigator as unknown as { clipboard?: unknown }).clipboard; if (exec) Object.defineProperty(document, 'execCommand', exec); else delete (document as unknown as { execCommand?: unknown }).execCommand; });

describe('compact and copyable fleet identity', () => {
    it('keeps one address visible and puts ID, source, group and remaining addresses behind a keyboard-native disclosure', async () => {
        const user = userEvent.setup(); render(<FleetIdentityName identity={identities().get(endpointDevice)} deviceId={endpointDevice} group="Managed devices"/>);
        expect(screen.getByText('fixture-linux')).toBeVisible(); expect(screen.getByText('192.0.2.19')).toBeVisible(); expect(screen.queryByText('2001:db8::19')).not.toBeInTheDocument();
        expect(screen.getByText(`ID: ${endpointDevice}`)).not.toBeVisible(); expect(screen.getByText('Managed devices')).not.toBeVisible(); expect(screen.getByText('Recent')).not.toBeVisible();
        expect(screen.getAllByRole('button', { name: /^Copy / })).toHaveLength(2);
        await user.click(screen.getByText('+4 more IPs')); await screen.findByText('2001:db8::19'); expect(screen.getByText(`ID: ${endpointDevice}`)).toBeVisible(); expect(screen.getAllByRole('button', { name: /^Copy IP address:/ })).toHaveLength(5);
        expect(screen.getByText('eth0 · link-local')).toBeVisible(); await user.click(screen.getByText('+4 more IPs')); await waitFor(() => expect(screen.queryByText('2001:db8::19')).not.toBeInTheDocument());
    });
    it('calls clipboard with exact hostname and every address, without navigating or collecting more data', async () => {
        const user = userEvent.setup(), writeText = vi.fn().mockResolvedValue(undefined), onSelect = vi.fn(); setClipboard(writeText);
        render(<DeviceTable devices={[device()]} identities={identities()} onSelect={onSelect}/>);
        await user.click(nameButton()); expect(writeText).toHaveBeenLastCalledWith('fixture-linux'); await user.click(ipButton()); expect(writeText).toHaveBeenLastCalledWith('192.0.2.19');
        await user.click(screen.getByText('+4 more IPs')); await screen.findByText('2001:db8::19');
        for (const button of screen.getAllByRole('button', { name: /^Copy IP address:/ })) await user.click(button);
        expect(writeText.mock.calls.map(call => call[0])).toEqual(['fixture-linux', '192.0.2.19', '192.0.2.19', '2001:db8::19', 'fe80::19', '127.0.0.1', '::1']); expect(onSelect).not.toHaveBeenCalled();
        expect(screen.queryByText('198.51.100.250')).not.toBeInTheDocument();
    });
    it('allows real text selection and ordinary row/text clicks without navigation; only the explicit arrow opens the device', async () => {
        const user = userEvent.setup(), onSelect = vi.fn(); render(<DeviceTable devices={[device()]} identities={identities()} onSelect={onSelect}/>);
        const text = screen.getByText('192.0.2.19'); expect(text.closest('button')).toBeNull(); const range = document.createRange(); range.selectNodeContents(text); window.getSelection()!.addRange(range); expect(window.getSelection()!.toString()).toBe('192.0.2.19');
        fireEvent.click(text); fireEvent.click(screen.getAllByRole('row')[1]); expect(onSelect).not.toHaveBeenCalled();
        const arrow = screen.getByRole('button', { name: 'Open details: fixture-linux' }); arrow.focus(); await user.keyboard('{Enter}'); expect(onSelect).toHaveBeenCalledExactlyOnceWith(device());
    });
    it('supports keyboard copying with Enter and Space', async () => {
        const user = userEvent.setup(), writeText = vi.fn().mockResolvedValue(undefined); setClipboard(writeText); render(<FleetIdentityName identity={identities().get(endpointDevice)} deviceId={endpointDevice}/>);
        nameButton().focus(); await user.keyboard('{Enter}'); await waitFor(() => expect(writeText).toHaveBeenCalledWith('fixture-linux'));
        ipButton().focus(); await user.keyboard(' '); await waitFor(() => expect(writeText).toHaveBeenCalledWith('192.0.2.19'));
    });
    it('uses actual document selection with legacy copy in insecure HTTP contexts instead of an unavailable secure clipboard', async () => {
        const user = userEvent.setup(), writeText = vi.fn().mockResolvedValue(undefined), legacy = vi.fn(() => { expect(window.getSelection()?.toString()).toBe('192.0.2.19'); return true; }); setClipboard(writeText); setLegacy(legacy); vi.stubGlobal('isSecureContext', false);
        render(<FleetCopyValue value="192.0.2.19" label="Copy fixture IP"/>); await user.click(screen.getByRole('button', { name: 'Copy fixture IP' })); await screen.findByText('Copied'); expect(legacy).toHaveBeenCalledExactlyOnceWith('copy'); expect(writeText).not.toHaveBeenCalled(); expect(screen.getByRole('button')).toHaveFocus();
    });
    it.each([false, 'throws'] as const)('selects real text for manual copying after clipboard rejection and legacy copy %s, without claiming success', async failure => {
        const user = userEvent.setup(), writeText = vi.fn().mockRejectedValue(new Error('Denied')), legacy = vi.fn(() => { if (failure === 'throws') throw new Error('Unavailable'); return false; }); setClipboard(writeText); setLegacy(legacy);
        render(<FleetCopyValue value="fe80::19" label="Copy fixture IP"/>); await user.click(screen.getByRole('button')); await screen.findByText('Text selected. Copy it manually.'); expect(window.getSelection()?.toString()).toBe('fe80::19'); expect(screen.queryByText('Copied')).not.toBeInTheDocument(); expect(writeText).toHaveBeenCalledExactlyOnceWith('fe80::19'); expect(legacy).toHaveBeenCalledExactlyOnceWith('copy');
    });
    it('selects text when clipboard APIs are absent and reports selection unavailable honestly', async () => {
        const user = userEvent.setup(); Object.defineProperty(navigator, 'clipboard', { configurable: true, value: undefined }); Object.defineProperty(document, 'execCommand', { configurable: true, value: undefined });
        const { rerender } = render(<FleetCopyValue value="fixture-linux" label="Copy fixture name"/>); await user.click(screen.getByRole('button')); await screen.findByText('Text selected. Copy it manually.'); expect(window.getSelection()?.toString()).toBe('fixture-linux');
        rerender(<FleetCopyValue value="another-host" label="Copy fixture name"/>); vi.spyOn(window, 'getSelection').mockReturnValue(null); await user.click(screen.getByRole('button')); await screen.findByText('Please select and copy the text manually.'); expect(screen.queryByText('Copied')).not.toBeInTheDocument();
    });
    it('does not fall back to copying or report stale success after identity disappears during a pending clipboard request', async () => {
        const user = userEvent.setup(); let reject!: (e: Error) => void; const writeText = vi.fn().mockImplementation(() => new Promise<void>((_, fail) => { reject = fail; })), legacy = vi.fn(() => true); setClipboard(writeText); setLegacy(legacy);
        const { rerender } = render(<FleetIdentityName identity={identities().get(endpointDevice)} deviceId={endpointDevice}/>); await user.dblClick(nameButton()); expect(writeText).toHaveBeenCalledTimes(1); expect(nameButton()).toBeDisabled();
        const expired = { ...identities().get(endpointDevice)!, status: 'expired' as const, hostname: null, addresses: [], collectedAt: null, coverage: null };
        rerender(<FleetIdentityName identity={expired} deviceId={endpointDevice}/>); await act(async () => reject(new Error('Denied'))); expect(legacy).not.toHaveBeenCalled(); expect(screen.queryByText('Copied')).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: /^Copy / })).not.toBeInTheDocument(); expect(screen.getByText('Expired')).toBeVisible();
    });
    it('keeps stale, partial and failed collection warnings visible when technical details are closed', () => {
        const identity = { ...identities().get(endpointDevice)!, status: 'stale' as const, coverage: 'partial' as const, hostname: null, hostnameReason: 'permission_denied' as const };
        render(<FleetIdentityName identity={identity} deviceId={endpointDevice}/>); for (const value of ['Stale', 'Partially collected', 'Permission denied']) expect(screen.getByText(value)).toBeVisible();
        expect(screen.queryByRole('button', { name: /^Copy hostname:/ })).not.toBeInTheDocument(); expect(ipButton()).toBeEnabled();
    });
});
