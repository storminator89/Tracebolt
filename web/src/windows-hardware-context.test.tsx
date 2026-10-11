import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, request, mutate } from './api';
import { setLocale } from './i18n';
import { WindowsInventoryWorkspace } from './windows-inventory';
import { useWindowsInventory } from './windows-inventory-resource';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import { windowsHardwareContextView } from './windows-hardware-context-fixture';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
const flush = () => act(async () => {});
function Harness({ session = 'fixture', device = windowsDeviceId, enabled = true }: { session?: string; device?: string; enabled?: boolean }) { return <WindowsInventoryWorkspace resource={useWindowsInventory(device, enabled, session)}/>; }
const ready = async (locale = 'en') => { await flush(); fireEvent.click(screen.getByRole('tab', { name: locale === 'de' ? 'Gerät' : 'Device' })); };
const refresh = () => fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' }));
const details = () => document.querySelector<HTMLDetailsElement>('.windows-hardware-details')!;
const namesGone = () => { expect(screen.queryByText('Example Laptop 14')).toBeNull(); expect(screen.queryByText('FIXTURE-CHASSIS-0042')).toBeNull(); expect(document.querySelector('.windows-hardware-details')).toBeNull(); };
beforeEach(() => { setLocale('en', false); vi.mocked(request).mockReset().mockResolvedValue(windowsHardwareContextView()); vi.mocked(mutate).mockReset(); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });
describe('Compact private Device tab', () => {
    it.each(['en', 'de'] as const)('shows hardware/power summary and optional source details in %s', async locale => {
        setLocale(locale, false); render(<Harness/>); await ready(locale); const de = locale === 'de', panel = screen.getByRole('region', { name: de ? 'Gerät' : 'Device' });
        for (const value of ['Fixture Devices', 'Example Laptop 14', 'FIXTURE-CHASSIS-0042', 'F.42', '2026-08-15', '74%']) expect(within(panel).getByText(value)).toBeVisible();
        expect(within(panel).getByText(de ? 'Gehäuseseriennummer (Win32_SystemEnclosure)' : 'Chassis serial (Win32_SystemEnclosure)')).toBeVisible();
        expect(within(panel).getByText(de ? 'BIOS-Seriennummer (Win32_BIOS)' : 'BIOS serial (Win32_BIOS)')).not.toBeVisible();
        expect(details().open).toBe(false); expect(panel.querySelector('time')).toHaveAttribute('datetime', windowsView().snapshot!.collectedAt);
        fireEvent.click(details().querySelector('summary')!); expect(within(details()).getByText(de ? 'Zugriff verweigert' : 'Access denied')).toBeVisible(); expect(details()).toHaveTextContent(de ? 'keine geprüfte Systemseriennummer' : 'not a verified system serial');
        expect(panel.querySelector('a,img,iframe,button,form,input')).toBeNull(); expect(mutate).not.toHaveBeenCalled(); expect(vi.mocked(request).mock.calls.map(([path]) => path)).toEqual([`/devices/${windowsDeviceId}/windows-inventory`]);
    });
    it('renders source labels as isolated text, never links or markup', async () => {
        const v = windowsHardwareContextView(); v.hardwareContext.system.model.value = '<img src=x onerror=alert(1)>'; v.hardwareContext.chassis.serialNumber.value = 'https://example.invalid/private'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeVisible(); expect(screen.getByText('https://example.invalid/private').tagName).toBe('BDI'); expect(document.querySelector('.windows-hardware-context a,.windows-hardware-context img')).toBeNull();
    });
    it('distinguishes absent battery, unknown battery, denied BIOS and empty chassis independently', async () => {
        const v = windowsHardwareContextView(); Object.assign(v.hardwareContext.power, { batteryPresence: 'absent', charging: 'unknown', batteryPercent: null }); v.hardwareContext.chassis.serialNumber = { value: null, quality: 'empty' }; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); expect(screen.getByText('No battery reported')).toBeVisible(); expect(within(screen.getByRole('region', { name: 'Chassis' })).getByText('Not reported')).toBeVisible(); expect(screen.getByText('Example Laptop 14')).toBeVisible();
        Object.assign(v.hardwareContext.power, { quality: 'partial', reason: 'windows_hardware_context_partial_result', batteryPresence: 'unknown' }); vi.mocked(request).mockResolvedValue(structuredClone(v)); refresh(); await flush(); expect(screen.queryByText('No battery reported')).toBeNull(); expect(within(screen.getByRole('region', { name: 'Power' })).getAllByText('Unknown').length).toBeGreaterThan(0);
    });
    it('resets disclosures after navigation and replacement generation', async () => {
        render(<Harness/>); await ready(); fireEvent.click(details().querySelector('summary')!); fireEvent.click(screen.getByRole('tab', { name: 'Hostname' })); namesGone(); await ready(); expect(details().open).toBe(false); fireEvent.click(details().querySelector('summary')!);
        const v = windowsHardwareContextView(); v.hardwareContext.generationId = v.snapshot!.generationId = `sample_${'9'.repeat(32)}`; vi.mocked(request).mockResolvedValue(v); refresh(); await flush(); expect(details().open).toBe(false);
    });
    it('shows consent absence and rejects unknown fields without rendering them', async () => {
        vi.mocked(request).mockResolvedValue(windowsView()); render(<Harness/>); await ready(); expect(screen.getByText(/Separate local approval/)).toBeVisible(); const v = windowsHardwareContextView(); Object.assign(v.hardwareContext, { uniqueDeviceId: 'private-marker' }); vi.mocked(request).mockResolvedValue(v); refresh(); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('inconsistent'); expect(document.body).not.toHaveTextContent('private-marker'); namesGone();
    });
    it('ages and expires private fields using original capture time', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const v = windowsHardwareContextView(); v.snapshot!.collectedAt = v.hardwareContext.collectedAt = '2026-10-07T11:58:10Z'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); expect(screen.queryByText(/Stale observation;/)).toBeNull(); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.getByText(/Stale observation;/)).toBeVisible(); cleanup();
        v.snapshot!.collectedAt = v.hardwareContext.collectedAt = '2026-10-06T12:00:11Z'; v.status = 'stale'; vi.setSystemTime(windowsNow); render(<Harness/>); await ready(); await act(async () => vi.advanceTimersByTimeAsync(1000)); namesGone(); expect(screen.getByText(/context expired/)).toBeVisible();
    });
    it('hides future captures until acceptance time reaches capture time', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const v = windowsHardwareContextView(); v.snapshot!.collectedAt = v.hardwareContext.collectedAt = '2026-10-07T12:00:11Z'; v.status = 'stale'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); namesGone(); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.getByText('Example Laptop 14')).toBeVisible();
    });
    it.each(['blur', 'pagehide', 'hashchange', AUTH_REQUIRED_EVENT])('removes collapsed identifying metadata on %s', async event => { render(<Harness/>); await ready(); act(() => window.dispatchEvent(new Event(event))); namesGone(); });
    it('discards revoked authority and ignores a late previous-session response', async () => {
        render(<Harness/>); await ready(); vi.mocked(request).mockResolvedValue({ ...windowsView(), status: 'revoked', snapshot: null }); refresh(); await flush(); namesGone(); cleanup();
        let resolve!: (v: ReturnType<typeof windowsHardwareContextView>) => void; vi.mocked(request).mockReturnValueOnce(new Promise(done => { resolve = done; })); const result = render(<Harness/>); await ready(); const signal = vi.mocked(request).mock.calls.at(-1)![1]?.signal; vi.mocked(request).mockResolvedValue(windowsView()); result.rerender(<Harness session="replacement"/>); await act(async () => resolve(windowsHardwareContextView())); expect(signal?.aborted).toBe(true); namesGone();
    });
});

describe('Hardware original-age retained observation', () => {
    function retained(at = '2026-10-07T11:00:00Z') {
        const v = windowsHardwareContextView(), old = structuredClone(v.hardwareContext); old.collectedAt = at; old.generationId = `sample_${'b'.repeat(32)}`;
        for (const key of ['system', 'firmware', 'chassis', 'power'] as const) {
            const source = v.hardwareContext[key]; source.quality = 'unavailable'; source.reason = 'windows_hardware_context_budget_exhausted';
            if (key === 'power') Object.assign(source, { acLineStatus: 'unknown', batteryPresence: 'unknown', charging: 'unknown', batteryPercent: null, estimatedSeconds: null });
            else for (const field of Object.values(source)) if (field && typeof field === 'object') Object.assign(field, { value: null, quality: 'unavailable' });
        }
        return { ...v, retainedContext: { hardwareContext: old } };
    }
    it('shows latest failure without silently replacing it with an older successful value', async () => {
        vi.mocked(request).mockResolvedValue(retained()); render(<Harness/>); await ready(); const current = document.querySelector('.windows-hardware-context')!;
        expect(current).not.toHaveTextContent('Example Laptop 14'); expect(current).toHaveTextContent('Unavailable'); expect(screen.getByText('Example Laptop 14')).not.toBeVisible(); fireEvent.click(screen.getByText('Show previous capture')); expect(screen.getByText('Example Laptop 14')).toBeVisible(); expect(screen.getByText(/keeps its original capture time/)).toBeVisible();
        expect(document.querySelector('time[datetime="2026-10-07T11:00:00Z"]')).not.toBeNull(); expect(current.querySelector('time')).toHaveAttribute('datetime', '2026-10-07T12:00:00Z');
        act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); namesGone(); expect(screen.queryByText('Show previous capture')).toBeNull();
    });
    it('expires the older capture independently while keeping current failure visible', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); vi.mocked(request).mockResolvedValue(retained('2026-10-06T12:00:11Z')); render(<Harness/>); await ready(); expect(screen.getByText('Show previous capture')).toBeVisible(); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.queryByText('Show previous capture')).toBeNull(); expect(screen.queryByText('FIXTURE-CHASSIS-0042')).toBeNull(); expect(document.querySelector('.windows-hardware-context')).toHaveTextContent('Unavailable');
    });
});
