import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, request, mutate } from './api';
import { setLocale } from './i18n';
import { WindowsInventoryWorkspace } from './windows-inventory';
import { useWindowsInventory } from './windows-inventory-resource';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import { windowsStorageContextView } from './windows-storage-context-fixture';
import { unavailableWindowsStorageGroup } from './windows-storage-context-fixture';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
const flush = () => act(async () => {});
function Harness({ session = 'fixture', device = windowsDeviceId, enabled = true }: { session?: string; device?: string; enabled?: boolean }) { return <WindowsInventoryWorkspace resource={useWindowsInventory(device, enabled, session)}/>; }
const ready = async (locale = 'en') => { await flush(); fireEvent.click(screen.getByRole('tab', { name: locale === 'de' ? 'Speicher' : 'Storage' })); };
const refresh = () => fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' }));
const details = () => document.querySelector<HTMLDetailsElement>('.windows-storage-details')!;
const namesGone = () => { expect(screen.queryAllByText('Fixture NVMe')).toHaveLength(0); expect(screen.queryByText('provider-local-04')).toBeNull(); expect(document.querySelector('.windows-storage-details')).toBeNull(); };
beforeEach(() => { setLocale('en', false); vi.mocked(request).mockReset().mockResolvedValue(windowsStorageContextView()); vi.mocked(mutate).mockReset(); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });
describe('Compact private Storage tab', () => {
    it.each(['en', 'de'] as const)('shows exact drive mapping, provider health and optional details in %s', async locale => {
        setLocale(locale, false); render(<Harness/>); await ready(locale); const de = locale === 'de', panel = document.querySelector('.windows-storage-context')!;
        expect(within(panel as HTMLElement).getAllByText('Fixture NVMe')[0]).toBeVisible(); expect(within(panel as HTMLElement).getByText('C:')).toBeVisible();
        expect(panel).toHaveTextContent(de ? 'MSFT_PhysicalDisk-Zustand' : 'MSFT_PhysicalDisk health'); expect(panel).toHaveTextContent(de ? 'Fehlerfrei (0)' : 'Healthy (0)');
        expect(screen.getByLabelText('9007199254740993 ' + (de ? 'Bytes' : 'bytes'))).toBeVisible(); expect(screen.getByLabelText('18446744073709551615 ' + (de ? 'Bytes' : 'bytes'))).toBeVisible();
        expect(details().open).toBe(false); expect(screen.getByText('provider-local-04')).not.toBeVisible();
        expect(panel.querySelector('time')).toHaveAttribute('datetime', windowsView().snapshot!.collectedAt); fireEvent.click(details().querySelector('summary')!);
        expect(screen.getByText('provider-local-04')).toBeVisible(); expect(screen.getByText('32768')).toBeVisible(); expect(details()).toHaveTextContent(de ? 'keine Datenträgernummer' : 'not an OS disk number');
        expect(panel).toHaveTextContent('SMART'); expect(panel).toHaveTextContent('Storage Spaces'); expect(panel.querySelector('a,img,iframe,button,form,input')).toBeNull(); expect(mutate).not.toHaveBeenCalled();
        expect(vi.mocked(request).mock.calls.map(([path]) => path)).toEqual([`/devices/${windowsDeviceId}/windows-inventory`]);
    });
    it('keeps provider text isolated and future status codes visible without guessed labels', async () => {
        const v = windowsStorageContextView(); v.storageContext.disks.rows[0].friendlyName.value = '<img src=x onerror=alert(1)>'; v.storageContext.disks.rows[0].deviceId.value = 'https://example.invalid/private'; v.storageContext.disks.rows[0].healthStatus = 65535;
        vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); expect(screen.getAllByText('<img src=x onerror=alert(1)>')[0]).toBeVisible(); expect(screen.getByText('https://example.invalid/private').tagName).toBe('BDI'); expect(screen.getAllByText('Code (65535)')[0]).toBeVisible(); expect(document.querySelector('.windows-storage-context a,.windows-storage-context img')).toBeNull();
    });
    it('shows denied, unsupported and complete empty source states independently', async () => {
        const v = windowsStorageContextView(); v.storageContext.disks = unavailableWindowsStorageGroup('denied'); vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); expect(document.querySelector('.windows-storage-disks')).toHaveTextContent('Access denied'); expect(document.querySelector('.windows-storage-drives')).toHaveTextContent('C:');
        v.storageContext.disks = unavailableWindowsStorageGroup('unavailable', 'windows_storage_context_unsupported_platform'); vi.mocked(request).mockResolvedValue(structuredClone(v)); refresh(); await flush(); expect(screen.getByText('Source unsupported.')).toBeVisible();
        Object.assign(v.storageContext.disks, { quality: 'observed', reason: '', complete: true, countExact: true }); vi.mocked(request).mockResolvedValue(structuredClone(v)); refresh(); await flush(); expect(screen.getByText('No provider disks returned.')).toBeVisible();
    });
    it('shows the C: mapping independently of a later capacity capture', async () => {
        const v = windowsStorageContextView(); v.volumes.collectedAt = '2026-10-07T12:00:02Z'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); expect(document.querySelector('.windows-storage-drives')).toHaveTextContent('C:'); expect(screen.getByLabelText('9007199254740993 bytes')).toBeVisible(); expect(document.querySelector('.windows-storage-context time')).toHaveAttribute('datetime', '2026-10-07T12:00:00Z'); expect(document.querySelector('time[datetime="2026-10-07T12:00:02Z"]')).not.toBeNull(); expect(document.querySelector('.windows-inventory-table')).not.toHaveTextContent('C:');
    });
    it('resets disclosures after navigation and replacement generation', async () => {
        render(<Harness/>); await ready(); fireEvent.click(details().querySelector('summary')!); fireEvent.click(screen.getByRole('tab', { name: 'Hostname' })); namesGone(); await ready(); expect(details().open).toBe(false); fireEvent.click(details().querySelector('summary')!);
        const v = windowsStorageContextView(); v.volumes.generationId = v.storageContext.generationId = v.snapshot!.generationId = `sample_${'9'.repeat(32)}`; vi.mocked(request).mockResolvedValue(v); refresh(); await flush(); expect(details().open).toBe(false);
    });
    it('shows consent absence and rejects unknown fields without rendering them', async () => {
        vi.mocked(request).mockResolvedValue(windowsView()); render(<Harness/>); await ready(); expect(screen.getByText(/Separate local approval/)).toBeVisible(); const v = windowsStorageContextView(); Object.assign(v.storageContext, { uniqueDeviceId: 'private-marker' }); vi.mocked(request).mockResolvedValue(v); refresh(); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('inconsistent'); expect(document.body).not.toHaveTextContent('private-marker'); namesGone();
    });
    it('ages and expires private fields using original capture time', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const v = windowsStorageContextView(); v.snapshot!.collectedAt = v.storageContext.collectedAt = '2026-10-07T11:58:10Z'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); expect(screen.queryByText(/Stale storage context;/)).toBeNull(); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.getByText(/Stale storage context;/)).toBeVisible(); cleanup();
        v.snapshot!.collectedAt = v.storageContext.collectedAt = '2026-10-06T12:00:11Z'; v.status = 'stale'; vi.setSystemTime(windowsNow); render(<Harness/>); await ready(); await act(async () => vi.advanceTimersByTimeAsync(1000)); namesGone(); expect(screen.getByText(/context expired/)).toBeVisible();
    });
    it('hides future captures until acceptance time reaches capture time', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const v = windowsStorageContextView(); v.snapshot!.collectedAt = v.storageContext.collectedAt = '2026-10-07T12:00:11Z'; v.status = 'stale'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); namesGone(); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.getAllByText('Fixture NVMe')[0]).toBeVisible();
    });
    it.each(['blur', 'pagehide', 'hashchange', AUTH_REQUIRED_EVENT])('removes collapsed identifying metadata on %s', async event => { render(<Harness/>); await ready(); act(() => window.dispatchEvent(new Event(event))); namesGone(); });
    it('discards revoked authority and ignores a late previous-session response', async () => {
        render(<Harness/>); await ready(); vi.mocked(request).mockResolvedValue({ ...windowsView(), status: 'revoked', snapshot: null }); refresh(); await flush(); namesGone(); cleanup();
        let resolve!: (v: ReturnType<typeof windowsStorageContextView>) => void; vi.mocked(request).mockReturnValueOnce(new Promise(done => { resolve = done; })); const result = render(<Harness/>); await ready(); const signal = vi.mocked(request).mock.calls.at(-1)![1]?.signal; vi.mocked(request).mockResolvedValue(windowsView()); result.rerender(<Harness session="replacement"/>); await act(async () => resolve(windowsStorageContextView())); expect(signal?.aborted).toBe(true); namesGone();
    });
});

describe('Storage original-age retained observation', () => {
    function retained(at = '2026-10-07T11:00:00Z') {
        const v = windowsStorageContextView(), old = structuredClone(v.storageContext); old.collectedAt = at; old.generationId = `sample_${'b'.repeat(32)}`;
        v.storageContext.drives = unavailableWindowsStorageGroup(); v.storageContext.disks = unavailableWindowsStorageGroup();
        return { ...v, retainedContext: { storageContext: old } };
    }
    it('shows latest failure without silently replacing it with an older successful value', async () => {
        vi.mocked(request).mockResolvedValue(retained()); render(<Harness/>); await ready(); const current = document.querySelector('.windows-storage-context')!;
        expect(current).not.toHaveTextContent('Fixture NVMe'); expect(current).not.toHaveTextContent('C:'); expect(current).toHaveTextContent('Unavailable'); expect(screen.getAllByText('Fixture NVMe')[0]).not.toBeVisible(); fireEvent.click(screen.getByText('Show previous capture')); expect(screen.getAllByText('Fixture NVMe')[0]).toBeVisible(); expect(screen.getByText('C:')).toBeVisible(); expect(screen.getByText(/keeps its original capture time/)).toBeVisible();
        expect(document.querySelector('time[datetime="2026-10-07T11:00:00Z"]')).not.toBeNull(); expect(current.querySelector('time')).toHaveAttribute('datetime', '2026-10-07T12:00:00Z'); expect(screen.getByLabelText('9007199254740993 bytes')).toBeVisible();
        act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); namesGone(); expect(screen.queryByText('Show previous capture')).toBeNull();
    });
    it('keeps an all-unknown current classification visible alongside an unchanged useful prior capture', async () => {
        const v = retained(), disks = windowsStorageContextView().storageContext.disks;
        for (const row of disks.rows) Object.assign(row, { deviceId: { value: null, quality: 'unavailable' }, friendlyName: { value: null, quality: 'unavailable' }, sizeBytes: null, healthStatus: 5, busType: 0, mediaType: 0, operationalStatus: [0, 1, 65535] });
        v.storageContext.disks = disks; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready();
        const current = document.querySelector('.windows-storage-context')!; expect(current).toHaveTextContent('Unknown (5)'); expect(current).toHaveTextContent('Unspecified (0)'); expect(current).not.toHaveTextContent('Fixture NVMe');
        expect(current.querySelector('time')).toHaveAttribute('datetime', '2026-10-07T12:00:00Z'); fireEvent.click(details().querySelector('summary')!); expect(within(details()).getAllByText('0, 1, 65535')[0]).toBeVisible();
        fireEvent.click(screen.getByText('Show previous capture')); expect(screen.getAllByText('Fixture NVMe')[0]).toBeVisible(); expect(document.querySelector('details.windows-inventory-bounds time')).toHaveAttribute('datetime', '2026-10-07T11:00:00Z');
    });
    it('expires the older capture independently while keeping current failure visible', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); vi.mocked(request).mockResolvedValue(retained('2026-10-06T12:00:11Z')); render(<Harness/>); await ready(); expect(screen.getByText('Show previous capture')).toBeVisible(); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.queryByText('Show previous capture')).toBeNull(); expect(screen.queryByText('provider-local-04')).toBeNull(); expect(document.querySelector('.windows-storage-context')).toHaveTextContent('Unavailable');
    });
});
