import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, request, mutate } from './api';
import { setLocale } from './i18n';
import { WindowsInventoryWorkspace } from './windows-inventory';
import { useWindowsInventory } from './windows-inventory-resource';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import { windowsStorageIOView, windowsStorageIO, unavailableWindowsStorageIO, unavailableWindowsStorageIOMetric, observedWindowsStorageIOMetric, summarizeWindowsStorageIO } from './windows-storage-io-fixture';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
const flush = () => act(async () => {});
function Harness({ session = 'fixture', enabled = true }: { session?: string; enabled?: boolean }) { return <WindowsInventoryWorkspace resource={useWindowsInventory(windowsDeviceId, enabled, session)}/>; }
const ready = async (locale = 'en') => { await flush(); fireEvent.click(screen.getByRole('tab', { name: locale === 'de' ? 'Speicher' : 'Storage' })); };
const refresh = () => fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' }));
const panel = () => document.querySelector<HTMLElement>('.windows-storage-io')!;
const details = () => panel().querySelector<HTMLDetailsElement>('.windows-storage-io-details')!;
function retained(at = '2026-10-07T11:00:00Z') {
    const v = windowsStorageIOView(), old = windowsStorageIO(); old.collectedAt = at; old.generationId = `sample_${'b'.repeat(32)}`;
    old.perfDisk.sampleStartedAt = new Date(Date.parse(at) + 250).toISOString(); old.perfDisk.sampleEndedAt = new Date(Date.parse(at) + 1250).toISOString();
    v.storageIO = unavailableWindowsStorageIO(); return { ...v, retainedContext: { storageIO: old } };
}
beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(windowsNow); setLocale('en', false); vi.mocked(request).mockReset().mockResolvedValue(windowsStorageIOView()); vi.mocked(mutate).mockReset(); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });
describe('Compact private Windows Disk I/O', () => {
    it.each(['en', 'de'] as const)('shows source rates, millisecond latency, independent time and queue semantics in %s', async locale => {
        setLocale(locale, false); render(<Harness/>); await ready(locale); const de = locale === 'de', root = within(panel());
        expect(root.getByRole('heading', { name: de ? 'Datenträger-I/O · PerfDisk gesamt' : 'Disk I/O · PerfDisk aggregate' })).toBeVisible();
        expect(root.getByRole('region', { name: de ? 'Mittlere Latenz' : 'Average latency' })).toHaveTextContent(de ? '1,25 ms' : '1.25 ms');
        expect(root.getByRole('region', { name: de ? 'Durchsatz' : 'Throughput' })).toHaveTextContent(de ? '12.582.912 B/s' : '12,582,912 B/s');
        expect(root.getByRole('region', { name: de ? 'Operationen' : 'Operations' })).toHaveTextContent(de ? '120,5 Vorgänge/s' : '120.5 ops/s');
        expect(panel()).toHaveTextContent(de ? 'Mittlere Warteschlangenlänge' : 'Average queue length'); expect(panel()).toHaveTextContent(de ? 'Am Messende ausstehend' : 'Outstanding at sample end'); expect(panel()).toHaveTextContent(de ? 'Einschließlich Anfragen in Bearbeitung' : 'Includes requests in service');
        expect(panel().querySelector('time')).toHaveAttribute('datetime', '2026-10-07T12:00:00.25Z'); expect(panel().querySelectorAll('time')[1]).toHaveAttribute('datetime', '2026-10-07T12:00:01.25Z'); expect(panel()).toHaveTextContent(de ? 'Alter der Messung: 8 s' : 'Sample age: 8 s');
        expect(document.querySelector('time[datetime="2026-10-07T12:00:02Z"]')).not.toBeNull(); expect(details().open).toBe(false);
        fireEvent.click(details().querySelector('summary')!); expect(details()).toHaveTextContent('PDH PhysicalDisk(_Total)'); expect(details()).toHaveTextContent(de ? 'keine einzelnen Datenträger' : 'does not identify individual disks'); expect(details()).toHaveTextContent('MSFT_PhysicalDisk'); expect(details()).toHaveTextContent(de ? 'Hot-Plug' : 'hot-plug');
        expect(panel().querySelector('a,img,iframe,button,form,input')).toBeNull(); expect(mutate).not.toHaveBeenCalled(); expect(vi.mocked(request).mock.calls.map(([path]) => path)).toEqual([`/devices/${windowsDeviceId}/windows-inventory`]);
    });
    it('distinguishes an idle side, observed zero latency and a missing throughput counter', async () => {
        const v = windowsStorageIOView(), p = v.storageIO.perfDisk; p.readOperationsPerSecond = observedWindowsStorageIOMetric(0); p.readLatencySeconds = unavailableWindowsStorageIOMetric('windows_storage_io_idle'); p.writeLatencySeconds = observedWindowsStorageIOMetric(0); p.readBytesPerSecond = unavailableWindowsStorageIOMetric('windows_storage_io_counter_missing'); summarizeWindowsStorageIO(v.storageIO);
        vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); const latency = within(panel()).getByRole('region', { name: 'Average latency' }); expect(latency).toHaveTextContent('Idle · no operations'); expect(latency).toHaveTextContent('0 ms'); expect(within(panel()).getByRole('region', { name: 'Throughput' })).toHaveTextContent('Counter unavailable');
    });
    it.each([['windows_storage_io_access_denied', 'Access denied'], ['windows_storage_io_counter_reset', 'Counter reset'], ['windows_storage_io_invalid_timebase', 'Invalid sample timebase'], ['windows_storage_io_budget_exhausted', 'Sample time limit reached'], ['windows_storage_io_unsupported_platform', 'Source unsupported']] as const)('shows actual failure %s without inventing zero values', async (reason, text) => {
        const v = windowsStorageIOView(); v.storageIO = unavailableWindowsStorageIO(reason); vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); expect(panel()).toHaveTextContent(text); expect(panel()).not.toHaveTextContent('0 B/s'); expect(panel()).not.toHaveTextContent('Sample age:'); expect(panel()).not.toHaveTextContent('approval');
    });
    it('does not infer missing consent from absent context', async () => { vi.mocked(request).mockResolvedValue(windowsView()); render(<Harness/>); await ready(); expect(screen.getByText('No disk I/O sample reported for this capture.')).toBeVisible(); expect(document.querySelector('.windows-storage-io-absent')).not.toHaveTextContent(/consent|approval|grant/); });
    it('rejects unknown data without rendering it', async () => { const v = windowsStorageIOView(); Object.assign(v.storageIO.perfDisk, { deviceId: 'private-marker' }); vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); expect(screen.getByRole('alert')).toHaveTextContent('inconsistent'); expect(document.body).not.toHaveTextContent('private-marker'); expect(panel()).toBeNull(); });
    it('resets details on tab navigation and generation replacement', async () => {
        render(<Harness/>); await ready(); fireEvent.click(details().querySelector('summary')!); expect(details().open).toBe(true); fireEvent.click(screen.getByRole('tab', { name: 'Hostname' })); expect(panel()).toBeNull(); await ready(); expect(details().open).toBe(false);
        fireEvent.click(details().querySelector('summary')!); const v = windowsStorageIOView(); v.storageIO.generationId = v.storageContext.generationId = v.volumes.generationId = v.snapshot!.generationId = `sample_${'9'.repeat(32)}`; vi.mocked(request).mockResolvedValue(v); refresh(); await flush(); expect(details().open).toBe(false);
    });
    it.each(['blur', 'pagehide', 'hashchange', AUTH_REQUIRED_EVENT])('clears both current and retained IO on %s', async event => { vi.mocked(request).mockResolvedValue(retained()); render(<Harness/>); await ready(); expect(document.querySelectorAll('.windows-storage-io')).toHaveLength(2); act(() => window.dispatchEvent(new Event(event))); expect(panel()).toBeNull(); expect(screen.queryByText('Show previous capture')).toBeNull(); });
    it('discards revoked authority and ignores a late previous-session response', async () => {
        render(<Harness/>); await ready(); vi.mocked(request).mockResolvedValue({ ...windowsView(), status: 'revoked', snapshot: null }); refresh(); await flush(); expect(panel()).toBeNull(); cleanup();
        let resolve!: (v: ReturnType<typeof windowsStorageIOView>) => void; vi.mocked(request).mockReturnValueOnce(new Promise(done => { resolve = done; })); const result = render(<Harness/>); await ready(); const signal = vi.mocked(request).mock.calls.at(-1)![1]?.signal; vi.mocked(request).mockResolvedValue(windowsView()); result.rerender(<Harness session="replacement"/>); await act(async () => resolve(windowsStorageIOView())); expect(signal?.aborted).toBe(true); expect(panel()).toBeNull();
    });
    it('keeps latest failure visible and reveals prior values only with original sample timing', async () => {
        vi.mocked(request).mockResolvedValue(retained()); render(<Harness/>); await ready(); expect(panel()).toHaveTextContent('Sample time limit reached'); expect(panel()).not.toHaveTextContent('120.5 ops/s'); expect(screen.getByText('120.5 ops/s')).not.toBeVisible(); fireEvent.click(screen.getByText('Show previous capture')); expect(screen.getByText('120.5 ops/s')).toBeVisible(); const old = document.querySelectorAll('.windows-storage-io')[1]; expect(old.querySelector('time')).toHaveAttribute('datetime', '2026-10-07T11:00:00.250Z'); expect(old).toHaveTextContent('Sample age: 3,608 s'); expect(old).toHaveTextContent('Stale sample');
    });
    it('expires prior IO independently without hiding the latest failure', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); vi.mocked(request).mockResolvedValue(retained('2026-10-06T12:00:10.999Z')); render(<Harness/>); await ready(); expect(screen.getByText('Show previous capture')).toBeVisible(); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.queryByText('Show previous capture')).toBeNull(); expect(panel()).toHaveTextContent('Sample time limit reached');
    });
    it('hides future sample-end values until acceptance time reaches the end', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const v = windowsStorageIOView(); v.storageIO.perfDisk.sampleStartedAt = windowsNow; v.storageIO.perfDisk.sampleEndedAt = '2026-10-07T12:00:11Z'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); expect(panel()).toBeNull(); expect(screen.getByText(/Disk I\/O is hidden/)).toBeVisible(); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(panel()).toBeVisible();
    });
    it('ages and expires current context from the original capture instead of the receipt', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const v = windowsStorageIOView(); v.storageIO = unavailableWindowsStorageIO(); v.snapshot!.collectedAt = v.storageIO.collectedAt = v.storageContext.collectedAt = '2026-10-07T11:58:10Z'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); expect(panel()).not.toHaveTextContent('Stale sample'); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(panel()).toHaveTextContent('Stale sample'); cleanup();
        v.snapshot!.collectedAt = v.storageIO.collectedAt = v.storageContext.collectedAt = '2026-10-06T12:00:10.999Z'; v.status = 'stale'; vi.setSystemTime(windowsNow); render(<Harness/>); await ready(); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(panel()).toBeNull(); expect(screen.getByText('Disk I/O capture expired after 24 hours.')).toBeVisible();
    });
});
