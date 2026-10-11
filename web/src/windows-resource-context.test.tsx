import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, request, mutate } from './api';
import { setLocale } from './i18n';
import { WindowsInventoryWorkspace } from './windows-inventory';
import { useWindowsInventory } from './windows-inventory-resource';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import { windowsResourceContextView, unavailableWindowsResourceContext } from './windows-resource-context-fixture';
import { windowsHardwareContext } from './windows-hardware-context-fixture';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
const flush = () => act(async () => {});
function Harness({ session = 'fixture', device = windowsDeviceId, enabled = true }: { session?: string; device?: string; enabled?: boolean }) { return <WindowsInventoryWorkspace resource={useWindowsInventory(device, enabled, session)}/>; }
const ready = async (locale = 'en') => { await flush(); fireEvent.click(screen.getByRole('tab', { name: locale === 'de' ? 'Gerät' : 'Device' })); };
const refresh = () => fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' }));
const details = () => document.querySelector<HTMLDetailsElement>('.windows-resource-details')!;
const namesGone = () => { expect(screen.queryAllByText('Fixture CPU 12-Core')).toHaveLength(0); expect(document.querySelector('.windows-resource-details')).toBeNull(); };
beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(windowsNow); setLocale('en', false); vi.mocked(request).mockReset().mockResolvedValue(windowsResourceContextView()); vi.mocked(mutate).mockReset(); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });
describe('Compact private CPU and memory in Device', () => {
    it.each(['en', 'de'] as const)('shows source-separated compact values and collapsed exact details in %s', async locale => {
        setLocale(locale, false); vi.mocked(request).mockResolvedValue({ ...windowsResourceContextView(), hardwareContext: windowsHardwareContext() }); render(<Harness/>); await ready(locale); const de = locale === 'de', panel = screen.getByRole('region', { name: de ? 'CPU & Arbeitsspeicher' : 'CPU & memory' });
        expect(screen.getByText('Example Laptop 14')).toBeVisible(); expect(within(panel).getAllByText('Fixture CPU 12-Core')[0]).toBeVisible(); expect(within(panel).getByText(de ? '32,0 GiB' : '32.0 GiB')).toBeVisible(); expect(within(panel).getByText(de ? '31,0 GiB' : '31.0 GiB')).toBeVisible();
        expect(within(panel).getByText(de ? '28,0 GiB' : '28.0 GiB')).toBeVisible(); expect(within(panel).getByText(de ? 'Installierter RAM (SMBIOS)' : 'Installed RAM (SMBIOS)', { selector: '.windows-resource-groups dt' })).toBeVisible();
        expect(details().open).toBe(false); expect(within(details()).getByText(`34359738368 ${de ? 'Bytes' : 'bytes'}`)).not.toBeVisible(); expect(panel.querySelector('time')).toHaveAttribute('datetime', windowsView().snapshot!.collectedAt);
        fireEvent.click(details().querySelector('summary')!); expect(within(details()).getByText(`34359738368 ${de ? 'Bytes' : 'bytes'}`)).toBeVisible(); expect(details()).toHaveTextContent('windows-resource-context-v1'); expect(details()).toHaveTextContent('K32GetPerformanceInfo'); expect(details()).toHaveTextContent(de ? 'keine physische Sockeltopologie' : 'do not establish physical socket topology');
        expect(details()).toHaveTextContent(de ? 'bei mehreren aktiven Prozessorgruppen nicht verfügbar' : 'unavailable with multiple active processor groups'); expect(details()).toHaveTextContent(de ? 'Die CPU-Konfiguration kann unabhängig davon verfügbar sein' : 'CPU configuration can remain independently available');
        expect(panel.querySelector('a,img,iframe,form,input,button')).toBeNull(); expect(panel.querySelector('[role="progressbar"]')).toBeNull(); expect(vi.mocked(mutate)).not.toHaveBeenCalled();
    });
    it('keeps CPU model labels inert and exact large integers intact', async () => {
        const v = windowsResourceContextView(); v.resourceContext.processors.rows[0].name.value = '<img src=x onerror=alert(1)>'; Object.assign(v.resourceContext.pagefiles, { totalBytes: '18446744073709551615', totalInUseBytes: '9007199254740993' }); vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); expect(screen.getAllByText('<img src=x onerror=alert(1)>')[0]).toBeVisible(); fireEvent.click(details().querySelector('summary')!); expect(screen.getByText('9007199254740993 bytes')).toBeVisible(); expect(screen.getByText('18446744073709551615 bytes')).toBeVisible(); expect(document.querySelector('.windows-resource-context img')).toBeNull();
    });
    it('distinguishes no pagefiles from unavailable and keeps sibling observations visible', async () => {
        const v = windowsResourceContextView(); Object.assign(v.resourceContext.pagefiles, { count: 0, totalBytes: '0', totalInUseBytes: '0' }); Object.assign(v.resourceContext.installedMemory, { quality: 'denied', reason: 'windows_resource_context_access_denied', installedBytes: null }); vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); expect(screen.getByText('No pagefiles reported')).toBeVisible(); expect(screen.getByText('31.0 GiB')).toBeVisible(); expect(within(screen.getByRole('region', { name: 'Physical memory' })).getByText('Access denied')).toBeVisible();
        v.resourceContext.pagefiles = unavailableWindowsResourceContext().pagefiles; vi.mocked(request).mockResolvedValue(structuredClone(v)); refresh(); await flush(); expect(screen.queryByText('No pagefiles reported')).toBeNull(); expect(screen.getAllByText('Fixture CPU 12-Core')[0]).toBeVisible(); fireEvent.click(details().querySelector('summary')!); expect(details()).toHaveTextContent('Source collection time limit reached.'); expect(details()).toHaveTextContent('Source access denied.');
    });
    it('shows unknown aggregate counts for partial CPUs without deriving logical counts or sockets', async () => {
        const v = windowsResourceContextView(); v.resourceContext.processors.rows[0].cores = { value: null, quality: 'unavailable' }; Object.assign(v.resourceContext.processors, { quality: 'partial', reason: 'windows_resource_context_partial_result', totalCores: null, totalLogicalProcessors: null }); vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); const panel = screen.getByRole('region', { name: 'CPU' }); expect(within(panel).getAllByText('Unknown')).toHaveLength(2); expect(panel).not.toHaveTextContent('socket'); expect(panel).toHaveTextContent('Partial');
    });
    it('resets details on navigation, source generation and session changes', async () => {
        const result = render(<Harness/>); await ready(); fireEvent.click(details().querySelector('summary')!); fireEvent.click(screen.getByRole('tab', { name: 'Hostname' })); namesGone(); await ready(); expect(details().open).toBe(false); fireEvent.click(details().querySelector('summary')!);
        const v = windowsResourceContextView(); v.resourceContext.generationId = v.snapshot!.generationId = `sample_${'9'.repeat(32)}`; vi.mocked(request).mockResolvedValue(v); refresh(); await flush(); expect(details().open).toBe(false);
        vi.mocked(request).mockReturnValue(new Promise(() => {})); result.rerender(<Harness session="replacement"/>); await flush(); namesGone();
    });
    it.each(['en', 'de'] as const)('shows neutral absence in %s and rejects forbidden or malformed fields before rendering', async locale => {
        setLocale(locale, false); vi.mocked(request).mockResolvedValue(windowsView()); render(<Harness/>); await ready(locale); expect(screen.getByText(locale === 'de' ? 'Für diese Erfassung wurden keine CPU- und Arbeitsspeicherdaten gemeldet.' : 'No CPU & memory context reported for this capture.')).toBeVisible(); const v = windowsResourceContextView(); Object.assign(v.resourceContext.pagefiles, { filename: 'private-marker' }); act(() => setLocale('en', false)); vi.mocked(request).mockResolvedValue(v); refresh(); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('inconsistent'); expect(document.body).not.toHaveTextContent('private-marker'); namesGone();
    });
    it('ages, expires and hides future observations from their original capture time', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const v = windowsResourceContextView(); v.snapshot!.collectedAt = v.resourceContext.collectedAt = '2026-10-07T11:58:10Z'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); expect(screen.queryByText(/Stale observation;/)).toBeNull(); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.getByText(/Stale observation;/)).toBeVisible(); cleanup();
        v.snapshot!.collectedAt = v.resourceContext.collectedAt = '2026-10-06T12:00:11Z'; v.status = 'stale'; vi.setSystemTime(windowsNow); render(<Harness/>); await ready(); await act(async () => vi.advanceTimersByTimeAsync(1000)); namesGone(); expect(screen.getByText(/CPU & memory context expired/)).toBeVisible(); cleanup();
        v.snapshot!.collectedAt = v.resourceContext.collectedAt = '2026-10-07T12:00:11Z'; vi.setSystemTime(windowsNow); render(<Harness/>); await ready(); namesGone(); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.getAllByText('Fixture CPU 12-Core')[0]).toBeVisible();
    });
    it.each(['blur', 'pagehide', 'hashchange', AUTH_REQUIRED_EVENT])('clears all private data on %s', async event => { render(<Harness/>); await ready(); act(() => window.dispatchEvent(new Event(event))); namesGone(); });
    it('clears visibility, device, disabled authority and late responses', async () => {
        const result = render(<Harness/>); await ready(); vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); namesGone(); cleanup(); vi.restoreAllMocks();
        render(<Harness/>); await ready(); vi.mocked(request).mockResolvedValue({ ...windowsView(), status: 'revoked', snapshot: null }); refresh(); await flush(); namesGone(); cleanup();
        let resolve!: (v: ReturnType<typeof windowsResourceContextView>) => void; vi.mocked(request).mockReset().mockReturnValueOnce(new Promise(done => { resolve = done; })); const late = render(<Harness/>); await ready(); const signal = vi.mocked(request).mock.calls.at(-1)![1]?.signal; vi.mocked(request).mockResolvedValue(windowsView()); late.rerender(<Harness device={`agent_${'8'.repeat(32)}`}/>); await act(async () => resolve(windowsResourceContextView())); expect(signal?.aborted).toBe(true); namesGone();
        result.unmount(); late.rerender(<Harness enabled={false}/>); namesGone();
    });
});
describe('Original-age CPU and memory retention', () => {
    function retained(at = '2026-10-07T11:00:00Z') { const v = windowsResourceContextView(), old = structuredClone(v.resourceContext); old.collectedAt = at; old.generationId = `sample_${'c'.repeat(32)}`; v.resourceContext = unavailableWindowsResourceContext(); return { ...v, retainedContext: { resourceContext: old } }; }
    it('keeps latest failures visible and prior independent capture collapsed', async () => {
        vi.mocked(request).mockResolvedValue(retained()); render(<Harness/>); await ready(); const current = document.querySelector('.windows-resource-context')!; expect(current).not.toHaveTextContent('Fixture CPU 12-Core'); expect(current).toHaveTextContent('Unavailable'); expect(screen.getAllByText('Fixture CPU 12-Core')[0]).not.toBeVisible(); fireEvent.click(screen.getByText('Show previous capture')); expect(screen.getAllByText('Fixture CPU 12-Core')[0]).toBeVisible(); expect(screen.getByText(/keeps its original capture time/)).toBeVisible(); expect(document.querySelector('time[datetime="2026-10-07T11:00:00Z"]')).not.toBeNull(); expect(current.querySelector('time')).toHaveAttribute('datetime', '2026-10-07T12:00:00Z'); act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); namesGone(); expect(screen.queryByText('Show previous capture')).toBeNull();
    });
    it('expires prior values without renewing them or hiding current failure', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); vi.mocked(request).mockResolvedValue(retained('2026-10-06T12:00:11Z')); render(<Harness/>); await ready(); expect(screen.getByText('Show previous capture')).toBeVisible(); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.queryByText('Show previous capture')).toBeNull(); expect(screen.queryAllByText('Fixture CPU 12-Core')).toHaveLength(0); expect(document.querySelector('.windows-resource-context')).toHaveTextContent('Unavailable');
    });
});
