import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, request } from './api';
import { setLocale } from './i18n';
import { WindowsInventoryWorkspace } from './windows-inventory';
import { useWindowsInventory } from './windows-inventory-resource';
import { validWindowsInventoryView } from './windows-inventory-types';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import { volumeBytes } from './windows-volumes';
import { fixtureVolumeId, windowsVolumes } from './windows-volumes-fixture';
import { validWindowsVolumes, type WindowsVolumes } from './windows-volumes-types';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
const flush = () => act(async () => {});
function view() { return { ...windowsView(), volumes: windowsVolumes() }; }
function Harness({ session = 'fixture' }: { session?: string }) { return <WindowsInventoryWorkspace resource={useWindowsInventory(windowsDeviceId, true, session)}/>; }
async function storage() { fireEvent.click(screen.getByRole('tab', { name: 'Storage' })); await screen.findByText(fixtureVolumeId); }
beforeEach(() => { setLocale('en', false); vi.mocked(request).mockReset().mockResolvedValue(view()); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });
describe('Windows volume strict contract', () => {
    it('formats IEC values with integer arithmetic and explicit approximation', () => {
        expect(volumeBytes('0', 'en')).toBe('0 B'); expect(volumeBytes('107374182400', 'en')).toBe('100 GiB');
        expect(volumeBytes('9007199254740993', 'en')).toBe('≈ 8 PiB'); expect(volumeBytes('18446744073709551615', 'de')).toBe('≈ 15,9 EiB');
    });
    it('keeps old views valid and preserves quota semantics and exact uint64 values', () => {
        expect(validWindowsInventoryView(windowsView(), windowsDeviceId)).toBe(true);
        expect(validWindowsInventoryView(view(), windowsDeviceId)).toBe(true);
        const v = windowsVolumes(); expect(v.rows[0].capacity!.freeBytes).toBe('18446744073709551615');
        expect(validWindowsVolumes(v, v.generationId, windowsNow)).toBe(true);
    });
    const mutations: [string, (v: WindowsVolumes) => void][] = [
        ['unknown snapshot member', v => Object.assign(v, { labels: [] })], ['unknown row member', v => Object.assign(v.rows[0], { path: 'C:\\' })], ['unknown capacity member', v => Object.assign(v.rows[0].capacity!, { usedBytes: '1' })],
        ['numeric bytes', v => Object.assign(v.rows[0].capacity!, { totalBytes: 9007199254740992 })], ['uint64 overflow', v => { v.rows[0].capacity!.freeBytes = '18446744073709551616'; }], ['leading zero', v => { v.rows[0].capacity!.totalBytes = '01'; }], ['negative bytes', v => { v.rows[0].capacity!.freeBytes = '-1'; }], ['fractional bytes', v => { v.rows[0].capacity!.freeBytes = '1.0'; }],
        ['quota contradiction', v => { v.rows[0].capacity!.availableBytes = '9007199254740994'; }], ['physical contradiction', v => { v.rows[0].capacity!.freeBytes = '41'; }], ['denied capacity', v => { v.rows[1].capacity = v.rows[0].capacity; }], ['denied empty reason', v => { v.rows[1].reason = ''; }], ['unavailable access denial', v => { v.rows[1].quality = 'unavailable'; }], ['observed null', v => { v.rows[0].capacity = null; }],
        ['network root', v => { v.rows[0].volumeId = '\\\\server\\share\\'; }], ['uppercase GUID', v => { v.rows[0].volumeId = fixtureVolumeId.replace('11111111', 'AAAAAAAA'); }], ['drive path', v => { v.rows[0].volumeId = 'C:\\'; }], ['remote drive', v => Object.assign(v.rows[0], { driveType: 'remote' })], ['observed unknown drive', v => { v.rows[0].driveType = 'unknown'; }], ['unsupported known drive', v => { v.rows[1].quality = 'unavailable'; v.rows[1].reason = 'windows_volumes_unsupported_drive_type'; }], ['duplicate volume', v => { v.rows[1].volumeId = v.rows[0].volumeId; }],
        ['bad grant', v => { v.grantId = ''; }], ['inventory scope is not consent', v => Object.assign(v, { scope: 'windows-inventory-v1' })], ['generation mismatch', v => { v.generationId = `sample_${'b'.repeat(32)}`; }], ['unknown reason', v => { v.rows[1].reason = 'private server error'; }], ['quality contradiction', v => { v.complete = false; }], ['count contradiction', v => { v.observedCount = 3; }], ['count limit', v => { v.observedCount = 129; v.truncated = true; v.complete = false; v.quality = 'bounded'; }], ['expired capture', v => { v.collectedAt = '2026-10-06T12:00:10Z'; }], ['future capture', v => { v.collectedAt = '2026-10-07T12:00:41Z'; }], ['invalid date', v => { v.collectedAt = '2026-02-30T12:00:00Z'; }],
    ];
    it.each(mutations)('rejects %s', (_name, mutate) => { const v = windowsVolumes(); mutate(v); expect(validWindowsVolumes(v, windowsVolumes().generationId, windowsNow)).toBe(false); });
    it('allows row failures independently of complete enumeration; supports bounded and partial', () => {
        const v = windowsVolumes(); expect(validWindowsVolumes(v, v.generationId, windowsNow)).toBe(true);
        Object.assign(v, { quality: 'bounded', complete: false, truncated: true, observedCount: 3 }); expect(validWindowsVolumes(v, v.generationId, windowsNow)).toBe(true);
        Object.assign(v, { quality: 'partial', countExact: false, reason: 'windows_volumes_source_unavailable' }); expect(validWindowsVolumes(v, v.generationId, windowsNow)).toBe(true);
        v.countExact = true; expect(validWindowsVolumes(v, v.generationId, windowsNow)).toBe(false);
        Object.assign(v, { countExact: false, reason: 'windows_volumes_access_denied', rows: [] }); expect(validWindowsVolumes(v, v.generationId, windowsNow)).toBe(true);
    });
    it('requires bounded counts to explain native or transport omission', () => {
        const v = windowsVolumes(); Object.assign(v, { quality: 'bounded', complete: false, truncated: true }); expect(validWindowsVolumes(v, v.generationId, windowsNow)).toBe(false);
        v.observedCount = 3; expect(validWindowsVolumes(v, v.generationId, windowsNow)).toBe(true);
        v.countExact = false; expect(validWindowsVolumes(v, v.generationId, windowsNow)).toBe(false);
        v.observedCount = 128; expect(validWindowsVolumes(v, v.generationId, windowsNow)).toBe(true);
    });
    it('distinguishes empty enumeration, denied and unavailable without successful-zero contradictions', () => {
        const v = windowsVolumes(); Object.assign(v, { rows: [], observedCount: 0 }); expect(validWindowsVolumes(v, v.generationId, windowsNow)).toBe(true);
        Object.assign(v, { quality: 'denied', complete: false, countExact: false, reason: 'windows_volumes_access_denied' }); expect(validWindowsVolumes(v, v.generationId, windowsNow)).toBe(true);
        v.quality = 'unavailable'; expect(validWindowsVolumes(v, v.generationId, windowsNow)).toBe(false);
        v.reason = 'windows_volumes_source_unavailable'; expect(validWindowsVolumes(v, v.generationId, windowsNow)).toBe(true);
        v.quality = 'observed'; expect(validWindowsVolumes(v, v.generationId, windowsNow)).toBe(false);
    });
    it('enforces both encoded-byte and row limits', () => {
        const v = windowsVolumes(); v.rows = Array.from({ length: 64 }, (_, i) => ({ ...v.rows[0], volumeId: fixtureVolumeId.replace('11111111', i.toString(16).padStart(8, '0')) })); v.observedCount = 64;
        expect(validWindowsVolumes(v, v.generationId, windowsNow)).toBe(false);
        v.rows = Array.from({ length: 65 }, (_, i) => ({ ...windowsVolumes().rows[1], volumeId: fixtureVolumeId.replace('11111111', i.toString(16).padStart(8, '0')) })); v.observedCount = 65;
        expect(validWindowsVolumes(v, v.generationId, windowsNow)).toBe(false);
    });
    it('never admits volumes on revoked, expired or null inventory and rejects explicit null', () => {
        for (const status of ['revoked', 'unavailable', 'awaiting', 'not_configured']) expect(validWindowsInventoryView({ ...view(), status, snapshot: null }, windowsDeviceId)).toBe(false);
        expect(validWindowsInventoryView({ ...windowsView(), volumes: null }, windowsDeviceId)).toBe(false);
    });
});
describe('Storage subtab and shared private-data lifecycle', () => {
    it('shows exact capacities, per-row denial, local scope and separate capture time', async () => {
        render(<Harness/>); await storage(); expect(screen.getByLabelText('9007199254740993 bytes')).toBeVisible(); expect(screen.getByLabelText('18446744073709551615 bytes')).toBeVisible(); expect(screen.getByText('Access denied')).toBeVisible(); expect(screen.getByText('Enumeration complete within scope')).toBeVisible(); expect(screen.getByText(/quota-limited/)).toBeVisible(); expect(document.querySelector('time[datetime="2026-10-07T12:00:02Z"]')).not.toBeNull(); expect(screen.queryByRole('link')).toBeNull();
    });
    it('marks independently stale storage while inventory is fresh', async () => { const v = view(); v.volumes.collectedAt = '2026-10-07T11:55:00Z'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await storage(); expect(screen.getByText('Recent observation')).toBeVisible(); expect(screen.getByText(/Stale storage observation/)).toBeVisible(); });
    it('keeps fresh storage independent of stale inventory capture', async () => { const v = view(); v.snapshot!.collectedAt = '2026-10-07T11:55:00Z'; v.status = 'stale'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await storage(); expect(screen.queryByText(/Stale storage observation/)).toBeNull(); });
    it('replaces retained capacities with denied enumeration without a successful zero', async () => {
        render(<Harness/>); await storage(); const v = view(); Object.assign(v.volumes, { quality: 'denied', reason: 'windows_volumes_access_denied', complete: false, countExact: false, observedCount: 0, rows: [] });
        vi.mocked(request).mockResolvedValue(v); fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); await screen.findByText('Access denied'); expect(screen.queryByText(fixtureVolumeId)).toBeNull(); expect(screen.getByText(/No volume rows available/)).toBeVisible(); expect(screen.queryByText('0 shown · 0 observed')).toBeNull();
    });
    it('shows missing scope without inventing empty or healthy storage', async () => { vi.mocked(request).mockResolvedValue(windowsView()); render(<Harness/>); await flush(); fireEvent.click(screen.getByRole('tab', { name: 'Storage' })); expect(screen.getByText(/Separate local consent is required/)).toBeVisible(); expect(screen.queryByRole('table')).toBeNull(); });
    it('uses German storage labels and keyboard selection', async () => { setLocale('de', false); render(<Harness/>); await flush(); fireEvent.keyDown(screen.getByRole('tab', { name: 'Prozesse' }), { key: 'End' }); expect(screen.getByRole('tab', { name: 'Speicher' })).toHaveFocus(); expect(screen.getByText('Aufrufer-Gesamt')).toBeVisible(); expect(screen.getByText('Zugriff verweigert')).toBeVisible(); });
    it.each(['blur', 'pagehide', 'hashchange', AUTH_REQUIRED_EVENT])('clears volume data on %s', async event => { render(<Harness/>); await storage(); act(() => window.dispatchEvent(new Event(event))); expect(screen.queryByText(fixtureVolumeId)).toBeNull(); expect(screen.queryByLabelText('9007199254740993 bytes')).toBeNull(); });
    it('clears on session change and ignores the interrupted late response', async () => { let resolve!: (v: ReturnType<typeof view>) => void; const result = render(<Harness/>); await storage(); vi.mocked(request).mockReturnValueOnce(new Promise(done => { resolve = done; })); fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); vi.mocked(request).mockResolvedValue(windowsView()); result.rerender(<Harness session="replacement"/>); await act(async () => resolve(view())); expect(screen.queryByText(fixtureVolumeId)).toBeNull(); });
    it('clears during refresh and never revives a response after timeout', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); render(<Harness/>); await flush(); fireEvent.click(screen.getByRole('tab', { name: 'Storage' })); expect(screen.getByText(fixtureVolumeId)).toBeVisible();
        let resolve!: (v: ReturnType<typeof view>) => void; vi.mocked(request).mockReturnValue(new Promise(done => { resolve = done; })); fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); expect(screen.queryByText(fixtureVolumeId)).toBeNull();
        await act(async () => vi.advanceTimersByTimeAsync(10001)); expect(screen.getByRole('alert')).toHaveTextContent('timed out'); await act(async () => resolve(view())); expect(screen.queryByText(fixtureVolumeId)).toBeNull();
    });
    it('rejects frozen responses instead of refreshing retained volume age', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); render(<Harness/>); await flush(); fireEvent.click(screen.getByRole('tab', { name: 'Storage' })); expect(screen.getByText(fixtureVolumeId)).toBeVisible();
        await act(async () => vi.advanceTimersByTimeAsync(15000)); expect(screen.queryByText(fixtureVolumeId)).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('time reference changed');
    });
    it('clears volumes on a regressed browser clock', async () => { vi.useFakeTimers(); vi.setSystemTime(windowsNow); render(<Harness/>); await flush(); fireEvent.click(screen.getByRole('tab', { name: 'Storage' })); expect(screen.getByText(fixtureVolumeId)).toBeVisible(); vi.setSystemTime('2026-10-07T11:00:00Z'); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.queryByText(fixtureVolumeId)).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('time reference changed'); });
    it('drops an expired volume sample without discarding still-visible inventory', async () => { vi.useFakeTimers(); vi.setSystemTime(windowsNow); const v = view(); v.volumes.collectedAt = '2026-10-06T12:00:11Z'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await flush(); fireEvent.click(screen.getByRole('tab', { name: 'Storage' })); expect(screen.getByText(fixtureVolumeId)).toBeVisible(); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.queryByText(fixtureVolumeId)).toBeNull(); fireEvent.click(screen.getByRole('tab', { name: 'Processes' })); expect(screen.getByText('fixture.exe')).toBeVisible(); });
});
