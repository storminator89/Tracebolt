import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, request } from './api';
import { setLocale } from './i18n';
import { WindowsInventoryWorkspace } from './windows-inventory';
import { useWindowsInventory } from './windows-inventory-resource';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import { windowsPatchContextView } from './windows-patch-context-fixture';
import { windowsUpdates } from './windows-updates-fixture';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
const flush = () => act(async () => {});
function Harness({ session = 'fixture' }: { session?: string }) { return <WindowsInventoryWorkspace resource={useWindowsInventory(windowsDeviceId, true, session)}/>; }
const ready = async () => { await flush(); fireEvent.click(screen.getByRole('tab', { name: 'Updates' })); };
const refresh = () => fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' }));
const details = () => document.querySelector<HTMLDetailsElement>('.windows-patch-details')!;
beforeEach(() => { setLocale('en', false); vi.mocked(request).mockReset().mockResolvedValue(windowsPatchContextView()); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('Compact patch context in the existing Updates tab', () => {
    it.each(['en', 'de'] as const)('shows separate OS/reboot evidence and collapsed retained history in %s', async locale => {
        setLocale(locale, false); render(<Harness/>); await ready(); const de = locale === 'de';
        expect(screen.getByText(/Windows 11 Pro ·/)).toHaveTextContent('26100.1000'); expect(document.querySelector('.windows-patch-reboot strong')).toHaveTextContent(de ? 'Ausstehend' : 'Pending');
        expect(screen.getByText('Synthetic cumulative update')).not.toBeVisible(); expect(details().open).toBe(false);
        fireEvent.click(details().querySelector('summary')!); expect(screen.getByRole('table', { name: de ? 'Gespeicherter Updateverlauf' : 'Retained update history' })).toBeVisible();
        expect(screen.getByText(de ? 'Dateioperationen' : 'File operations')).toBeVisible(); expect(within(screen.getByRole('region', { name: de ? 'Patch-Kontext' : 'Patch context' })).getByText(de ? 'Nicht verfügbar' : 'Unavailable')).toBeVisible();
        expect(screen.getByText(de ? 'Deinstallation' : 'Uninstallation')).toBeVisible(); expect(screen.getByText('HRESULT: 80240022')).toBeVisible();
        expect(screen.getByText(de ? /kein aktueller Installationsbestand/ : /not current installed inventory/)).toBeVisible();
        const headers = screen.getAllByRole('columnheader').map(cell => cell.textContent); for (const row of screen.getAllByRole('row').slice(1)) expect(within(row).getAllByRole('cell').map(cell => cell.dataset.label)).toEqual(headers);
        expect(screen.queryByRole('link')).toBeNull(); expect(screen.queryByRole('button', { name: /install|reboot|enable|grant|scan|apply/i })).toBeNull();
    });
    it('coexists with separately granted cached rows and resets history details on tab navigation', async () => {
        vi.mocked(request).mockResolvedValue({ ...windowsPatchContextView(), updates: windowsUpdates() }); render(<Harness/>); await ready(); expect(screen.getByText('Synthetic cached update 001')).toBeVisible(); fireEvent.click(details().querySelector('summary')!); expect(screen.getAllByRole('table')).toHaveLength(2);
        fireEvent.click(screen.getByRole('tab', { name: 'Hostname' })); fireEvent.click(screen.getByRole('tab', { name: 'Updates' })); expect(details().open).toBe(false);
    });
    it('does not invent healthy reboot or installed-inventory conclusions from unknown/empty evidence', async () => {
        const v = windowsPatchContextView(); Object.assign(v.patchContext.history, { rows: [], totalCount: 0, truncated: false }); v.patchContext.reboot.windowsUpdate = 'clear'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); expect(screen.getByText('Unknown')).toBeVisible(); fireEvent.click(details().querySelector('summary')!); expect(screen.getByText(/No retained events returned/)).toBeVisible(); expect(screen.queryByRole('table')).toBeNull();
        v.patchContext.reboot.fileOperations = 'clear'; refresh(); await flush(); expect(screen.getByText('No checked indicator set')).toBeVisible();
    });
    it('keeps denied OS/history quality explicit and renders source titles as inert text', async () => {
        const v = windowsPatchContextView(); v.patchContext.os.edition = { value: null, quality: 'denied' }; v.patchContext.history.rows[0].title = '<img src=x onerror=alert(1)>'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); fireEvent.click(details().querySelector('summary')!); expect(screen.getByText(/Access denied ·/)).toBeVisible(); expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeVisible(); expect(document.querySelector('img, iframe, a')).toBeNull();
        Object.assign(v.patchContext.history, { quality: 'denied', reason: 'windows_patch_context_access_denied', countExact: false, totalCount: 0, truncated: false, rows: [] }); refresh(); await flush(); fireEvent.click(details().querySelector('summary')!); expect(screen.getByText(/History unavailable/)).toBeVisible(); expect(screen.queryByText('<img src=x onerror=alert(1)>')).toBeNull();
    });
    it('hides the subsection when the optional scope is absent or malformed', async () => {
        vi.mocked(request).mockResolvedValue(windowsView()); render(<Harness/>); await ready(); expect(screen.queryByRole('region', { name: 'Patch context' })).toBeNull();
        vi.mocked(request).mockResolvedValue({ ...windowsPatchContextView(), patchContext: { ...windowsPatchContextView().patchContext, raw: 'private raw marker' } }); refresh(); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('inconsistent'); expect(document.body).not.toHaveTextContent('private raw marker');
    });
});

describe('Patch context authority and original-capture lifetime', () => {
    it('turns stale after two minutes and expires at the original 24-hour limit', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const v = windowsPatchContextView(); v.snapshot!.collectedAt = v.patchContext.collectedAt = '2026-10-07T11:58:10Z'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); expect(screen.queryByText(/Stale context/)).toBeNull(); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.getByText(/Stale context/)).toBeVisible(); cleanup();
        vi.setSystemTime(windowsNow); v.snapshot!.collectedAt = v.patchContext.collectedAt = '2026-10-06T12:00:11Z'; v.status = 'stale'; v.patchContext.history.rows.forEach(row => { row.occurredAt = '2026-10-05T10:00:00Z'; }); vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); fireEvent.click(details().querySelector('summary')!); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.queryByText('Synthetic cumulative update')).toBeNull(); expect(screen.getByText(/Patch context expired/)).toBeVisible();
    });
    it('does not show a future capture until the manager acceptance clock catches up', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const v = windowsPatchContextView(); v.snapshot!.collectedAt = v.patchContext.collectedAt = '2026-10-07T12:00:11Z'; v.status = 'stale'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); expect(screen.queryByText(/Windows 11 Pro/)).toBeNull(); expect(screen.getByText(/until its capture time/)).toBeVisible(); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.getByText(/Windows 11 Pro/)).toBeVisible();
    });
    it.each(['blur', 'pagehide', 'hashchange', AUTH_REQUIRED_EVENT])('clears patch fields and hidden history on %s', async event => {
        render(<Harness/>); await ready(); act(() => window.dispatchEvent(new Event(event))); expect(screen.queryByText(/Windows 11 Pro/)).toBeNull(); expect(screen.queryByText('Synthetic cumulative update')).toBeNull();
    });
    it.each(['revoked', 'unavailable', 'awaiting', 'not_configured'] as const)('removes old patch context when authority becomes %s', async status => {
        render(<Harness/>); await ready(); vi.mocked(request).mockResolvedValue({ ...windowsView(), status, snapshot: null, ...(['awaiting', 'not_configured'].includes(status) ? { sequence: null, receivedAt: null } : {}) }); refresh(); await flush(); expect(screen.queryByText(/Windows 11 Pro/)).toBeNull(); expect(screen.queryByText('Synthetic cumulative update')).toBeNull();
    });
    it('rejects frozen manager time and late replies after session replacement', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); render(<Harness/>); await ready(); await act(async () => vi.advanceTimersByTimeAsync(15000)); expect(screen.queryByText(/Windows 11 Pro/)).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('time reference changed'); cleanup(); vi.useRealTimers();
        let resolve!: (v: ReturnType<typeof windowsPatchContextView>) => void; vi.mocked(request).mockReturnValueOnce(new Promise(done => { resolve = done; })); const result = render(<Harness/>); await ready(); const signal = vi.mocked(request).mock.calls.at(-1)![1]?.signal; vi.mocked(request).mockResolvedValue(windowsView()); result.rerender(<Harness session="replacement"/>); await act(async () => resolve(windowsPatchContextView())); expect(signal?.aborted).toBe(true); expect(screen.queryByText('Synthetic cumulative update')).toBeNull();
    });
});
