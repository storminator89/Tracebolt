import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, request, mutate } from './api';
import { setLocale } from './i18n';
import { WindowsInventoryWorkspace } from './windows-inventory';
import { useWindowsInventory } from './windows-inventory-resource';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import { windowsSessionContextView } from './windows-session-context-fixture';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
const flush = () => act(async () => {});
function Harness({ session = 'fixture', device = windowsDeviceId, enabled = true }: { session?: string; device?: string; enabled?: boolean }) { return <WindowsInventoryWorkspace resource={useWindowsInventory(device, enabled, session)}/>; }
const ready = async (locale = 'en') => { await flush(); fireEvent.click(screen.getByRole('tab', { name: locale === 'de' ? 'Benutzer / Sitzungen' : 'Users / Sessions' })); };
const refresh = () => fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' }));
const details = () => document.querySelector<HTMLDetailsElement>('.windows-session-details')!;
const namesGone = () => { expect(screen.queryByText('fixture-alex')).toBeNull(); expect(screen.queryByText('FIXTURE-WORKGROUP')).toBeNull(); expect(document.querySelector('.windows-session-details')).toBeNull(); };
beforeEach(() => { setLocale('en', false); vi.mocked(request).mockReset().mockResolvedValue(windowsSessionContextView()); vi.mocked(mutate).mockReset(); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('Compact private Users / Sessions tab', () => {
    it.each(['en', 'de'] as const)('shows bounded rows, original capture and collapsed coverage in %s', async locale => {
        setLocale(locale, false); render(<Harness/>); await ready(locale); const de = locale === 'de', panel = screen.getByRole('region', { name: de ? 'Benutzer / Sitzungen' : 'Users / Sessions' });
        expect(within(panel).getByText('fixture-alex')).toBeVisible(); expect(within(panel).getByText('FIXTURE-WORKGROUP')).toBeVisible(); expect(within(panel).getByText(de ? 'Arbeitsgruppe' : 'Workgroup')).toBeVisible();
        expect(within(panel).getByText(de ? '3 angezeigt · 3 beobachtet' : '3 shown · 3 observed')).toBeVisible(); expect(within(panel).getByText(de ? 'Teilweise' : 'Partial')).toBeVisible();
        expect(panel.querySelector('time')).toHaveAttribute('dateTime', windowsView().snapshot!.collectedAt); expect(details().open).toBe(false);
        expect(within(panel).getByText(de ? 'Lokale Windows-Sitzungs-API (WTS)' : 'Local Windows session API (WTS)')).not.toBeVisible();
        fireEvent.click(details().querySelector('summary')!); expect(within(panel).getByText(de ? 'Lokale Windows-Sitzungs-API (WTS)' : 'Local Windows session API (WTS)')).toBeVisible();
        expect(within(panel).getByText(de ? 'Einige Felder waren nicht verfügbar.' : 'Some fields were not available.')).toBeVisible();
        const table = within(panel).getByRole('table'), headers = within(table).getAllByRole('columnheader').map(cell => cell.textContent);
        expect(within(table).getAllByRole('row')).toHaveLength(4); for (const row of within(table).getAllByRole('row').slice(1)) expect(within(row).getAllByRole('cell').map(cell => cell.dataset.label)).toEqual(headers);
        expect(within(table).getByText(de ? 'Zugriff verweigert' : 'Access denied')).toBeVisible(); expect(within(table).getByText(de ? 'Nicht verfügbar' : 'Unavailable')).toBeVisible(); expect(within(table).getAllByText(de ? 'Keine Angabe' : 'No label')).toHaveLength(2);
        expect(panel).toHaveTextContent(de ? 'keine vollständige Benutzer- oder Kontenliste' : 'not all users or accounts'); expect(panel).toHaveTextContent(de ? 'KI-/Provider-Export ausgeschlossen' : 'excluded from AI/provider export');
        expect(panel.querySelector('a,img,iframe,button,form,input')).toBeNull(); expect(mutate).not.toHaveBeenCalled(); expect(vi.mocked(request).mock.calls.map(([path]) => path)).toEqual([`/devices/${windowsDeviceId}/windows-inventory`]);
    });
    it('renders adversarial labels as isolated text with no navigation or markup', async () => {
        const v = windowsSessionContextView(); v.sessionContext.sessions.rows[1].userName = '<img src=x onerror=alert(1)>'; v.sessionContext.join.name = 'https://example.invalid/private'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeVisible(); expect(screen.getByText('https://example.invalid/private')).toBeVisible(); expect(document.querySelector('.windows-session-context img, .windows-session-context a')).toBeNull(); expect(screen.getByText('<img src=x onerror=alert(1)>').tagName).toBe('BDI');
    });
    it.each(['denied', 'unavailable'] as const)('does not interpret %s sessions as empty or hide readable membership', async quality => {
        const v = windowsSessionContextView(); v.sessionContext.sessions = { quality, reason: quality === 'denied' ? 'windows_session_context_access_denied' : 'windows_session_context_unavailable', observedCount: null, retainedCount: 0, truncatedCount: null, rows: [] }; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); expect(screen.getByText(/An empty session list cannot be established/)).toBeVisible(); expect(screen.getByText('FIXTURE-WORKGROUP')).toBeVisible(); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByText(/0 shown/)).toBeNull();
        fireEvent.click(details().querySelector('summary')!); expect(within(details()).getAllByText('Unknown')).toHaveLength(2);
    });
    it('keeps observed-empty separate from omitted rows and partial membership', async () => {
        const v = windowsSessionContextView(); Object.assign(v.sessionContext.sessions, { quality: 'observed', reason: '', observedCount: 0, retainedCount: 0, rows: [] }); v.sessionContext.join = { quality: 'observed', reason: '', status: 'unjoined', name: null }; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); expect(screen.getByText('No sessions observed within the caller-visible scope.')).toBeVisible(); expect(screen.getByText('Unjoined')).toBeVisible(); expect(screen.getByText('0 shown · 0 observed')).toBeVisible();
        Object.assign(v.sessionContext.sessions, { quality: 'partial', reason: 'windows_session_context_bounds', observedCount: 4096, truncatedCount: 4096 }); v.sessionContext.join = { quality: 'partial', reason: 'windows_session_context_invalid_metadata', status: 'domain', name: null }; vi.mocked(request).mockResolvedValue(structuredClone(v)); refresh(); await flush(); expect(screen.getByText('0 shown · 4096 observed · 4096 omitted')).toBeVisible(); expect(screen.getByText(/No session rows were retained/)).toBeVisible(); expect(screen.getByText('Domain')).toBeVisible(); expect(screen.getByText('Unknown')).toBeVisible();
    });
    it('does not let denied membership erase readable sessions', async () => {
        const v = windowsSessionContextView(); v.sessionContext.join = { quality: 'denied', reason: 'windows_session_context_access_denied', status: 'unknown', name: null }; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); expect(screen.getByText('Unknown membership')).toBeVisible(); expect(within(screen.getByRole('region', { name: 'Device membership' })).getByText('Access denied')).toBeVisible(); expect(screen.getByText('fixture-alex')).toBeVisible();
    });
    it('resets source detail on keyboard tab navigation and replacement identity', async () => {
        render(<Harness/>); await ready(); fireEvent.click(details().querySelector('summary')!); const tab = screen.getByRole('tab', { name: 'Users / Sessions' }); fireEvent.keyDown(tab, { key: 'ArrowRight' }); expect(screen.getByRole('tab', { name: 'Hostname' })).toHaveFocus(); namesGone(); fireEvent.keyDown(screen.getByRole('tab', { name: 'Hostname' }), { key: 'ArrowLeft' }); expect(tab).toHaveFocus(); expect(details().open).toBe(false);
        fireEvent.click(details().querySelector('summary')!); const v = windowsSessionContextView(); v.sessionContext.grantId = 'd'.repeat(32); v.sessionContext.generationId = v.snapshot!.generationId = `sample_${'9'.repeat(32)}`; v.sessionContext.sessions.rows[1].userName = 'fixture-replacement'; vi.mocked(request).mockResolvedValue(v); refresh(); await flush(); expect(details().open).toBe(false); expect(screen.queryByText('fixture-alex')).toBeNull(); expect(screen.getByText('fixture-replacement')).toBeVisible();
    });
    it('shows absent consent and rejects untrusted fields before rendering them', async () => {
        vi.mocked(request).mockResolvedValue(windowsView()); render(<Harness/>); await ready(); expect(screen.getByText(/Separate local approval/)).toBeVisible();
        const v = windowsSessionContextView(); Object.assign(v.sessionContext.sessions.rows[0], { clientIP: 'private-marker' }); vi.mocked(request).mockResolvedValue(v); refresh(); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('inconsistent'); expect(document.body).not.toHaveTextContent('private-marker'); namesGone();
    });
});

describe('Session authority and original-capture lifetime', () => {
    it('turns stale after two minutes and removes every private field at 24-hour expiry', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const v = windowsSessionContextView(); v.snapshot!.collectedAt = v.sessionContext.collectedAt = '2026-10-07T11:58:10Z'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); expect(screen.queryByText(/Stale observation;/)).toBeNull(); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.getByText(/Stale observation;/)).toBeVisible(); cleanup();
        vi.setSystemTime(windowsNow); v.snapshot!.collectedAt = v.sessionContext.collectedAt = '2026-10-06T12:00:11Z'; v.status = 'stale'; render(<Harness/>); await ready(); await act(async () => vi.advanceTimersByTimeAsync(1000)); namesGone(); expect(screen.getByText(/Session context expired/)).toBeVisible();
    });
    it('hides future rows until capture time is reached on the acceptance clock', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const v = windowsSessionContextView(); v.snapshot!.collectedAt = v.sessionContext.collectedAt = '2026-10-07T12:00:11Z'; v.status = 'stale'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); namesGone(); expect(screen.getByText(/until its capture time/)).toBeVisible(); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.getByText('fixture-alex')).toBeVisible();
    });
    it.each(['blur', 'pagehide', 'hashchange', AUTH_REQUIRED_EVENT])('clears visible and collapsed personal metadata on %s', async event => {
        render(<Harness/>); await ready(); act(() => window.dispatchEvent(new Event(event))); namesGone();
    });
    it.each(['revoked', 'unavailable', 'awaiting', 'not_configured', 'absent'] as const)('discards all metadata when the scope becomes %s', async status => {
        render(<Harness/>); await ready(); vi.mocked(request).mockResolvedValue(status === 'absent' ? windowsView() : { ...windowsView(), status, snapshot: null, ...(['awaiting', 'not_configured'].includes(status) ? { sequence: null, receivedAt: null } : {}) }); refresh(); await flush(); namesGone();
    });
    it('clears on hidden visibility and disabled authority, with a fresh read on restore', async () => {
        const result = render(<Harness/>); await ready(); const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); namesGone(); visibility.mockReturnValue('visible'); act(() => document.dispatchEvent(new Event('visibilitychange'))); await flush(); expect(screen.getByText('fixture-alex')).toBeVisible(); result.rerender(<Harness enabled={false}/>); namesGone();
    });
    it('clears on device navigation and ignores the older pending response', async () => {
        let resolve!: (v: ReturnType<typeof windowsSessionContextView>) => void; const result = render(<Harness/>); await ready(); vi.mocked(request).mockReturnValueOnce(new Promise(done => { resolve = done; })); refresh(); namesGone(); const signal = vi.mocked(request).mock.calls.at(-1)![1]?.signal, device = `agent_${'8'.repeat(32)}`; vi.mocked(request).mockResolvedValue({ ...windowsView(), deviceId: device }); result.rerender(<Harness device={device}/>); await act(async () => resolve(windowsSessionContextView())); expect(signal?.aborted).toBe(true); namesGone();
    });
    it('rejects a frozen manager clock and a late response from the replaced session', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); render(<Harness/>); await ready(); await act(async () => vi.advanceTimersByTimeAsync(15000)); namesGone(); expect(screen.getByRole('alert')).toHaveTextContent('time reference changed'); cleanup(); vi.useRealTimers();
        let resolve!: (v: ReturnType<typeof windowsSessionContextView>) => void; vi.mocked(request).mockReturnValueOnce(new Promise(done => { resolve = done; })); const result = render(<Harness/>); await ready(); const signal = vi.mocked(request).mock.calls.at(-1)![1]?.signal; vi.mocked(request).mockResolvedValue(windowsView()); result.rerender(<Harness session="replacement"/>); await act(async () => resolve(windowsSessionContextView())); expect(signal?.aborted).toBe(true); namesGone();
    });
});
