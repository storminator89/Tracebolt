import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, abortProtectedRequests, AUTH_REQUIRED_EVENT, mutate, request } from './api';
import { useOperator } from './auth';
import { DeviceDetail } from './details';
import { setLocale } from './i18n';
import { WindowsInventoryWorkspace } from './windows-inventory';
import { useWindowsInventory, type WindowsInventoryResource } from './windows-inventory-resource';
import { windowsDevice, windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import { windowsUpdates, windowsUpdatesView } from './windows-updates-fixture';
import { capturedWindowsUpdateRows } from './windows-updates';
import { WINDOWS_INVENTORY_VIEW_BYTES, type WindowsInventoryView } from './windows-inventory-types';
import { historyFixture } from './resource-history-fixture';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: '2026-10-07T13:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
const flush = () => act(async () => {});
function resource(view: WindowsInventoryView = windowsUpdatesView()): WindowsInventoryResource { return { updates: view.updates ?? null, updatesStale: view.status === 'stale', updatesExpired: false, updatesAhead: false, serviceStartup: null, serviceStartupStale: false, elapsedMS: 0, view, snapshot: view.snapshot, status: view.status, loading: false, error: null, refresh: vi.fn(), processMetrics: null, processMetricsStale: false, network: null, networkStale: false, networkExpired: false, adapterContext: null, adapterContextStale: false, adapterContextExpired: false, patchContext: null, patchContextStale: false, patchContextExpired: false, patchContextAhead: false, storageContext: null, storageContextStale: false, storageContextExpired: false, storageContextAhead: false, hardwareContext: null, hardwareContextStale: false, hardwareContextExpired: false, hardwareContextAhead: false, sessionContext: null, sessionContextStale: false, sessionContextExpired: false, sessionContextAhead: false, securityCoverage: null, securityCoverageStale: false, securityCoverageExpired: false, securityCoverageAhead: false, securityPosture: null, securityPostureStale: false, securityPostureExpired: false, securityPostureAhead: false, volumes: null, volumesStale: false, events: null, eventsStale: false }; }
function Harness({ id = windowsDeviceId, session = 'fixture', enabled = true }: { id?: string; session?: string; enabled?: boolean }) { return <WindowsInventoryWorkspace key={`${id}:${session}`} resource={useWindowsInventory(id, enabled, session)}/>; }
const select = () => fireEvent.click(screen.getByRole('tab', { name: 'Updates' }));
const ready = async () => { await flush(); select(); };
const rows = () => within(screen.getByRole('table')).getAllByRole('row').slice(1);
const refresh = () => fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' }));
beforeEach(() => { setLocale('en', false); vi.mocked(request).mockReset().mockResolvedValue(windowsUpdatesView()); vi.mocked(mutate).mockReset(); vi.mocked(useOperator).mockReturnValue(operator); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('read-only cached Windows Updates panel', () => {
    it.each(['en', 'de'] as const)('shows original capture, cache caveats and bounded controls with %s column/mobile labels', locale => {
        setLocale(locale, false); const de = locale === 'de'; render(<WindowsInventoryWorkspace resource={resource()}/>); select();
        expect(screen.getByRole('heading', { name: de ? 'Windows-Updates aus dem Cache' : 'Cached Windows Updates' })).toBeVisible();
        expect(screen.getByText(de ? /Die Aktualität des Caches ist unbekannt/ : /Cache freshness is unknown/)).toBeVisible();
        expect(screen.getByText(de ? /Es startet keine Online-Suche/ : /It does not start an online scan/)).toBeVisible();
        expect(screen.getByRole('searchbox', { name: de ? 'Erfasste Updates filtern' : 'Filter captured updates' })).toHaveAttribute('maxLength', '256');
        expect(screen.getByRole('combobox', { name: de ? 'Erfasste Updates sortieren' : 'Sort captured updates' })).toHaveValue('title-asc');
        expect(document.querySelector('time[datetime="2026-10-07T12:00:00Z"]')).not.toBeNull();
        expect(screen.getByText('KB1000000')).toBeVisible(); expect(screen.getByText(de ? 'Kritisch' : 'Critical')).toBeVisible(); expect(screen.getByText(de ? 'Titel oder KB-Metadaten gekürzt' : 'Title or KB metadata shortened')).toBeVisible();
        const headers = screen.getAllByRole('columnheader').map(cell => cell.textContent);
        expect(headers).toEqual(de ? ['Titel', 'KB-Artikel', 'Hersteller-Schweregrad', 'Bereits heruntergeladen', 'Update-ID / Revision'] : ['Title', 'KB articles', 'Vendor severity', 'Already downloaded', 'Update ID / revision']);
        for (const row of rows()) expect(within(row).getAllByRole('cell').map(cell => cell.getAttribute('data-label'))).toEqual(headers);
        expect(within(rows()[0]).getByText(de ? 'Ja' : 'Yes')).toBeVisible(); expect(within(rows()[1]).getByText(de ? 'Nein' : 'No')).toBeVisible();
        fireEvent.click(screen.getByText(de ? 'Umfang & Grenzen' : 'Scope & limits'));
        expect(screen.getByText(de ? /kein CVE-Abgleich/ : /not a CVE match/)).toBeVisible(); expect(screen.getByText(de ? /Keine Updateaktionen/ : /No update actions/)).toBeVisible();
        expect(screen.queryByRole('link')).toBeNull(); expect(screen.queryByRole('button', { name: /scan|download|install|reboot|export|grant|enable|apply/i })).toBeNull(); expect(request).not.toHaveBeenCalled(); expect(mutate).not.toHaveBeenCalled();
    });
    it('renders markup-shaped title only as inert text, without executable elements, links or source mutation', () => {
        const v = windowsUpdatesView(); v.updates.rows[0].title = '<img src=x onerror=alert(1)> & <script>alert(1)</script>'; const before = JSON.stringify(v);
        render(<WindowsInventoryWorkspace resource={resource(v)}/>); select(); expect(screen.getByText(v.updates.rows[0].title)).toBeVisible(); expect(document.querySelector('img, script, iframe, a')).toBeNull(); expect(JSON.stringify(v)).toBe(before);
    });
    it('uses keyboard tab selection and leaves other Windows subviews intact', async () => {
        render(<Harness/>); await flush(); fireEvent.keyDown(screen.getByRole('tab', { name: 'Software' }), { key: 'ArrowRight' }); expect(screen.getByRole('tab', { name: 'Updates' })).toHaveFocus(); expect(screen.getByText('Synthetic cached update 001')).toBeVisible();
        fireEvent.keyDown(screen.getByRole('tab', { name: 'Updates' }), { key: 'ArrowRight' }); expect(screen.getByRole('tab', { name: 'Security' })).toHaveFocus(); expect(screen.getByText(/Separate local approval/)).toBeVisible();
        fireEvent.keyDown(screen.getByRole('tab', { name: 'Security' }), { key: 'ArrowRight' }); expect(screen.getByRole('tab', { name: 'Users / Sessions' })).toHaveFocus(); expect(screen.getByText(/Separate local approval/)).toBeVisible();
        fireEvent.keyDown(screen.getByRole('tab', { name: 'Users / Sessions' }), { key: 'ArrowRight' }); expect(screen.getByRole('tab', { name: 'Hostname' })).toHaveFocus(); expect(screen.getByText('fixture-windows')).toBeVisible();
        fireEvent.keyDown(screen.getByRole('tab', { name: 'Hostname' }), { key: 'Home' }); expect(screen.getByRole('tab', { name: 'Device' })).toHaveFocus(); expect(screen.getByText(/Separate local approval/)).toBeVisible();
        fireEvent.keyDown(screen.getByRole('tab', { name: 'Device' }), { key: 'ArrowRight' }); expect(screen.getByRole('tab', { name: 'Processes' })).toHaveFocus(); expect(screen.getByText('fixture.exe')).toBeVisible();
    });
    it.each(['en', 'de'] as const)('pages only retained rows and resets page on literal localized filtering and sorting in %s', locale => {
        setLocale(locale, false); const de = locale === 'de', v = windowsUpdatesView(61); v.updates.observedCount = 1000; v.updates.truncated = true; v.updates.rows[59].title = 'Literal [.*] update';
        render(<WindowsInventoryWorkspace resource={resource(v)}/>); select();
        const next = () => screen.getByRole('button', { name: de ? 'Nächste Seite' : 'Next page' }), previous = () => screen.getByRole('button', { name: de ? 'Vorherige Seite' : 'Previous page' });
        expect(rows()).toHaveLength(25); expect(previous()).toBeDisabled(); expect(screen.getByText(de ? '61 erfasst · 1000 Cache-Ergebnisse beobachtet' : '61 captured · 1000 cached results observed')).toBeVisible();
        fireEvent.click(next()); expect(rows()).toHaveLength(25); fireEvent.click(next()); expect(rows()).toHaveLength(11); expect(next()).toBeDisabled();
        expect(screen.getByText(de ? 'Zeilen 51–61 von 61 Treffern · 61 erfasst' : 'Rows 51–61 of 61 matching · 61 captured')).toBeVisible();
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: '[.*]' } }); expect(rows()).toHaveLength(1); expect(previous()).toBeDisabled(); expect(next()).toBeDisabled(); expect(screen.getByText('Literal [.*] update')).toBeVisible();
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'KB1000060' } }); expect(rows()).toHaveLength(1); expect(screen.getByText('Synthetic cached update 061')).toBeVisible();
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'no-such-update' } }); expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByText(de ? 'Keine erfassten Updates entsprechen diesem Filter.' : 'No captured updates match this filter.')).toBeVisible();
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: '' } }); fireEvent.change(screen.getByRole('combobox'), { target: { value: 'severity-desc' } }); expect(rows()).toHaveLength(25); expect(within(rows()[0]).getByText(de ? 'Kritisch' : 'Critical')).toBeVisible(); expect(screen.getByRole('columnheader', { name: de ? 'Hersteller-Schweregrad' : 'Vendor severity' })).toHaveAttribute('aria-sort', 'descending');
        fireEvent.click(next()); fireEvent.change(screen.getByRole('combobox'), { target: { value: 'downloaded-desc' } }); expect(previous()).toBeDisabled(); expect(within(rows()[0]).getByText(de ? 'Ja' : 'Yes')).toBeVisible();
        expect(request).not.toHaveBeenCalled(); expect(mutate).not.toHaveBeenCalled();
    });
    it.each(['en', 'de'] as const)('sorts vendor levels truthfully, keeps unspecified last and preserves immutable deterministic ties in %s', locale => {
        const v = windowsUpdates(64), before = JSON.stringify(v);
        for (const sort of ['title-asc', 'title-desc', 'severity-asc', 'severity-desc', 'downloaded-asc', 'downloaded-desc'] as const) { const result = capturedWindowsUpdateRows(v, '', sort, locale); expect(result).toHaveLength(64); expect(new Set(result.map(row => row.updateId)).size).toBe(64); }
        expect(capturedWindowsUpdateRows(v, '', 'severity-desc', locale)[0].severity).toBe('critical'); expect(capturedWindowsUpdateRows(v, '', 'severity-asc', locale)[0].severity).toBe('low');
        expect(capturedWindowsUpdateRows(v, '', 'severity-desc', locale).at(-1)!.severity).toBe('unspecified'); expect(capturedWindowsUpdateRows(v, '', 'severity-asc', locale).at(-1)!.severity).toBe('unspecified');
        expect(capturedWindowsUpdateRows(v, locale === 'de' ? 'Kritisch' : 'Critical', 'severity-desc', locale).every(row => row.severity === 'critical')).toBe(true);
        v.rows[1].title = v.rows[0].title; expect(capturedWindowsUpdateRows(v, v.rows[0].title, 'title-desc', locale).slice(0, 2).map(row => row.updateId)).toEqual(v.rows.slice(0, 2).map(row => row.updateId)); v.rows[1].title = windowsUpdates(64).rows[1].title;
        expect(JSON.stringify(v)).toBe(before);
    });
    it('does not turn absent scope, successful empty, bounded zero or partial zero into a patched claim', () => {
        const ui = render(<WindowsInventoryWorkspace resource={resource(windowsView())}/>); select(); expect(screen.getByText(/requires separate local consent/)).toBeVisible(); expect(screen.queryByRole('table')).toBeNull();
        const v = windowsUpdatesView(0); ui.rerender(<WindowsInventoryWorkspace resource={resource(v)}/>); expect(screen.getByText(/No non-hidden, not-installed software updates/)).toBeVisible(); expect(screen.getByText('0 captured · 0 cached results observed')).toBeVisible();
        v.updates.observedCount = 10; v.updates.truncated = true; ui.rerender(<WindowsInventoryWorkspace resource={resource(v)}/>); expect(screen.getByText('Bounded cached result')).toBeVisible(); expect(screen.getByText(/No update rows are available/)).toBeVisible(); expect(screen.queryByText(/No non-hidden, not-installed software updates/)).toBeNull();
        Object.assign(v.updates, { quality: 'partial', reason: 'windows_updates_partial_result', observedCount: 0, truncated: false, countExact: false }); ui.rerender(<WindowsInventoryWorkspace resource={resource(v)}/>); expect(screen.getByText('0 captured · at least 0 cached results observed')).toBeVisible(); expect(screen.getByText('Partial cached result')).toBeVisible();
    });
    it.each(['denied', 'unavailable'] as const)('shows fixed %s reason without count or old rows', async quality => {
        render(<Harness/>); await ready(); const v = windowsUpdatesView(0); Object.assign(v.updates, { quality, reason: quality === 'denied' ? 'windows_updates_access_denied' : 'windows_updates_offline_not_verified', countExact: false }); vi.mocked(request).mockResolvedValue(v); refresh(); await flush();
        expect(screen.queryByText('Synthetic cached update 001')).toBeNull(); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByText(/0 captured/)).toBeNull(); expect(screen.getByText(/No update rows are available/)).toBeVisible(); expect(screen.getByText(quality === 'denied' ? 'The local caller was denied access.' : 'Offline-only inspection could not be verified; collection stopped.')).toBeVisible();
    });
});

describe('Updates share the existing private resource and expiry', () => {
    it('reads only the same bounded endpoint and refreshes manager reports without mutation', async () => {
        render(<Harness/>); await ready(); refresh(); await flush(); expect(request).toHaveBeenCalledTimes(2);
        for (const call of vi.mocked(request).mock.calls) expect(call).toEqual([`/devices/${windowsDeviceId}/windows-inventory`, { signal: expect.any(AbortSignal) }, WINDOWS_INVENTORY_VIEW_BYTES]); expect(mutate).not.toHaveBeenCalled();
    });
    it('lives in the authenticated shared Windows device inventory with no Linux endpoint calls', async () => {
        const history = historyFixture(); history.deviceId = windowsDeviceId;
        vi.mocked(request).mockImplementation(async path => path === `/devices/${windowsDeviceId}` ? windowsDevice() : path.endsWith('/windows-inventory') ? windowsUpdatesView() : path.endsWith('/resource-history') ? history : Promise.reject(new Error('Unexpected fixture route')));
        render(<DeviceDetail id={windowsDeviceId} onClose={vi.fn()} onCase={vi.fn()}/>); await screen.findByRole('heading', { name: 'fixture-windows' }); fireEvent.click(screen.getByRole('tab', { name: 'Inventory' })); select(); expect(screen.getByText('Synthetic cached update 001')).toBeVisible();
        expect(vi.mocked(request).mock.calls.map(([path]) => path).every(path => path === `/devices/${windowsDeviceId}` || path.endsWith('/windows-inventory') || path.endsWith('/resource-history'))).toBe(true); expect(mutate).not.toHaveBeenCalled(); expect(screen.queryByRole('tab', { name: /CVE|Security coverage/ })).toBeNull();
    });
    it('keeps filters for a same-generation reread but clears them on changed generation/grant/capture and tab departure', async () => {
        vi.mocked(request).mockResolvedValue(windowsUpdatesView(61)); render(<Harness/>); await ready();
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'Synthetic' } }); fireEvent.change(screen.getByRole('combobox'), { target: { value: 'title-desc' } }); fireEvent.click(screen.getByRole('button', { name: 'Next page' })); refresh(); expect(screen.queryByRole('table')).toBeNull(); await flush(); expect(screen.getByRole('searchbox')).toHaveValue('Synthetic'); expect(screen.getByRole('combobox')).toHaveValue('title-desc'); expect(screen.getByText('Page 2 of 3')).toBeVisible();
        for (const kind of ['generation', 'grant', 'capture']) { const v = windowsUpdatesView(61); if (kind === 'generation') v.snapshot!.generationId = v.updates.generationId = `sample_${'b'.repeat(32)}`; if (kind === 'grant') v.updates.grantId = 'e'.repeat(32); if (kind === 'capture') v.snapshot!.collectedAt = v.updates.collectedAt = '2026-10-07T12:00:01Z'; vi.mocked(request).mockResolvedValue(v); refresh(); await flush(); expect(screen.getByRole('searchbox')).toHaveValue(''); expect(screen.getByRole('combobox')).toHaveValue('title-asc'); expect(screen.getByText('Page 1 of 3')).toBeVisible(); fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'private filter' } }); }
        fireEvent.click(screen.getByRole('tab', { name: 'Hostname' })); select(); expect(screen.getByRole('searchbox')).toHaveValue('');
    });
    it.each(['blur', 'pagehide', 'hashchange', AUTH_REQUIRED_EVENT])('clears rows and private filters immediately on %s', async event => {
        render(<Harness/>); await ready(); fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'Synthetic' } }); act(() => window.dispatchEvent(new Event(event))); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByRole('searchbox')).toBeNull(); expect(screen.queryByText('Synthetic cached update 001')).toBeNull();
        if (event !== AUTH_REQUIRED_EVENT) { act(() => window.dispatchEvent(new Event('focus'))); await flush(); expect(screen.getByRole('searchbox')).toHaveValue(''); }
    });
    it('clears on hidden page and avoids reads until visible; disabled scopes do not fetch', async () => {
        const ui = render(<Harness/>); await ready(); const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); expect(screen.queryByRole('table')).toBeNull(); vi.mocked(request).mockClear(); act(() => window.dispatchEvent(new Event('focus'))); await flush(); expect(request).not.toHaveBeenCalled();
        visibility.mockReturnValue('visible'); act(() => document.dispatchEvent(new Event('visibilitychange'))); await flush(); expect(screen.getByText('Synthetic cached update 001')).toBeVisible(); ui.rerender(<Harness enabled={false}/>); await flush(); expect(screen.queryByRole('table')).toBeNull(); vi.mocked(request).mockClear(); refresh(); await flush(); expect(request).not.toHaveBeenCalled();
    });
    it('aborts on device/session replacement and ignores the old response', async () => {
        let resolve!: (v: WindowsInventoryView) => void; const ui = render(<Harness/>); await ready(); vi.mocked(request).mockReturnValueOnce(new Promise(done => { resolve = done; })); refresh(); const signal = vi.mocked(request).mock.calls.at(-1)![1]!.signal;
        const next = windowsView(), id = `agent_${'8'.repeat(32)}`; next.deviceId = id; vi.mocked(request).mockResolvedValue(next); ui.rerender(<Harness id={id} session="new-session"/>); await act(async () => resolve(windowsUpdatesView())); expect(signal!.aborted).toBe(true); select(); expect(screen.queryByText('Synthetic cached update 001')).toBeNull(); expect(screen.queryByRole('table')).toBeNull();
    });
    it('discards an older overlapping refresh and clears during every read', async () => {
        let resolve!: (v: WindowsInventoryView) => void; render(<Harness/>); await ready(); vi.mocked(request).mockReturnValueOnce(new Promise(done => { resolve = done; })); refresh(); expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByRole('button', { name: 'Refresh Windows inventory' })).toBeDisabled();
        act(() => window.dispatchEvent(new Event('blur'))); vi.mocked(request).mockResolvedValue(windowsView()); act(() => window.dispatchEvent(new Event('focus'))); await flush(); await act(async () => resolve(windowsUpdatesView())); expect(screen.queryByText('Synthetic cached update 001')).toBeNull(); expect(screen.getByText(/requires separate local consent/)).toBeVisible();
    });
    it.each(['revoked', 'unavailable', 'awaiting', 'not_configured'] as const)('removes updates and controls on manager status %s', async status => {
        render(<Harness/>); await ready(); vi.mocked(request).mockResolvedValue({ ...windowsView(), status, snapshot: null, ...(['awaiting', 'not_configured'].includes(status) ? { sequence: null, receivedAt: null } : {}) }); refresh(); await flush(); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByRole('searchbox')).toBeNull(); expect(screen.queryByText('Synthetic cached update 001')).toBeNull();
    });
    it('clears a missing sibling after a new report instead of retaining rows from the prior generation', async () => { render(<Harness/>); await ready(); vi.mocked(request).mockResolvedValue(windowsView()); refresh(); await flush(); expect(screen.getByText(/requires separate local consent/)).toBeVisible(); expect(screen.queryByText('Synthetic cached update 001')).toBeNull(); });
    it('never displays arbitrary server fields/error prose and recovers from an invalid response', async () => {
        render(<Harness/>); await ready(); vi.mocked(request).mockResolvedValue({ ...windowsUpdatesView(), updates: { ...windowsUpdates(), secret: 'private-error-prose' } }); refresh(); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('inconsistent'); expect(screen.queryByRole('table')).toBeNull(); expect(document.body).not.toHaveTextContent('private-error-prose');
        vi.mocked(request).mockRejectedValue(new APIError('private-error-prose', 503)); refresh(); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('unavailable'); expect(document.body).not.toHaveTextContent('private-error-prose'); vi.mocked(request).mockResolvedValue(windowsUpdatesView()); refresh(); await flush(); expect(screen.getByText('Synthetic cached update 001')).toBeVisible();
    });
    it('locks after 401/protected epoch loss and never revives late private rows', async () => {
        render(<Harness/>); await ready(); vi.mocked(request).mockRejectedValue(new APIError('private', 401)); refresh(); await flush(); expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('Sign in again'); const count = vi.mocked(request).mock.calls.length; act(() => window.dispatchEvent(new Event('focus'))); await flush(); expect(request).toHaveBeenCalledTimes(count);
        cleanup(); let resolve!: (v: WindowsInventoryView) => void; vi.mocked(request).mockReturnValue(new Promise(done => { resolve = done; })); render(<Harness session="new"/>); await ready(); abortProtectedRequests(); await act(async () => resolve(windowsUpdatesView())); expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('Sign in again');
    });
    it('expires the original capture at 24h without minting age from receipt, hiding all private sibling rows', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const v = windowsUpdatesView(); v.snapshot!.collectedAt = v.updates.collectedAt = '2026-10-06T12:00:11Z'; v.status = 'stale'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); expect(screen.getByText('Synthetic cached update 001')).toBeVisible(); expect(screen.getByText(/Stale inspection/)).toBeVisible();
        await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByRole('searchbox')).toBeNull(); expect(screen.getByText(/Rows are hidden 24 hours/)).toBeVisible(); fireEvent.click(screen.getByRole('tab', { name: 'Processes' })); expect(screen.queryByText('fixture.exe')).toBeNull();
    });
    it('changes recent to stale at two minutes while preserving unknown cache freshness', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const v = windowsUpdatesView(); v.snapshot!.collectedAt = v.updates.collectedAt = '2026-10-07T11:58:10Z'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); expect(screen.queryByText(/Stale inspection/)).toBeNull(); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.getByText(/Stale inspection/)).toBeVisible(); expect(screen.getByText(/Cache freshness is unknown/)).toBeVisible();
    });
    it('preserves the base view under allowed future skew while withholding update rows, then ages them without a scan', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const v = windowsUpdatesView(); v.snapshot!.collectedAt = v.updates.collectedAt = '2026-10-07T12:00:11Z'; v.status = 'stale'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready();
        expect(screen.queryByRole('alert')).toBeNull(); expect(screen.getByText(/capture time is ahead/)).toBeVisible(); expect(screen.queryByRole('table')).toBeNull(); fireEvent.click(screen.getByRole('tab', { name: 'Processes' })); expect(screen.getByText('fixture.exe')).toBeVisible(); select(); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.getByText('Synthetic cached update 001')).toBeVisible(); expect(screen.getByText(/Stale inspection/)).toBeVisible(); expect(request).toHaveBeenCalledTimes(1);
    });
    it('does not use request latency to reveal a still-future capture early', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); let resolve!: (v: WindowsInventoryView) => void; vi.mocked(request).mockReturnValue(new Promise(done => { resolve = done; })); render(<Harness/>); await ready(); await act(async () => vi.advanceTimersByTimeAsync(2000));
        const v = windowsUpdatesView(); v.snapshot!.collectedAt = v.updates.collectedAt = '2026-10-07T12:00:11Z'; v.status = 'stale'; await act(async () => resolve(v)); expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByText(/capture time is ahead/)).toBeVisible();
        await act(async () => vi.advanceTimersByTimeAsync(999)); expect(screen.queryByRole('table')).toBeNull(); await act(async () => vi.advanceTimersByTimeAsync(1)); expect(screen.getByText('Synthetic cached update 001')).toBeVisible();
    });
    it('withholds future rows when a two-stage clock shift invalidates only the response-acceptance anchor', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const origin = Date.parse(windowsNow); let resolve!: (v: WindowsInventoryView) => void; vi.mocked(request).mockReturnValue(new Promise(done => { resolve = done; })); render(<Harness/>); await ready();
        // Each offset is within the original request anchor's 1.5-second
        // tolerance, but the acceptance anchor crosses it by 2.98 seconds.
        vi.setSystemTime(new Date(origin + 1490)); const v = windowsUpdatesView(); v.snapshot!.collectedAt = v.updates.collectedAt = '2026-10-07T12:00:11Z'; v.status = 'stale'; await act(async () => resolve(v)); expect(screen.queryByRole('table')).toBeNull();
        vi.setSystemTime(new Date(origin - 1490)); await act(async () => vi.advanceTimersByTimeAsync(2000)); expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByText(/time reference changed. Update rows are hidden/)).toBeVisible(); expect(screen.queryByRole('alert')).toBeNull();
        fireEvent.click(screen.getByRole('tab', { name: 'Processes' })); expect(screen.getByText('fixture.exe')).toBeVisible(); select(); expect(screen.queryByText('Synthetic cached update 001')).toBeNull();
    });
    it('timeout aborts and a late response cannot restore rows', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); let resolve!: (v: WindowsInventoryView) => void; render(<Harness/>); await ready(); vi.mocked(request).mockReturnValue(new Promise(done => { resolve = done; })); refresh(); await act(async () => vi.advanceTimersByTimeAsync(10001)); expect(screen.getByRole('alert')).toHaveTextContent('timed out'); await act(async () => resolve(windowsUpdatesView())); expect(screen.queryByRole('table')).toBeNull();
    });
    it.each(['frozen server', 'browser clock change'])('does not renew rows after %s', async cause => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); render(<Harness/>); await ready(); if (cause === 'browser clock change') vi.setSystemTime('2026-10-07T11:00:00Z'); await act(async () => vi.advanceTimersByTimeAsync(cause === 'frozen server' ? 15000 : 1000)); expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('time reference changed');
    });
});
