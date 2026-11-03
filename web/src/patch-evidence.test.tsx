import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { setLocale } from './i18n';
import { LinuxPatchEvidence, WindowsPatchEvidence } from './patch-evidence';
import { updateDevice, updateView } from './complete-updates-fixtures';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import { windowsPatchContextView } from './windows-patch-context-fixture';
import { windowsUpdates } from './windows-updates-fixture';
import { useWindowsInventory } from './windows-inventory-resource';
import type { CompleteUpdateView } from './complete-updates-types';
import type { WindowsInventoryView } from './windows-inventory-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
let linux = updateView(), windows: WindowsInventoryView = { ...windowsPatchContextView(), updates: windowsUpdates() };
const openSource = vi.fn();
const flush = () => act(async () => {});
const value = (label: string, scope: HTMLElement = document.body) => within(scope).getByText(label, { selector: 'dt' }).parentElement!.querySelector('dd')!;
function WindowsHarness() { return <WindowsPatchEvidence resource={useWindowsInventory(windowsDeviceId, true, 'fixture-session')} onOpenSource={openSource}/>; }
beforeEach(() => {
    setLocale('en', false); linux = updateView(); windows = { ...windowsPatchContextView(), updates: windowsUpdates() }; openSource.mockReset();
    vi.mocked(request).mockReset().mockImplementation(async path => path.endsWith('/complete-updates') ? linux : windows);
    vi.mocked(mutateRaw).mockReset();
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('metadata-only Linux patch overview', () => {
    it.each(['en', 'de'] as const)('keeps original source times, counts and limits visible without row or action queries in %s', async locale => {
        setLocale(locale, false); render(<LinuxPatchEvidence deviceId={updateDevice} onOpenSource={openSource}/>); await flush();
        const de = locale === 'de';
        expect(value(de ? 'Bekannte neuere Kandidaten' : 'Known newer candidates')).toHaveTextContent('1213');
        expect(value(de ? 'Ursprünglicher Erfassungszeitpunkt' : 'Original capture time').querySelector('time')).toHaveAttribute('datetime', linux.complete!.manifest.collectedAt);
        expect(value(de ? 'Änderungszeit des ältesten Paketindex' : 'Oldest package-index modification time').querySelector('time')).toHaveAttribute('datetime', linux.complete!.manifest.metadata.oldestIndexModifiedAt);
        expect(screen.getByText(de ? /Null Kandidaten belegt keinen vollständigen Patchstand/ : /Zero candidates is not proof of a fully patched device/)).toBeVisible();
        expect(request).toHaveBeenCalledTimes(1); expect(vi.mocked(request).mock.calls[0][0]).toBe(`/devices/${updateDevice}/inventory/complete-updates`);
        expect(mutateRaw).not.toHaveBeenCalled(); expect(screen.queryByRole('table')).toBeNull();
        fireEvent.click(screen.getByRole('button', { name: de ? 'Quellenansicht öffnen' : 'Open source view' })); expect(openSource).toHaveBeenCalledOnce();
        expect(screen.getAllByRole('button')).toHaveLength(2);
    });
    it('does not interpret a zero known total with failed comparisons or unknown cache freshness as patch coverage', async () => {
        linux = updateView(0); Object.assign(linux.complete!.manifest, { comparisonCoverage: 'partial', comparisonReason: 'candidate_unknown', unknownCount: 1, installedCount: 4, checkedCount: 3 });
        Object.assign(linux.complete!.manifest.metadata, { freshness: 'unknown', ageSeconds: 3600, oldestIndexModifiedAt: '2026-10-05T03:00:00Z' });
        render(<LinuxPatchEvidence deviceId={updateDevice} onOpenSource={openSource}/>); await flush();
        expect(value('Known newer candidates')).toHaveTextContent(/^0$/); expect(value('Unknown package comparisons')).toHaveTextContent(/^1$/);
        expect(screen.getByText(/known-candidate count is a lower bound, including when it is zero/)).toBeVisible(); expect(value('Cache freshness')).toHaveTextContent('Unknown');
    });
    it('retains the old capture and stale cache beside a newer failed attempt and pending transfer', async () => {
        linux.complete!.binding.sequence = '1';
        const binding = { ...linux.complete!.binding, sequence: '2', generationId: `sample_${'d'.repeat(32)}` };
        linux.failure = { sequence: binding.sequence, generationId: binding.generationId, attemptedAt: '2026-10-05T04:00:06Z', receivedAt: '2026-10-05T04:00:07Z', reason: 'source_changed' };
        linux.transfer = { binding, state: 'pending', declaredRows: 12, acceptedRows: 0, expectedChunks: 1, acceptedChunks: 0, collectedAt: '2026-10-05T04:00:06Z', startedAt: '2026-10-05T04:00:07Z', expiresAt: '2026-10-05T04:05:07Z' };
        render(<LinuxPatchEvidence deviceId={updateDevice} onOpenSource={openSource}/>); await flush();
        expect(value('Original capture time')).toHaveTextContent('2026-10-05T04:00:00Z'); expect(value('Latest failed capture attempt')).toHaveTextContent('Source changed during capture');
        expect(value('Latest transfer')).toHaveTextContent('Pending'); expect(screen.getByText(/does not refresh or replace/)).toBeVisible();
        fireEvent.click(screen.getByRole('button', { name: 'Refresh saved patch evidence' })); await flush();
        expect(value('Original capture time')).toHaveTextContent('2026-10-05T04:00:00Z'); expect(value('Cache freshness')).toHaveTextContent('Stale at capture'); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it.each(['not_configured', 'awaiting', 'unavailable', 'revoked'] as const)('keeps %s distinct from an empty successful result', async status => {
        linux = { ...linux, status, complete: null, transfer: null, failure: null };
        render(<LinuxPatchEvidence deviceId={updateDevice} onOpenSource={openSource}/>); await flush();
        expect(screen.queryByText('Known newer candidates')).toBeNull();
        expect(screen.getByRole('status')).toHaveTextContent(status === 'not_configured' ? 'not configured' : status === 'awaiting' ? 'Awaiting' : status === 'revoked' ? 'revoked' : 'No eligible');
    });
    it('expires a pending transfer at its immutable deadline while keeping the earlier complete capture unchanged', async () => {
        vi.useFakeTimers(); vi.setSystemTime(linux.serverNow); linux.complete!.binding.sequence = '1';
        linux.transfer = { binding: { ...linux.complete!.binding, sequence: '2', generationId: `sample_${'d'.repeat(32)}` }, state: 'pending', declaredRows: 12, acceptedRows: 0, expectedChunks: 1, acceptedChunks: 0, collectedAt: '2026-10-05T04:00:06Z', startedAt: '2026-10-05T04:00:07Z', expiresAt: '2026-10-05T04:00:11Z' };
        render(<LinuxPatchEvidence deviceId={updateDevice} onOpenSource={openSource}/>); await flush(); expect(value('Latest transfer')).toHaveTextContent('Pending');
        await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(value('Latest transfer')).toHaveTextContent('Expired'); expect(value('Original capture time')).toHaveTextContent('2026-10-05T04:00:00Z');
    });
    it('turns historical and expires on the original deadline without a refresh renewing capture age', async () => {
        vi.useFakeTimers(); vi.setSystemTime('2026-10-05T04:00:10Z');
        render(<LinuxPatchEvidence deviceId={updateDevice} onOpenSource={openSource}/>); await flush(); expect(screen.getByText('Recent capture')).toBeVisible();
        await act(async () => vi.advanceTimersByTimeAsync(111000)); expect(screen.getByText('Historical capture')).toBeVisible(); cleanup();
        linux.serverNow = '2026-10-06T03:59:59Z'; vi.setSystemTime(linux.serverNow); render(<LinuxPatchEvidence deviceId={updateDevice} onOpenSource={openSource}/>); await flush();
        expect(value('Known newer candidates')).toHaveTextContent('1213'); await act(async () => vi.advanceTimersByTimeAsync(1000));
        expect(screen.queryByText('Known newer candidates')).toBeNull(); expect(screen.getByText(/Original observation expired/)).toBeVisible();
    });
    it('clears on invalid response, a request failure, session end and a replaced device while pending', async () => {
        vi.mocked(request).mockResolvedValueOnce({ ...linux, unexpected: 'private marker' });
        const ui = render(<LinuxPatchEvidence key="first" deviceId={updateDevice} onOpenSource={openSource}/>); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('could not be verified');
        expect(document.body).not.toHaveTextContent('private marker');
        vi.mocked(request).mockRejectedValueOnce(new APIError('synthetic', 503));
        fireEvent.click(screen.getByRole('button', { name: 'Refresh saved patch evidence' })); await flush(); expect(screen.queryByText('Known newer candidates')).toBeNull();
        vi.mocked(request).mockResolvedValueOnce(linux); fireEvent.click(screen.getByRole('button', { name: 'Refresh saved patch evidence' })); await flush();
        await act(async () => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); expect(screen.queryByText('Known newer candidates')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('session has ended');
        let resolve!: (value: CompleteUpdateView) => void; let signal: AbortSignal | undefined;
        vi.mocked(request).mockImplementationOnce(async (_path, init) => { signal = init?.signal as AbortSignal; return new Promise<CompleteUpdateView>(done => { resolve = done; }); });
        ui.rerender(<LinuxPatchEvidence key="pending" deviceId={updateDevice} onOpenSource={openSource}/>); await flush();
        ui.rerender(<LinuxPatchEvidence key="other" deviceId="agent_other" onOpenSource={openSource}/>); await flush(); expect(signal?.aborted).toBe(true);
        await act(async () => resolve(linux)); expect(screen.queryByText('Known newer candidates')).toBeNull();
    });
});

describe('Windows patch overview keeps independent source meanings', () => {
    it.each(['en', 'de'] as const)('shows separate cache and retained-history totals, methods, times and reboot limits in %s', async locale => {
        setLocale(locale, false); render(<WindowsHarness/>); await flush(); const de = locale === 'de';
        const cache = screen.getByRole('region', { name: de ? 'Windows · Updateergebnisse aus dem Cache' : 'Windows · cached update results' });
        const history = screen.getByRole('region', { name: de ? 'Windows · gespeicherter Verlauf und Neustartkontext' : 'Windows · retained history and reboot context' });
        expect(value(de ? 'Beobachtete Cache-Ergebnisse' : 'Cached results observed', cache)).toHaveTextContent(String(windows.updates!.observedCount));
        expect(value(de ? 'Gespeicherte Ereignisse' : 'Retained events', history)).toHaveTextContent('8');
        expect(value(de ? 'Methode' : 'Method', history)).toHaveTextContent('QueryHistory'); expect(value(de ? 'Methode' : 'Method', cache)).toHaveTextContent('WUA');
        expect(value(de ? 'Neustartindikatoren' : 'Reboot indicators', history)).toHaveTextContent(de ? 'Mindestens ein' : 'At least one');
        expect(cache.querySelector('time')).toHaveAttribute('datetime', windows.updates!.collectedAt); expect(history.querySelector('time')).toHaveAttribute('datetime', windows.patchContext!.collectedAt);
        expect(screen.queryByRole('table')).toBeNull(); expect(mutateRaw).not.toHaveBeenCalled(); expect(request).toHaveBeenCalledOnce();
        fireEvent.click(screen.getByRole('button', { name: de ? 'Quellenansicht öffnen' : 'Open source view' })); expect(openSource).toHaveBeenCalledOnce();
    });
    it('shows zero partial cache counts as lower bounds and never substitutes retained success for a denied latest attempt', async () => {
        const old = windowsUpdates(); Object.assign(windows.updates!, { quality: 'partial', reason: 'windows_updates_partial_result', observedCount: 0, countExact: false, rows: [], truncated: false });
        Object.assign(windows.patchContext!.history, { quality: 'denied', reason: 'windows_patch_context_access_denied', countExact: false, totalCount: 0, rows: [], truncated: false });
        windows.retainedContext = { patchContext: { ...windowsPatchContextView().patchContext, generationId: `sample_${'d'.repeat(32)}`, collectedAt: '2026-10-07T11:50:00Z' }, updates: { ...old, generationId: `sample_${'d'.repeat(32)}`, collectedAt: '2026-10-07T11:50:00Z' } };
        render(<WindowsHarness/>); await flush();
        expect(value('Cached results observed')).toHaveTextContent('at least 0'); expect(screen.getByText('Access denied')).toBeVisible(); expect(screen.queryByText('Retained events', { selector: 'dt' })).toBeNull();
        expect(document.querySelector('time[datetime="2026-10-07T11:50:00Z"]')).toBeNull();
    });
    it('does not claim QueryHistory for a successful empty history or reboot clearance from incomplete sources', async () => {
        Object.assign(windows.patchContext!.history, { rows: [], totalCount: 0, truncated: false });
        windows.patchContext!.reboot.windowsUpdate = 'clear'; render(<WindowsHarness/>); await flush();
        expect(screen.getByText('GetTotalHistoryCount; no QueryHistory needed for zero retained events')).toBeVisible(); expect(value('Reboot indicators')).toHaveTextContent('Unknown / incomplete');
    });
    it('does not claim a successful source read for offline-unverified partial cache or history', async () => {
        Object.assign(windows.updates!, { quality: 'partial', reason: 'windows_updates_offline_not_verified', observedCount: 0, countExact: false, rows: [], truncated: false });
        Object.assign(windows.patchContext!.history, { quality: 'partial', reason: 'windows_patch_context_offline_not_verified', totalCount: 0, countExact: false, rows: [], truncated: false });
        render(<WindowsHarness/>); await flush(); expect(screen.getAllByText('No successful source read verified')).toHaveLength(2);
    });
    it('keeps absent, expired, future and session-ended evidence unknown and hides all source counts', async () => {
        windows = windowsView(); render(<WindowsHarness/>); await flush(); expect(screen.getAllByText(/does not include the separate source/)).toHaveLength(2); cleanup();
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); windows = { ...windowsPatchContextView(), updates: windowsUpdates() };
        windows.snapshot!.collectedAt = windows.patchContext!.collectedAt = windows.updates!.collectedAt = '2026-10-06T12:00:11Z'; windows.status = 'stale';
        windows.patchContext!.history.rows = []; windows.patchContext!.history.totalCount = 0; windows.patchContext!.history.truncated = false;
        render(<WindowsHarness/>); await flush(); await act(async () => vi.advanceTimersByTimeAsync(1000));
        expect(screen.queryByText('Cached results observed')).toBeNull(); expect(screen.queryByText('Retained events', { selector: 'dt' })).toBeNull(); expect(screen.getAllByText(/Original observation expired/)).toHaveLength(2); cleanup();
        windows = { ...windowsPatchContextView(), updates: windowsUpdates() }; windows.status = 'stale'; windows.snapshot!.collectedAt = windows.patchContext!.collectedAt = windows.updates!.collectedAt = '2026-10-07T12:00:12Z';
        render(<WindowsHarness/>); await flush(); expect(screen.queryByText('Cached results observed')).toBeNull(); expect(screen.getAllByText(/time reference cannot be verified/)).toHaveLength(2);
        await act(async () => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); expect(screen.getAllByText(/session has ended/)).toHaveLength(2); expect(screen.queryByText('Retained events', { selector: 'dt' })).toBeNull();
    });
});
