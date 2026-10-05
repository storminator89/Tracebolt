import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, AUTH_REQUIRED_EVENT, abortProtectedRequests, request } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { LinuxCVEPanel } from './linux-cve';
import { LINUX_CVE_BUNDLE_BYTES, LINUX_CVE_VIEW_BYTES } from './linux-cve-types';
import { linuxCVEDeviceId as id, linuxCVEView, missingLinuxCVEView, staleLinuxCVEView } from './linux-cve-fixtures';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: '2026-10-05T08:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
const path = `/devices/${id}/security/cves`;
function defer<T>() { let resolve!: (v: T) => void; return { promise: new Promise<T>(done => { resolve = done; }), resolve }; }
const flush = () => act(async () => { await Promise.resolve(); await Promise.resolve(); });
async function show(view = linuxCVEView()) { vi.mocked(request).mockResolvedValue(view); const rendered = render(<LinuxCVEPanel deviceId={id} sessionKey="one"/>); await screen.findByText('Limited coverage'); return rendered; }
function choose(file = new File(['{"schemaVersion":"first","schemaVersion":"second"}'], 'private-file-name.json')) { fireEvent.click(screen.getByText('Manual JSON bundle import')); fireEvent.change(screen.getByLabelText('Choose JSON bundle'), { target: { files: [file] } }); return file; }
beforeEach(() => { setLocale('en', false); vi.mocked(request).mockReset(); vi.mocked(useOperator).mockReturnValue(operator); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('Linux CVE warnings panel', () => {
    it('reads once, shows compact warning evidence and progressively discloses binaries/import', async () => {
        const storage = vi.spyOn(Storage.prototype, 'setItem'); await show();
        expect(request).toHaveBeenCalledExactlyOnceWith(path, { signal: expect.any(AbortSignal) }, LINUX_CVE_VIEW_BYTES);
        const card = screen.getByRole('article', { name: 'CVE-2026-999999: fixture' }); expect(within(card).getByText('2:1.0-1')).toBeVisible(); expect(within(card).getByText('2:1.0-2')).toBeVisible();
        expect(screen.getByRole('link', { name: 'CVE-2026-999999' })).toHaveAttribute('href', 'https://security-tracker.debian.org/tracker/CVE-2026-999999');
        expect(screen.getByText('libfixture:amd64')).not.toBeVisible(); expect(screen.getByLabelText('Choose JSON bundle')).not.toBeVisible();
        expect(screen.getByRole('button', { name: 'Update security data' })).toBeEnabled(); expect(screen.getByText(/published fix is not an installable APT candidate/)).toBeVisible();
        expect(screen.getByText('Feed download age')).toBeVisible(); expect(screen.queryByRole('button', { name: /install|upgrade/i })).not.toBeInTheDocument(); expect(storage).not.toHaveBeenCalled();
    });
    it('groups multiple installed versions into one CVE/source package warning', async () => {
        const view = linuxCVEView(), row = structuredClone(view.report!.findings[0]); row.installedSourceVersion = '2:1.0-0'; row.binaries[0].architecture = 'arm64'; row.binaries[0].version = '2:1.0-0'; row.publishedFixedVersion = '2:1.0-3'; view.report!.findings.push(row); view.report!.evaluatedSourceCount = 1; view.inventory!.rowCount = 2;
        await show(view); expect(screen.getAllByRole('article')).toHaveLength(1); expect(screen.getByText('Package warnings').previousElementSibling).toHaveTextContent('1'); expect(screen.getByText('2 distribution package/version matches')).toBeVisible();
        expect(screen.getByText('2:1.0-0', { selector: 'dd' })).toBeVisible(); expect(screen.getByText('2:1.0-3')).toBeVisible();
    });
    it.each(['feed_missing', 'inventory_unavailable', 'not_configured', 'unsupported'] as const)('does not present unknown %s state as zero warnings', async status => {
        const view = missingLinuxCVEView(); view.status = status; if (status === 'inventory_unavailable' || status === 'not_configured') view.inventory = null;
        vi.mocked(request).mockResolvedValue(view); render(<LinuxCVEPanel deviceId={id}/>); expect(await screen.findByText('Warnings unavailable')).toBeVisible(); expect(screen.queryByText(/No package\/version matches/)).not.toBeInTheDocument(); expect(screen.queryByRole('article')).not.toBeInTheDocument();
    });
    it('distinguishes evaluated empty output and stale retained matches', async () => {
        const empty = linuxCVEView(); empty.report!.findings = []; const rendered = await show(empty); expect(screen.getByText(/No package\/version matches/)).toBeVisible(); expect(screen.getByText('Package warnings').previousElementSibling).toHaveTextContent('0');
        rendered.unmount(); await show(staleLinuxCVEView()); expect(screen.getByText(/Old data: these matches describe earlier snapshots/)).toBeVisible(); expect(screen.getByRole('article')).toBeVisible(); expect(screen.getByText('3 d · Stale')).toBeVisible();
    });
    it('shows failed update with retained previous matches', async () => {
        const view = linuxCVEView(); view.feeds.outcome = 'failed'; view.feeds.failureReason = 'import_failed'; await show(view); expect(screen.getByText(/last data update failed/)).toBeVisible(); expect(screen.getByRole('article')).toBeVisible();
    });
    it('distinguishes an uncertain disk commit and blocks further writes pending restart', async () => {
        const view = linuxCVEView(); view.feeds.outcome = 'failed'; view.feeds.failureReason = 'cache_commit_uncertain'; await show(view);
        expect(screen.getByText(/Security-data save uncertain/)).toBeVisible(); expect(screen.queryByText(/Any previous snapshot is retained/)).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Update security data' })).toBeDisabled(); expect(screen.getByRole('button', { name: 'Refresh assessment' })).toBeEnabled();
        fireEvent.click(screen.getByText('Manual JSON bundle import')); expect(screen.getByLabelText('Choose JSON bundle')).toBeDisabled(); expect(screen.getByRole('button', { name: 'Import bundle' })).toBeDisabled();
    });
    it('attributes Ubuntu data and its license under source details', async () => {
        const view = linuxCVEView(); for (const feed of [view.feeds.snapshots[0], view.report!.feed!]) Object.assign(feed, { provider: 'canonical-ubuntu-osv', target: 'ubuntu-24.04-noble', sourceUrl: 'https://security-metadata.canonical.com/osv/', license: 'CC-BY-SA-4.0' }); view.report!.findings[0].advisoryUrl = 'https://ubuntu.com/security/CVE-2026-999999';
        await show(view); fireEvent.click(screen.getByText('Data sources and coverage')); expect(screen.getByText(/Source attribution: Canonical/)).toBeVisible(); expect(screen.getByRole('link', { name: 'CC-BY-SA-4.0' })).toHaveAttribute('href', 'https://creativecommons.org/licenses/by-sa/4.0/');
    });
    it('shows origin and skipped coverage caveats within secondary details', async () => {
        await show(); fireEvent.click(screen.getByText('Data sources and coverage')); expect(screen.getByText(/backports, PPAs and locally rebuilt/)).toBeVisible(); expect(screen.getByText(/Manual bundle origin and supplied fetch time are unverified/)).toBeVisible(); expect(screen.getByText(/Upstream publication freshness is unknown/)).toBeVisible();
    });
    it('provides German copy and never fetches without authenticated LAN scope', async () => {
        setLocale('de', false); vi.mocked(request).mockResolvedValue(linuxCVEView()); const shown = render(<LinuxCVEPanel deviceId={id}/>); await screen.findByText('Begrenzte Abdeckung'); expect(screen.getByRole('button', { name: 'Sicherheitsdaten aktualisieren' })).toBeVisible(); shown.unmount(); vi.mocked(request).mockClear();
        for (const context of [null, { ...operator, authenticated: false }, { ...operator, mode: 'development' as const }]) { vi.mocked(useOperator).mockReturnValue(context); const rendered = render(<LinuxCVEPanel deviceId={id}/>); expect(screen.queryByRole('button')).not.toBeInTheDocument(); rendered.unmount(); } expect(request).not.toHaveBeenCalled();
    });
});

describe('Linux CVE protected lifecycle', () => {
    it.each(['unmount', 'device', 'session', 'auth', 'pagehide', 'hashchange', 'popstate', 'hidden'] as const)('cancels pending output and rejects late success on %s', async transition => {
        const old = defer<unknown>(); vi.mocked(request).mockReturnValue(old.promise); const rendered = render(<LinuxCVEPanel deviceId={id} sessionKey="one"/>); const signal = vi.mocked(request).mock.calls[0][1]!.signal as AbortSignal;
        if (transition === 'unmount') rendered.unmount(); else if (transition === 'device') rendered.rerender(<LinuxCVEPanel deviceId="agent_other" sessionKey="one"/>); else if (transition === 'session') { vi.mocked(request).mockResolvedValue(missingLinuxCVEView()); rendered.rerender(<LinuxCVEPanel deviceId={id} sessionKey="two"/>); } else if (transition === 'hidden') { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); } else act(() => window.dispatchEvent(new Event(transition === 'auth' ? AUTH_REQUIRED_EVENT : transition)));
        expect(signal.aborted).toBe(true); await act(async () => old.resolve(linuxCVEView())); expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(document.body.textContent).not.toContain('libfixture');
    });
    it('does not let a pre-suspension response replace a restored request', async () => {
        const old = defer<unknown>(); vi.mocked(request).mockReturnValue(old.promise); render(<LinuxCVEPanel deviceId={id}/>); act(() => window.dispatchEvent(new Event('pagehide'))); vi.mocked(request).mockResolvedValue(missingLinuxCVEView()); act(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }))); await screen.findByText('Warnings unavailable'); await act(async () => old.resolve(linuxCVEView())); expect(screen.queryByRole('article')).not.toBeInTheDocument();
    });
    it('clears displayed output before a refresh and rejects duplicate response rows', async () => {
        await show(); const pending = defer<unknown>(); vi.mocked(request).mockReturnValue(pending.promise); fireEvent.click(screen.getByRole('button', { name: 'Refresh assessment' })); expect(screen.queryByRole('article')).not.toBeInTheDocument(); const duplicate = linuxCVEView(); duplicate.report!.findings.push(duplicate.report!.findings[0]); await act(async () => pending.resolve(duplicate)); expect(screen.getByRole('alert')).toHaveTextContent('inconsistent or unsupported');
    });
    it('rejects auth epoch changes without needing a 401 response', async () => {
        vi.useFakeTimers(); vi.mocked(request).mockResolvedValue(linuxCVEView()); render(<LinuxCVEPanel deviceId={id}/>); await flush(); act(() => abortProtectedRequests()); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('session has ended'); expect(screen.getByRole('button', { name: 'Refresh assessment' })).toBeDisabled();
    });
    it.each(['lease', 'clock'] as const)('expires displayed results after %s invalidation', async kind => {
        vi.useFakeTimers(); vi.mocked(request).mockResolvedValue(linuxCVEView()); render(<LinuxCVEPanel deviceId={id}/>); await flush(); if (kind === 'clock') vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 5000); await act(async () => vi.advanceTimersByTimeAsync(kind === 'lease' ? 60000 : 1000)); expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('view expired or its clock changed');
    });
    it('aborts a timed-out read and discards a later success', async () => {
        vi.useFakeTimers(); const pending = defer<unknown>(); vi.mocked(request).mockReturnValue(pending.promise); render(<LinuxCVEPanel deviceId={id}/>); const signal = vi.mocked(request).mock.calls[0][1]!.signal as AbortSignal; await act(async () => vi.advanceTimersByTimeAsync(10000)); expect(signal.aborted).toBe(true); expect(screen.getByRole('alert')).toHaveTextContent('did not respond in time'); await act(async () => pending.resolve(linuxCVEView())); expect(screen.queryByRole('article')).not.toBeInTheDocument();
    });
    it('retries only the same storage_busy read once within its deadline', async () => {
        vi.useFakeTimers(); vi.mocked(request).mockRejectedValueOnce(new APIError('private detail', 429, 'storage_busy')).mockResolvedValueOnce(linuxCVEView()); render(<LinuxCVEPanel deviceId={id}/>); await flush(); expect(screen.getByRole('status')).toHaveTextContent('Retrying this read once'); await act(async () => vi.advanceTimersByTimeAsync(2000)); expect(request).toHaveBeenCalledTimes(2); expect(vi.mocked(request).mock.calls[0][1]!.signal).toBe(vi.mocked(request).mock.calls[1][1]!.signal); expect(screen.getByRole('article')).toBeVisible(); expect(document.body.textContent).not.toContain('private detail');
    });
});

describe('explicit local-manager feed writes', () => {
    it('syncs only after clicking, posts fixed empty JSON and then rereads', async () => {
        await show(); vi.mocked(request).mockImplementation(async route => route === '/session' ? { csrfToken: 'fixture-token' } : route === '/security/cves/sync' ? linuxCVEView(true).feeds : linuxCVEView(true)); fireEvent.click(screen.getByRole('button', { name: 'Update security data' })); await screen.findByText('Debian security data updated in the local manager.'); await screen.findByRole('article');
        expect(vi.mocked(request).mock.calls.filter(([route]) => route === '/security/cves/sync')).toHaveLength(1); expect(request).toHaveBeenCalledWith('/security/cves/sync', expect.objectContaining({ method: 'POST', body: '{}', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': 'fixture-token' }, signal: expect.any(AbortSignal) }), LINUX_CVE_VIEW_BYTES);
    });
    it('selects a file without transmitting and sends original bytes only after import', async () => {
        await show(); const file = choose(); expect(request).toHaveBeenCalledTimes(1); expect(document.body.textContent).not.toContain(file.name);
        vi.mocked(request).mockImplementation(async route => route === '/session' ? { csrfToken: 'fixture-token' } : route === '/security/cves/import' ? linuxCVEView().feeds : linuxCVEView()); fireEvent.click(screen.getByRole('button', { name: 'Import bundle' })); await screen.findByText('Bundle imported into the local manager.'); await screen.findByRole('article');
        expect(request).toHaveBeenCalledWith('/security/cves/import', expect.objectContaining({ method: 'POST', body: file }), LINUX_CVE_VIEW_BYTES);
    });
    it('rejects empty/oversized file selection without requesting mutation', async () => {
        await show(); choose(new File([], 'empty.json')); expect(screen.getByRole('alert')).toHaveTextContent('non-empty'); const file = new File(['x'], 'large.json'); Object.defineProperty(file, 'size', { value: LINUX_CVE_BUNDLE_BYTES + 1 }); fireEvent.change(screen.getByLabelText('Choose JSON bundle'), { target: { files: [file] } }); expect(screen.getByRole('alert')).toHaveTextContent('32 MiB'); expect(request).toHaveBeenCalledTimes(1);
    });
    it('keeps file picker focus loss from discarding local selection', async () => {
        await show(); act(() => window.dispatchEvent(new Event('blur'))); choose(); act(() => window.dispatchEvent(new Event('focus'))); expect(screen.getByRole('button', { name: 'Import bundle' })).toBeEnabled(); expect(request).toHaveBeenCalledTimes(1);
    });
    it('does not post if the auth epoch changes during the CSRF read', async () => {
        await show(); const session = defer<unknown>(); vi.mocked(request).mockReturnValue(session.promise); fireEvent.click(screen.getByRole('button', { name: 'Update security data' })); act(() => abortProtectedRequests()); await act(async () => session.resolve({ csrfToken: 'fixture-token' })); expect(vi.mocked(request).mock.calls.some(([route]) => route === '/security/cves/sync')).toBe(false); expect(screen.getByRole('alert')).toHaveTextContent('session has ended');
    });
    it('aborts a sync on pagehide and never repeats an uncertain mutation', async () => {
        await show(); const pending = defer<unknown>(); vi.mocked(request).mockImplementation(async route => route === '/session' ? { csrfToken: 'fixture-token' } : route === '/security/cves/sync' ? pending.promise : linuxCVEView()); fireEvent.click(screen.getByRole('button', { name: 'Update security data' })); await waitFor(() => expect(vi.mocked(request).mock.calls.some(([route]) => route === '/security/cves/sync')).toBe(true)); const signal = vi.mocked(request).mock.calls.find(([route]) => route === '/security/cves/sync')![1]!.signal as AbortSignal; act(() => window.dispatchEvent(new Event('pagehide'))); expect(signal.aborted).toBe(true); await act(async () => pending.resolve(linuxCVEView(true).feeds)); expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(screen.getByRole('status')).toHaveTextContent('not confirmed'); act(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }))); await screen.findByRole('article'); expect(vi.mocked(request).mock.calls.filter(([route]) => route === '/security/cves/sync')).toHaveLength(1);
    });
    it('enforces the 60-second sync deadline without resubmitting', async () => {
        vi.useFakeTimers(); const pending = defer<unknown>(); vi.mocked(request).mockImplementation(async route => route === '/session' ? { csrfToken: 'fixture-token' } : route === '/security/cves/sync' ? pending.promise : linuxCVEView()); render(<LinuxCVEPanel deviceId={id}/>); await flush();
        fireEvent.click(screen.getByRole('button', { name: 'Update security data' })); await flush(); const signal = vi.mocked(request).mock.calls.find(([route]) => route === '/security/cves/sync')![1]!.signal as AbortSignal;
        await act(async () => vi.advanceTimersByTimeAsync(60000)); expect(signal.aborted).toBe(true); expect(screen.getByRole('alert')).toHaveTextContent('not confirmed'); await act(async () => pending.resolve(linuxCVEView(true).feeds)); expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(vi.mocked(request).mock.calls.filter(([route]) => route === '/security/cves/sync')).toHaveLength(1);
    });
    it('clears file selection when disclosure closes without sending', async () => {
        await show(); choose(); const details = screen.getByText('Manual JSON bundle import').closest('details')!; details.open = false; fireEvent(details, new Event('toggle')); await flush(); details.open = true; fireEvent(details, new Event('toggle')); await flush(); expect(screen.getByRole('button', { name: 'Import bundle' })).toBeDisabled(); expect(request).toHaveBeenCalledTimes(1);
    });
    it('reports write errors without leaking server detail or retrying writes', async () => {
        await show(); vi.mocked(request).mockImplementation(async route => { if (route === '/session') return { csrfToken: 'fixture-token' }; throw new APIError('/private/secret', 429, 'storage_busy'); }); fireEvent.click(screen.getByRole('button', { name: 'Update security data' })); expect(await screen.findByRole('alert')).toHaveTextContent('manager is busy'); expect(document.body.textContent).not.toContain('/private/secret'); expect(vi.mocked(request).mock.calls.filter(([route]) => route === '/security/cves/sync')).toHaveLength(1);
    });
});
