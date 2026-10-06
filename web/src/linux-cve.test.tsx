import { act, cleanup, fireEvent, render, renderHook, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, AUTH_REQUIRED_EVENT, abortProtectedRequests, request } from './api';
import { useOperator } from './auth';
import { useLinuxCVE } from './linux-cve-resource';
import { setLocale } from './i18n';
import { LinuxCVEPanel } from './linux-cve';
import { LINUX_CVE_BUNDLE_BYTES, LINUX_CVE_VIEW_BYTES } from './linux-cve-types';
import { linuxCVEDeviceId as id, linuxCVEView, emptyLinuxCVEView, incompleteLinuxCVEView, missingLinuxCVEView, staleLinuxCVEView, unavailableLinuxCVEView, unassessedLinuxCVEView } from './linux-cve-fixtures';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const writeSession = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'fixture-token', serverNow: '2026-10-05T07:00:00Z', expiresAt: '2026-10-05T08:00:00Z', expiresInSeconds: 3600, loginMode: 'shared', actorId: null, capabilities: ['read'] };
const operator: NonNullable<ReturnType<typeof useOperator>> = { hasExplicitMetadata: true, loginMode: 'shared', actorId: null, capabilities: ['read'], mode: 'lan' as const, authenticated: true, expiresAt: '2026-10-05T08:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
const path = `/devices/${id}/security/cves`;
function defer<T>() { let resolve!: (v: T) => void; return { promise: new Promise<T>(done => { resolve = done; }), resolve }; }
const flush = () => act(async () => { await Promise.resolve(); await Promise.resolve(); });
async function show(view = linuxCVEView()) { vi.mocked(request).mockResolvedValue(view); if (view.report?.continuation.state === 'pending') vi.mocked(request).mockResolvedValueOnce(view).mockReturnValue(new Promise(() => {})); const rendered = render(<LinuxCVEPanel deviceId={id} sessionKey="one"/>); await screen.findByText('Limited coverage'); return rendered; }
function choose(file = new File(['{"schemaVersion":"first","schemaVersion":"second"}'], 'private-file-name.json')) { fireEvent.click(screen.getByText('Manual JSON bundle import')); fireEvent.change(screen.getByLabelText('Choose JSON bundle'), { target: { files: [file] } }); return file; }
beforeEach(() => { setLocale('en', false); vi.mocked(request).mockReset(); vi.mocked(useOperator).mockReturnValue(operator); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('Linux CVE warnings panel', () => {
    it.each([
        ['named read', { loginMode: 'named' as const, actorId: 'operator_0123456789abcdef0123456789abcdef', capabilities: ['read'] as const }],
        ['named maintenance', { loginMode: 'named' as const, actorId: 'operator_0123456789abcdef0123456789abcdef', capabilities: ['read', 'plan_updates', 'execute_updates', 'restart_service'] as const }],
        ['legacy display defaults', { hasExplicitMetadata: false }],
        ['missing metadata indicator', { hasExplicitMetadata: undefined }],
        ['missing capabilities', { capabilities: undefined }],
    ])('keeps CVEs readable without feed-write controls for %s', async (_name, metadata) => {
        vi.mocked(useOperator).mockReturnValue({ ...operator, ...metadata }); await show();
        expect(screen.getByRole('article')).toBeVisible();
        expect(screen.getByRole('button', { name: 'Refresh assessment' })).toBeEnabled();
        expect(screen.queryByRole('button', { name: 'Update security data' })).not.toBeInTheDocument();
        expect(screen.queryByText('Manual JSON bundle import')).not.toBeInTheDocument();
        expect(screen.queryByLabelText('Choose JSON bundle')).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Refresh assessment' })); await screen.findByRole('article');
        expect(vi.mocked(request).mock.calls.every(([route, init]) => route === path && !init?.method)).toBe(true);
    });
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
        Object.assign(view.report!.coverage, { totalCheckCount: 2, completedCheckCount: 2, comparisonCount: 2, matchedFindingCount: 2 });
        await show(view); expect(screen.getAllByRole('article')).toHaveLength(1); expect(screen.getByText('Package warnings').previousElementSibling).toHaveTextContent('1'); expect(screen.getByText('Matched version rows')).not.toBeVisible(); fireEvent.click(screen.getByText('Data sources and coverage')); expect(screen.getByText('Matched version rows').nextElementSibling).toHaveTextContent('2');
        expect(screen.getByText('2:1.0-0', { selector: 'dd' })).toBeVisible(); expect(screen.getByText('2:1.0-3')).toBeVisible();
    });
    it.each(['feed_missing', 'inventory_unavailable', 'not_configured', 'unsupported'] as const)('does not present unknown %s state as zero warnings', async status => {
        const view = missingLinuxCVEView(); view.status = status; if (status === 'inventory_unavailable' || status === 'not_configured') view.inventory = null;
        vi.mocked(request).mockResolvedValue(view); render(<LinuxCVEPanel deviceId={id}/>); expect(await screen.findByText('Warnings unavailable')).toBeVisible(); expect(screen.queryByText(/No package\/version matches/)).not.toBeInTheDocument(); expect(screen.queryByRole('article')).not.toBeInTheDocument();
    });
    it('distinguishes evaluated empty output and stale retained matches', async () => {
        const empty = emptyLinuxCVEView(); const rendered = await show(empty); expect(screen.getByText(/No package\/version matches/)).toBeVisible(); expect(screen.getByText('Package warnings').previousElementSibling).toHaveTextContent('0');
        rendered.unmount(); await show(staleLinuxCVEView()); expect(screen.getByText(/Old data: these matches describe earlier snapshots/)).toBeVisible(); expect(screen.getByRole('article')).toBeVisible(); expect(screen.getByText('3 d · Stale')).toBeVisible();
    });
    it.each([
        ['en', '1 advisory record has a data or comparison gap.', 'Some published-fix versions are unsupported. Those records could not be fully evaluated.', 'Data sources and coverage'],
        ['de', '1 Sicherheitshinweis mit Daten- oder Vergleichslücke.', 'Einige veröffentlichte Fix-Versionen werden nicht unterstützt. Die zugehörigen Einträge konnten nicht vollständig bewertet werden.', 'Datenquellen und Abdeckung'],
    ] as const)('shows zero matches with an explicit unassessed record warning in %s', async (locale, warning, reason, details) => {
        setLocale(locale, false); vi.mocked(request).mockResolvedValue(unassessedLinuxCVEView()); render(<LinuxCVEPanel deviceId={id}/>);
        expect(await screen.findByText(warning)).toBeVisible(); expect(screen.queryByRole('article')).not.toBeInTheDocument();
        expect(screen.getByText(warning).closest('.linux-cve-summary')!.querySelector('strong')).toHaveTextContent('0');
        expect(screen.getByText(reason)).not.toBeVisible(); fireEvent.click(screen.getByText(details)); expect(screen.getByText(reason)).toBeVisible();
    });
    it('keeps completed vendor gaps exact when binary details are omitted', async () => {
        const view = linuxCVEView(); view.inventory!.rowCount = 1396;
        const row = view.report!.findings[0]; view.report!.findings = Array.from({ length: 6 }, (_, index) => ({ ...structuredClone(row), cveId: `CVE-2026-${999990 + index}`, advisoryUrl: `https://security-tracker.debian.org/tracker/CVE-2026-${999990 + index}`, binariesTruncated: true }));
        view.report!.unassessedRecordCount = 627; view.report!.feed!.recordCount = 633; view.feeds.snapshots[0].recordCount = 633;
        view.report!.reasonCodes.push('vendor_fixed_version_unsupported', 'binary_limit_exceeded'); view.report!.truncated = true;
        Object.assign(view.report!.coverage, { totalCheckCount: 633, completedCheckCount: 633, matchedFindingCount: 6, matchedWarningCount: 6, unassessedReasons: [{ reason: 'vendor_fixed_version_unsupported', count: 627 }] });
        await show(view); expect(screen.getByText('627 advisory records have data or comparison gaps.')).toBeVisible(); expect(screen.getByText('Package warnings').previousElementSibling).toHaveTextContent(/^6$/); expect(screen.getAllByRole('article')).toHaveLength(6);
        expect(screen.queryByRole('alert')).not.toBeInTheDocument(); expect(screen.queryByText(/lower bound|At least|Processing incomplete/)).not.toBeInTheDocument();
        expect(screen.getByText('Completed / planned checks')).not.toBeVisible(); expect(screen.getByText('Received dpkg rows')).not.toBeVisible();
        fireEvent.click(screen.getByText('Data sources and coverage'));
        expect(screen.getByText('Completed / planned checks').nextElementSibling).toHaveTextContent('633 / 633'); expect(screen.getByText('Received dpkg rows').nextElementSibling).toHaveTextContent('1,396');
        expect(screen.getByRole('list', { name: 'Unassessed records by reason' })).toHaveTextContent('627'); expect(screen.getByText(/Display details were omitted/)).toBeVisible();
    });
    it.each([
        ['en', 'Processing incomplete:', '17 checks pending.', 'Checks continue automatically', 'Data sources and coverage'],
        ['de', 'Verarbeitung unvollständig:', '17 Prüfungen ausstehend.', 'Prüfungen laufen automatisch weiter', 'Datenquellen und Abdeckung'],
    ] as const)('shows a compact actionable processing alert with accurate pending checks in %s', async (locale, title, pending, action, details) => {
        setLocale(locale, false); vi.mocked(request).mockResolvedValueOnce(incompleteLinuxCVEView()).mockReturnValue(new Promise(() => {})); render(<LinuxCVEPanel deviceId={id}/>);
        const alert = await screen.findByText(new RegExp(title)); expect(alert).toHaveTextContent(title); expect(alert).toHaveTextContent(pending); expect(alert).toHaveTextContent(action);
        expect(screen.getByRole('article')).toBeVisible(); expect(screen.getByLabelText(locale === 'en' ? 'At least 1' : 'Mindestens 1')).toHaveTextContent('≥ 1');
        expect(screen.queryByText(/advisory records? (?:has|have) (?:a )?data or comparison gap/)).not.toBeInTheDocument();
        const disclosure = screen.getByText(details).closest('details')!; expect(disclosure).not.toHaveAttribute('open');
        fireEvent.click(screen.getByText(details)); expect(disclosure).toHaveAttribute('open');
    });
    it('keeps a blocked saved assessment explicit without automatic retries', async () => {
        const view = incompleteLinuxCVEView(); view.report!.continuation.state = 'blocked'; view.report!.continuation.advancedCheckCount = 0;
        await show(view); expect(screen.getByRole('alert')).toHaveTextContent('Processing cannot advance');
        expect(screen.getByText(/Refresh to recheck the saved assessment/)).toBeVisible(); expect(request).toHaveBeenCalledTimes(1);
    });
    it('uses lower bounds for vendor gaps only while checks remain pending', async () => {
        const view = incompleteLinuxCVEView(); view.report!.unassessedRecordCount = 2; view.report!.reasonCodes.push('vendor_fixed_version_unsupported');
        view.report!.coverage.unassessedReasons = [{ reason: 'vendor_fixed_version_unsupported', count: 2 }];
        await show(view); expect(screen.getByText('At least 2 advisory records have data or comparison gaps.')).toBeVisible(); expect(screen.getByText('Package warnings').previousElementSibling).toHaveTextContent('≥ 1');
        expect(screen.getByText(/Processing incomplete:/)).toHaveTextContent('17 checks pending.');
    });
    it('does not claim checked records or an evaluated zero when processing is incomplete', async () => {
        const view = incompleteLinuxCVEView(); view.report!.findings = []; view.report!.coverage.matchedFindingCount = 0; view.report!.coverage.matchedWarningCount = 0;
        await show(view); expect(screen.getByText('No matches found so far. Checks remain pending.')).toBeVisible();
        expect(screen.queryByText(/Planned checks finished|No package\/version matches in the loaded records/)).not.toBeInTheDocument();
        expect(screen.getByText('Package warnings').previousElementSibling).toHaveTextContent('≥ 0');
    });
    it.each([false, true])('uses total warning counts when matched rows are omitted (all=%s)', async all => {
        const view = linuxCVEView(); view.report!.truncated = true; view.report!.reasonCodes.push('finding_limit_exceeded');
        view.report!.feed!.recordCount = 110; view.feeds.snapshots[0].recordCount = 110;
        Object.assign(view.report!.coverage, { totalCheckCount: 110, completedCheckCount: 110, matchedFindingCount: 110, matchedWarningCount: 110 });
        if (all) view.report!.findings = [];
        await show(view); expect(screen.getByText('Package warnings').previousElementSibling).toHaveTextContent(/^110$/);
        expect(screen.getByText(all ? 'Warning details were omitted from this response.' : 'Some warning cards are omitted from this response.')).toBeVisible();
        expect(screen.queryByText(/No package\/version matches|At least|lower bound/)).not.toBeInTheDocument(); expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });
    it('distinguishes omitted versions within a displayed warning from omitted warning cards', async () => {
        const view = linuxCVEView(); view.inventory!.rowCount = 2; view.report!.truncated = true; view.report!.reasonCodes.push('response_byte_limit_exceeded');
        Object.assign(view.report!.coverage, { totalCheckCount: 2, completedCheckCount: 2, matchedFindingCount: 2 });
        await show(view); expect(screen.getByText('Some matched version details are omitted.')).toBeVisible(); expect(screen.queryByText('Some warning cards are omitted from this response.')).not.toBeInTheDocument();
        expect(screen.getByText('Package warnings').previousElementSibling).toHaveTextContent(/^1$/);
    });
    it('discloses package gaps compactly and keeps their breakdown collapsed', async () => {
        const view = emptyLinuxCVEView(); view.inventory!.rowCount = 3; view.report!.skippedPackageCount = 3; view.report!.evaluatedSourceCount = 0;
        view.report!.continuation.advancedCheckCount = 0; Object.assign(view.report!.coverage, { totalCheckCount: 0, completedCheckCount: 0, comparisonCount: 0, packageGaps: { installationIncomplete: 1, nonstandardVersion: 1, sourceMissing: 1 } });
        view.report!.reasonCodes.push('package_installation_incomplete', 'nonstandard_package_version', 'source_package_not_in_import');
        await show(view); expect(screen.getByText('3 package rows could not be assessed.')).toBeVisible(); expect(screen.queryByRole('alert')).not.toBeInTheDocument();
        expect(screen.getByText('Rows without matching-release records')).not.toBeVisible(); fireEvent.click(screen.getByText('Data sources and coverage'));
        for (const label of ['Incomplete installation rows', 'Nonstandard version rows', 'Rows without matching-release records']) expect(screen.getByText(label).nextElementSibling).toHaveTextContent(/^1$/);
        expect(screen.getByText('A missing vendor record does not mean the package is safe.')).toBeVisible();
    });
    it('keeps zero unavailable coverage distinct from incomplete active processing', async () => {
        vi.mocked(request).mockResolvedValue(unavailableLinuxCVEView()); render(<LinuxCVEPanel deviceId={id}/>);
        expect(await screen.findByText('Warnings unavailable')).toBeVisible(); expect(screen.queryByRole('alert')).not.toBeInTheDocument();
        expect(screen.queryByText(/No package\/version matches|Processing incomplete/)).not.toBeInTheDocument();
    });
    it('omits the unassessed warning when the count is zero', async () => {
        await show(); expect(screen.queryByText(/advisory records? (?:has|have) (?:a )?data or comparison gap/)).not.toBeInTheDocument();
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
    it.each(['sync', 'import'] as const)('retains a preflight denial across read refresh for %s', async kind => {
        await show(); if (kind === 'import') choose();
        vi.mocked(request).mockImplementation(async route => route === '/auth/session' ? { ...writeSession, loginMode: 'named', actorId: 'operator_0123456789abcdef0123456789abcdef' } : linuxCVEView());
        fireEvent.click(screen.getByRole('button', { name: kind === 'sync' ? 'Update security data' : 'Import bundle' }));
        expect(await screen.findByRole('alert')).toHaveTextContent('Access to update security data could not be confirmed');
        expect(document.body.textContent).not.toContain('The data update was not confirmed');
        expect(screen.queryByText('Selected bundle')).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Refresh assessment' })); await screen.findByRole('article');
        expect(screen.queryByRole('button', { name: 'Update security data' })).not.toBeInTheDocument();
        expect(screen.queryByText('Manual JSON bundle import')).not.toBeInTheDocument();
        expect(vi.mocked(request).mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
    });
    it.each(['sync', 'import'] as const)('rejects a replacement shared session before %s', async kind => {
        await show(); if (kind === 'import') choose();
        vi.mocked(request).mockResolvedValue({ ...writeSession, expiresAt: '2026-10-05T09:00:00Z' });
        fireEvent.click(screen.getByRole('button', { name: kind === 'sync' ? 'Update security data' : 'Import bundle' }));
        expect(await screen.findByRole('alert')).toHaveTextContent('Access to update security data could not be confirmed');
        expect(document.body.textContent).not.toContain('The data update was not confirmed');
        expect(vi.mocked(request).mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
    });
    it('keeps missing fresh metadata ineligible for writes after a read refresh', async () => {
        await show();
        const { loginMode: _mode, actorId: _actor, capabilities: _capabilities, ...legacy } = writeSession;
        vi.mocked(request).mockImplementation(async route => route === '/auth/session' ? legacy : linuxCVEView());
        fireEvent.click(screen.getByRole('button', { name: 'Update security data' }));
        expect(await screen.findByRole('alert')).toHaveTextContent('Access to update security data could not be confirmed');
        fireEvent.click(screen.getByRole('button', { name: 'Refresh assessment' })); await screen.findByRole('article');
        expect(screen.queryByRole('button', { name: 'Update security data' })).not.toBeInTheDocument();
        expect(screen.queryByText('Manual JSON bundle import')).not.toBeInTheDocument();
        expect(vi.mocked(request).mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
        expect(document.body.textContent).not.toContain('The data update was not confirmed');
    });
    it('treats explicit POST permission denial as rejected admission without an uncertain-save notice', async () => {
        await show();
        vi.mocked(request).mockImplementation(async route => { if (route === '/auth/session') return writeSession; throw new APIError('private reason', 403); });
        fireEvent.click(screen.getByRole('button', { name: 'Update security data' }));
        expect(await screen.findByRole('alert')).toHaveTextContent('Access to update security data could not be confirmed');
        expect(document.body.textContent).not.toContain('The data update was not confirmed'); expect(document.body.textContent).not.toContain('private reason');
        expect(screen.queryByRole('button', { name: 'Update security data' })).not.toBeInTheDocument();
        expect(vi.mocked(request).mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
    });
    it('discards a selected bundle and hides controls on permission loss without blocking reads', async () => {
        const rendered = await show(); choose();
        vi.mocked(useOperator).mockReturnValue({ ...operator, loginMode: 'named', actorId: 'operator_0123456789abcdef0123456789abcdef' });
        rendered.rerender(<LinuxCVEPanel deviceId={id} sessionKey="one"/>);
        expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('Operator access changed'); expect(screen.queryByText(/Selected bundle/)).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Update security data' })).not.toBeInTheDocument();
        vi.mocked(useOperator).mockReturnValue(operator); rendered.rerender(<LinuxCVEPanel deviceId={id} sessionKey="one"/>);
        fireEvent.click(screen.getByRole('button', { name: 'Refresh assessment' })); await screen.findByRole('article');
        fireEvent.click(screen.getByText('Manual JSON bundle import')); expect(screen.getByRole('button', { name: 'Import bundle' })).toBeDisabled();
        expect(request).toHaveBeenCalledTimes(2);
    });
    it.each(['permission', 'pagehide', 'timeout'] as const)('does not label an undispatched preflight as uncertain after %s', async transition => {
        vi.useFakeTimers(); vi.mocked(request).mockResolvedValue(linuxCVEView());
        const rendered = render(<LinuxCVEPanel deviceId={id} sessionKey="one"/>); await flush();
        const preflight = defer<unknown>(); vi.mocked(request).mockReturnValue(preflight.promise);
        fireEvent.click(screen.getByRole('button', { name: 'Update security data' }));
        const signal = vi.mocked(request).mock.calls.at(-1)![1]!.signal as AbortSignal;
        if (transition === 'permission') { vi.mocked(useOperator).mockReturnValue({ ...operator, hasExplicitMetadata: false }); rendered.rerender(<LinuxCVEPanel deviceId={id} sessionKey="one"/>); }
        else if (transition === 'pagehide') act(() => window.dispatchEvent(new Event('pagehide')));
        else await act(async () => vi.advanceTimersByTimeAsync(60000));
        expect(signal.aborted).toBe(true);
        await act(async () => preflight.resolve(writeSession));
        expect(vi.mocked(request).mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
        expect(document.body.textContent).not.toContain('The data update was not confirmed');
        expect(screen.queryByText('Debian security data updated in the local manager.')).not.toBeInTheDocument();
    });
    it('keeps a sent update uncertain and suppresses late success after permission loss', async () => {
        const rendered = await show(), post = defer<unknown>();
        vi.mocked(request).mockImplementation(async route => route === '/auth/session' ? writeSession : post.promise);
        fireEvent.click(screen.getByRole('button', { name: 'Update security data' }));
        await waitFor(() => expect(vi.mocked(request).mock.calls.some(([, init]) => init?.method === 'POST')).toBe(true));
        const signal = vi.mocked(request).mock.calls.at(-1)![1]!.signal as AbortSignal;
        vi.mocked(useOperator).mockReturnValue({ ...operator, hasExplicitMetadata: false }); rendered.rerender(<LinuxCVEPanel deviceId={id} sessionKey="one"/>);
        expect(signal.aborted).toBe(true); expect(screen.getByRole('status')).toHaveTextContent('The data update was not confirmed');
        await act(async () => post.resolve(linuxCVEView(true).feeds));
        expect(screen.queryByText('Debian security data updated in the local manager.')).not.toBeInTheDocument();
        expect(screen.queryByRole('article')).not.toBeInTheDocument();
        expect(vi.mocked(request).mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
    });
    it.each([
        ['auth event', false], ['auth epoch', false], ['auth event', true], ['auth epoch', true],
    ] as const)('retains uncertainty only after dispatch on %s (sent=%s)', async (transition, sent) => {
        vi.useFakeTimers(); vi.mocked(request).mockResolvedValue(linuxCVEView());
        render(<LinuxCVEPanel deviceId={id}/>); await flush();
        const pending = defer<unknown>();
        vi.mocked(request).mockImplementation(async route => route === '/auth/session' && sent ? writeSession : pending.promise);
        fireEvent.click(screen.getByRole('button', { name: 'Update security data' })); await flush();
        expect(vi.mocked(request).mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(sent ? 1 : 0);
        const signal = vi.mocked(request).mock.calls.at(-1)![1]!.signal as AbortSignal;
        act(() => { if (transition === 'auth event') window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)); else abortProtectedRequests(); });
        await act(async () => vi.advanceTimersByTimeAsync(1000));
        expect(signal.aborted).toBe(true); expect(screen.getByRole('alert')).toHaveTextContent('session has ended');
        if (sent) expect(screen.getByRole('status')).toHaveTextContent('The data update was not confirmed');
        else expect(screen.queryByRole('status')).not.toBeInTheDocument();
        await act(async () => pending.resolve(sent ? linuxCVEView(true).feeds : writeSession));
        expect(screen.queryByText('Debian security data updated in the local manager.')).not.toBeInTheDocument();
        expect(screen.queryByRole('article')).not.toBeInTheDocument();
        expect(vi.mocked(request).mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(sent ? 1 : 0);
    });
    it('does not let retained callbacks select or write after the latest guard changes', async () => {
        vi.mocked(request).mockResolvedValue(linuxCVEView());
        const hook = renderHook(({ allowed }) => useLinuxCVE(id, allowed, operator.expiresAt), { initialProps: { allowed: true } });
        await waitFor(() => expect(hook.result.current.view).not.toBeNull());
        const held = hook.result.current, file = new File(['{}'], 'private.json');
        act(() => held.selectFile(file)); expect(hook.result.current.selectedBytes).toBe(2);
        hook.rerender({ allowed: false }); expect(hook.result.current.selectedBytes).toBeNull();
        await act(async () => { held.selectFile(file); await held.importSelected(); await held.sync(); });
        expect(hook.result.current.selectedBytes).toBeNull(); expect(request).toHaveBeenCalledTimes(1);
    });
    it('rejects held callbacks and a deferred old preflight after the session scope changes', async () => {
        vi.mocked(request).mockResolvedValue(linuxCVEView());
        const hook = renderHook(({ expiry }) => useLinuxCVE(id, true, expiry), { initialProps: { expiry: operator.expiresAt } });
        await waitFor(() => expect(hook.result.current.view).not.toBeNull());
        const held = hook.result.current, preflight = defer<unknown>();
        vi.mocked(request).mockReturnValue(preflight.promise); act(() => { void held.sync(); });
        const signal = vi.mocked(request).mock.calls.at(-1)![1]!.signal as AbortSignal;
        hook.rerender({ expiry: '2026-10-05T09:00:00Z' }); expect(signal.aborted).toBe(true);
        await act(async () => preflight.resolve(writeSession));
        vi.mocked(request).mockResolvedValue(linuxCVEView()); await act(async () => hook.result.current.load());
        const reads = vi.mocked(request).mock.calls.length;
        await act(async () => { held.selectFile(new File(['{}'], 'private.json')); await held.importSelected(); await held.sync(); });
        expect(hook.result.current.selectedBytes).toBeNull(); expect(request).toHaveBeenCalledTimes(reads);
        expect(hook.result.current.notice).not.toBe('uncertain');
        expect(vi.mocked(request).mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
    });
    it('remounts on replacement session expiry even with an explicit session key', async () => {
        const rendered = await show(); choose();
        vi.mocked(useOperator).mockReturnValue({ ...operator, expiresAt: '2026-10-05T09:00:00Z' });
        rendered.rerender(<LinuxCVEPanel deviceId={id} sessionKey="one"/>); await screen.findByRole('article');
        fireEvent.click(screen.getByText('Manual JSON bundle import')); expect(screen.getByRole('button', { name: 'Import bundle' })).toBeDisabled();
        expect(vi.mocked(request).mock.calls.filter(([route]) => route === path)).toHaveLength(2);
    });
    it('syncs only after clicking, posts fixed empty JSON and then rereads', async () => {
        await show(); vi.mocked(request).mockImplementation(async route => route === '/auth/session' ? writeSession : route === '/security/cves/sync' ? linuxCVEView(true).feeds : linuxCVEView(true)); fireEvent.click(screen.getByRole('button', { name: 'Update security data' })); await screen.findByText('Debian security data updated in the local manager.'); await screen.findByRole('article');
        expect(vi.mocked(request).mock.calls.filter(([route]) => route === '/security/cves/sync')).toHaveLength(1); expect(request).toHaveBeenCalledWith('/security/cves/sync', expect.objectContaining({ method: 'POST', body: '{}', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': 'fixture-token' }, signal: expect.any(AbortSignal) }), LINUX_CVE_VIEW_BYTES);
    });
    it('selects a file without transmitting and sends original bytes only after import', async () => {
        await show(); const file = choose(); expect(request).toHaveBeenCalledTimes(1); expect(document.body.textContent).not.toContain(file.name);
        vi.mocked(request).mockImplementation(async route => route === '/auth/session' ? writeSession : route === '/security/cves/import' ? linuxCVEView().feeds : linuxCVEView()); fireEvent.click(screen.getByRole('button', { name: 'Import bundle' })); await screen.findByText('Bundle imported into the local manager.'); await screen.findByRole('article');
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
        await show(); const pending = defer<unknown>(); vi.mocked(request).mockImplementation(async route => route === '/auth/session' ? writeSession : route === '/security/cves/sync' ? pending.promise : linuxCVEView()); fireEvent.click(screen.getByRole('button', { name: 'Update security data' })); await waitFor(() => expect(vi.mocked(request).mock.calls.some(([route]) => route === '/security/cves/sync')).toBe(true)); const signal = vi.mocked(request).mock.calls.find(([route]) => route === '/security/cves/sync')![1]!.signal as AbortSignal; act(() => window.dispatchEvent(new Event('pagehide'))); expect(signal.aborted).toBe(true); await act(async () => pending.resolve(linuxCVEView(true).feeds)); expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(screen.getByRole('status')).toHaveTextContent('not confirmed'); act(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }))); await screen.findByRole('article'); expect(vi.mocked(request).mock.calls.filter(([route]) => route === '/security/cves/sync')).toHaveLength(1);
    });
    it('enforces the 60-second sync deadline without resubmitting', async () => {
        vi.useFakeTimers(); const pending = defer<unknown>(); vi.mocked(request).mockImplementation(async route => route === '/auth/session' ? writeSession : route === '/security/cves/sync' ? pending.promise : linuxCVEView()); render(<LinuxCVEPanel deviceId={id}/>); await flush();
        fireEvent.click(screen.getByRole('button', { name: 'Update security data' })); await flush(); const signal = vi.mocked(request).mock.calls.find(([route]) => route === '/security/cves/sync')![1]!.signal as AbortSignal;
        await act(async () => vi.advanceTimersByTimeAsync(60000)); expect(signal.aborted).toBe(true); expect(screen.getByRole('alert')).toHaveTextContent('not confirmed'); await act(async () => pending.resolve(linuxCVEView(true).feeds)); expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(vi.mocked(request).mock.calls.filter(([route]) => route === '/security/cves/sync')).toHaveLength(1);
    });
    it('clears file selection when disclosure closes without sending', async () => {
        await show(); choose(); const details = screen.getByText('Manual JSON bundle import').closest('details')!; details.open = false; fireEvent(details, new Event('toggle')); await flush(); details.open = true; fireEvent(details, new Event('toggle')); await flush(); expect(screen.getByRole('button', { name: 'Import bundle' })).toBeDisabled(); expect(request).toHaveBeenCalledTimes(1);
    });
    it('reports write errors without leaking server detail or retrying writes', async () => {
        await show(); vi.mocked(request).mockImplementation(async route => { if (route === '/auth/session') return writeSession; throw new APIError('/private/secret', 429, 'storage_busy'); }); fireEvent.click(screen.getByRole('button', { name: 'Update security data' })); expect(await screen.findByRole('alert')).toHaveTextContent('manager is busy'); expect(document.body.textContent).not.toContain('/private/secret'); expect(vi.mocked(request).mock.calls.filter(([route]) => route === '/security/cves/sync')).toHaveLength(1);
    });
});
