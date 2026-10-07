import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, AUTH_REQUIRED_EVENT, request } from './api';
import { AuthBoundary } from './auth';
import type { OperatorSession } from './auth';
import { DeviceDetail } from './details';
import { setLocale } from './i18n';
import { PackageObservationsPanel } from './package-observations';
import { effectivePackageStatus, packageSnapshotVisible, validPackageSnapshot, validPackageView } from './package-observations-types';
import type { PackageRow, PackageView } from './package-observations-types';
import type { Device, Metric } from './types';

// Independent synthetic operator DTOs; no package source, browser or network access.
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
const selectedId = 'agent_independent_review';
const disclosure = 'Release and source-package observations';
const timestamp = '2026-10-04T02:00:10Z';
const session: OperatorSession = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'synthetic-review-token', serverNow: timestamp, expiresAt: '2026-10-04T02:30:00Z', expiresInSeconds: 1800 };
const metric: Metric = { value: null, unit: '%', quality: 'unknown', source: 'Synthetic review fixture', collectedAt: '0001-01-01T00:00:00Z' };
function device(id = selectedId): Device { return { id, name: 'Synthetic review device', platform: 'linux', os: 'Synthetic OS', site: 'Review', group: 'Review', ip: null, status: 'unknown', source: 'lan', synthetic: false, lastSeen: '0001-01-01T00:00:00Z', agentVersion: 'fixture', cpu: metric, memory: metric, disk: metric, uptime: '', tags: [], capabilities: [], evidence: [], trend: [], caseIds: [] }; }
function row(name = 'review-binary', architecture = 'amd64'): PackageRow { return { name, version: '7:2.0~pre1-3+b8', architecture, sourcePackage: name, sourceVersion: '7:2.0~pre1-3+b8', sourceMapping: 'binary-default', installState: 'installed' }; }
function view(): PackageView { return { schemaVersion: 'tracebolt.package-view.v1', deviceId: selectedId, status: 'fresh', serverNow: timestamp, receivedAt: '2026-10-04T02:00:05Z', sequence: 7, maxAgeSeconds: 120, snapshot: { schemaVersion: 'tracebolt.linux-packages.v1', scope: 'agent-visible-dpkg', generationId: `sample_${'7'.repeat(32)}`, collectedAt: '2026-10-04T02:00:00Z', durationMs: 0, release: { quality: 'healthy', reason: 'none', fields: { id: 'debian', versionId: '13', versionCodename: 'trixie' } }, inventory: { quality: 'healthy', reason: 'none', complete: true, truncated: false, countExact: true, observedCount: 1, installedCount: 1, items: [row()] } } }; }
function defer<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }
let currentSession: OperatorSession, packageResponse: PackageView;
function response(path: string): unknown {
    if (path === '/auth/session') return currentSession;
    if (path === `/devices/${selectedId}`) return device();
    if (path === `/devices/${selectedId}/packages`) return packageResponse;
    throw new Error('Unexpected synthetic review route');
}
function packageCalls() { return vi.mocked(request).mock.calls.filter(([path]) => path.endsWith('/packages')); }
async function openPanel() {
    const rendered = render(<AuthBoundary><PackageObservationsPanel deviceId={selectedId}/></AuthBoundary>);
    fireEvent.click(await screen.findByRole('button', { name: disclosure }));
    return rendered;
}
async function loadedPanel() { const rendered = await openPanel(); await screen.findByRole('table'); return rendered; }
beforeEach(() => {
    localStorage.clear(); sessionStorage.clear(); setLocale('en', false);
    currentSession = { ...session }; packageResponse = view();
    vi.mocked(request).mockReset().mockImplementation(async path => response(path));
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('independent manager DTO invariants', () => {
    it('keeps full-source counts when the bounded export contains no selected rows', () => {
        const value = view(); Object.assign(value.snapshot!.inventory, { reason: 'byte_limit', complete: false, truncated: true, observedCount: 12, installedCount: 9, items: [] });
        expect(validPackageView(value, selectedId)).toBe(true);
        Object.assign(value.snapshot!.inventory, { observedCount: 0, installedCount: 0 }); expect(validPackageView(value, selectedId)).toBe(false);
    });
    it('checks feasible omitted installed rows without collapsing incomplete rows', () => {
        const value = view(); Object.assign(value.snapshot!.inventory, { reason: 'item_limit', complete: false, truncated: true, observedCount: 3, installedCount: 1, items: [{ ...row(), installState: 'incomplete' }] });
        expect(validPackageView(value, selectedId)).toBe(true);
        value.snapshot!.inventory.installedCount = 3; expect(validPackageView(value, selectedId)).toBe(false);
    });
    it('preserves separately sorted architectures and rejects duplicate binary identities', () => {
        const value = view(); Object.assign(value.snapshot!.inventory, { observedCount: 2, installedCount: 2, items: [row('same-binary', 'all'), row('same-binary', 'arm64')] });
        expect(validPackageView(value, selectedId)).toBe(true);
        value.snapshot!.inventory.items.reverse(); expect(validPackageView(value, selectedId)).toBe(false);
        value.snapshot!.inventory.items = [row(), row()]; expect(validPackageView(value, selectedId)).toBe(false);
    });
    it('never derives a source version by stripping a binNMU suffix', () => {
        const value = view(); expect(validPackageView(value, selectedId)).toBe(true);
        value.snapshot!.inventory.items[0].sourceVersion = '7:2.0~pre1-3'; expect(validPackageView(value, selectedId)).toBe(false);
        value.snapshot!.inventory.items[0].sourceMapping = 'source-field'; expect(validPackageView(value, selectedId)).toBe(true);
    });
    it.each(['receivedAt', 'collectedAt'] as const)('rejects one-nanosecond future %s across a seconds rollover', field => {
        const value = view(); value.serverNow = '2026-10-04T02:00:09.999999999Z';
        if (field === 'receivedAt') value.receivedAt = '2026-10-04T02:00:10Z'; else value.snapshot!.collectedAt = '2026-10-04T02:00:10Z';
        expect(validPackageView(value, selectedId)).toBe(false);
    });
    it('honors exact nanosecond retention and fresh-window edges', () => {
        const value = view(); value.snapshot!.collectedAt = '2026-10-03T02:00:10.000000001Z'; value.status = 'stale';
        expect(validPackageView(value, selectedId)).toBe(true); expect(packageSnapshotVisible(value, 0)).toBe(true);
        expect(packageSnapshotVisible(value, 0.000001)).toBe(false);
        value.snapshot!.collectedAt = '2026-10-03T02:00:10Z'; expect(validPackageView(value, selectedId)).toBe(false);
        const fresh = view(); fresh.serverNow = '2026-10-04T02:02:00Z'; expect(validPackageView(fresh, selectedId)).toBe(true);
        expect(effectivePackageStatus(fresh, 0.000001)).toBe('stale');
    });
    it.each(['not_configured', 'awaiting', 'unavailable'] as const)('does not let %s carry previous source rows', status => {
        expect(validPackageView({ ...view(), status }, selectedId)).toBe(false);
    });
    it('keeps release source failure independent of a successful inventory', () => {
        const value = view(); value.snapshot!.release = { quality: 'denied', reason: 'permission_denied', fields: { id: null, versionId: null, versionCodename: null } };
        expect(validPackageView(value, selectedId)).toBe(true);
        value.snapshot!.release.fields.id = ''; expect(validPackageView(value, selectedId)).toBe(false);
    });
    it('rejects unsolicited source URLs, absent nullable counts and control characters', () => {
        for (const mutate of [
            (value: PackageView) => { Object.assign(value.snapshot!.inventory.items[0], { repositoryUrl: 'https://private.invalid' }); },
            (value: PackageView) => { delete (value.snapshot!.inventory as unknown as Record<string, unknown>).installedCount; },
            (value: PackageView) => { value.snapshot!.inventory.items[0].sourceVersion = '1\nprivate'; },
        ]) { const value = view(); mutate(value); expect(validPackageSnapshot(value.snapshot)).toBe(false); }
    });
});

describe('independent private UI and selected identity regressions', () => {
    it('rejects a device-detail identity different from the selected route before exposing package controls', async () => {
        vi.mocked(request).mockImplementation(async path => path === `/devices/${selectedId}` ? device('agent_other_review') : response(path));
        render(<AuthBoundary><DeviceDetail id={selectedId} onClose={() => {}} onCase={() => {}}/></AuthBoundary>);
        await screen.findByRole('alert');
        expect(screen.queryByRole('tab', { name: 'Security coverage' })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: disclosure })).not.toBeInTheDocument(); expect(packageCalls()).toHaveLength(0);
    });
    it('clears a wrong-device package response without rendering even one supplied row', async () => {
        packageResponse.deviceId = 'agent_other_review'; await openPanel();
        expect(await screen.findByRole('alert')).toHaveTextContent('unsupported or inconsistent');
        expect(screen.queryByText('review-binary')).not.toBeInTheDocument(); expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });
    it('renders an empty selected export as partial with known nonzero totals', async () => {
        Object.assign(packageResponse.snapshot!.inventory, { reason: 'byte_limit', complete: false, truncated: true, observedCount: 12, installedCount: 9, items: [] });
        await openPanel(); await screen.findByText('Partial exported inventory');
        const region = screen.getByRole('region', { name: 'Package sample' });
        expect(within(region).getByText('9')).toBeVisible(); expect(within(region).getAllByText('12')).toHaveLength(2); expect(within(region).getByText('0')).toBeVisible();
        expect(screen.queryByText(/successfully parsed source contains zero/)).not.toBeInTheDocument(); expect(screen.queryByText(/No package inventory evidence/)).not.toBeInTheDocument();
    });
    it.each(['en', 'de'] as const)('renders independent release denial and exact binary defaults in %s without links or inventory persistence', async locale => {
        packageResponse.snapshot!.release = { quality: 'denied', reason: 'permission_denied', fields: { id: null, versionId: null, versionCodename: null } };
        await loadedPanel(); const storage = vi.spyOn(Storage.prototype, 'setItem'); act(() => setLocale(locale, false));
        expect(screen.getByRole('table')).toBeVisible(); expect(screen.getAllByText('7:2.0~pre1-3+b8')).toHaveLength(2);
        expect(screen.getByText(locale === 'de' ? 'Source-Feld fehlt: Binärvorgabe' : 'Absent Source field: binary default')).toBeVisible();
        expect(screen.getByText(locale === 'de' ? 'Die Leseberechtigung für die Quelle wurde verweigert.' : 'Permission to read the source was denied.')).toBeVisible();
        expect(screen.queryByText(/Exact Debian|Exakte Debian/)).not.toBeInTheDocument(); expect(screen.queryByRole('link')).not.toBeInTheDocument(); expect(storage).not.toHaveBeenCalled();
        expect(JSON.stringify({ ...localStorage, ...sessionStorage })).not.toContain('review-binary');
        expect(document.body.textContent).not.toMatch(/(?:0|zero) (?:CVEs|updates|vulnerabilities)/i);
    });
    it('drops expansion on private-session replacement even when expiration text is unchanged', async () => {
        await loadedPanel(); act(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })));
        expect(screen.queryByRole('table')).not.toBeInTheDocument(); currentSession = { ...session, csrfToken: 'synthetic-replacement-token' };
        act(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })));
        await waitFor(() => expect(screen.getByRole('button', { name: disclosure })).toHaveAttribute('aria-expanded', 'false'));
        expect(screen.queryByText('review-binary')).not.toBeInTheDocument();
    });
    it('ignores a suspended old response after a replacement response establishes unknown source facts', async () => {
        const old = defer<PackageView>(); let count = 0;
        vi.mocked(request).mockImplementation(async path => path.endsWith('/packages') && ++count === 1 ? old.promise : response(path));
        await openPanel(); const signal = packageCalls()[0][1]!.signal!;
        act(() => window.dispatchEvent(new Event('blur'))); expect(signal.aborted).toBe(true);
        packageResponse.snapshot!.inventory = { quality: 'unknown', reason: 'source_changed', complete: false, truncated: false, countExact: false, observedCount: null, installedCount: null, items: [] };
        act(() => window.dispatchEvent(new Event('focus'))); await screen.findByText('The source changed during collection.');
        await act(async () => old.resolve(view())); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.queryByText('review-binary')).not.toBeInTheDocument();
    });
    it('does not reload a hidden view through focus or BFCache signals', async () => {
        await loadedPanel(); const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
        act(() => document.dispatchEvent(new Event('visibilitychange'))); const calls = packageCalls().length;
        await act(async () => { window.dispatchEvent(new Event('focus')); window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })); });
        expect(packageCalls()).toHaveLength(calls); expect(screen.queryByRole('table')).not.toBeInTheDocument();
        visibility.mockReturnValue('visible'); act(() => document.dispatchEvent(new Event('visibilitychange'))); await screen.findByRole('table');
    });
    it('clears rows immediately on refresh and keeps raw errors private', async () => {
        await loadedPanel(); const pending = defer<PackageView>();
        vi.mocked(request).mockImplementation(path => path.endsWith('/packages') ? pending.promise : Promise.resolve(response(path)));
        fireEvent.click(screen.getByRole('button', { name: 'Refresh package observations' })); expect(screen.queryByRole('table')).not.toBeInTheDocument();
        await act(async () => pending.resolve({ ...view(), snapshot: null })); await screen.findByRole('alert');
        vi.mocked(request).mockImplementation(async path => { if (path.endsWith('/packages')) throw new APIError('secret-path /home/operator/private-packages', 500); return response(path); });
        fireEvent.click(screen.getByRole('button', { name: 'Refresh package observations' })); await screen.findByText('Package observations could not be read. Refresh to try again.');
        expect(document.body.textContent).not.toContain('secret-path'); expect(document.body.textContent).not.toContain('private-packages');
    });
    it('makes an auth-loss lock irreversible by focus or pageshow without a new session', async () => {
        await loadedPanel(); act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); await screen.findByLabelText('Operator password');
        const calls = packageCalls().length;
        await act(async () => { window.dispatchEvent(new Event('focus')); window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })); });
        expect(packageCalls()).toHaveLength(calls); expect(screen.queryByText('review-binary')).not.toBeInTheDocument();
    });
});
