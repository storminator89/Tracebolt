import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, request } from './api';
import { AuthBoundary } from './auth';
import type { OperatorSession } from './auth';
import { DeviceDetail } from './details';
import { setLocale } from './i18n';
import type { Device, Metric } from './types';
import type { PackageView } from './package-observations-types';
import { SecurityCoveragePanel } from './security-coverage';
import { validSecurityCoverageView } from './security-coverage-types';
import type { SecurityCoverageView } from './security-coverage-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
const id = 'agent_fixture', now = '2026-10-04T00:00:10Z';
const session: OperatorSession = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'fixture-token', serverNow: now, expiresAt: '2026-10-04T00:30:00Z', expiresInSeconds: 1800 };
const metric: Metric = { value: null, unit: '%', quality: 'unknown', source: 'Synthetic fixture', collectedAt: '0001-01-01T00:00:00Z' };
function device(overrides: Partial<Device> = {}): Device { return { id, name: 'Fixture', platform: 'linux', os: 'Linux fixture', site: 'Fixture', group: 'Fixture', ip: null, status: 'unknown', source: 'lan', synthetic: false, lastSeen: '0001-01-01T00:00:00Z', agentVersion: 'fixture', cpu: metric, memory: metric, disk: metric, uptime: '', tags: [], capabilities: [], evidence: [], trend: [], caseIds: [], ...overrides }; }
function packages(): PackageView { return { schemaVersion: 'tracebolt.package-view.v1', deviceId: id, serverNow: now, status: 'fresh', maxAgeSeconds: 120, receivedAt: '2026-10-04T00:00:05Z', sequence: 1, snapshot: { schemaVersion: 'tracebolt.linux-packages.v1', scope: 'agent-visible-dpkg', generationId: `sample_${'a'.repeat(32)}`, collectedAt: '2026-10-04T00:00:00Z', durationMs: 1, release: { quality: 'healthy', reason: 'none', fields: { id: 'ubuntu', versionId: '24.04', versionCodename: 'noble' } }, inventory: { quality: 'healthy', reason: 'none', complete: true, truncated: false, countExact: true, observedCount: 1, installedCount: 1, items: [{ name: 'fixture-package', version: '1.0+b1', architecture: 'all', sourcePackage: 'fixture-package', sourceVersion: '1.0+b1', sourceMapping: 'binary-default', installState: 'installed' }] } } }; }
function coverage(): SecurityCoverageView { return { schemaVersion: 'tracebolt.security-coverage.v1', deviceId: id, serverNow: now, maxAgeSeconds: 120, receivedAt: null, collectionStatus: 'awaiting', inventory: { coverage: 'unknown', freshness: 'unknown', reportedItemCount: null, installedCount: null, observedCount: null, countExact: false, truncated: false, collectedAt: null, generationId: null, scope: 'reported-installed-binary-packages', originAssurance: 'unverified' }, catalog: { configured: false, revision: `revision_${'a'.repeat(32)}`, sha256: null, originAssurance: 'unverified', freshness: 'unknown' }, offeredUpdates: { coverage: 'unknown', offeredCount: null, reason: 'native_update_adapter_unimplemented' }, vulnerabilities: { coverage: 'unknown', affectedCves: null, reviewCandidates: null, reasonCodes: ['advisory_snapshot_unavailable', 'source_package_mapping_not_assessed', 'client_release_not_assessed', 'installed_artifact_origin_unverified'] } }; }
let currentSession: OperatorSession, currentDevice: Device;
function answer(path: string) { if (path === '/auth/session') return currentSession; if (path === `/devices/${id}`) return currentDevice; if (path.endsWith('/security')) return coverage(); if (path === `/devices/${id}/inventory/packages`) return { schemaVersion: 'tracebolt.complete-package-view.v1', deviceId: id, serverNow: now, collectionProfile: 'managed-operations-v2', status: 'not_configured', complete: null, transfer: null, failure: null }; if (path === `/devices/${id}/packages`) return packages(); throw new Error('Unexpected synthetic fixture route'); }
function detail() { return <AuthBoundary><DeviceDetail id={id} onClose={vi.fn()} onCase={vi.fn()}/></AuthBoundary>; }
async function openSecurity() { fireEvent.click(await screen.findByRole('tab', { name: 'Security coverage' })); }
async function openPackages() { await openSecurity(); fireEvent.click(await screen.findByRole('button', { name: 'Release and source-package observations' })); }
beforeEach(() => { setLocale('en', false); localStorage.clear(); sessionStorage.clear(); currentSession = { ...session }; currentDevice = device(); vi.mocked(request).mockReset().mockImplementation(async path => answer(path)); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe('package details in the authenticated device Security tab', () => {
    it('remains lazy inside the Security tab and preserves the independent inventory and coverage views', async () => {
        render(detail()); await screen.findByRole('tab', { name: 'Inventory' }); expect(vi.mocked(request).mock.calls.some(([path]) => path === `/devices/${id}/packages`)).toBe(false); await openSecurity();
        await screen.findByText('Source-package mapping is not evaluated by this assessment.'); expect(vi.mocked(request).mock.calls.some(([path]) => path === `/devices/${id}/packages`)).toBe(false);
        fireEvent.click(screen.getByRole('button', { name: 'Release and source-package observations' })); await screen.findByRole('table'); expect(screen.getByText('Absent Source field: binary default')).toBeVisible(); expect(screen.getByText('Exact Ubuntu 24.04 / Noble identifiers observed')).toBeVisible();
        expect(screen.getAllByText('1.0+b1')).toHaveLength(2); expect(screen.getByRole('heading', { name: 'CVE coverage' })).toBeVisible(); expect(screen.queryByText('Client source-package mapping is missing.')).not.toBeInTheDocument();
    });
    it.each([{ synthetic: true }, { source: 'sandbox' as const }, { source: 'local' as const }, { platform: 'windows' as const }, { platform: 'macos' as const }])('never mounts package details for ineligible device %j', async overrides => {
        currentDevice = device(overrides); render(detail()); await screen.findByRole('tab', { name: 'Overview' }); expect(screen.queryByRole('tab', { name: 'Security coverage' })).not.toBeInTheDocument(); expect(vi.mocked(request).mock.calls.some(([path]) => path === `/devices/${id}/packages`)).toBe(false);
    });
    it('allows an unknown-platform LAN identity without inferring inventory coverage', async () => { currentDevice = device({ platform: 'unknown' }); render(detail()); await openPackages(); await screen.findByRole('table'); expect(screen.getByText(/do not establish host-wide coverage/)).toBeVisible(); });
    it('never exposes package details in development mode', async () => { currentSession = { ...session, mode: 'development', authenticated: false, authenticationRequired: false, csrfToken: null, expiresAt: null, expiresInSeconds: null }; render(detail()); await screen.findByRole('tab', { name: 'Overview' }); expect(screen.queryByRole('tab', { name: 'Security coverage' })).not.toBeInTheDocument(); });
    it.each(['tab', 'auth', 'pagehide'] as const)('aborts pending package reads and suppresses late rows on %s', async transition => {
        let resolve!: (value: PackageView) => void, signal!: AbortSignal;
        vi.mocked(request).mockImplementation(async (path, options) => path === `/devices/${id}/packages` ? new Promise<PackageView>(done => { resolve = done; signal = options!.signal as AbortSignal; }) : answer(path));
        render(detail()); await openPackages(); await waitFor(() => expect(signal).toBeDefined());
        if (transition === 'tab') fireEvent.click(screen.getByRole('tab', { name: 'Overview' })); if (transition === 'auth') { act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); await screen.findByLabelText('Operator password'); } if (transition === 'pagehide') act(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })));
        expect(signal.aborted).toBe(true); await act(async () => resolve(packages())); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(document.body.textContent).not.toContain('fixture-package');
    });
    it('drops expanded details across BFCache restoration with an authenticated session replacement', async () => {
        render(detail()); await openPackages(); await screen.findByRole('table'); act(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }))); expect(screen.queryByRole('table')).not.toBeInTheDocument();
        currentSession = { ...session, csrfToken: 'replacement-token', expiresAt: '2026-10-04T00:31:00Z' }; act(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })));
        await screen.findByRole('tab', { name: 'Overview' }); expect(screen.queryByRole('table')).not.toBeInTheDocument(); await openSecurity(); expect(screen.getByRole('button', { name: 'Release and source-package observations' })).toHaveAttribute('aria-expanded', 'false');
    });
});

describe('coherent security coverage reason pair', () => {
    it('accepts v2 not-assessed and v1 unavailable pairs, configured catalog vocabulary, and rejects mixed or expanded reasons', () => {
        const value = coverage(); expect(validSecurityCoverageView(value, id)).toBe(true);
        const old = ['advisory_snapshot_unavailable', 'source_package_mapping_unavailable', 'client_release_unverified', 'installed_artifact_origin_unverified'];
        expect(validSecurityCoverageView({ ...value, vulnerabilities: { ...value.vulnerabilities, reasonCodes: old } }, id)).toBe(true);
        for (const pair of [['source_package_mapping_not_assessed', 'client_release_unverified'], ['source_package_mapping_unavailable', 'client_release_not_assessed'], ['source_package_mapping_not_assessed', 'client_release_not_assessed', 'client_release_unverified']]) expect(validSecurityCoverageView({ ...value, vulnerabilities: { ...value.vulnerabilities, reasonCodes: ['advisory_snapshot_unavailable', ...pair, 'installed_artifact_origin_unverified'] } }, id)).toBe(false);
        value.catalog.configured = true; value.catalog.sha256 = 'a'.repeat(64); value.vulnerabilities.reasonCodes[0] = 'advisory_authority_unverified'; expect(validSecurityCoverageView(value, id)).toBe(true);
    });
    it('renders German fixed not-assessed reasons and leaves offered updates and CVEs unknown', async () => {
        setLocale('de', false); render(<AuthBoundary><SecurityCoveragePanel deviceId={id}/></AuthBoundary>); await screen.findByText('Die Quellpaket-Zuordnung wird in dieser Bewertung nicht ausgewertet.'); expect(screen.getByText('Die genaue Distributionsversion des Clients wird in dieser Bewertung nicht ausgewertet.')).toBeVisible(); expect(screen.getAllByText('Unbekannt').length).toBeGreaterThanOrEqual(3); expect(document.body.textContent).not.toMatch(/0 CVEs|0 Updates/);
    });
});
