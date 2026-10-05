import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, request } from './api';
import { AuthBoundary } from './auth';
import type { OperatorSession } from './auth';
import { DeviceDetail } from './details';
import { setLocale } from './i18n';
import type { Device, Metric } from './types';
import type { PackageView } from './package-observations-types';
import type { SecurityCoverageView } from './security-coverage-types';
import { reviewView } from './advisory-review-fixtures';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
const id = 'agent_fixture', now = '2026-10-04T00:00:10Z';
const session: OperatorSession = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'fixture-token', serverNow: now, expiresAt: '2026-10-04T00:30:00Z', expiresInSeconds: 1800 };
const metric: Metric = { value: null, unit: '%', quality: 'unknown', source: 'Synthetic fixture', collectedAt: '0001-01-01T00:00:00Z' };
function device(overrides: Partial<Device> = {}): Device { return { id, name: 'Fixture', platform: 'linux', os: 'Linux fixture', site: 'Fixture', group: 'Fixture', ip: null, status: 'unknown', source: 'lan', synthetic: false, lastSeen: '0001-01-01T00:00:00Z', agentVersion: 'fixture', cpu: metric, memory: metric, disk: metric, uptime: '', tags: [], capabilities: [], evidence: [], trend: [], caseIds: [], ...overrides }; }
function packages(): PackageView { return { schemaVersion: 'tracebolt.package-view.v1', deviceId: id, serverNow: now, status: 'fresh', maxAgeSeconds: 120, receivedAt: '2026-10-04T00:00:05Z', sequence: 1, snapshot: { schemaVersion: 'tracebolt.linux-packages.v1', scope: 'agent-visible-dpkg', generationId: `sample_${'a'.repeat(32)}`, collectedAt: '2026-10-04T00:00:00Z', durationMs: 1, release: { quality: 'healthy', reason: 'none', fields: { id: 'ubuntu', versionId: '24.04', versionCodename: 'noble' } }, inventory: { quality: 'healthy', reason: 'none', complete: true, truncated: false, countExact: true, observedCount: 1, installedCount: 1, items: [{ name: 'fixture-package', version: '1.0+b1', architecture: 'all', sourcePackage: 'fixture-package', sourceVersion: '1.0+b1', sourceMapping: 'binary-default', installState: 'installed' }] } } }; }
function coverage(): SecurityCoverageView { return { schemaVersion: 'tracebolt.security-coverage.v1', deviceId: id, serverNow: now, maxAgeSeconds: 120, receivedAt: null, collectionStatus: 'awaiting', inventory: { coverage: 'unknown', freshness: 'unknown', reportedItemCount: null, installedCount: null, observedCount: null, countExact: false, truncated: false, collectedAt: null, generationId: null, scope: 'reported-installed-binary-packages', originAssurance: 'unverified' }, catalog: { configured: false, revision: `revision_${'a'.repeat(32)}`, sha256: null, originAssurance: 'unverified', freshness: 'unknown' }, offeredUpdates: { coverage: 'unknown', offeredCount: null, reason: 'native_update_adapter_unimplemented' }, vulnerabilities: { coverage: 'unknown', affectedCves: null, reviewCandidates: null, reasonCodes: ['advisory_snapshot_unavailable', 'source_package_mapping_not_assessed', 'client_release_not_assessed', 'installed_artifact_origin_unverified'] } }; }
let currentSession: OperatorSession, currentDevice: Device;
function answer(path: string) { if (path === '/auth/session') return currentSession; if (path === `/devices/${id}`) return currentDevice; if (path.endsWith('/security')) return coverage(); if (path === `/devices/${id}/inventory/packages`) return { schemaVersion: 'tracebolt.complete-package-view.v1', deviceId: id, serverNow: now, collectionProfile: 'managed-operations-v2', status: 'not_configured', complete: null, transfer: null, failure: null }; if (path === `/devices/${id}/packages`) return packages(); if (path.endsWith('/security/review')) return reviewView(); throw new Error('Unexpected synthetic fixture route'); }
function detail() { return <AuthBoundary><DeviceDetail id={id} onClose={vi.fn()} onCase={vi.fn()}/></AuthBoundary>; }
async function openSecurity() { fireEvent.click(await screen.findByRole('tab', { name: 'Security coverage' })); fireEvent.click(screen.getByText('Legacy diagnostics', { selector: 'summary' })); fireEvent.change(screen.getByLabelText('Diagnostic source'), { target: { value: 'legacy-coverage' } }); }
async function openReview() { await openSecurity(); fireEvent.click(await screen.findByRole('button', { name: 'Conditional advisory review candidates' })); }
beforeEach(() => { setLocale('en', false); localStorage.clear(); sessionStorage.clear(); currentSession = { ...session }; currentDevice = device(); vi.mocked(request).mockReset().mockImplementation(async path => answer(path)); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe('review candidates mounted in private Security tab', () => {
    it('keeps both package and review requests lazy and leaves the existing coverage unknown', async () => {
        render(detail()); await screen.findByRole('tab', { name: 'Inventory' }); expect(vi.mocked(request).mock.calls.some(([path]) => path.endsWith('/security/review'))).toBe(false); await openSecurity(); await screen.findByText('Source-package mapping is not evaluated by this assessment.'); expect(vi.mocked(request).mock.calls.some(([path]) => path.endsWith('/security/review') || path === `/devices/${id}/packages`)).toBe(false);
        fireEvent.click(screen.getByRole('button', { name: 'Conditional advisory review candidates' })); await screen.findByRole('article', { name: 'Review candidate: fixture-binary / CVE-2099-1234' }); expect(screen.getByRole('heading', { name: 'CVE coverage' })).toBeVisible(); expect(screen.queryByRole('button', { name: 'Release and source-package observations' })).not.toBeInTheDocument(); expect(vi.mocked(request).mock.calls.some(([path]) => path === `/devices/${id}/packages`)).toBe(false);
    });
    it.each([{ synthetic: true }, { source: 'sandbox' as const }, { source: 'local' as const }, { platform: 'windows' as const }, { platform: 'macos' as const }])('does not mount review UI for ineligible identity %j', async overrides => {
        currentDevice = device(overrides); render(detail()); await screen.findByRole('tab', { name: 'Overview' }); expect(screen.queryByRole('tab', { name: 'Security coverage' })).not.toBeInTheDocument(); expect(vi.mocked(request).mock.calls.some(([path]) => path.endsWith('/security/review'))).toBe(false);
    });
    it.each(['tab', 'auth', 'pagehide'] as const)('aborts pending review results on %s', async transition => {
        let resolve!: (value: unknown) => void, signal!: AbortSignal;
        vi.mocked(request).mockImplementation(async (path, options) => path.endsWith('/security/review') ? new Promise(done => { resolve = done; signal = options!.signal as AbortSignal; }) : answer(path)); render(detail()); await openReview(); await waitFor(() => expect(signal).toBeDefined());
        if (transition === 'tab') fireEvent.click(screen.getByRole('tab', { name: 'Overview' })); else if (transition === 'auth') { act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); await screen.findByLabelText('Operator password'); } else act(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })));
        expect(signal.aborted).toBe(true); await act(async () => resolve(reviewView())); expect(document.body.textContent).not.toContain('fixture-binary');
    });
    it('collapses review disclosure on BFCache authenticated session replacement', async () => {
        render(detail()); await openReview(); await screen.findByRole('article', { name: 'Review candidate: fixture-binary / CVE-2099-1234' }); act(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }))); expect(document.body.textContent).not.toContain('fixture-binary'); currentSession = { ...session, csrfToken: 'replacement-token', expiresAt: '2026-10-04T00:31:00Z' }; act(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }))); await screen.findByRole('tab', { name: 'Overview' }); await openSecurity(); expect(screen.getByRole('button', { name: 'Conditional advisory review candidates' })).toHaveAttribute('aria-expanded', 'false');
    });
});
