import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { APIError, AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { AuthBoundary } from './auth';
import type { OperatorSession } from './auth';
import { DeviceDetail } from './details';
import { setLocale } from './i18n';
import type { AIConfig } from './ai-types';
import type { Capabilities, Device, Metric, Overview } from './types';
import type { OfflineCatalogView, SecurityCoverageView } from './security-coverage-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
const now = '2026-10-04T00:00:10Z';
const firstID = `agent_${'7'.repeat(32)}`, secondID = `agent_${'8'.repeat(32)}`;
const revision = `revision_${'a'.repeat(32)}`;
const rawCatalog = '{"schema":"debian-tracker-normalized-1","synthetic":true,"coveredSources":["fixture-package"],"rules":[]}';
const metric: Metric = { value: null, unit: '%', quality: 'unknown', source: 'Synthetic integration fixture', collectedAt: '0001-01-01T00:00:00Z' };
function device(id = firstID, overrides: Partial<Device> = {}): Device {
    return { id, name: `Synthetic ${id === firstID ? 'first' : 'second'} fixture`, platform: 'linux', os: 'Linux fixture', site: 'Fixture', group: 'Fixture', ip: null, status: 'unknown', source: 'lan', synthetic: false, lastSeen: '0001-01-01T00:00:00Z', agentVersion: 'fixture', cpu: metric, memory: metric, disk: metric, uptime: '', tags: [], capabilities: [], evidence: [], trend: [], caseIds: [], ...overrides };
}
function coverage(id = firstID): SecurityCoverageView {
    return { schemaVersion: 'tracebolt.security-coverage.v1', deviceId: id, serverNow: now, maxAgeSeconds: 120, receivedAt: null, collectionStatus: 'not_configured', inventory: { coverage: 'unknown', freshness: 'unknown', reportedItemCount: null, installedCount: null, observedCount: null, countExact: false, truncated: false, collectedAt: null, generationId: null, scope: 'reported-installed-binary-packages', originAssurance: 'unverified' }, catalog: { configured: false, revision, sha256: null, originAssurance: 'unverified', freshness: 'unknown' }, offeredUpdates: { coverage: 'unknown', offeredCount: null, reason: 'native_update_adapter_unimplemented' }, vulnerabilities: { coverage: 'unknown', affectedCves: null, reviewCandidates: null, reasonCodes: ['advisory_snapshot_unavailable', 'source_package_mapping_unavailable', 'client_release_unverified', 'installed_artifact_origin_unverified'] } };
}
function catalog(enabled = true): OfflineCatalogView {
    return { schemaVersion: 'tracebolt.offline-catalog.v1', enabled, serverNow: now, revision: enabled ? revision : '', storage: 'memory-only', resetsOnRestart: true, catalog: null, limits: { maxBytes: 2097152, maxRules: 10000, maxInFlight: 1 } };
}
function loadedCatalog(): OfflineCatalogView {
    return { ...catalog(), revision: `revision_${'b'.repeat(32)}`, catalog: { id: `catalog_${'c'.repeat(32)}`, sha256: 'd'.repeat(64), format: 'debian-tracker-normalized-1', provider: 'debian-security-tracker', declaredRelease: 'trixie', importedAt: '2026-10-04T00:00:05Z', publishedAt: null, freshness: 'unknown', originAssurance: 'unverified', synthetic: true, byteCount: new TextEncoder().encode(rawCatalog).byteLength, ruleCount: 0, coveredSourceCount: 1 } };
}
const lanSession: OperatorSession = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'synthetic-session', serverNow: now, expiresAt: '2026-10-04T00:30:00Z', expiresInSeconds: 1800 };
const developmentSession: OperatorSession = { ...lanSession, mode: 'development', authenticationRequired: false, authenticated: false, csrfToken: null, expiresAt: null, expiresInSeconds: null };
const capabilities: Capabilities = { mode: 'lan', syntheticFleet: false, realCollector: 'Synthetic fixture', remoteEnrollment: false, manualDeviceApproval: true, shellExecution: false, aiConnected: false, persistence: 'Synthetic fixture', limitations: [], version: 'fixture' };
const aiConfig: AIConfig = { revision: 'fixture', configured: false, provider: 'openai-compatible', baseURL: 'http://127.0.0.1:11434/v1', endpointOrigin: 'http://127.0.0.1:11434', model: '', keyConfigured: false, useLegacyMaxTokens: false, allowRemoteEvidence: false, storage: 'memory-only', resetsOnRestart: true, busy: false, limitations: [] };
let currentSession: OperatorSession, currentDevice: Device, currentCatalog: unknown;
function answer(path: string): unknown {
    if (path === '/auth/session') return currentSession;
    if (path === '/security/catalog') return currentCatalog;
    if (path === '/capabilities') return capabilities;
    if (path === '/ai/config') return aiConfig;
    if (path === '/enrollment') return { schemaVersion: 'tracebolt.enrollment-operator.v2', serverNow: now, enabled: false, platforms: [], recordLimit: 25, items: [] };
    if (path === '/overview') return { product: 'Tracebolt fixture', mode: currentSession.mode, generatedAt: now, stats: { totalDevices: 2, healthyDevices: 0, attentionDevices: 0, unknownDevices: 2, openCases: 0, criticalCases: 0 }, devices: [currentDevice, device(secondID)], cases: [], activity: [] } satisfies Overview;
    if (path.endsWith('/security')) return coverage(path.includes(secondID) ? secondID : firstID);
    if (path === `/devices/${firstID}`) return currentDevice;
    if (path === `/devices/${secondID}`) return device(secondID);
    throw new Error('Unexpected fixture route');
}
function readPaths() { return vi.mocked(request).mock.calls.map(([path]) => path); }
async function navigate(hash: string) { await act(async () => { window.history.replaceState({}, '', `/#/${hash}`); window.dispatchEvent(new HashChangeEvent('hashchange')); }); }
function renderDetail() { return render(<AuthBoundary><DeviceDetail id={currentDevice.id} onClose={vi.fn()} onCase={vi.fn()}/></AuthBoundary>); }
async function openSecurity() { fireEvent.click(await screen.findByRole('tab', { name: 'Security coverage' })); }
async function openCatalog() {
    await navigate('settings'); render(<App/>);
    await screen.findByText('Import a normalized JSON catalog');
}
async function selectCatalog() {
    fireEvent.click(screen.getByText('Import a normalized JSON catalog'));
    fireEvent.change(screen.getByLabelText('Choose JSON file'), { target: { files: [new File([rawCatalog], 'private-fixture-name.json', { type: 'application/json' })] } });
    await waitFor(() => expect(screen.getByRole('button', { name: 'Import catalog' })).toBeEnabled());
}
beforeEach(() => {
    setLocale('en', false); localStorage.clear(); sessionStorage.clear();
    window.history.replaceState({}, '', '/');
    currentSession = { ...lanSession }; currentDevice = device(); currentCatalog = catalog();
    vi.mocked(request).mockReset().mockImplementation(async path => answer(path));
    vi.mocked(mutateRaw).mockReset();
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe('Security coverage in the real device drawer', () => {
    it('is lazy, preserves Inventory, and renders explicit unknown findings with accessible tab relationships', async () => {
        renderDetail(); const tab = await screen.findByRole('tab', { name: 'Security coverage' });
        expect(screen.getByRole('tab', { name: 'Inventory' })).toBeInTheDocument();
        expect(readPaths().some(path => path.endsWith('/security') || path === '/security/catalog')).toBe(false);
        fireEvent.click(tab);
        const panel = screen.getByRole('tabpanel');
        await within(panel).findByRole('heading', { name: 'Security coverage' });
        await within(panel).findByText('Client source-package mapping is missing.');
        expect(tab).toHaveAttribute('aria-selected', 'true'); expect(panel).toHaveAttribute('aria-labelledby', tab.id); expect(tab).toHaveAttribute('aria-controls', panel.id);
        expect(within(panel).getAllByText('Unknown').length).toBeGreaterThanOrEqual(3);
        expect(within(panel).queryByText(/^0$/)).not.toBeInTheDocument(); expect(within(panel).queryByText('Secure')).not.toBeInTheDocument();
        expect(readPaths()).toContain(`/devices/${firstID}/security`); expect(readPaths().some(path => path.endsWith('/operational'))).toBe(false);
    });
    it.each([{ synthetic: true }, { source: 'synthetic' as const }, { source: 'sandbox' as const }, { source: 'local' as const }, { platform: 'windows' as const }, { platform: 'macos' as const }])('does not advertise coverage for %j', async overrides => {
        currentDevice = device(firstID, overrides); renderDetail(); await screen.findByRole('tab', { name: 'Overview' });
        expect(screen.queryByRole('tab', { name: 'Security coverage' })).not.toBeInTheDocument(); expect(readPaths().some(path => path.endsWith('/security'))).toBe(false);
    });
    it('allows unknown-platform LAN identities without asserting Linux collection', async () => {
        currentDevice = device(firstID, { platform: 'unknown' }); renderDetail(); await openSecurity();
        await screen.findByText('Client source-package mapping is missing.');
        expect(document.querySelector('.detail-badges .status-unknown')).toHaveTextContent('Not assessed');
    });
    it('does not add coverage to development mode even for a LAN-shaped fixture', async () => {
        currentSession = developmentSession; renderDetail(); await screen.findByRole('tab', { name: 'Overview' });
        expect(screen.queryByRole('tab', { name: 'Security coverage' })).not.toBeInTheDocument(); expect(readPaths().some(path => path.endsWith('/security'))).toBe(false);
    });
    it('switches tab and panel copy when the locale changes', async () => {
        renderDetail(); await openSecurity(); await screen.findByRole('heading', { name: 'Security coverage' });
        act(() => setLocale('de', false));
        expect(screen.getByRole('tab', { name: 'Sicherheitsabdeckung' })).toHaveAttribute('aria-selected', 'true');
        expect(screen.getByRole('heading', { name: 'Sicherheitsabdeckung' })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Sicherheitsabdeckung aktualisieren' })).toBeInTheDocument();
    });
    it('includes coverage in keyboard navigation without moving the operational tab', async () => {
        renderDetail(); const overview = await screen.findByRole('tab', { name: 'Overview' });
        fireEvent.keyDown(overview, { key: 'ArrowRight' }); const inventory = screen.getByRole('tab', { name: 'Inventory' }); expect(inventory).toHaveFocus();
        fireEvent.keyDown(inventory, { key: 'ArrowRight' }); const security = screen.getByRole('tab', { name: 'Security coverage' }); expect(security).toHaveFocus(); expect(security).toHaveAttribute('aria-selected', 'true');
        fireEvent.keyDown(security, { key: 'Home' }); expect(overview).toHaveFocus(); expect(overview).toHaveAttribute('aria-selected', 'true');
    });
    it.each(['tab', 'device', 'close', 'auth'] as const)('aborts a coverage read and suppresses late data after %s transition', async transition => {
        let resolve!: (value: SecurityCoverageView) => void, signal: AbortSignal | undefined;
        vi.mocked(request).mockImplementation(async (path, options) => path === `/devices/${firstID}/security` ? new Promise<SecurityCoverageView>(done => { resolve = done; signal = options?.signal as AbortSignal; }) : answer(path));
        await navigate(`devices/${firstID}`); render(<App/>); await openSecurity(); await waitFor(() => expect(signal).toBeDefined());
        if (transition === 'tab') fireEvent.click(screen.getByRole('tab', { name: 'Overview' }));
        if (transition === 'device') { await navigate(`devices/${secondID}`); await screen.findByRole('region', { name: 'Device Synthetic second fixture' }); }
        if (transition === 'close') { fireEvent.keyDown(document, { key: 'Escape' }); await waitFor(() => expect(screen.queryByRole('region', { name: 'Device Synthetic first fixture' })).not.toBeInTheDocument()); expect(window.location.hash).toBe('#/devices'); }
        if (transition === 'auth') { act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); await screen.findByLabelText('Operator password'); }
        expect(signal!.aborted).toBe(true); await act(async () => resolve(coverage()));
        expect(screen.queryByRole('heading', { name: 'Security coverage' })).not.toBeInTheDocument(); expect(readPaths()).not.toContain(`/devices/${secondID}/security`);
    });
});

describe('Offline catalog in the real Settings and access boundary', () => {
    it('discovers support from its endpoint, with bounded abortable reads and memory-only warnings', async () => {
        await openCatalog();
        expect(request).toHaveBeenCalledWith('/security/catalog', expect.objectContaining({ signal: expect.any(AbortSignal) }), expect.any(Number));
        expect(screen.getByRole('heading', { name: 'Offline advisory catalog' })).toBeInTheDocument();
        expect(screen.getByText('Memory only · resets on manager restart')).toBeVisible();
        expect(screen.queryByRole('button', { name: /Install|Download feed/ })).not.toBeInTheDocument(); expect(mutateRaw).not.toHaveBeenCalled();
        expect(readPaths().every(path => path.startsWith('/'))).toBe(true);
    });
    it('keeps import unavailable when a LAN basic/manual manager reports disabled', async () => {
        currentCatalog = catalog(false); await navigate('settings'); render(<App/>);
        await screen.findByText('Offline catalogs require the managed-operations profile. Import is unavailable on this manager.');
        expect(screen.queryByLabelText('Choose JSON file')).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Import catalog' })).not.toBeInTheDocument(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('does not query or show catalogs in development Settings', async () => {
        currentSession = developmentSession; await navigate('settings'); render(<App/>); await screen.findByRole('heading', { name: 'Settings' });
        expect(screen.queryByRole('heading', { name: 'Offline advisory catalog' })).not.toBeInTheDocument(); expect(readPaths()).not.toContain('/security/catalog');
    });
    it.each(['invalid', 'failure'] as const)('removes an older usable import form when its own discovery refresh is %s', async failure => {
        await openCatalog(); await selectCatalog();
        if (failure === 'invalid') currentCatalog = { ...catalog(), enabled: 'yes' };
        else vi.mocked(request).mockImplementation(async path => { if (path === '/security/catalog') throw new APIError('Private raw failure', 404); return answer(path); });
        fireEvent.click(screen.getByRole('button', { name: 'Refresh catalog status' }));
        await waitFor(() => expect(screen.queryByLabelText('Choose JSON file')).not.toBeInTheDocument());
        expect(screen.queryByRole('button', { name: 'Import catalog' })).not.toBeInTheDocument(); expect(screen.queryByText(/Private raw failure/)).not.toBeInTheDocument(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('clears selected bytes on navigation and never persists or discloses the filename or raw data', async () => {
        await openCatalog(); const storage = vi.spyOn(Storage.prototype, 'setItem'); await selectCatalog();
        expect(document.body.textContent).not.toContain(rawCatalog); expect(document.body.textContent).not.toContain('private-fixture-name.json');
        expect(window.location.href).not.toContain('private-fixture-name'); expect(storage).not.toHaveBeenCalled();
        await navigate('overview'); expect(screen.queryByLabelText('Choose JSON file')).not.toBeInTheDocument();
        await navigate('settings'); await screen.findByText('Import a normalized JSON catalog'); fireEvent.click(screen.getByText('Import a normalized JSON catalog'));
        expect(screen.getByRole('button', { name: 'Import catalog' })).toBeDisabled(); expect(screen.queryByText(/JSON file selected/)).not.toBeInTheDocument(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it.each(['navigate', 'auth', 'pagehide'] as const)('aborts an import on %s and suppresses its late success', async transition => {
        let resolve!: (value: OfflineCatalogView) => void, signal: AbortSignal | undefined;
        vi.mocked(mutateRaw).mockImplementation(async (_path, _body, _headers, passedSignal) => new Promise<OfflineCatalogView>(done => { resolve = done; signal = passedSignal; }));
        await openCatalog(); await selectCatalog(); fireEvent.click(screen.getByRole('button', { name: 'Import catalog' }));
        await waitFor(() => expect(signal).toBeDefined());
        if (transition === 'navigate') await navigate('overview');
        if (transition === 'auth') { act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); await screen.findByLabelText('Operator password'); }
        if (transition === 'pagehide') act(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })));
        expect(signal!.aborted).toBe(true); await act(async () => resolve(loadedCatalog()));
        expect(screen.queryByText('Catalog imported into memory. Its origin and freshness remain unverified.')).not.toBeInTheDocument();
        expect(screen.queryByText(/JSON file selected/)).not.toBeInTheDocument();
        if (transition === 'pagehide') expect(document.querySelector('.auth-private-view')).toHaveAttribute('aria-hidden', 'true');
    });
    it('drops file selection across BFCache restoration into a replaced authenticated session', async () => {
        await openCatalog(); await selectCatalog();
        act(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })));
        currentSession = { ...lanSession, csrfToken: 'synthetic-replaced-session', expiresAt: '2026-10-04T00:31:00Z' };
        act(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })));
        await waitFor(() => expect(document.querySelector('.auth-private-view')).not.toHaveAttribute('aria-hidden'));
        await screen.findByText('Import a normalized JSON catalog'); fireEvent.click(screen.getByText('Import a normalized JSON catalog'));
        expect(screen.getByRole('button', { name: 'Import catalog' })).toBeDisabled(); expect(screen.queryByText(/JSON file selected/)).not.toBeInTheDocument(); expect(mutateRaw).not.toHaveBeenCalled();
    });
});
