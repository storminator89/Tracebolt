import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { OfflineCatalogPanel, SecurityCoveragePanel } from './security-coverage';
import { CATALOG_MAX_BYTES, effectiveSecurityCollectionStatus, effectiveSecurityFreshness, SECURITY_RESPONSE_MAX_BYTES, SECURITY_VIEW_LEASE_MS, validOfflineCatalogView, validSecurityCoverageView } from './security-coverage-types';
import type { OfflineCatalogView, SecurityCoverageView } from './security-coverage-types';

vi.mock('./api', async importOriginal => ({ ...await importOriginal<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async importOriginal => ({ ...await importOriginal<typeof import('./auth')>(), useOperator: vi.fn() }));
const now = '2026-10-04T00:00:10Z';
const revision = `revision_${'a'.repeat(32)}`;
const nextRevision = `revision_${'b'.repeat(32)}`;
const raw = '{ "schema":"debian-tracker-normalized-1", "synthetic":true, "coveredSources":["fixture-source"], "rules":[] }\n';
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: '2026-10-04T00:30:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
function catalog(loaded = false): OfflineCatalogView {
    return { schemaVersion: 'tracebolt.offline-catalog.v1', enabled: true, serverNow: now, revision, storage: 'memory-only', resetsOnRestart: true, limits: { maxBytes: 2097152, maxRules: 10000, maxInFlight: 1 }, catalog: loaded ? { id: `catalog_${'c'.repeat(32)}`, sha256: 'd'.repeat(64), format: 'debian-tracker-normalized-1', provider: 'debian-security-tracker', declaredRelease: 'trixie', importedAt: '2026-10-04T00:00:05Z', publishedAt: null, freshness: 'unknown', originAssurance: 'unverified', synthetic: true, byteCount: new TextEncoder().encode(raw).byteLength, ruleCount: 0, coveredSourceCount: 1 } : null };
}
function coverage(): SecurityCoverageView {
    return { schemaVersion: 'tracebolt.security-coverage.v1', deviceId: 'agent_fixture', serverNow: now, maxAgeSeconds: 120, receivedAt: '2026-10-04T00:00:05Z', collectionStatus: 'fresh', inventory: { coverage: 'partial', freshness: 'fresh', reportedItemCount: 5, installedCount: null, observedCount: 500, countExact: true, truncated: true, collectedAt: '2026-10-04T00:00:00Z', generationId: `sample_${'e'.repeat(32)}`, scope: 'reported-installed-binary-packages', originAssurance: 'unverified' }, catalog: { configured: false, revision, sha256: null, originAssurance: 'unverified', freshness: 'unknown' }, offeredUpdates: { coverage: 'unknown', offeredCount: null, reason: 'native_update_adapter_unimplemented' }, vulnerabilities: { coverage: 'unknown', affectedCves: null, reviewCandidates: null, reasonCodes: ['advisory_snapshot_unavailable', 'source_package_mapping_unavailable', 'client_release_unverified', 'installed_artifact_origin_unverified'] } };
}
function unknownCoverage(): SecurityCoverageView { const value = coverage(); return { ...value, collectionStatus: 'not_configured', receivedAt: null, inventory: { ...value.inventory, coverage: 'unknown', freshness: 'unknown', reportedItemCount: null, installedCount: null, observedCount: null, countExact: false, truncated: false, collectedAt: null, generationId: null } }; }
function defer<T>() { let resolve!: (value: T) => void, reject!: (value: unknown) => void; const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
function openImport() { fireEvent.click(screen.getByText('Import a normalized JSON catalog')); }
async function showCatalog(value = catalog()) { vi.mocked(request).mockResolvedValue(value); render(<OfflineCatalogPanel/>); await screen.findByText('Import a normalized JSON catalog'); openImport(); }
async function choose(text = raw) {
    fireEvent.change(screen.getByLabelText('Choose JSON file'), { target: { files: [new File([text], 'private-source-label.json', { type: 'application/json' })] } });
    await waitFor(() => expect(screen.getByRole('button', { name: /^(Import catalog|Replace current catalog)$/ })).toBeEnabled());
}
function importButton() { return screen.getByRole('button', { name: /^(Import catalog|Replace current catalog)$/ }); }

beforeEach(() => { vi.mocked(request).mockReset(); vi.mocked(mutateRaw).mockReset(); vi.mocked(useOperator).mockReturnValue(operator); setLocale('en', false); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('strict offline security contracts', () => {
    it('accepts explicit unknown coverage, partial observed metadata and catalog states', () => {
        expect(validSecurityCoverageView(coverage(), 'agent_fixture')).toBe(true);
        expect(validSecurityCoverageView(unknownCoverage(), 'agent_fixture')).toBe(true);
        expect(validOfflineCatalogView(catalog())).toBe(true); expect(validOfflineCatalogView(catalog(true))).toBe(true);
        expect(validOfflineCatalogView({ ...catalog(), enabled: false, revision: '' })).toBe(true);
    });
    it('rejects expanded, cross-device, inconsistent and invented assessment responses', () => {
        const base = coverage();
        for (const value of [
            { ...base, deviceId: 'agent_other' }, { ...base, rawRules: [] }, { ...base, maxAgeSeconds: 121 }, { ...base, receivedAt: undefined },
            { ...base, inventory: { ...base.inventory, installedCount: 500 } }, { ...base, inventory: { ...base.inventory, reportedItemCount: 257 } },
            { ...base, inventory: { ...base.inventory, observedCount: 4 } }, { ...base, inventory: { ...base.inventory, collectedAt: '2026-02-31T00:00:00Z' } },
            { ...base, inventory: { ...base.inventory, originAssurance: 'verified' } }, { ...base, inventory: { ...base.inventory, generationId: '<script>' } },
            { ...base, offeredUpdates: { ...base.offeredUpdates, offeredCount: 0 } }, { ...base, vulnerabilities: { ...base.vulnerabilities, affectedCves: 0 } },
            { ...base, vulnerabilities: { ...base.vulnerabilities, reviewCandidates: 0 } }, { ...base, vulnerabilities: { ...base.vulnerabilities, reasonCodes: [...base.vulnerabilities.reasonCodes, 'extra'] } },
            { ...base, vulnerabilities: { ...base.vulnerabilities, reasonCodes: ['source_package_mapping_unavailable', ...base.vulnerabilities.reasonCodes.slice(1)] } },
            { ...base, catalog: { ...base.catalog, configured: true } }, { ...base, receivedAt: '2027-10-04T00:00:00Z' },
        ]) expect(validSecurityCoverageView(value, 'agent_fixture')).toBe(false);
    });
    it('allows complete zero binary inventory without manufacturing zero CVEs', () => {
        const value = coverage(); Object.assign(value.inventory, { coverage: 'observed', reportedItemCount: 0, installedCount: 0, observedCount: 0, countExact: true, truncated: false });
        expect(validSecurityCoverageView(value, 'agent_fixture')).toBe(true);
        value.inventory.countExact = false; expect(validSecurityCoverageView(value, 'agent_fixture')).toBe(false);
        value.inventory.countExact = true; value.inventory.truncated = true; expect(validSecurityCoverageView(value, 'agent_fixture')).toBe(false);
    });
    it('requires explicit format metadata, finite limits and unverified origin/freshness', () => {
        const base = catalog(true);
        for (const value of [
            { ...base, extra: 'private' }, { ...base, storage: 'disk' }, { ...base, resetsOnRestart: false }, { ...base, enabled: false }, { ...base, revision: '' },
            { ...base, limits: { ...base.limits, maxBytes: 999999999 } }, { ...base, catalog: { ...base.catalog, synthetic: 'true' } },
            { ...base, catalog: { ...base.catalog, publishedAt: now } }, { ...base, catalog: { ...base.catalog, importedAt: '2027-01-01T00:00:00Z' } },
            { ...base, catalog: { ...base.catalog, originAssurance: 'verified' } }, { ...base, catalog: { ...base.catalog, freshness: 'fresh' } },
            { ...base, catalog: { ...base.catalog, ruleCount: 10001 } }, { ...base, catalog: { ...base.catalog, coveredSourceCount: -1 } }, { ...base, catalog: { ...base.catalog, coveredSourceCount: 0 } },
            { ...base, catalog: { ...base.catalog, byteCount: CATALOG_MAX_BYTES + 1 } }, { ...base, catalog: { ...base.catalog, declaredRelease: 'bookworm' } },
            { ...base, catalog: { ...base.catalog, provider: 'https://example.invalid' } }, { ...base, catalog: { ...base.catalog, filename: 'secret' } },
        ]) expect(validOfflineCatalogView(value)).toBe(false);
    });
    it('ages from server and monotonic time while retained, revoked and expired data never becomes fresh', () => {
        vi.spyOn(Date, 'now').mockReturnValue(0);
        const value = coverage(); expect(effectiveSecurityFreshness(value, 110000)).toBe('fresh'); expect(effectiveSecurityFreshness(value, 110001)).toBe('stale');
        value.inventory.freshness = 'stale'; expect(effectiveSecurityFreshness(value, 0)).toBe('stale');
        value.inventory.freshness = 'fresh'; value.collectionStatus = 'revoked'; expect(validSecurityCoverageView(value, 'agent_fixture')).toBe(false);
        value.collectionStatus = 'fresh'; value.receivedAt = null; expect(validSecurityCoverageView(value, 'agent_fixture')).toBe(false);
        const unknown = unknownCoverage(); unknown.collectionStatus = 'fresh'; expect(validSecurityCoverageView(unknown, 'agent_fixture')).toBe(false);
        unknown.receivedAt = '2026-10-03T23:00:00Z'; expect(validSecurityCoverageView(unknown, 'agent_fixture')).toBe(false);
        unknown.receivedAt = '2026-10-04T00:00:05Z'; expect(validSecurityCoverageView(unknown, 'agent_fixture')).toBe(true);
        expect(effectiveSecurityCollectionStatus(unknown, 115000)).toBe('fresh'); expect(effectiveSecurityCollectionStatus(unknown, 115001)).toBe('stale');
        value.receivedAt = '2026-10-04T00:00:05Z'; value.inventory.freshness = 'stale'; expect(effectiveSecurityCollectionStatus(value, 0)).toBe('fresh');
    });
});

describe('coverage presentation and request lifecycle', () => {
    it('uses the bounded real endpoint and separates partial/stale inventory, offers and missing CVE evidence', async () => {
        const value = coverage(); value.inventory.freshness = 'stale'; vi.mocked(request).mockResolvedValue(value); render(<SecurityCoveragePanel deviceId="agent_fixture"/>);
        await screen.findByText('Partial inventory'); expect(screen.getByText('Stale / historical evidence')).toBeVisible();
        expect(request).toHaveBeenCalledExactlyOnceWith('/devices/agent_fixture/security', { signal: expect.any(AbortSignal) }, SECURITY_RESPONSE_MAX_BYTES);
        expect(screen.getByText('Client source-package mapping is missing.')).toBeVisible(); expect(screen.getByText('The client’s exact distribution release is unverified.')).toBeVisible();
        for (const title of ['Offered updates', 'CVE coverage']) expect(within(screen.getByRole('heading', { name: title }).closest('article')!).getByText('Unknown')).toBeVisible();
        expect(document.body.textContent).not.toMatch(/0 CVEs|secure device|verified origin/i);
    });
    it('rejects stale device responses after switching device or session key', async () => {
        const delayed = defer<SecurityCoverageView>(); vi.mocked(request).mockReturnValueOnce(delayed.promise).mockResolvedValueOnce({ ...coverage(), deviceId: 'agent_other' });
        const rendered = render(<SecurityCoveragePanel deviceId="agent_fixture" sessionKey="one"/>);
        const signal = vi.mocked(request).mock.calls[0][1]!.signal!;
        rendered.rerender(<SecurityCoveragePanel deviceId="agent_other" sessionKey="two"/>); expect(signal.aborted).toBe(true);
        await screen.findByText('Partial inventory'); await act(async () => delayed.resolve(unknownCoverage())); expect(screen.queryByText('Collection not configured')).not.toBeInTheDocument();
    });
    it('reanchors coverage after blur/focus and cannot keep fresh data across a paused-clock sleep', async () => {
        vi.mocked(request).mockResolvedValue(coverage()); render(<SecurityCoveragePanel deviceId="agent_fixture"/>); await screen.findByText('Partial inventory');
        act(() => window.dispatchEvent(new Event('blur'))); expect(screen.queryByText('Partial inventory')).not.toBeInTheDocument();
        act(() => window.dispatchEvent(new Event('focus'))); await screen.findByText('Partial inventory'); expect(request).toHaveBeenCalledTimes(2);
        const wall = Date.now(); vi.spyOn(Date, 'now').mockReturnValue(wall + 3600000);
        await waitFor(() => expect(screen.queryByText('Partial inventory')).not.toBeInTheDocument(), { timeout: 1500 });
        expect(screen.getByRole('alert')).toHaveTextContent('Status needs refreshing');
    });
    it('ages the collection header independently of missing or retained software', async () => {
        const value = unknownCoverage(); value.collectionStatus = 'fresh'; value.receivedAt = '2026-10-03T23:58:11Z';
        vi.mocked(request).mockResolvedValue(value); render(<SecurityCoveragePanel deviceId="agent_fixture"/>); await screen.findByText('Current collection received', { selector: 'span' });
        await waitFor(() => expect(screen.getByText('Collection is stale')).toBeVisible(), { timeout: 2500 });
        expect(screen.getByText('No inventory evidence')).toBeVisible();
    });
    it('clears invalid refresh data instead of rendering old counts', async () => {
        vi.mocked(request).mockResolvedValueOnce(coverage()).mockResolvedValueOnce({ ...coverage(), extra: true }); render(<SecurityCoveragePanel deviceId="agent_fixture"/>);
        await screen.findByText('Partial inventory'); fireEvent.click(screen.getByRole('button', { name: 'Refresh security coverage' }));
        await screen.findByRole('alert'); expect(screen.queryByText('Partial inventory')).not.toBeInTheDocument();
    });
    it('conceals a suspended response and requires a fresh read after BFCache', async () => {
        const delayed = defer<SecurityCoverageView>(); vi.mocked(request).mockReturnValueOnce(delayed.promise).mockResolvedValueOnce(unknownCoverage());
        render(<SecurityCoveragePanel deviceId="agent_fixture"/>); const signal = vi.mocked(request).mock.calls[0][1]!.signal!;
        act(() => window.dispatchEvent(new Event('pagehide'))); expect(signal.aborted).toBe(true);
        await act(async () => delayed.resolve(coverage())); expect(screen.queryByText('Partial inventory')).not.toBeInTheDocument();
        act(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }))); await screen.findByText('Collection not configured'); expect(request).toHaveBeenCalledTimes(2);
    });
    it('fails closed without an authenticated operator and blocks 401 retries', async () => {
        vi.mocked(useOperator).mockReturnValue(null); const rendered = render(<SecurityCoveragePanel deviceId="agent_fixture"/>); expect(request).not.toHaveBeenCalled();
        vi.mocked(useOperator).mockReturnValue(operator); vi.mocked(request).mockRejectedValue(new APIError('raw private error', 401)); rendered.rerender(<SecurityCoveragePanel deviceId="agent_fixture"/>);
        await screen.findByText('Your session has ended. Sign in again.'); expect(screen.getByRole('button', { name: 'Refresh security coverage' })).toBeDisabled(); expect(document.body.textContent).not.toContain('raw private');
    });
    it('translates component-local labels through the existing locale context', async () => {
        setLocale('de', false); vi.mocked(request).mockResolvedValue(coverage()); render(<SecurityCoveragePanel deviceId="agent_fixture"/>);
        await screen.findByText('Teilweise erfasst'); expect(screen.getByRole('heading', { name: 'Ältere Inventarbelege' })).toBeVisible(); expect(screen.getByRole('heading', { name: 'Angebotene Updates' })).toBeVisible();
    });
});

describe('memory-only catalog import and clear', () => {
    it('requires explicit authenticated access and the server enabled profile', async () => {
        vi.mocked(useOperator).mockReturnValue({ ...operator, mode: 'development', authenticated: false }); render(<OfflineCatalogPanel/>); expect(request).not.toHaveBeenCalled(); cleanup();
        vi.mocked(useOperator).mockReturnValue(operator); vi.mocked(request).mockResolvedValue({ ...catalog(), enabled: false, revision: '' }); render(<OfflineCatalogPanel/>);
        await screen.findByText(/Import is unavailable on this manager/); expect(screen.queryByLabelText('Choose JSON file')).not.toBeInTheDocument(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('imports the original text once with exact CAS revision and bounded helper without exporting filename', async () => {
        const unusual = '{"schema":"first","schema":"second"}\n'; vi.mocked(mutateRaw).mockResolvedValue({ ...catalog(true), revision: nextRevision }); await showCatalog(); await choose(unusual);
        const button = importButton(); fireEvent.click(button); fireEvent.click(button);
        await screen.findByText('Catalog imported into memory. Its origin and freshness remain unverified.');
        expect(mutateRaw).toHaveBeenCalledExactlyOnceWith('/security/catalog', unusual, { 'X-Tracebolt-Catalog-Revision': revision }, expect.any(AbortSignal), SECURITY_RESPONSE_MAX_BYTES);
        expect(document.body.textContent).not.toContain('private-source-label'); expect(document.body.textContent).not.toContain(unusual);
        expect(JSON.stringify({ ...localStorage, ...sessionStorage })).not.toContain('private-source-label');
        expect(JSON.stringify({ ...localStorage, ...sessionStorage })).not.toContain(unusual);
        expect(screen.getByText('Rules in file')).toBeVisible(); expect(screen.getByText(/These counts describe this file’s format/)).toBeVisible(); expect(screen.queryByText('JSON file selected')).not.toBeInTheDocument();
    });
    it.each(['focus-before-change', 'change-before-focus'])('keeps native picker selection for %s without renewing its lease', async order => {
        await showCatalog(); act(() => window.dispatchEvent(new Event('blur'))); expect(screen.getByLabelText('Choose JSON file')).toBeInTheDocument();
        if (order === 'focus-before-change') act(() => window.dispatchEvent(new Event('focus')));
        await choose(); if (order === 'change-before-focus') act(() => window.dispatchEvent(new Event('focus'))); expect(importButton()).toBeEnabled(); expect(request).toHaveBeenCalledTimes(1);
        const wall = Date.now(); vi.spyOn(Date, 'now').mockReturnValue(wall + 3600000); fireEvent.click(importButton());
        expect(mutateRaw).not.toHaveBeenCalled(); expect(screen.queryByLabelText('Choose JSON file')).not.toBeInTheDocument();
    });
    it('preserves a UTF-8 BOM for server rejection rather than silently changing supplied bytes', async () => {
        vi.mocked(mutateRaw).mockRejectedValue(new APIError('synthetic rejection', 400)); await showCatalog(); await choose('\ufeff' + raw); fireEvent.click(importButton());
        await screen.findByRole('alert'); expect(vi.mocked(mutateRaw).mock.calls[0][1]).toBe('\ufeff' + raw);
    });
    it('rejects empty, oversized and invalid UTF-8 files without a mutation', async () => {
        await showCatalog(); const input = screen.getByLabelText('Choose JSON file');
        fireEvent.change(input, { target: { files: [new File([], 'empty.json')] } }); await screen.findByText('Choose a non-empty UTF-8 JSON file no larger than 2 MiB.');
        const huge = new File(['x'], 'huge.json'); Object.defineProperty(huge, 'size', { value: CATALOG_MAX_BYTES + 1 }); fireEvent.change(input, { target: { files: [huge] } }); await screen.findByText('The file exceeds the 2 MiB limit.');
        fireEvent.change(input, { target: { files: [new File([new Uint8Array([0xff, 0xfe])], 'bad.json')] } }); await screen.findByText('Choose a non-empty UTF-8 JSON file no larger than 2 MiB.'); expect(importButton()).toBeDisabled(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('clears file selection on cancel and never sends it until explicit import', async () => {
        await showCatalog(); await choose(); fireEvent.click(screen.getByRole('button', { name: 'Cancel file selection' })); expect(importButton()).toBeDisabled(); expect(screen.queryByText(/JSON file selected/)).not.toBeInTheDocument(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('uses an explicit clear confirmation and an exact JSON expectedRevision body', async () => {
        vi.mocked(mutateRaw).mockResolvedValue({ ...catalog(), revision: nextRevision }); await showCatalog(catalog(true)); fireEvent.click(screen.getByRole('button', { name: 'Clear catalog' })); expect(mutateRaw).not.toHaveBeenCalled();
        fireEvent.click(screen.getByRole('button', { name: 'Confirm clear' })); await screen.findByText('Catalog cleared from manager memory.');
        expect(mutateRaw).toHaveBeenCalledExactlyOnceWith('/security/catalog/clear', JSON.stringify({ expectedRevision: revision }), {}, expect.any(AbortSignal), SECURITY_RESPONSE_MAX_BYTES);
    });
    it.each([[409, 'The catalog changed.'], [429, 'Another catalog import is in progress.'], [413, 'The file exceeds'], [400, 'The catalog was rejected.'], [404, 'Offline catalogs are unavailable.']] as const)('discards file and mutation authority after HTTP %s without replay', async (status, message) => {
        vi.mocked(mutateRaw).mockRejectedValue(new APIError('private raw body', status)); await showCatalog(); await choose(); fireEvent.click(importButton()); await screen.findByRole('alert');
        expect(screen.getByRole('alert')).toHaveTextContent(message); expect(screen.queryByLabelText('Choose JSON file')).not.toBeInTheDocument(); expect(document.body.textContent).not.toContain('private raw body'); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
    it('does not keep an old upload form after invalid configuration refresh', async () => {
        await showCatalog(); await choose(); const oldButton = importButton(); vi.mocked(request).mockResolvedValue({ ...catalog(), enabled: undefined });
        fireEvent.click(screen.getByRole('button', { name: 'Refresh catalog status' })); fireEvent.click(oldButton); await screen.findByRole('alert');
        expect(screen.queryByLabelText('Choose JSON file')).not.toBeInTheDocument(); expect(mutateRaw).not.toHaveBeenCalled();
        vi.mocked(request).mockResolvedValue(catalog()); fireEvent.click(screen.getByRole('button', { name: 'Refresh catalog status' })); await screen.findByText('Import a normalized JSON catalog'); openImport(); expect(importButton()).toBeDisabled();
    });
    it('cancels pending upload before a configuration read and ignores its delayed result', async () => {
        const delayed = defer<OfflineCatalogView>(); vi.mocked(mutateRaw).mockReturnValue(delayed.promise); await showCatalog(); await choose(); fireEvent.click(importButton()); const signal = vi.mocked(mutateRaw).mock.calls[0][3]!;
        vi.mocked(request).mockResolvedValue({ ...catalog(), enabled: false, revision: '' }); fireEvent.click(screen.getByRole('button', { name: 'Refresh catalog status' })); expect(signal.aborted).toBe(true);
        await screen.findByText(/Import is unavailable on this manager/); await act(async () => delayed.resolve({ ...catalog(true), revision: nextRevision }));
        expect(screen.queryByText('Rules in file')).not.toBeInTheDocument(); expect(screen.getByRole('status')).toHaveTextContent('The action was not confirmed'); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
    it('does not replay or recover a canceled or uncertain mutation and clears file state', async () => {
        const delayed = defer<OfflineCatalogView>(); vi.mocked(mutateRaw).mockReturnValue(delayed.promise); await showCatalog(); await choose(); fireEvent.click(importButton());
        const signal = vi.mocked(mutateRaw).mock.calls[0][3]!; fireEvent.click(screen.getByRole('button', { name: 'Cancel request' })); expect(signal.aborted).toBe(true);
        await act(async () => delayed.resolve({ ...catalog(true), revision: nextRevision })); expect(screen.queryByText('Rules in file')).not.toBeInTheDocument(); expect(screen.queryByLabelText('Choose JSON file')).not.toBeInTheDocument(); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
    it('clears an actually in-flight file read on pagehide and ignores a late FileReader callback', async () => {
        let delayedReader!: FileReader;
        vi.spyOn(FileReader.prototype, 'readAsArrayBuffer').mockImplementation(function (this: FileReader) { delayedReader = this; });
        const abort = vi.spyOn(FileReader.prototype, 'abort');
        await showCatalog(); fireEvent.change(screen.getByLabelText('Choose JSON file'), { target: { files: [new File([raw], 'private.json')] } });
        expect(screen.getByText('Reading selected file…')).toBeVisible(); act(() => window.dispatchEvent(new Event('pagehide'))); expect(abort).toHaveBeenCalled();
        Object.defineProperty(delayedReader, 'result', { value: new TextEncoder().encode(raw).buffer });
        act(() => delayedReader.onload?.call(delayedReader, new ProgressEvent('load') as ProgressEvent<FileReader>));
        expect(screen.queryByLabelText('Choose JSON file')).not.toBeInTheDocument();
        act(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }))); await screen.findByText('Import a normalized JSON catalog'); openImport(); expect(importButton()).toBeDisabled(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('clears selection on route change while allowing a still-mounted panel to refresh', async () => {
        await showCatalog(); await choose(); act(() => window.dispatchEvent(new Event('hashchange'))); expect(screen.queryByLabelText('Choose JSON file')).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Refresh catalog status' })); await screen.findByText('Import a normalized JSON catalog'); openImport(); expect(importButton()).toBeDisabled(); expect(request).toHaveBeenCalledTimes(2);
    });
    it('clears an upload immediately on authentication loss and rejects a late success', async () => {
        const delayed = defer<OfflineCatalogView>(); vi.mocked(mutateRaw).mockReturnValue(delayed.promise); await showCatalog(); await choose(); fireEvent.click(importButton());
        const signal = vi.mocked(mutateRaw).mock.calls[0][3]!; act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); expect(signal.aborted).toBe(true);
        await act(async () => delayed.resolve({ ...catalog(true), revision: nextRevision })); expect(screen.queryByText('Rules in file')).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Refresh catalog status' })).toBeDisabled();
    });
    it('expires an existing file selection with monotonic lease time', async () => {
        vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'performance', 'Date'] });
        vi.spyOn(FileReader.prototype, 'readAsArrayBuffer').mockImplementation(function (this: FileReader) {
            const buffer = new ArrayBuffer(raw.length); new Uint8Array(buffer).set(new TextEncoder().encode(raw));
            Object.defineProperty(this, 'result', { value: buffer });
            this.onload?.call(this, new ProgressEvent('load') as ProgressEvent<FileReader>);
        });
        vi.mocked(request).mockResolvedValue(catalog()); render(<OfflineCatalogPanel/>); await act(async () => {}); openImport();
        fireEvent.change(screen.getByLabelText('Choose JSON file'), { target: { files: [new File([raw], 'private.json')] } }); expect(importButton()).toBeEnabled();
        await act(async () => { await vi.advanceTimersByTimeAsync(SECURITY_VIEW_LEASE_MS + 1); });
        expect(screen.getByRole('alert')).toHaveTextContent('Status needs refreshing'); expect(screen.queryByLabelText('Choose JSON file')).not.toBeInTheDocument(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('times out an unconfirmed write with no automatic retry', async () => {
        await showCatalog(); await choose(); vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] }); vi.mocked(mutateRaw).mockReturnValue(new Promise(() => {}));
        fireEvent.click(importButton()); const signal = vi.mocked(mutateRaw).mock.calls[0][3]!; await act(async () => { await vi.advanceTimersByTimeAsync(15001); });
        expect(signal.aborted).toBe(true); expect(screen.getByRole('alert')).toHaveTextContent('The action was not confirmed'); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
    it('invalidates catalog state when sessionKey changes and never reuses selected text', async () => {
        vi.mocked(request).mockResolvedValue(catalog()); const rendered = render(<OfflineCatalogPanel sessionKey="old"/>); await screen.findByText('Import a normalized JSON catalog'); openImport(); await choose();
        rendered.rerender(<OfflineCatalogPanel sessionKey="new"/>); await screen.findByText('Import a normalized JSON catalog'); openImport(); expect(importButton()).toBeDisabled(); expect(mutateRaw).not.toHaveBeenCalled();
    });
});
