import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { useEffect } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { AuthBoundary } from './auth';
import { setLocale } from './i18n';
import { OfflineCatalogPanel } from './security-coverage';
import { effectiveSecurityFreshness, validOfflineCatalogView, validSecurityCoverageView } from './security-coverage-types';
import type { OfflineCatalogView, SecurityCoverageView } from './security-coverage-types';

// Independent fixtures use invented identifiers and metadata only. No browser
// or external endpoint is used; fetch is replaced with bounded Response streams.
const at = '2026-10-04T00:00:00Z';
const revision = `revision_${'1'.repeat(32)}`;
const json = (value: unknown) => new Response(JSON.stringify(value));
function catalog(): OfflineCatalogView {
    return { schemaVersion: 'tracebolt.offline-catalog.v1', enabled: true, serverNow: at, revision, storage: 'memory-only', resetsOnRestart: true, limits: { maxBytes: 2097152, maxRules: 10000, maxInFlight: 1 }, catalog: { id: `catalog_${'2'.repeat(32)}`, sha256: '3'.repeat(64), format: 'debian-tracker-normalized-1', provider: 'debian-security-tracker', declaredRelease: 'trixie', importedAt: at, publishedAt: null, freshness: 'unknown', originAssurance: 'unverified', synthetic: false, byteCount: 1234, ruleCount: 0, coveredSourceCount: 1 } };
}
function coverage(): SecurityCoverageView {
    return { schemaVersion: 'tracebolt.security-coverage.v1', deviceId: 'agent_review', serverNow: at, maxAgeSeconds: 120, receivedAt: at, collectionStatus: 'fresh', inventory: { coverage: 'observed', freshness: 'fresh', reportedItemCount: 0, observedCount: 0, installedCount: 0, countExact: true, truncated: false, collectedAt: at, generationId: `sample_${'4'.repeat(32)}`, scope: 'reported-installed-binary-packages', originAssurance: 'unverified' }, catalog: { configured: true, revision, sha256: '3'.repeat(64), originAssurance: 'unverified', freshness: 'unknown' }, offeredUpdates: { coverage: 'unknown', offeredCount: null, reason: 'native_update_adapter_unimplemented' }, vulnerabilities: { coverage: 'unknown', affectedCves: null, reviewCandidates: null, reasonCodes: ['advisory_authority_unverified', 'source_package_mapping_unavailable', 'client_release_unverified', 'installed_artifact_origin_unverified'] } };
}
afterEach(() => { cleanup(); abortProtectedRequests(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('independent offline HTTP client boundary', () => {
    it('retains raw JSON including BOM and duplicate keys and sets controlled credentials/headers', async () => {
        const raw = '\ufeff{"schema":"first","schema":"second"}\n';
        const fetch = vi.fn().mockResolvedValueOnce(json({ csrfToken: 'review-token' })).mockResolvedValueOnce(json(catalog()));
        vi.stubGlobal('fetch', fetch);
        await expect(mutateRaw('/security/catalog', raw, { 'X-Tracebolt-Catalog-Revision': revision })).resolves.toEqual(catalog());
        expect(fetch.mock.calls.map(call => call[0])).toEqual(['/api/session', '/api/security/catalog']);
        expect(fetch.mock.calls[1][1]).toEqual({ signal: expect.any(AbortSignal), credentials: 'same-origin', method: 'POST', headers: { Accept: 'application/json', 'X-Tracebolt-Catalog-Revision': revision, 'Content-Type': 'application/json', 'X-CSRF-Token': 'review-token' }, body: raw });
    });
    it('caps UTF-8 bytes before requesting a session, rather than character count', async () => {
        const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
        await expect(mutateRaw('/security/catalog', '€'.repeat(699051))).rejects.toMatchObject({ status: 400 });
        expect(fetch).not.toHaveBeenCalled();
    });
    it.each(['X-CSRF-Token', 'Origin', 'Cookie', 'Authorization', 'Content-Type', 'x-tracebolt-catalog-revision'])('rejects caller-controlled %s before any request', async header => {
        const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
        await expect(mutateRaw('/security/catalog', '{}', { [header]: 'review-ignored' })).rejects.toMatchObject({ status: 400 });
        expect(fetch).not.toHaveBeenCalled();
    });
    it('cancels a chunked oversized response as soon as the byte budget is crossed', async () => {
        const cancel = vi.fn();
        const stream = new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(new Uint8Array(17)); controller.enqueue(new Uint8Array(17)); }, cancel });
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(stream)));
        await expect(request('/security/catalog', undefined, 32)).rejects.toThrow();
        expect(cancel).toHaveBeenCalledOnce();
    });
    it('uses actual streamed bytes even if Content-Length understates the body', async () => {
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(' '.repeat(33), { headers: { 'Content-Length': '1' } })));
        await expect(request('/security/catalog', undefined, 32)).rejects.toThrow();
    });
    it('revokes the protected epoch during CSRF body consumption before any raw write', async () => {
        let controller!: ReadableStreamDefaultController<Uint8Array>;
        const response = new Response(new ReadableStream<Uint8Array>({ start(value) { controller = value; } }));
        const fetch = vi.fn().mockResolvedValue(response); vi.stubGlobal('fetch', fetch);
        const operation = mutateRaw('/security/catalog', '{}').catch(error => error);
        await Promise.resolve(); await Promise.resolve();
        abortProtectedRequests();
        controller.enqueue(new TextEncoder().encode('{"csrfToken":"expired-review-token"}')); controller.close();
        await expect(operation).resolves.toHaveProperty('name', 'AbortError');
        expect(fetch).toHaveBeenCalledOnce();
    });
    it('signals 401 without consuming its response body or sending a write', async () => {
        const notify = vi.fn(); window.addEventListener(AUTH_REQUIRED_EVENT, notify);
        try {
            const fetch = vi.fn().mockResolvedValue(new Response('private-response-not-JSON', { status: 401 })); vi.stubGlobal('fetch', fetch);
            await expect(mutateRaw('/security/catalog', '{}')).rejects.toMatchObject({ status: 401 });
            expect(notify).toHaveBeenCalledOnce(); expect(fetch).toHaveBeenCalledOnce();
        } finally { window.removeEventListener(AUTH_REQUIRED_EVENT, notify); }
    });
});

describe('independent offline authority and coverage contracts', () => {
    it('accepts complete empty inventory while assessment and update counts remain null', () => {
        expect(validSecurityCoverageView(coverage(), 'agent_review')).toBe(true);
        expect(validOfflineCatalogView(catalog())).toBe(true);
    });
    it('rejects trust upgrades, source gaps hidden by duplicates, invented zeros and full totals from partial input', () => {
        const base = coverage();
        for (const view of [
            { ...base, inventory: { ...base.inventory, originAssurance: 'verified' } },
            { ...base, inventory: { ...base.inventory, coverage: 'partial', installedCount: 0 } },
            { ...base, catalog: { ...base.catalog, freshness: 'fresh' } },
            { ...base, vulnerabilities: { ...base.vulnerabilities, affectedCves: 0 } },
            { ...base, offeredUpdates: { ...base.offeredUpdates, offeredCount: 0 } },
            { ...base, vulnerabilities: { ...base.vulnerabilities, reasonCodes: ['advisory_authority_unverified', 'source_package_mapping_unavailable', 'source_package_mapping_unavailable', 'installed_artifact_origin_unverified'] } },
        ]) expect(validSecurityCoverageView(view, 'agent_review')).toBe(false);
        const imported = catalog();
        for (const extra of [{ coveredSourceCount: 0 }, { publishedAt: at }, { freshness: 'fresh' }, { originAssurance: 'vendor_signature_verified' }, { declaredRelease: 'noble' }, { profile: 'verified' }, { publicURL: 'https://example.invalid/private' }])
            expect(validOfflineCatalogView({ ...imported, catalog: { ...imported.catalog, ...extra } })).toBe(false);
    });
    it('rejects pre-expired and future evidence and cannot refresh stale evidence from elapsed time', () => {
        const base = coverage();
        for (const changes of [{ receivedAt: '2026-10-03T23:57:59Z' }, { receivedAt: '2026-10-04T00:00:01Z' }, { inventory: { ...base.inventory, collectedAt: '2026-10-03T23:57:59Z' } }, { inventory: { ...base.inventory, collectedAt: '2026-10-04T00:00:01Z' } }])
            expect(validSecurityCoverageView({ ...base, ...changes }, 'agent_review')).toBe(false);
        base.inventory.freshness = 'stale';
        for (const elapsed of [0, -Infinity, Infinity, -100000000, NaN]) expect(effectiveSecurityFreshness(base, elapsed)).toBe('stale');
    });
});

describe('independent main access epoch', () => {
    it('remounts a catalog form when the CSRF identity changes even with the same expiry time', async () => {
        setLocale('en', false); localStorage.clear(); sessionStorage.clear();
        const expiry = '2026-10-04T00:30:00Z';
        let token = 'synthetic-first-session', mounts = 0;
        const fetch = vi.fn().mockImplementation(async (path: string) => {
            if (path === '/api/auth/session') return json({ mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: token, serverNow: at, expiresAt: expiry, expiresInSeconds: 1800 });
            if (path === '/api/security/catalog') return json(catalog());
            throw new Error('Unexpected synthetic review route');
        });
        vi.stubGlobal('fetch', fetch);
        function Form() { useEffect(() => { mounts++; }, []); return <OfflineCatalogPanel/>; }
        render(<AuthBoundary><Form/></AuthBoundary>);
        fireEvent.click(await screen.findByText('Import a normalized JSON catalog'));
        fireEvent.change(screen.getByLabelText('Choose JSON file'), { target: { files: [new File(['{"schema":"synthetic-review"}'], 'private-review-file.json')] } });
        await waitFor(() => expect(screen.getByRole('button', { name: 'Replace current catalog' })).toBeEnabled());
        expect(mounts).toBe(1);
        act(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })));
        token = 'synthetic-second-session';
        act(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })));
        await waitFor(() => expect(mounts).toBe(2));
        fireEvent.click(await screen.findByText('Import a normalized JSON catalog'));
        expect(screen.getByRole('button', { name: 'Replace current catalog' })).toBeDisabled();
        expect(screen.queryByText(/JSON file selected/)).not.toBeInTheDocument();
        expect(fetch.mock.calls.every(call => call[1].method !== 'POST')).toBe(true);
    });
});
