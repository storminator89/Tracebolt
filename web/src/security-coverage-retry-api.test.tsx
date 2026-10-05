import { act, cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, mutateRaw, request } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { SecurityCoveragePanel } from './security-coverage';
import { SECURITY_RESPONSE_MAX_BYTES } from './security-coverage-types';
import type { SecurityCoverageView } from './security-coverage-types';
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
const busy = () => json({ error: { code: 'storage_busy', message: 'private path must not render' } }, 429);
const advance = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
function coverage(): SecurityCoverageView {
    return { schemaVersion: 'tracebolt.security-coverage.v1', deviceId: 'agent_fixture', serverNow: '2026-10-04T00:00:10Z', maxAgeSeconds: 120, receivedAt: null, collectionStatus: 'not_configured', inventory: { coverage: 'unknown', freshness: 'unknown', reportedItemCount: null, installedCount: null, observedCount: null, countExact: false, truncated: false, collectedAt: null, generationId: null, scope: 'reported-installed-binary-packages', originAssurance: 'unverified' }, catalog: { configured: false, revision: `revision_${'a'.repeat(32)}`, sha256: null, originAssurance: 'unverified', freshness: 'unknown' }, offeredUpdates: { coverage: 'unknown', offeredCount: null, reason: 'native_update_adapter_unimplemented' }, vulnerabilities: { coverage: 'unknown', affectedCves: null, reviewCandidates: null, reasonCodes: ['advisory_snapshot_unavailable', 'source_package_mapping_unavailable', 'client_release_unverified', 'installed_artifact_origin_unverified'] } };
}
async function mount() { const mounted = render(<SecurityCoveragePanel deviceId="agent_fixture"/>); await act(async () => {}); return mounted; }
beforeEach(() => { vi.useFakeTimers(); setLocale('en', false); vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, expiresAt: '2026-10-04T00:30:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() }); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('coverage recovery uses exact bounded API errors within the original access scope', () => {
    it('recovers a real bounded 429 response with exactly two same-origin GETs', async () => {
        const fetch = vi.fn().mockResolvedValueOnce(busy()).mockResolvedValueOnce(json(coverage())); vi.stubGlobal('fetch', fetch); await mount();
        expect(screen.getByRole('status')).toHaveTextContent('Storage is busy'); expect(screen.queryByRole('article')).not.toBeInTheDocument(); await advance(2000); expect(screen.getByText('Collection not configured')).toBeVisible();
        expect(fetch).toHaveBeenCalledTimes(2); for (const [url, options] of fetch.mock.calls) { expect(url).toBe('/api/devices/agent_fixture/security'); expect(options).toMatchObject({ credentials: 'same-origin', headers: { Accept: 'application/json' }, signal: expect.any(AbortSignal) }); expect(options.method).toBeUndefined(); expect(options.body).toBeUndefined(); }
        expect(document.body.textContent).not.toContain('private path');
    });
    it.each([undefined, 'review_busy', 'STORAGE_BUSY', 'storage_busy ', ['storage_busy'], { code: 'storage_busy' }])('does not promote a malformed or different machine code %j to a retry', async code => {
        const fetch = vi.fn().mockResolvedValue(json({ error: { code, message: 'storage_busy' } }, 429)); vi.stubGlobal('fetch', fetch); await mount(); await advance(3000);
        expect(fetch).toHaveBeenCalledTimes(1); expect(screen.getByRole('alert')).toHaveTextContent('Refresh security coverage to try again');
    });
    it.each(['json', 'utf8', 'oversized'] as const)('does not recover a retry code from a malformed %s body', async kind => {
        const response = kind === 'json' ? new Response('{"error":{"code":"storage_busy"}', { status: 429 }) : kind === 'utf8' ? new Response(new Uint8Array([255]), { status: 429 }) : new Response(JSON.stringify({ error: { code: 'storage_busy' } }) + ' '.repeat(SECURITY_RESPONSE_MAX_BYTES), { status: 429 });
        const fetch = vi.fn().mockResolvedValue(response); vi.stubGlobal('fetch', fetch); await mount(); await advance(3000);
        expect(fetch).toHaveBeenCalledTimes(1); expect(screen.getByRole('alert')).toHaveTextContent('Refresh security coverage to try again');
    });
    it('keeps code and status separate so a 403 storage_busy cannot retry', async () => {
        const fetch = vi.fn().mockResolvedValue(json({ error: { code: 'storage_busy' } }, 403)); vi.stubGlobal('fetch', fetch); await mount(); await advance(3000);
        expect(fetch).toHaveBeenCalledTimes(1); expect(screen.getByRole('alert')).toHaveTextContent('Current status could not be confirmed');
    });
    it('refuses retry when logout changes the protected epoch between completed HTTP requests', async () => {
        const fetch = vi.fn().mockResolvedValueOnce(busy()).mockResolvedValueOnce(json(coverage())); vi.stubGlobal('fetch', fetch); await mount(); expect(fetch).toHaveBeenCalledTimes(1);
        act(() => abortProtectedRequests()); await advance(3000); expect(fetch).toHaveBeenCalledTimes(1); expect(screen.getByRole('alert')).toHaveTextContent('session has ended'); expect(screen.queryByRole('article')).not.toBeInTheDocument();
    });
    it('locks the panel when the retry gets a real 401 and never starts a third read', async () => {
        const fetch = vi.fn().mockResolvedValueOnce(busy()).mockResolvedValueOnce(json({ error: { code: 'storage_busy' } }, 401)); vi.stubGlobal('fetch', fetch); await mount(); await advance(2000);
        expect(screen.getByRole('alert')).toHaveTextContent('session has ended'); expect(screen.getByRole('button', { name: 'Refresh security coverage' })).toBeDisabled(); await advance(3000); expect(fetch).toHaveBeenCalledTimes(2);
    });
    it('does not replay catalog imports or add retries to the generic API helper', async () => {
        const fetch = vi.fn().mockResolvedValueOnce(json({ csrfToken: 'synthetic-csrf-fixture' })).mockResolvedValueOnce(busy()); vi.stubGlobal('fetch', fetch);
        await expect(mutateRaw('/security/catalog', '{"synthetic":true}', { 'X-Tracebolt-Catalog-Revision': `revision_${'a'.repeat(32)}` }, undefined, SECURITY_RESPONSE_MAX_BYTES)).rejects.toMatchObject({ status: 429, code: 'storage_busy' });
        await advance(3000); expect(fetch).toHaveBeenCalledTimes(2); expect(fetch.mock.calls[0][0]).toBe('/api/session'); expect(fetch.mock.calls[1][1]).toMatchObject({ method: 'POST' });
    });
    it('does not add automatic retries to page GETs', async () => {
        const fetch = vi.fn().mockResolvedValueOnce(busy()); vi.stubGlobal('fetch', fetch);
        await expect(request('/devices/agent_fixture/packages/complete?cursor=synthetic', undefined, SECURITY_RESPONSE_MAX_BYTES)).rejects.toMatchObject({ status: 429, code: 'storage_busy' }); await advance(3000); expect(fetch).toHaveBeenCalledTimes(1);
    });
});
