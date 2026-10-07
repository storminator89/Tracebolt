import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { AdvisoryReviewPanel } from './advisory-review';
import { ADVISORY_REVIEW_RESPONSE_MAX_BYTES, advisoryReviewVisible, validAdvisoryReviewView } from './advisory-review-types';
import type { AdvisoryReviewView } from './advisory-review-types';

// Independent synthetic manager DTO, not imported from implementation-owner fixtures.
function responseView(): AdvisoryReviewView {
    return {
        schemaVersion: 'tracebolt.advisory-review-view.v1', deviceId: 'agent_review_independent',
        serverNow: '2026-10-04T00:00:20Z', maxAgeSeconds: 120, collectionStatus: 'fresh',
        receivedAt: '2026-10-04T00:00:10Z', sequence: 7,
        review: {
            schemaVersion: 'tracebolt.offline-review.v1', scope: 'conditional-reported-source-catalog-review', status: 'complete',
            reasonCodes: ['catalog_origin_unverified', 'catalog_freshness_unknown', 'installed_artifact_origin_unknown', 'snapshot_freshness_not_evaluated'],
            revision: `revision_${'8'.repeat(32)}`,
            catalog: { id: `catalog_${'9'.repeat(32)}`, sha256: 'a'.repeat(64), format: 'debian-tracker-normalized-1', provider: 'debian-security-tracker', declaredRelease: 'trixie', importedAt: '2026-10-04T00:00:00Z', publishedAt: null, freshness: 'unknown', originAssurance: 'unverified', synthetic: false, byteCount: 900, ruleCount: 1, coveredSourceCount: 1 },
            catalogUsage: 'unverified-conditional-review',
            snapshot: { generationId: `sample_${'b'.repeat(32)}`, collectedAt: '2026-10-04T00:00:05Z', release: { id: 'debian', versionId: '13', versionCodename: 'trixie' }, inventoryComplete: true, inventoryRows: 1 },
            installedArtifactOrigin: 'unknown', snapshotFreshness: 'unknown',
            candidates: [{ package: 'independent-binary', architecture: 'arm64', reportedSourcePackage: 'independent-source', reportedSourceVersion: '00002:1.0~rc1-1+b7', sourceMapping: 'source-field', advisoryId: 'INDEPENDENT-2099-001', declaredStatus: 'resolved', declaredFixedVersion: '2:1.0-1+deb13u1', qualifications: ['no-dsa'], basis: 'conditional_reported_source_below_declared_fix', reason: 'reported_source_below_declared_fix' }],
            affectedCves: null, offeredUpdates: null, pairsInspected: 1, comparisons: 1,
            limits: { maxRows: 128, maxPairs: 4096, maxComparisons: 1024, maxBytes: 65536 },
        },
    };
}
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: '2026-10-04T00:30:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
function json(value: unknown) { return new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } }); }
function expand() { fireEvent.click(screen.getByRole('button', { name: 'Conditional advisory review candidates' })); }
function mount() { const value = render(<AdvisoryReviewPanel deviceId="agent_review_independent"/>); expand(); return value; }
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }
beforeEach(() => { setLocale('en', false); vi.mocked(useOperator).mockReturnValue(operator); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('independent conditional review boundary', () => {
    it('accepts exactly 65 KiB of UTF-8 wire bytes while preserving source versions and null counts', async () => {
        const raw = JSON.stringify(responseView());
        const wire = raw + ' '.repeat(ADVISORY_REVIEW_RESPONSE_MAX_BYTES - new TextEncoder().encode(raw).byteLength);
        expect(new TextEncoder().encode(wire)).toHaveLength(66560);
        const fetch = vi.fn().mockResolvedValue(new Response(wire)); vi.stubGlobal('fetch', fetch);
        const storage = vi.spyOn(Storage.prototype, 'setItem'); mount();
        await screen.findByRole('article');
        expect(screen.getByText('00002:1.0~rc1-1+b7')).toBeVisible();
        expect(screen.getByText('2:1.0-1+deb13u1')).toBeVisible();
        expect(screen.getByText(/Affected CVEs and available updates remain unknown./)).toBeVisible();
        expect(fetch).toHaveBeenCalledExactlyOnceWith('/api/devices/agent_review_independent/security/review', expect.objectContaining({ credentials: 'same-origin', headers: { Accept: 'application/json' } }));
        expect(storage).not.toHaveBeenCalled();
    });

    it.each([undefined, '1'])('rejects 65 KiB plus one byte even with Content-Length %s', async length => {
        const raw = JSON.stringify(responseView()), cancel = vi.fn();
        const wire = new TextEncoder().encode(raw + ' '.repeat(66561 - raw.length));
        const stream = new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(wire.subarray(0, 66560)); controller.enqueue(wire.subarray(66560)); }, cancel });
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(stream, { headers: length ? { 'Content-Length': length } : {} })));
        mount(); expect(await screen.findByRole('alert')).toHaveTextContent('could not be read');
        expect(cancel).toHaveBeenCalledOnce(); expect(screen.queryByRole('article')).not.toBeInTheDocument();
        expect(document.body.textContent).not.toContain('independent-source');
    });

    it('keeps accepted URL-like catalog tokens inert and rejects markup rather than creating links', async () => {
        const value = responseView(); value.review!.candidates[0].advisoryId = 'https://example.invalid/advisory';
        value.review!.candidates[0].qualifications = ['javascript:alert', 'https://example.invalid/qualification'];
        const fetch = vi.fn().mockResolvedValue(json(value)); vi.stubGlobal('fetch', fetch); mount();
        await screen.findByRole('article');
        expect(screen.getByText('javascript:alert, https://example.invalid/qualification')).toBeVisible();
        expect(document.querySelectorAll('a, iframe, script, img')).toHaveLength(0);
        value.review!.candidates[0].advisoryId = '<img src=x onerror=alert(1)>';
        fetch.mockResolvedValue(json(value)); fireEvent.click(screen.getByRole('button', { name: 'Refresh review candidates' }));
        expect(await screen.findByRole('alert')).toHaveTextContent('unsupported or inconsistent');
        expect(document.querySelectorAll('a, iframe, script, img')).toHaveLength(0);
        expect(screen.queryByRole('article')).not.toBeInTheDocument();
    });

    it.each([
        { id: null, versionId: '', versionCodename: 'trixie', reason: 'release_facts_missing' as const },
        { id: 'ubuntu', versionId: '24.04', versionCodename: 'noble', reason: 'unsupported_release' as const },
    ])('retains exact unavailable release evidence %j without live candidate rows', async fields => {
        const value = responseView(), review = value.review!;
        Object.assign(review, { status: 'unavailable', candidates: [], pairsInspected: 0, comparisons: 0 });
        review.reasonCodes.push(fields.reason); review.snapshot.release = { id: fields.id, versionId: fields.versionId, versionCodename: fields.versionCodename };
        expect(validAdvisoryReviewView(value, value.deviceId)).toBe(true);
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(value))); mount();
        const facts = await screen.findByRole('region', { name: 'Exact reported release fields' });
        for (const field of [fields.id ?? 'Absent field', fields.versionId || 'Explicitly empty field', fields.versionCodename]) expect(within(facts).getByText(field)).toBeVisible();
        expect(screen.queryByRole('article')).not.toBeInTheDocument();
        expect(screen.getByText(/No review candidate rows were returned/)).toHaveTextContent('not evidence of zero affected CVEs');
    });

    it('never treats a complete empty review as zero affected CVEs or offered updates', async () => {
        const value = responseView(), review = value.review!;
        Object.assign(review, { candidates: [], pairsInspected: 0, comparisons: 0 }); review.snapshot.inventoryRows = 0;
        expect(validAdvisoryReviewView(value, value.deviceId)).toBe(true);
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(value))); mount();
        await screen.findByText('Selected-scope inspection completed');
        expect(screen.getByText(/Affected CVEs and available updates remain unknown./)).toBeVisible();
        expect(screen.getByText(/No review candidate rows were returned/)).toHaveTextContent('not evidence of zero affected CVEs');
        expect(screen.queryByRole('article')).not.toBeInTheDocument();
    });

    it('keeps collection and receipt nanoseconds distinct and rejects future evidence', () => {
        const value = responseView(); value.serverNow = '2026-10-04T00:02:05.000000001Z';
        expect(validAdvisoryReviewView(value, value.deviceId)).toBe(false);
        value.serverNow = '2026-10-04T00:02:05Z'; expect(validAdvisoryReviewView(value, value.deviceId)).toBe(true);
        expect(advisoryReviewVisible(value, 0)).toBe(true); expect(advisoryReviewVisible(value, 0.000001)).toBe(false);
        value.serverNow = '2026-10-04T00:00:20Z'; value.receivedAt = '2026-10-04T00:00:20.000000001Z';
        expect(validAdvisoryReviewView(value, value.deviceId)).toBe(false);
    });

    it.each(['reportedSourcePackage', 'reportedSourceVersion', 'sourceMapping'] as const)('rejects mutually inconsistent %s for a single binary/architecture identity', field => {
        const value = responseView(), review = value.review!;
        review.catalog!.ruleCount = 2; review.pairsInspected = 2; review.comparisons = 2;
        const first = review.candidates[0];
        if (field === 'sourceMapping') first.reportedSourcePackage = first.package;
        const second = { ...first, advisoryId: 'INDEPENDENT-2099-002', qualifications: [...first.qualifications] };
        if (field === 'reportedSourcePackage') second.reportedSourcePackage = 'different-source';
        if (field === 'reportedSourceVersion') second.reportedSourceVersion = '2:0.5-1';
        if (field === 'sourceMapping') second.sourceMapping = 'binary-default';
        review.candidates.push(second);
        expect(validAdvisoryReviewView(value, value.deviceId)).toBe(false);
    });

    it.each(['declaredStatus', 'declaredFixedVersion', 'qualifications'] as const)('rejects contradictory %s for one declared source/advisory rule', field => {
        const value = responseView(), review = value.review!;
        review.snapshot.inventoryRows = 2; review.pairsInspected = 2; review.comparisons = 2;
        const second = { ...review.candidates[0], package: 'independent-other', qualifications: ['no-dsa'] };
        if (field === 'declaredStatus') { second.declaredStatus = 'open'; second.declaredFixedVersion = ''; second.basis = 'declared_unresolved'; second.reason = 'declared_status_requires_review'; review.comparisons = 1; }
        if (field === 'declaredFixedVersion') second.declaredFixedVersion = '2:1.1-1';
        if (field === 'qualifications') second.qualifications = ['postponed'];
        review.candidates.push(second);
        expect(validAdvisoryReviewView(value, value.deviceId)).toBe(false);
    });

    it('preserves legitimate source-version differences across distinct architectures', () => {
        const value = responseView(), review = value.review!;
        review.snapshot.inventoryRows = 2; review.pairsInspected = 2; review.comparisons = 2;
        review.candidates[0].architecture = 'amd64';
        review.candidates.push({ ...review.candidates[0], architecture: 'arm64', reportedSourceVersion: '00002:0.9-1', qualifications: ['no-dsa'] });
        expect(validAdvisoryReviewView(value, value.deviceId)).toBe(true);
    });

    it('allows different advisory rules for the same source to retain different declarations', () => {
        const value = responseView(), review = value.review!;
        review.catalog!.ruleCount = 2; review.pairsInspected = 2; review.comparisons = 2;
        review.candidates.push({ ...review.candidates[0], advisoryId: 'INDEPENDENT-2099-002', declaredFixedVersion: '2:1.2-1', qualifications: ['postponed'] });
        expect(validAdvisoryReviewView(value, value.deviceId)).toBe(true);
    });
});

describe('independent actual-request lifecycle', () => {
    it('subtracts pending-request time from the strict sixty-second display lease', async () => {
        vi.useFakeTimers(); const pending = deferred<Response>(); vi.stubGlobal('fetch', vi.fn().mockReturnValue(pending.promise)); mount();
        await act(async () => vi.advanceTimersByTimeAsync(9000));
        await act(async () => pending.resolve(json(responseView()))); expect(screen.getByRole('article')).toBeVisible();
        await act(async () => vi.advanceTimersByTimeAsync(50999)); expect(screen.getByRole('article')).toBeVisible();
        await act(async () => vi.advanceTimersByTimeAsync(1)); expect(screen.queryByRole('article')).not.toBeInTheDocument();
        expect(screen.getByRole('alert')).toHaveTextContent('expired or its time anchor changed');
    });

    it('never flashes candidates when request latency consumes remaining collection freshness', async () => {
        vi.useFakeTimers(); const value = responseView(); value.serverNow = '2026-10-04T00:02:04Z';
        const pending = deferred<Response>(); vi.stubGlobal('fetch', vi.fn().mockReturnValue(pending.promise)); mount();
        await act(async () => vi.advanceTimersByTimeAsync(2000)); await act(async () => pending.resolve(json(value)));
        expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('expired or its time anchor changed');
        expect(document.body.textContent).not.toContain('independent-source');
    });

    it('revokes an in-flight actual helper response on protected-session epoch change', async () => {
        let body!: ReadableStreamDefaultController<Uint8Array>;
        const fetch = vi.fn().mockResolvedValue(new Response(new ReadableStream<Uint8Array>({ start(controller) { body = controller; } })));
        vi.stubGlobal('fetch', fetch); mount(); await act(async () => {});
        const signal = fetch.mock.calls[0][1].signal as AbortSignal;
        act(() => abortProtectedRequests()); expect(signal.aborted).toBe(true);
        await act(async () => { body.enqueue(new TextEncoder().encode(JSON.stringify(responseView()))); body.close(); });
        expect(screen.queryByRole('article')).not.toBeInTheDocument(); expect(document.body.textContent).not.toContain('independent-source');
    });

    it('keeps the newly opened session independent of a closed session and its late response', async () => {
        const old = deferred<Response>(); const newer = responseView(); newer.review!.snapshot.generationId = `sample_${'c'.repeat(32)}`;
        const fetch = vi.fn().mockReturnValueOnce(old.promise).mockResolvedValueOnce(json(newer)); vi.stubGlobal('fetch', fetch);
        const mounted = mount(); const oldSignal = fetch.mock.calls[0][1].signal as AbortSignal;
        mounted.rerender(<AdvisoryReviewPanel deviceId="agent_review_independent" sessionKey="new-private-session"/>);
        expect(oldSignal.aborted).toBe(true); expect(screen.getByRole('button', { name: 'Conditional advisory review candidates' })).toHaveAttribute('aria-expanded', 'false');
        expand(); await screen.findByText(`sample_${'c'.repeat(32)}`);
        await act(async () => old.resolve(json(responseView())));
        expect(screen.getByText(`sample_${'c'.repeat(32)}`)).toBeVisible(); expect(screen.queryByText(`sample_${'b'.repeat(32)}`)).not.toBeInTheDocument();
    });

    it('replaces BFCache-hidden rows only after the new response validates', async () => {
        const pending = deferred<Response>(); const fetch = vi.fn().mockResolvedValueOnce(json(responseView())).mockReturnValueOnce(pending.promise); vi.stubGlobal('fetch', fetch);
        mount(); await screen.findByRole('article');
        act(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })));
        expect(screen.queryByRole('article')).not.toBeInTheDocument();
        act(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })));
        expect(fetch).toHaveBeenCalledTimes(2); expect(screen.queryByRole('article')).not.toBeInTheDocument();
        const invalid = responseView(); invalid.deviceId = 'agent_other'; await act(async () => pending.resolve(json(invalid)));
        expect(screen.getByRole('alert')).toHaveTextContent('unsupported or inconsistent'); expect(document.body.textContent).not.toContain('independent-source');
    });
});
