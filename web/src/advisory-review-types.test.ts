import { describe, expect, it } from 'vitest';
import { ADVISORY_REVIEW_MAX_BYTES, ADVISORY_REVIEW_RESPONSE_MAX_BYTES, advisoryReviewReasons, advisoryReviewVisible, validAdvisoryReviewView } from './advisory-review-types';
import type { AdvisoryReview, AdvisoryReviewCandidate } from './advisory-review-types';
import { reviewCandidate, reviewDeviceId, reviewResult, reviewView, syntheticReviewView } from './advisory-review-fixtures';
const valid = (value: unknown) => validAdvisoryReviewView(value, reviewDeviceId);
describe('strict conditional review contract', () => {
    it('accepts exact core output, unavailable catalog and synthetic catalog without live rows', () => {
        expect(valid(reviewView())).toBe(true); expect(valid(syntheticReviewView())).toBe(true);
        const value = reviewView(), r = value.review!; Object.assign(r, { catalog: null, catalogUsage: 'unavailable', status: 'unavailable', candidates: [], comparisons: 0, pairsInspected: 0, reasonCodes: ['installed_artifact_origin_unknown', 'snapshot_freshness_not_evaluated', 'catalog_unavailable'] }); expect(valid(value)).toBe(true);
        for (const field of ['affectedCves', 'offeredUpdates']) { const changed = reviewView(); Object.assign(changed.review!, { [field]: 0 }); expect(valid(changed)).toBe(false); }
    });
    it('requires all exact keys at every nested boundary and rejects unsolicited output', () => {
        const selectors = [(v: ReturnType<typeof reviewView>) => v, (v: ReturnType<typeof reviewView>) => v.review!, (v: ReturnType<typeof reviewView>) => v.review!.snapshot, (v: ReturnType<typeof reviewView>) => v.review!.snapshot.release, (v: ReturnType<typeof reviewView>) => v.review!.catalog!, (v: ReturnType<typeof reviewView>) => v.review!.limits, (v: ReturnType<typeof reviewView>) => v.review!.candidates[0]];
        for (const select of selectors) for (const key of [...Object.keys(select(reviewView())), 'externalUrl']) { const value = reviewView(), target = select(value) as unknown as Record<string, unknown>; if (key === 'externalUrl') target[key] = 'https://untrusted.invalid'; else delete target[key]; expect(valid(value), key).toBe(false); }
    });
    it('rejects changed schema, target, identifiers, trust claims, bounds and lifecycle', () => {
        for (const changed of [{ schemaVersion: 'other' }, { deviceId: 'agent_other' }, { review: null }, { sequence: 0 }, { sequence: 1.1 }, { sequence: Number.MAX_SAFE_INTEGER + 1 }, { sequence: null }, { receivedAt: null }, { maxAgeSeconds: 121 }, { collectionStatus: 'trusted' }, { serverNow: '2026-02-31T00:00:00Z' }, { serverNow: '2026-10-04T00:00:10+00:00' }]) expect(valid({ ...reviewView(), ...changed })).toBe(false);
        for (const status of ['not_configured', 'awaiting', 'stale', 'revoked', 'unavailable']) { expect(valid({ ...reviewView(), collectionStatus: status })).toBe(false); expect(valid({ ...reviewView(), collectionStatus: status, review: null, ...(status === 'not_configured' || status === 'awaiting' ? { sequence: null, receivedAt: null } : {}) })).toBe(true); }
        for (const changed of [{ scope: 'host-wide' }, { status: 'secure' }, { revision: 'revision_bad' }, { installedArtifactOrigin: 'verified' }, { snapshotFreshness: 'fresh' }, { catalogUsage: 'trusted' }, { pairsInspected: 4097 }, { comparisons: 1025 }, { pairsInspected: 0 }, { comparisons: -1 }]) { const value = reviewView(); Object.assign(value.review!, changed); expect(valid(value)).toBe(false); }
        for (const changed of [{ originAssurance: 'verified' }, { publishedAt: '2026-10-04T00:00:00Z' }, { sha256: 'z'.repeat(64) }, { freshness: 'fresh' }, { synthetic: true }, { importedAt: '2026-10-04T00:00:10.000000001Z' }]) { const value = reviewView(); Object.assign(value.review!.catalog!, changed); expect(valid(value)).toBe(false); }
        for (const key of Object.keys(reviewResult().limits)) { const value = reviewView(); Object.assign(value.review!.limits, { [key]: 1 }); expect(valid(value)).toBe(false); }
    });
    it('enforces nanosecond future and stale boundaries independently for receipt and collection', () => {
        for (const which of ['receivedAt', 'collectedAt']) for (const time of ['2026-10-04T00:00:10.000000001Z', '2026-10-03T23:58:09.999999999Z']) { const value = reviewView(); if (which === 'receivedAt') value.receivedAt = time; else value.review!.snapshot.collectedAt = time; expect(valid(value)).toBe(false); }
        const value = reviewView(); value.serverNow = '2026-10-04T00:02:00Z'; expect(valid(value)).toBe(true); expect(advisoryReviewVisible(value, 0)).toBe(true); expect(advisoryReviewVisible(value, 0.000001)).toBe(false);
        expect(advisoryReviewVisible(reviewView(), 59999)).toBe(true); for (const elapsed of [60000, NaN, Infinity, -1]) expect(advisoryReviewVisible(reviewView(), elapsed)).toBe(false);
    });
    it('rejects unsafe tokens, oversized fields, bad mappings, basis contradictions, duplicate and unordered rows', () => {
        const changes: Partial<AdvisoryReviewCandidate>[] = [{ package: 'x' }, { reportedSourcePackage: '<img>' }, { reportedSourceVersion: 'v1' }, { reportedSourceVersion: '1'.repeat(513) }, { architecture: 'any-amd64' }, { architecture: 'source' }, { architecture: 'x'.repeat(65) }, { sourceMapping: 'binary-default' }, { advisoryId: '<script>' }, { advisoryId: 'x'.repeat(129) }, { declaredStatus: 'x\n' }, { declaredFixedVersion: '0' }, { declaredFixedVersion: '1-' }, { qualifications: Array(17).fill('no-dsa') }, { qualifications: ['javascript:<script>'] }, { reason: 'declared_status_requires_review' }, { basis: 'declared_unresolved' }];
        for (const changed of changes) { const value = reviewView(); Object.assign(value.review!.candidates[0], changed); expect(valid(value), JSON.stringify(changed)).toBe(false); }
        for (const rows of [[reviewCandidate(), reviewCandidate()], [{ ...reviewCandidate(), package: 'zz-package' }, reviewCandidate()]]) { const value = reviewView(); value.review!.candidates = rows; value.review!.pairsInspected = 2; expect(valid(value)).toBe(false); }
        const fallback = reviewView(); Object.assign(fallback.review!.candidates[0], { sourceMapping: 'binary-default', reportedSourcePackage: 'fixture-binary' }); expect(valid(fallback)).toBe(true);
    });
    it('accepts unresolved and failed comparison candidates only with coherent status and reasons', () => {
        for (const declaredStatus of ['open', 'undetermined']) { const value = reviewView(); Object.assign(value.review!.candidates[0], { declaredStatus, declaredFixedVersion: '', basis: 'declared_unresolved', reason: 'declared_status_requires_review' }); value.review!.comparisons = 0; expect(valid(value)).toBe(true); }
        for (const reason of ['comparator_unavailable', 'comparison_failed', 'declared_rule_uninterpretable'] as const) { const value = reviewView(), r = value.review!; r.status = 'partial'; r.reasonCodes.push(reason); Object.assign(r.candidates[0], { basis: 'comparison_unavailable', reason, ...(reason === 'declared_rule_uninterpretable' ? { declaredStatus: 'future-status', declaredFixedVersion: '' } : {}) }); expect(valid(value)).toBe(true); r.status = 'complete'; expect(valid(value)).toBe(false); }
    });
    it('requires fixed unique reasons, explicit partial inventory, unavailable prerequisites and synthetic suppression', () => {
        for (const reasonCodes of [[], [...reviewResult().reasonCodes, 'raw /private/error'], [...reviewResult().reasonCodes, 'catalog_freshness_unknown']]) { const value = reviewView(); Object.assign(value.review!, { reasonCodes }); expect(valid(value)).toBe(false); }
        for (const reason of advisoryReviewReasons.filter(reason => ['inventory_partial', 'package_installation_incomplete', 'source_package_not_covered', 'review_row_limit', 'review_pair_limit', 'review_comparison_limit', 'review_byte_limit'].includes(reason))) { const value = reviewView(); value.review!.status = 'partial'; value.review!.reasonCodes.push(reason); if (reason === 'inventory_partial') value.review!.snapshot.inventoryComplete = false; expect(valid(value), reason).toBe(true); }
        const partial = reviewView(); partial.review!.snapshot.inventoryComplete = false; expect(valid(partial)).toBe(false);
        const synthetic = syntheticReviewView(); synthetic.review!.candidates = [reviewCandidate()]; synthetic.review!.pairsInspected = 1; expect(valid(synthetic)).toBe(false);
        const unavailable = reviewView(); Object.assign(unavailable.review!, { status: 'unavailable', candidates: [], pairsInspected: 0, comparisons: 0 }); expect(valid(unavailable)).toBe(false); unavailable.review!.reasonCodes.push('inventory_unavailable'); expect(valid(unavailable)).toBe(true);
    });
    it('accepts exactly the canonical 64 KiB core limit and rejects one byte more', () => {
        const value = reviewView(), r = value.review!; r.pairsInspected = 64; r.comparisons = 64; r.catalog!.ruleCount = 64; r.candidates = Array.from({ length: 64 }, (_, i) => ({ ...reviewCandidate(), advisoryId: `A-${String(i).padStart(4, '0')}`, reportedSourceVersion: '1'.repeat(512), declaredFixedVersion: '2'.repeat(512) }));
        const size = () => new TextEncoder().encode(JSON.stringify(r)).byteLength;
        while (size() > ADVISORY_REVIEW_MAX_BYTES) { const row = r.candidates.find(row => row.declaredFixedVersion.length > 1)!; row.declaredFixedVersion = row.declaredFixedVersion.slice(0, -1); }
        expect(size()).toBe(ADVISORY_REVIEW_MAX_BYTES); expect(valid(value)).toBe(true); r.candidates.find(row => row.declaredFixedVersion.length < 512)!.declaredFixedVersion += '1'; expect(size()).toBe(ADVISORY_REVIEW_MAX_BYTES + 1); expect(valid(value)).toBe(false);
    });
    it('rejects impossible work counters independently of row and byte limits', () => {
        for (const edit of [(r: AdvisoryReview) => { r.snapshot.inventoryRows = 0; }, (r: AdvisoryReview) => { r.catalog!.ruleCount = 0; }, (r: AdvisoryReview) => { r.pairsInspected = 2; }, (r: AdvisoryReview) => { r.comparisons = 0; }]) { const value = reviewView(); edit(value.review!); expect(valid(value)).toBe(false); }
    });
    it('enforces the independent 64 KiB core cap and 128 row limit', () => {
        const value = reviewView(), r = value.review!; r.pairsInspected = 128; r.comparisons = 128; r.catalog!.ruleCount = 129; r.candidates = Array.from({ length: 128 }, (_, i) => ({ ...reviewCandidate(), advisoryId: `ADVISORY-${String(i).padStart(4, '0')}`, reportedSourceVersion: '1'.repeat(512) }));
        expect(new TextEncoder().encode(JSON.stringify(r)).byteLength).toBeGreaterThan(ADVISORY_REVIEW_MAX_BYTES); expect(valid(value)).toBe(false);
        r.candidates = Array.from({ length: 129 }, (_, i) => ({ ...reviewCandidate(), advisoryId: `A-${String(i).padStart(4, '0')}` })); r.pairsInspected = 129; expect(valid(value)).toBe(false); expect(ADVISORY_REVIEW_RESPONSE_MAX_BYTES).toBe(65 * 1024);
        const invalid = reviewResult() as AdvisoryReview; invalid.snapshot.inventoryRows = 129; const boundary = reviewView(); boundary.review = invalid; expect(valid(boundary)).toBe(false);
    });
});
