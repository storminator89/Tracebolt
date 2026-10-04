/** Conditional review of reported metadata only, never a vulnerability verdict. */
import { validOfflineCatalogView } from './security-coverage-types';
import type { OfflineCatalog } from './security-coverage-types';
import type { PackageStatus } from './package-observations-types';

export const ADVISORY_REVIEW_MAX_BYTES = 64 * 1024;
export const ADVISORY_REVIEW_RESPONSE_MAX_BYTES = 65 * 1024;
export const ADVISORY_REVIEW_LEASE_MS = 60_000;
export const advisoryReviewReasons = [
    'catalog_origin_unverified', 'catalog_freshness_unknown', 'installed_artifact_origin_unknown', 'snapshot_freshness_not_evaluated',
    'catalog_unavailable', 'synthetic_catalog', 'release_unavailable', 'release_facts_missing', 'release_facts_inconsistent', 'catalog_release_mismatch', 'unsupported_release', 'inventory_unavailable',
    'inventory_partial', 'package_installation_incomplete', 'source_package_not_covered', 'review_row_limit', 'review_pair_limit', 'review_comparison_limit', 'review_byte_limit',
    'comparator_unavailable', 'comparison_failed', 'declared_rule_uninterpretable',
] as const;
export type AdvisoryReviewReason = typeof advisoryReviewReasons[number];
export interface AdvisoryReviewCandidate {
    package: string; architecture: string; reportedSourcePackage: string; reportedSourceVersion: string; sourceMapping: 'source-field' | 'binary-default';
    advisoryId: string; declaredStatus: string; declaredFixedVersion: string; qualifications: string[];
    basis: 'conditional_reported_source_below_declared_fix' | 'comparison_unavailable' | 'declared_unresolved';
    reason: 'reported_source_below_declared_fix' | 'comparator_unavailable' | 'comparison_failed' | 'declared_status_requires_review' | 'declared_rule_uninterpretable';
}
export interface AdvisoryReview {
    schemaVersion: 'tracebolt.offline-review.v1'; scope: 'conditional-reported-source-catalog-review'; status: 'complete' | 'partial' | 'unavailable';
    reasonCodes: AdvisoryReviewReason[]; revision: string; catalog: OfflineCatalog | null;
    catalogUsage: 'unavailable' | 'unverified-conditional-review' | 'synthetic-fixture-not-for-live-review';
    snapshot: { generationId: string; collectedAt: string; release: { id: string | null; versionId: string | null; versionCodename: string | null }; inventoryComplete: boolean; inventoryRows: number };
    installedArtifactOrigin: 'unknown'; snapshotFreshness: 'unknown'; candidates: AdvisoryReviewCandidate[]; affectedCves: null; offeredUpdates: null;
    pairsInspected: number; comparisons: number; limits: { maxRows: 128; maxPairs: 4096; maxComparisons: 1024; maxBytes: 65536 };
}
export interface AdvisoryReviewView {
    schemaVersion: 'tracebolt.advisory-review-view.v1'; deviceId: string; serverNow: string; maxAgeSeconds: 120;
    collectionStatus: PackageStatus; receivedAt: string | null; sequence: number | null; review: AdvisoryReview | null;
}
type RecordValue = Record<string, unknown>;
function record(value: unknown, keys: readonly string[]): value is RecordValue { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function integer(value: unknown, max = Number.MAX_SAFE_INTEGER): value is number { return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= max; }
function member(value: unknown, values: readonly string[]): boolean { return typeof value === 'string' && values.includes(value); }
function timestamp(value: unknown): value is string { return typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value) && Number(value.slice(0, 4)) >= 1970 && Number.isFinite(Date.parse(value)) && new Date(Date.parse(value)).toISOString().slice(0, 19) === value.slice(0, 19); }
// Preserve RFC3339 nanoseconds at the fresh/future boundaries.
function ageMs(now: string, then: string): number { const fraction = (value: string) => Number((value.includes('.') ? value.slice(20, -1) : '').padEnd(9, '0')) / 1e6; return Date.parse(now.slice(0, 19) + 'Z') - Date.parse(then.slice(0, 19) + 'Z') + fraction(now) - fraction(then); }
function version(value: unknown): value is string {
    if (typeof value !== 'string' || !value.length || value.length > 512) return false;
    let remainder = value; const colon = value.indexOf(':');
    if (colon >= 0) { if (!/^\d+$/.test(value.slice(0, colon))) return false; remainder = value.slice(colon + 1); }
    if (!/^[0-9]/.test(remainder)) return false;
    const hyphen = remainder.lastIndexOf('-');
    return (hyphen < 0 || /^[A-Za-z0-9.+~]+$/.test(remainder.slice(hyphen + 1))) && /^[A-Za-z0-9.+~:-]+$/.test(hyphen < 0 ? remainder : remainder.slice(0, hyphen));
}
function packageName(value: unknown): value is string { return typeof value === 'string' && /^[a-z0-9][a-z0-9+.-]{1,255}$/.test(value); }
function token(value: unknown): value is string { return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:+/-]{0,127}$/.test(value); }
function validCandidate(value: unknown): value is AdvisoryReviewCandidate {
    if (!record(value, ['package', 'architecture', 'reportedSourcePackage', 'reportedSourceVersion', 'sourceMapping', 'advisoryId', 'declaredStatus', 'declaredFixedVersion', 'qualifications', 'basis', 'reason']) || !packageName(value.package) || !packageName(value.reportedSourcePackage) || !version(value.reportedSourceVersion) || typeof value.architecture !== 'string' || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(value.architecture) || value.architecture === 'source' || value.architecture.split('-').includes('any') || !(value.sourceMapping === 'source-field' || value.sourceMapping === 'binary-default' && value.reportedSourcePackage === value.package) || !token(value.advisoryId) || !token(value.declaredStatus) || !(value.declaredFixedVersion === '' || version(value.declaredFixedVersion)) || !Array.isArray(value.qualifications) || value.qualifications.length > 16 || !value.qualifications.every(token)) return false;
    const fixed = value.declaredStatus === 'resolved' && value.declaredFixedVersion !== '' && value.declaredFixedVersion !== '0';
    const unresolved = member(value.declaredStatus, ['open', 'undetermined']) && value.declaredFixedVersion === '';
    if (value.declaredStatus === 'resolved' && value.declaredFixedVersion === '0') return false;
    if (value.basis === 'conditional_reported_source_below_declared_fix') return fixed && value.reason === 'reported_source_below_declared_fix';
    if (value.basis === 'declared_unresolved') return unresolved && value.reason === 'declared_status_requires_review';
    return value.basis === 'comparison_unavailable' && (fixed ? member(value.reason, ['comparator_unavailable', 'comparison_failed']) : !unresolved && value.reason === 'declared_rule_uninterpretable');
}
export function validAdvisoryReview(value: unknown, serverNow: string): value is AdvisoryReview {
    if (!record(value, ['schemaVersion', 'scope', 'status', 'reasonCodes', 'revision', 'catalog', 'catalogUsage', 'snapshot', 'installedArtifactOrigin', 'snapshotFreshness', 'candidates', 'affectedCves', 'offeredUpdates', 'pairsInspected', 'comparisons', 'limits']) || value.schemaVersion !== 'tracebolt.offline-review.v1' || value.scope !== 'conditional-reported-source-catalog-review' || !member(value.status, ['complete', 'partial', 'unavailable']) || !Array.isArray(value.reasonCodes) || value.reasonCodes.length > advisoryReviewReasons.length || !value.reasonCodes.every(reason => member(reason, advisoryReviewReasons)) || new Set(value.reasonCodes).size !== value.reasonCodes.length || value.installedArtifactOrigin !== 'unknown' || value.snapshotFreshness !== 'unknown' || value.affectedCves !== null || value.offeredUpdates !== null) return false;
    if (!validOfflineCatalogView({ schemaVersion: 'tracebolt.offline-catalog.v1', enabled: true, serverNow, revision: value.revision, storage: 'memory-only', resetsOnRestart: true, catalog: value.catalog, limits: { maxBytes: 2097152, maxRules: 10000, maxInFlight: 1 } })) return false;
    const catalog = value.catalog as OfflineCatalog | null;
    if (catalog && ageMs(serverNow, catalog.importedAt) < 0) return false;
    const snapshot = value.snapshot;
    if (!record(snapshot, ['generationId', 'collectedAt', 'release', 'inventoryComplete', 'inventoryRows']) || typeof snapshot.generationId !== 'string' || !/^sample_[a-f0-9]{32}$/.test(snapshot.generationId) || !timestamp(snapshot.collectedAt) || ageMs(serverNow, snapshot.collectedAt) < 0 || ageMs(serverNow, snapshot.collectedAt) > 120000 || typeof snapshot.inventoryComplete !== 'boolean' || !integer(snapshot.inventoryRows, 128) || !record(snapshot.release, ['id', 'versionId', 'versionCodename']) || !Object.values(snapshot.release).every(field => field === null || typeof field === 'string' && /^[a-z0-9._-]{0,128}$/.test(field))) return false;
    if (!record(value.limits, ['maxRows', 'maxPairs', 'maxComparisons', 'maxBytes']) || value.limits.maxRows !== 128 || value.limits.maxPairs !== 4096 || value.limits.maxComparisons !== 1024 || value.limits.maxBytes !== ADVISORY_REVIEW_MAX_BYTES || !integer(value.pairsInspected, 4096) || !integer(value.comparisons, Math.min(value.pairsInspected, 1024)) || !Array.isArray(value.candidates) || value.candidates.length > 128 || value.candidates.length > value.pairsInspected) return false;
    const reasons = new Set(value.reasonCodes), base = ['installed_artifact_origin_unknown', 'snapshot_freshness_not_evaluated'];
    if (catalog) base.push('catalog_origin_unverified', 'catalog_freshness_unknown');
    if (!base.every(reason => reasons.has(reason))) return false;
    if (!catalog) {
        if (value.catalogUsage !== 'unavailable' || value.status !== 'unavailable' || !reasons.has('catalog_unavailable') || reasons.size !== 3) return false;
    } else if (catalog.synthetic) {
        if (value.catalogUsage !== 'synthetic-fixture-not-for-live-review' || value.status !== 'unavailable' || !reasons.has('synthetic_catalog') || reasons.size !== 5) return false;
    } else if (value.catalogUsage !== 'unverified-conditional-review' || reasons.has('catalog_unavailable') || reasons.has('synthetic_catalog')) return false;
    const unavailableReasons = ['release_unavailable', 'release_facts_missing', 'release_facts_inconsistent', 'catalog_release_mismatch', 'unsupported_release', 'inventory_unavailable'];
    if ((snapshot.inventoryRows === 0 || catalog?.ruleCount === 0) && value.pairsInspected !== 0) return false;
    if (catalog && value.pairsInspected > snapshot.inventoryRows * catalog.ruleCount) return false;
    if (value.status === 'unavailable') {
        if (value.candidates.length || value.pairsInspected || value.comparisons || catalog && !catalog.synthetic && (reasons.size !== 5 || !unavailableReasons.some(reason => reasons.has(reason)))) return false;
    } else {
        if (!catalog || catalog.synthetic || unavailableReasons.some(reason => reasons.has(reason)) || snapshot.release.id !== 'debian' || snapshot.release.versionId !== '13' || snapshot.release.versionCodename !== 'trixie' || !snapshot.inventoryComplete && !reasons.has('inventory_partial') || snapshot.inventoryComplete && reasons.has('inventory_partial') || (value.status === 'complete' ? reasons.size !== base.length : reasons.size <= base.length)) return false;
    }
    let previous: AdvisoryReviewCandidate | null = null, comparedRows = 0;
    const packageIdentities = new Set<string>(), declaredRules = new Map<string, AdvisoryReviewCandidate>();
    for (const row of value.candidates) {
        if (!validCandidate(row) || previous && (row.package < previous.package || row.package === previous.package && (row.architecture < previous.architecture || row.architecture === previous.architecture && row.advisoryId <= previous.advisoryId))) return false;
        // Every advisory for one unique binary/architecture comes from the same PackageRow.
        if (previous && row.package === previous.package && row.architecture === previous.architecture && (row.reportedSourcePackage !== previous.reportedSourcePackage || row.reportedSourceVersion !== previous.reportedSourceVersion || row.sourceMapping !== previous.sourceMapping)) return false;
        // One normalized source/advisory rule supplies the same declarations to every binary.
        const ruleKey = `${row.reportedSourcePackage}:${row.advisoryId}`, declared = declaredRules.get(ruleKey);
        if (declared && (row.declaredStatus !== declared.declaredStatus || row.declaredFixedVersion !== declared.declaredFixedVersion || row.qualifications.length !== declared.qualifications.length || row.qualifications.some((value, index) => value !== declared.qualifications[index]))) return false;
        declaredRules.set(ruleKey, row);
        if (row.basis === 'comparison_unavailable' && (value.status !== 'partial' || !reasons.has(row.reason))) return false;
        if (row.basis === 'conditional_reported_source_below_declared_fix' || row.reason === 'comparison_failed') comparedRows++;
        packageIdentities.add(`${row.package}:${row.architecture}`);
        previous = row;
    }
    return comparedRows <= value.comparisons && packageIdentities.size <= snapshot.inventoryRows && new TextEncoder().encode(JSON.stringify(value)).byteLength <= ADVISORY_REVIEW_MAX_BYTES;
}
export function validAdvisoryReviewView(value: unknown, expectedDeviceId: string): value is AdvisoryReviewView {
    if (!record(value, ['schemaVersion', 'deviceId', 'serverNow', 'maxAgeSeconds', 'collectionStatus', 'receivedAt', 'sequence', 'review']) || value.schemaVersion !== 'tracebolt.advisory-review-view.v1' || value.deviceId !== expectedDeviceId || typeof value.deviceId !== 'string' || !/^agent_[A-Za-z0-9_-]{1,120}$/.test(value.deviceId) || !timestamp(value.serverNow) || value.maxAgeSeconds !== 120 || !member(value.collectionStatus, ['not_configured', 'awaiting', 'fresh', 'stale', 'revoked', 'unavailable']) || !(value.receivedAt === null || timestamp(value.receivedAt) && ageMs(value.serverNow, value.receivedAt) >= 0) || !(value.sequence === null || integer(value.sequence) && value.sequence > 0) || (value.receivedAt === null) !== (value.sequence === null)) return false;
    if (value.collectionStatus === 'not_configured' || value.collectionStatus === 'awaiting') return value.review === null && value.sequence === null;
    if (value.collectionStatus !== 'fresh') return value.review === null && (value.collectionStatus !== 'stale' || value.sequence !== null);
    return value.receivedAt !== null && ageMs(value.serverNow, value.receivedAt as string) <= 120000 && validAdvisoryReview(value.review, value.serverNow);
}
/** The collection window is separate from the core's unknown snapshot/catalog freshness. */
export function advisoryReviewRemainingMs(view: AdvisoryReviewView): number {
    if (view.collectionStatus !== 'fresh' || !view.review || !view.receivedAt) return 0;
    return Math.min(120000 - ageMs(view.serverNow, view.review.snapshot.collectedAt), 120000 - ageMs(view.serverNow, view.receivedAt));
}
export function advisoryReviewVisible(view: AdvisoryReviewView, elapsedMs: number): boolean { return Number.isFinite(elapsedMs) && elapsedMs >= 0 && view.collectionStatus === 'fresh' && view.review !== null && elapsedMs <= advisoryReviewRemainingMs(view) && elapsedMs < ADVISORY_REVIEW_LEASE_MS; }
