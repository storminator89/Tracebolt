/** Offline metadata only. These contracts never describe verified vendor origin. */
export const SECURITY_RESPONSE_MAX_BYTES = 32 * 1024;
export const CATALOG_MAX_BYTES = 2 * 1024 * 1024;
export const SECURITY_VIEW_LEASE_MS = 60_000;
export type SecurityCollectionStatus = 'not_configured' | 'awaiting' | 'fresh' | 'stale' | 'revoked' | 'unavailable';
export type SecurityReason = 'advisory_snapshot_unavailable' | 'advisory_authority_unverified' | 'source_package_mapping_unavailable' | 'client_release_unverified' | 'installed_artifact_origin_unverified' | 'source_package_mapping_not_assessed' | 'client_release_not_assessed';
export interface OfflineCatalog {
    id: string; sha256: string; format: 'debian-tracker-normalized-1'; provider: 'debian-security-tracker'; declaredRelease: 'trixie';
    importedAt: string; publishedAt: null; freshness: 'unknown'; originAssurance: 'unverified'; synthetic: boolean;
    byteCount: number; ruleCount: number; coveredSourceCount: number;
}
export interface OfflineCatalogView {
    schemaVersion: 'tracebolt.offline-catalog.v1'; enabled: boolean; serverNow: string; revision: string;
    storage: 'memory-only'; resetsOnRestart: true; catalog: OfflineCatalog | null;
    limits: { maxBytes: 2097152; maxRules: 10000; maxInFlight: 1 };
}
export interface SecurityCoverageView {
    schemaVersion: 'tracebolt.security-coverage.v1'; deviceId: string; serverNow: string; maxAgeSeconds: 120; receivedAt: string | null; collectionStatus: SecurityCollectionStatus;
    inventory: {
        coverage: 'unknown' | 'partial' | 'observed'; freshness: 'unknown' | 'fresh' | 'stale';
        reportedItemCount: number | null; installedCount: number | null; observedCount: number | null;
        countExact: boolean; truncated: boolean; collectedAt: string | null; generationId: string | null;
        scope: 'reported-installed-binary-packages'; originAssurance: 'unverified';
    };
    catalog: { configured: boolean; revision: string; sha256: string | null; originAssurance: 'unverified'; freshness: 'unknown' };
    offeredUpdates: { coverage: 'unknown'; offeredCount: null; reason: 'native_update_adapter_unimplemented' };
    vulnerabilities: { coverage: 'unknown'; affectedCves: null; reviewCandidates: null; reasonCodes: SecurityReason[] };
}

type ObjectValue = Record<string, unknown>;
function record(value: unknown, keys: readonly string[]): value is ObjectValue {
    return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}
function integer(value: unknown, max = Number.MAX_SAFE_INTEGER): value is number { return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= max; }
function nullableInteger(value: unknown, max = Number.MAX_SAFE_INTEGER): boolean { return value === null || integer(value, max); }
function timestamp(value: unknown): value is string {
    if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value) || !Number.isFinite(Date.parse(value))) return false;
    return Number(value.slice(0, 4)) >= 1970 && new Date(Date.parse(value)).toISOString().slice(0, 19) === value.slice(0, 19);
}
function revision(value: unknown): value is string { return typeof value === 'string' && /^revision_[a-f0-9]{32}$/.test(value); }
function digest(value: unknown): value is string { return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value); }
function member(value: unknown, values: readonly string[]): boolean { return typeof value === 'string' && values.includes(value); }
function validCatalog(value: unknown, serverNow: string): value is OfflineCatalog {
    return record(value, ['id', 'sha256', 'format', 'provider', 'declaredRelease', 'importedAt', 'publishedAt', 'freshness', 'originAssurance', 'synthetic', 'byteCount', 'ruleCount', 'coveredSourceCount']) &&
        typeof value.id === 'string' && /^catalog_[a-f0-9]{32}$/.test(value.id) && digest(value.sha256) &&
        value.format === 'debian-tracker-normalized-1' && value.provider === 'debian-security-tracker' && value.declaredRelease === 'trixie' &&
        timestamp(value.importedAt) && Date.parse(value.importedAt) <= Date.parse(serverNow) && value.publishedAt === null && value.freshness === 'unknown' && value.originAssurance === 'unverified' &&
        typeof value.synthetic === 'boolean' && integer(value.byteCount, CATALOG_MAX_BYTES) && value.byteCount > 0 && integer(value.ruleCount, 10_000) && integer(value.coveredSourceCount, 10_000) && value.coveredSourceCount >= 1;
}
export function validOfflineCatalogView(value: unknown): value is OfflineCatalogView {
    if (!record(value, ['schemaVersion', 'enabled', 'serverNow', 'revision', 'storage', 'resetsOnRestart', 'catalog', 'limits']) || value.schemaVersion !== 'tracebolt.offline-catalog.v1' || typeof value.enabled !== 'boolean' || !timestamp(value.serverNow) || value.storage !== 'memory-only' || value.resetsOnRestart !== true || !record(value.limits, ['maxBytes', 'maxRules', 'maxInFlight']) || value.limits.maxBytes !== CATALOG_MAX_BYTES || value.limits.maxRules !== 10_000 || value.limits.maxInFlight !== 1) return false;
    return value.enabled ? revision(value.revision) && (value.catalog === null || validCatalog(value.catalog, value.serverNow)) : value.revision === '' && value.catalog === null;
}
export function validSecurityCoverageView(value: unknown, expectedDeviceId: string): value is SecurityCoverageView {
    if (!record(value, ['schemaVersion', 'deviceId', 'serverNow', 'maxAgeSeconds', 'receivedAt', 'collectionStatus', 'inventory', 'catalog', 'offeredUpdates', 'vulnerabilities']) || value.schemaVersion !== 'tracebolt.security-coverage.v1' || typeof value.deviceId !== 'string' || !/^agent_[A-Za-z0-9_-]{1,120}$/.test(value.deviceId) || value.deviceId !== expectedDeviceId || !timestamp(value.serverNow) || value.maxAgeSeconds !== 120 || !(value.receivedAt === null || timestamp(value.receivedAt) && Date.parse(value.receivedAt) <= Date.parse(value.serverNow)) || !member(value.collectionStatus, ['not_configured', 'awaiting', 'fresh', 'stale', 'revoked', 'unavailable'])) return false;
    if (value.collectionStatus === 'fresh' && (value.receivedAt === null || Date.parse(value.serverNow) - Date.parse(value.receivedAt as string) > 120_000)) return false;
    const inventory = value.inventory;
    if (!record(inventory, ['coverage', 'freshness', 'reportedItemCount', 'installedCount', 'observedCount', 'countExact', 'truncated', 'collectedAt', 'generationId', 'scope', 'originAssurance']) || !member(inventory.coverage, ['unknown', 'partial', 'observed']) || !member(inventory.freshness, ['unknown', 'fresh', 'stale']) || !nullableInteger(inventory.reportedItemCount, 256) || !nullableInteger(inventory.installedCount) || !nullableInteger(inventory.observedCount) || typeof inventory.countExact !== 'boolean' || typeof inventory.truncated !== 'boolean' || inventory.scope !== 'reported-installed-binary-packages' || inventory.originAssurance !== 'unverified') return false;
    if (inventory.coverage === 'unknown') {
        if (inventory.freshness !== 'unknown' || inventory.reportedItemCount !== null || inventory.installedCount !== null || inventory.observedCount !== null || inventory.countExact || inventory.truncated || inventory.collectedAt !== null || inventory.generationId !== null) return false;
    } else {
        if (!integer(inventory.reportedItemCount, 256) || !integer(inventory.observedCount) || inventory.observedCount < inventory.reportedItemCount || !timestamp(inventory.collectedAt) || Date.parse(inventory.collectedAt) > Date.parse(value.serverNow) || typeof inventory.generationId !== 'string' || !/^sample_[a-f0-9]{32}$/.test(inventory.generationId) || inventory.freshness === 'unknown') return false;
        if (inventory.freshness === 'fresh' && (value.collectionStatus !== 'fresh' || value.receivedAt === null || Date.parse(value.serverNow) - Date.parse(inventory.collectedAt) > 120_000)) return false;
        if (inventory.coverage === 'partial' && inventory.installedCount !== null) return false;
        if (inventory.coverage === 'observed' && (!inventory.countExact || inventory.truncated || inventory.installedCount !== inventory.observedCount || inventory.observedCount !== inventory.reportedItemCount)) return false;
    }
    const catalog = value.catalog;
    if (!record(catalog, ['configured', 'revision', 'sha256', 'originAssurance', 'freshness']) || typeof catalog.configured !== 'boolean' || !(revision(catalog.revision) || catalog.revision === '') || catalog.originAssurance !== 'unverified' || catalog.freshness !== 'unknown' || (catalog.configured ? !revision(catalog.revision) || !digest(catalog.sha256) : catalog.sha256 !== null)) return false;
    const updates = value.offeredUpdates;
    if (!record(updates, ['coverage', 'offeredCount', 'reason']) || updates.coverage !== 'unknown' || updates.offeredCount !== null || updates.reason !== 'native_update_adapter_unimplemented') return false;
    const vulnerabilities = value.vulnerabilities;
    if (!record(vulnerabilities, ['coverage', 'affectedCves', 'reviewCandidates', 'reasonCodes']) || vulnerabilities.coverage !== 'unknown' || vulnerabilities.affectedCves !== null || vulnerabilities.reviewCandidates !== null || !Array.isArray(vulnerabilities.reasonCodes) || vulnerabilities.reasonCodes.length !== 4) return false;
    const reasons = new Set(vulnerabilities.reasonCodes);
    const coherentMapping = reasons.has('source_package_mapping_unavailable') && reasons.has('client_release_unverified') || reasons.has('source_package_mapping_not_assessed') && reasons.has('client_release_not_assessed');
    return reasons.size === 4 && coherentMapping && [catalog.configured ? 'advisory_authority_unverified' : 'advisory_snapshot_unavailable', 'installed_artifact_origin_unverified'].every(reason => reasons.has(reason));
}

/** Monotonic elapsed time cannot make a retained section fresh or extend its lifetime. */
export function effectiveSecurityFreshness(view: SecurityCoverageView, elapsedMs: number): SecurityCoverageView['inventory']['freshness'] {
    if (view.inventory.freshness !== 'fresh') return view.inventory.freshness;
    const now = Date.parse(view.serverNow) + (Number.isFinite(elapsedMs) ? Math.max(0, elapsedMs) : Number.POSITIVE_INFINITY);
    return !view.inventory.collectedAt || !view.receivedAt || now - Date.parse(view.inventory.collectedAt) > view.maxAgeSeconds * 1000 || now - Date.parse(view.receivedAt) > view.maxAgeSeconds * 1000 ? 'stale' : 'fresh';
}

/** Overall collection age is separate from a retained/unknown software section. */
export function effectiveSecurityCollectionStatus(view: SecurityCoverageView, elapsedMs: number): SecurityCollectionStatus {
    if (view.collectionStatus !== 'fresh') return view.collectionStatus;
    const now = Date.parse(view.serverNow) + (Number.isFinite(elapsedMs) ? Math.max(0, elapsedMs) : Number.POSITIVE_INFINITY);
    return !view.receivedAt || now - Date.parse(view.receivedAt) > view.maxAgeSeconds * 1000 ? 'stale' : 'fresh';
}
