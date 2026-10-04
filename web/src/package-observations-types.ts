/** Package observations only: no update, CVE, vendor-origin or host-coverage claims.
 * This operator DTO is generated canonically by the authenticated manager.
 * The existing request helper bounds its whole UTF-8 response; validation here
 * checks parsed exact shapes, cross-field semantics and canonical snapshot bytes.
 * It does not reproduce raw agent-wire Decode checks (duplicate decoded keys,
 * numeric spelling or per-component raw bytes); those belong to frame ingestion.
 */
export const PACKAGE_SNAPSHOT_MAX_BYTES = 16 * 1024;
export const PACKAGE_RESPONSE_MAX_BYTES = PACKAGE_SNAPSHOT_MAX_BYTES + 1024;
export const PACKAGE_MAX_ROWS = 128;
export const PACKAGE_RETENTION_MS = 24 * 60 * 60 * 1000;
export type PackageStatus = 'not_configured' | 'awaiting' | 'fresh' | 'stale' | 'revoked' | 'unavailable';
export type PackageQuality = 'healthy' | 'unknown' | 'denied';
export const packageReasons = ['none', 'source_missing', 'permission_denied', 'not_supported', 'timeout', 'invalid_source', 'read_failed', 'source_changed', 'item_limit', 'byte_limit', 'not_implemented', 'collector_busy'] as const;
export type PackageReason = typeof packageReasons[number];
export interface PackageRow {
    name: string; version: string; architecture: string; sourcePackage: string; sourceVersion: string;
    sourceMapping: 'source-field' | 'binary-default'; installState: 'installed' | 'incomplete';
}
export interface PackageSnapshot {
    schemaVersion: 'tracebolt.linux-packages.v1'; scope: 'agent-visible-dpkg'; generationId: string; collectedAt: string; durationMs: number;
    release: { quality: PackageQuality; reason: PackageReason; fields: { id: string | null; versionId: string | null; versionCodename: string | null } };
    inventory: { quality: PackageQuality; reason: PackageReason; complete: boolean; truncated: boolean; countExact: boolean; observedCount: number | null; installedCount: number | null; items: PackageRow[] };
}
export interface PackageView {
    schemaVersion: 'tracebolt.package-view.v1'; deviceId: string; status: PackageStatus; serverNow: string;
    receivedAt: string | null; sequence: number | null; maxAgeSeconds: 120; snapshot: PackageSnapshot | null;
}
type RecordValue = Record<string, unknown>;
function record(value: unknown, keys: readonly string[]): value is RecordValue {
    return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}
function integer(value: unknown, max = Number.MAX_SAFE_INTEGER): value is number { return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= max; }
function member(value: unknown, values: readonly string[]): boolean { return typeof value === 'string' && values.includes(value); }
function timestamp(value: unknown): value is string {
    if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value) || !Number.isFinite(Date.parse(value))) return false;
    return Number(value.slice(0, 4)) >= 1970 && new Date(Date.parse(value)).toISOString().slice(0, 19) === value.slice(0, 19);
}
// Preserve RFC3339 nanoseconds for boundary comparisons; Date.parse truncates them.
function ageMs(now: string, then: string): number {
    const fraction = (value: string) => Number((value.includes('.') ? value.slice(20, -1) : '').padEnd(9, '0')) / 1e6;
    return Date.parse(now.slice(0, 19) + 'Z') - Date.parse(then.slice(0, 19) + 'Z') + fraction(now) - fraction(then);
}
function qualityReason(quality: unknown, reason: unknown): boolean {
    if (!member(reason, packageReasons)) return false;
    if (quality === 'healthy') return reason === 'none' || reason === 'item_limit' || reason === 'byte_limit';
    if (quality === 'denied') return reason === 'permission_denied';
    return quality === 'unknown' && reason !== 'none' && reason !== 'permission_denied';
}
/** Mirrors the bounded Debian grammar, never compares versions or removes suffixes. */
function version(value: unknown): value is string {
    if (typeof value !== 'string' || !value.length || value.length > 512) return false;
    let remainder = value;
    const colon = value.indexOf(':');
    if (colon >= 0) { if (!/^\d+$/.test(value.slice(0, colon))) return false; remainder = value.slice(colon + 1); }
    if (!/^[0-9]/.test(remainder)) return false;
    const hyphen = remainder.lastIndexOf('-');
    if (hyphen >= 0 && !/^[A-Za-z0-9.+~]+$/.test(remainder.slice(hyphen + 1))) return false;
    return /^[A-Za-z0-9.+~:-]+$/.test(hyphen < 0 ? remainder : remainder.slice(0, hyphen));
}
function packageName(value: unknown): value is string { return typeof value === 'string' && /^[a-z0-9][a-z0-9+.-]{1,255}$/.test(value); }
function validRow(value: unknown): value is PackageRow {
    return record(value, ['name', 'version', 'architecture', 'sourcePackage', 'sourceVersion', 'sourceMapping', 'installState']) && packageName(value.name) && packageName(value.sourcePackage) && version(value.version) && version(value.sourceVersion) &&
        typeof value.architecture === 'string' && /^[a-z0-9][a-z0-9-]{0,63}$/.test(value.architecture) && value.architecture !== 'source' && !value.architecture.split('-').includes('any') && member(value.installState, ['installed', 'incomplete']) &&
        (value.sourceMapping === 'source-field' || value.sourceMapping === 'binary-default' && value.sourcePackage === value.name && value.sourceVersion === value.version);
}
export function validPackageSnapshot(value: unknown): value is PackageSnapshot {
    if (!record(value, ['schemaVersion', 'scope', 'generationId', 'collectedAt', 'durationMs', 'release', 'inventory']) || value.schemaVersion !== 'tracebolt.linux-packages.v1' || value.scope !== 'agent-visible-dpkg' || typeof value.generationId !== 'string' || !/^sample_[a-f0-9]{32}$/.test(value.generationId) || !timestamp(value.collectedAt) || !integer(value.durationMs)) return false;
    const release = value.release;
    if (!record(release, ['quality', 'reason', 'fields']) || !qualityReason(release.quality, release.reason) || release.quality === 'healthy' && release.reason !== 'none' || !record(release.fields, ['id', 'versionId', 'versionCodename'])) return false;
    for (const field of Object.values(release.fields)) if (field !== null && (release.quality !== 'healthy' || typeof field !== 'string' || !/^[a-z0-9._-]{0,128}$/.test(field))) return false;
    const inventory = value.inventory;
    if (!record(inventory, ['quality', 'reason', 'complete', 'truncated', 'countExact', 'observedCount', 'installedCount', 'items']) || !qualityReason(inventory.quality, inventory.reason) || typeof inventory.complete !== 'boolean' || typeof inventory.truncated !== 'boolean' || typeof inventory.countExact !== 'boolean' || !Array.isArray(inventory.items) || inventory.items.length > PACKAGE_MAX_ROWS) return false;
    if (inventory.quality !== 'healthy') {
        if (inventory.complete || inventory.truncated || inventory.countExact || inventory.observedCount !== null || inventory.installedCount !== null || inventory.items.length) return false;
    } else {
        if (!inventory.countExact || !integer(inventory.observedCount, 100000) || !integer(inventory.installedCount, inventory.observedCount) || inventory.observedCount < inventory.items.length) return false;
        if (inventory.complete ? inventory.truncated || inventory.reason !== 'none' || inventory.observedCount !== inventory.items.length : !inventory.truncated || inventory.observedCount <= inventory.items.length || !member(inventory.reason, ['item_limit', 'byte_limit'])) return false;
        let previous: PackageRow | null = null, installed = 0;
        for (const row of inventory.items) {
            if (!validRow(row) || previous && (row.name < previous.name || row.name === previous.name && row.architecture <= previous.architecture)) return false;
            previous = row; if (row.installState === 'installed') installed++;
        }
        if (installed > inventory.installedCount || inventory.installedCount - installed > inventory.observedCount - inventory.items.length) return false;
    }
    // The response helper bounds raw bytes; canonical snapshot size is independently capped.
    return new TextEncoder().encode(JSON.stringify(value)).byteLength <= PACKAGE_SNAPSHOT_MAX_BYTES;
}
export function validPackageView(value: unknown, expectedDeviceId: string): value is PackageView {
    if (!record(value, ['schemaVersion', 'deviceId', 'status', 'serverNow', 'receivedAt', 'sequence', 'maxAgeSeconds', 'snapshot']) || value.schemaVersion !== 'tracebolt.package-view.v1' || value.deviceId !== expectedDeviceId || typeof value.deviceId !== 'string' || !/^agent_[A-Za-z0-9_-]{1,120}$/.test(value.deviceId) || !member(value.status, ['not_configured', 'awaiting', 'fresh', 'stale', 'revoked', 'unavailable']) || !timestamp(value.serverNow) || value.maxAgeSeconds !== 120) return false;
    if (!(value.receivedAt === null || timestamp(value.receivedAt) && ageMs(value.serverNow, value.receivedAt) >= 0) || !(value.sequence === null || integer(value.sequence) && value.sequence > 0) || (value.receivedAt === null) !== (value.sequence === null)) return false;
    if (value.status === 'not_configured' || value.status === 'awaiting') return value.snapshot === null && value.sequence === null;
    if (value.snapshot === null) return (value.status === 'unavailable' && value.sequence !== null) || value.status === 'revoked';
    if (!validPackageSnapshot(value.snapshot) || value.receivedAt === null || value.status === 'unavailable') return false;
    const age = ageMs(value.serverNow, value.snapshot.collectedAt);
    if (age < 0 || age >= PACKAGE_RETENTION_MS) return false;
    return value.status !== 'fresh' || age <= 120000 && ageMs(value.serverNow, value.receivedAt as string) <= 120000;
}
/** The wall clock cannot grant freshness. A failed monotonic anchor invalidates the view. */
export function effectivePackageStatus(view: PackageView, elapsedMs: number): PackageStatus {
    if (!Number.isFinite(elapsedMs) || elapsedMs < 0) return 'unavailable';
    const collectedAge = view.snapshot ? ageMs(view.serverNow, view.snapshot.collectedAt) + elapsedMs : null;
    const receiptAge = view.receivedAt ? ageMs(view.serverNow, view.receivedAt) + elapsedMs : null;
    if (collectedAge !== null && collectedAge >= PACKAGE_RETENTION_MS) return view.status === 'revoked' ? 'revoked' : 'unavailable';
    if (view.status !== 'fresh') return view.status;
    return receiptAge === null || collectedAge === null || receiptAge < 0 || collectedAge < 0 || receiptAge > 120000 || collectedAge > 120000 ? 'stale' : 'fresh';
}
export function packageSnapshotVisible(view: PackageView, elapsedMs: number): boolean {
    if (!view.snapshot || !Number.isFinite(elapsedMs) || elapsedMs < 0) return false;
    const age = ageMs(view.serverNow, view.snapshot.collectedAt) + elapsedMs;
    return age >= 0 && age < PACKAGE_RETENTION_MS;
}
export function releaseApplicability(fields: PackageSnapshot['release']['fields']): 'debian' | 'ubuntu' | 'incomplete' | 'inconsistent' | 'unsupported' {
    if (!fields.id || !fields.versionId || !fields.versionCodename) return 'incomplete';
    if (fields.id === 'debian') { if (fields.versionId === '13' && fields.versionCodename === 'trixie') return 'debian'; if (fields.versionId === '13' || fields.versionCodename === 'trixie') return 'inconsistent'; }
    if (fields.id === 'ubuntu') { if (fields.versionId === '24.04' && fields.versionCodename === 'noble') return 'ubuntu'; if (fields.versionId === '24.04' || fields.versionCodename === 'noble') return 'inconsistent'; }
    return 'unsupported';
}
