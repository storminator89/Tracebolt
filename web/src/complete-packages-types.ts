import { packageReasons, validPackageRow } from './package-observations-types';
import type { PackageRow, PackageSnapshot } from './package-observations-types';

/** Operator JSON only. Completion is established by the manager's atomic ledger,
 * never by counting a displayed page or recomputing hashes in the browser. */
export const COMPLETE_STATUS_BYTES = 16384;
export const COMPLETE_PAGE_BYTES = 262144;
export const COMPLETE_PAGE_ROWS = 100;
export const COMPLETE_SCAN_ROWS = 2048;
export interface InventoryBinding { sequence: string; generationId: string; manifestHash: string }
export interface CompleteManifest {
    schemaVersion: 'tracebolt.complete-linux-packages.v1'; scope: 'agent-visible-dpkg'; generationId: string;
    collectedAt: string; durationMs: number; release: PackageSnapshot['release']; observedCount: number;
    installedCount: number; chunkCount: number; canonicalRowBytes: number; rowsSha256: string;
}
export interface CompleteGeneration { binding: InventoryBinding; manifest: CompleteManifest; state: 'complete' | 'expired'; completedAt: string; retainedUntil: string }
export interface CompletePackageView {
    schemaVersion: 'tracebolt.complete-package-view.v1'; deviceId: string; serverNow: string; collectionProfile: string;
    status: 'not_configured' | 'awaiting' | 'available' | 'revoked' | 'unavailable'; complete: CompleteGeneration | null;
    transfer: null | { binding: InventoryBinding; state: 'pending' | 'complete' | 'expired' | 'failed'; declaredRows: number; acceptedRows: number; expectedChunks: number; acceptedChunks: number; collectedAt: string; startedAt: string; expiresAt: string };
    failure: null | { sequence: string; generationId: string; attemptedAt: string; receivedAt: string; reason: 'source_missing' | 'source_invalid' | 'source_changed' | 'resource_limit' | 'collection_failed' };
}
export interface CompletePackagePage {
    schemaVersion: 'tracebolt.complete-package-page.v1'; deviceId: string; serverNow: string; binding: InventoryBinding;
    collectedAt: string; completedAt: string; retainedUntil: string; totalRows: number; items: PackageRow[];
    scannedRows: number; exhausted: boolean; searchIncomplete: boolean; nextCursor: string; cursorExpiresAt: string;
}
function record(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
    return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}
function integer(value: unknown, max = Number.MAX_SAFE_INTEGER): value is number { return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= max; }
function member(value: unknown, values: readonly string[]): boolean { return typeof value === 'string' && values.includes(value); }
function generation(value: unknown): value is string { return typeof value === 'string' && /^sample_[a-f0-9]{32}$/.test(value); }
function digest(value: unknown): value is string { return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value); }
export function inventorySequence(value: unknown): value is string { return typeof value === 'string' && /^[1-9][0-9]{0,18}$/.test(value) && (value.length < 19 || value <= '9223372036854775807'); }
function timestamp(value: unknown): value is string {
    return typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value) && Number.isFinite(Date.parse(value)) && Number(value.slice(0, 4)) >= 1970 && new Date(Date.parse(value)).toISOString().slice(0, 19) === value.slice(0, 19);
}
// Preserve sub-millisecond ordering at retention/cursor boundaries.
export function inventoryAge(now: string, then: string): number {
    const fraction = (s: string) => Number((s.includes('.') ? s.slice(20, -1) : '').padEnd(9, '0')) / 1e6;
    return Date.parse(now.slice(0, 19) + 'Z') - Date.parse(then.slice(0, 19) + 'Z') + fraction(now) - fraction(then);
}
function binding(value: unknown): value is InventoryBinding { return record(value, ['sequence', 'generationId', 'manifestHash']) && inventorySequence(value.sequence) && generation(value.generationId) && digest(value.manifestHash); }
export function sameInventoryBinding(a: InventoryBinding, b: InventoryBinding): boolean { return a.sequence === b.sequence && a.generationId === b.generationId && a.manifestHash === b.manifestHash; }
function validRelease(value: unknown): boolean {
    if (!record(value, ['quality', 'reason', 'fields']) || !member(value.reason, packageReasons) || !record(value.fields, ['id', 'versionId', 'versionCodename'])) return false;
    if (value.quality === 'healthy' ? value.reason !== 'none' : value.quality === 'denied' ? value.reason !== 'permission_denied' : value.quality !== 'unknown' || value.reason === 'none' || value.reason === 'permission_denied') return false;
    return Object.values(value.fields).every(field => field === null || value.quality === 'healthy' && typeof field === 'string' && /^[a-z0-9._-]{0,128}$/.test(field));
}
export function validCompleteManifest(value: unknown): value is CompleteManifest {
    if (!record(value, ['schemaVersion', 'scope', 'generationId', 'collectedAt', 'durationMs', 'release', 'observedCount', 'installedCount', 'chunkCount', 'canonicalRowBytes', 'rowsSha256']) || value.schemaVersion !== 'tracebolt.complete-linux-packages.v1' || value.scope !== 'agent-visible-dpkg' || !generation(value.generationId) || !timestamp(value.collectedAt) || !integer(value.durationMs) || !validRelease(value.release) || !integer(value.observedCount, 100000) || !integer(value.installedCount, value.observedCount) || !integer(value.chunkCount, 1024) || !integer(value.canonicalRowBytes, 32 << 20) || !digest(value.rowsSha256)) return false;
    return value.observedCount === 0 ? value.chunkCount === 0 && value.canonicalRowBytes === 0 && value.rowsSha256 === '25f4c92ff2c083fc7ad93865b91de92887fbd084b9fe543436e0ecd7703f4a61' : value.chunkCount > 0 && value.chunkCount <= value.observedCount && value.observedCount <= value.chunkCount * 128 && value.canonicalRowBytes >= value.observedCount && value.canonicalRowBytes <= value.chunkCount * 65536;
}
export function validCompletePackageView(value: unknown, deviceId: string): value is CompletePackageView {
    if (!record(value, ['schemaVersion', 'deviceId', 'serverNow', 'collectionProfile', 'status', 'complete', 'transfer', 'failure']) || value.schemaVersion !== 'tracebolt.complete-package-view.v1' || value.deviceId !== deviceId || !/^agent_[A-Za-z0-9_-]{1,120}$/.test(deviceId) || !timestamp(value.serverNow) || !member(value.collectionProfile, ['', 'basic-readonly-v1', 'managed-operations-v1', 'managed-operations-v2', 'managed-operations-v3']) || !member(value.status, ['not_configured', 'awaiting', 'available', 'revoked', 'unavailable'])) return false;
    const complete = value.complete, transfer = value.transfer, failure = value.failure;
    if (complete !== null) {
        if (!record(complete, ['binding', 'manifest', 'state', 'completedAt', 'retainedUntil']) || !binding(complete.binding) || !validCompleteManifest(complete.manifest) || complete.binding.generationId !== complete.manifest.generationId || !member(complete.state, ['complete', 'expired']) || !timestamp(complete.completedAt) || !timestamp(complete.retainedUntil) || inventoryAge(complete.completedAt, complete.manifest.collectedAt) < 0 || inventoryAge(value.serverNow, complete.completedAt) < 0 || inventoryAge(complete.retainedUntil, complete.manifest.collectedAt) !== 86400000 || (complete.state === 'complete') !== (inventoryAge(complete.retainedUntil, value.serverNow) > 0)) return false;
    }
    if (transfer !== null) {
        if (!record(transfer, ['binding', 'state', 'declaredRows', 'acceptedRows', 'expectedChunks', 'acceptedChunks', 'collectedAt', 'startedAt', 'expiresAt']) || !binding(transfer.binding) || !member(transfer.state, ['pending', 'complete', 'expired', 'failed']) || !integer(transfer.declaredRows, 100000) || !integer(transfer.acceptedRows, transfer.declaredRows) || !integer(transfer.expectedChunks, 1024) || !integer(transfer.acceptedChunks, transfer.expectedChunks) || !timestamp(transfer.collectedAt) || !timestamp(transfer.startedAt) || !timestamp(transfer.expiresAt) || inventoryAge(transfer.startedAt, transfer.collectedAt) < 0 || inventoryAge(value.serverNow, transfer.startedAt) < 0 || inventoryAge(transfer.expiresAt, transfer.startedAt) < 0) return false;
        if (transfer.state === 'complete' && (transfer.acceptedRows !== transfer.declaredRows || transfer.acceptedChunks !== transfer.expectedChunks)) return false;
        if (transfer.state === 'pending' && inventoryAge(transfer.expiresAt, value.serverNow) <= 0) return false;
        if (complete !== null && BigInt((transfer.binding as InventoryBinding).sequence) < BigInt((complete as unknown as CompleteGeneration).binding.sequence)) return false;
    }
    if (failure !== null && (!record(failure, ['sequence', 'generationId', 'attemptedAt', 'receivedAt', 'reason']) || !inventorySequence(failure.sequence) || !generation(failure.generationId) || !timestamp(failure.attemptedAt) || !timestamp(failure.receivedAt) || inventoryAge(failure.receivedAt, failure.attemptedAt) < 0 || inventoryAge(value.serverNow, failure.receivedAt) < 0 || !member(failure.reason, ['source_missing', 'source_invalid', 'source_changed', 'resource_limit', 'collection_failed']))) return false;
    if (value.collectionProfile !== 'managed-operations-v3') return value.status === 'not_configured' && complete === null && transfer === null && failure === null;
    if (value.status === 'not_configured') return complete === null && transfer === null && failure === null;
    if (value.status === 'awaiting') return complete === null;
    return value.status !== 'available' || complete !== null;
}
export function validCompletePackagePage(value: unknown, deviceId: string, selected: CompleteGeneration, search: string, cursor: string): value is CompletePackagePage {
    if (!record(value, ['schemaVersion', 'deviceId', 'serverNow', 'binding', 'collectedAt', 'completedAt', 'retainedUntil', 'totalRows', 'items', 'scannedRows', 'exhausted', 'searchIncomplete', 'nextCursor', 'cursorExpiresAt']) || value.schemaVersion !== 'tracebolt.complete-package-page.v1' || value.deviceId !== deviceId || !timestamp(value.serverNow) || !binding(value.binding) || !sameInventoryBinding(value.binding, selected.binding) || value.collectedAt !== selected.manifest.collectedAt || value.completedAt !== selected.completedAt || value.retainedUntil !== selected.retainedUntil || value.totalRows !== selected.manifest.observedCount || !timestamp(value.cursorExpiresAt) || inventoryAge(value.serverNow, selected.completedAt) < 0 || inventoryAge(value.retainedUntil, value.serverNow) <= 0 || inventoryAge(value.cursorExpiresAt, value.serverNow) <= 0 || inventoryAge(value.retainedUntil, value.cursorExpiresAt) < 0 || inventoryAge(value.cursorExpiresAt, value.serverNow) > 900000 || !Array.isArray(value.items) || value.items.length > COMPLETE_PAGE_ROWS || !integer(value.scannedRows, COMPLETE_SCAN_ROWS) || value.scannedRows < value.items.length || value.scannedRows > selected.manifest.observedCount || typeof value.exhausted !== 'boolean' || value.searchIncomplete !== (search.trim() !== '' && !value.exhausted) || typeof value.nextCursor !== 'string' || new TextEncoder().encode(value.nextCursor).byteLength > 1024 || (value.exhausted ? value.nextCursor !== '' : value.nextCursor === '' || value.nextCursor === cursor || value.scannedRows === 0)) return false;
    if (!search.trim() && value.items.length !== value.scannedRows) return false;
    let previous: PackageRow | null = null;
    for (const row of value.items) { if (!validPackageRow(row) || previous && (row.name < previous.name || row.name === previous.name && row.architecture <= previous.architecture) || search.trim() && !Object.values(row).join(' ').toLowerCase().includes(search.trim().toLowerCase())) return false; previous = row; }
    return true;
}
export function completeGenerationVisible(view: CompletePackageView, elapsed: number): boolean {
    return Number.isFinite(elapsed) && elapsed >= 0 && view.status === 'available' && view.complete?.state === 'complete' && inventoryAge(view.complete.retainedUntil, view.serverNow) > elapsed;
}
