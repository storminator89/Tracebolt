import { inventoryAge, inventorySequence, sameInventoryBinding } from './complete-packages-types';
import { validCachedUpdateRow, validCachedUpdatesSnapshot } from './cached-updates-types';
import type { CachedUpdateRow, CachedUpdatesSnapshot } from './cached-updates-types';

/** Operator JSON only. Completion is established by the manager's atomic ledger,
 * never by counting a displayed page or recomputing hashes in the browser. */
export const COMPLETE_UPDATES_STATUS_BYTES = 16384;
export const COMPLETE_UPDATES_PAGE_BYTES = 262144;
export const COMPLETE_UPDATES_PAGE_ROWS = 100;
export const COMPLETE_UPDATES_SCAN_ROWS = 2048;
export interface InventoryBinding { sequence: string; generationId: string; manifestHash: string }
export interface CompleteUpdateManifest {
    schemaVersion: 'tracebolt.complete-cached-apt-updates.v1'; scope: 'agent-visible-complete-known-cached-apt-candidate-rows'; generationId: string; collectedAt: string; durationMs: number;
    release: CachedUpdatesSnapshot['release']; metadata: CachedUpdatesSnapshot['metadata']; comparisonCoverage: 'complete' | 'partial'; comparisonReason: 'none' | 'candidate_unknown';
    installedCount: number; checkedCount: number; candidateCount: number; heldCount: number; unknownCount: number; chunkCount: number; canonicalRowBytes: number; rowsSha256: string;
}
export interface CompleteUpdateGeneration { binding: InventoryBinding; manifest: CompleteUpdateManifest; state: 'complete' | 'expired'; completedAt: string; retainedUntil: string }
export interface CompleteUpdateView {
    schemaVersion: 'tracebolt.complete-update-view.v1'; deviceId: string; serverNow: string; collectionProfile: string;
    status: 'not_configured' | 'awaiting' | 'available' | 'revoked' | 'unavailable'; complete: CompleteUpdateGeneration | null;
    transfer: null | { binding: InventoryBinding; state: 'pending' | 'complete' | 'expired' | 'failed'; declaredRows: number; acceptedRows: number; expectedChunks: number; acceptedChunks: number; collectedAt: string; startedAt: string; expiresAt: string };
    failure: null | { sequence: string; generationId: string; attemptedAt: string; receivedAt: string; reason: 'not_supported' | 'source_missing' | 'source_invalid' | 'source_changed' | 'resource_limit' | 'collection_failed' };
}
export interface CompleteUpdatePage {
    schemaVersion: 'tracebolt.complete-update-page.v1'; deviceId: string; serverNow: string; binding: InventoryBinding;
    collectedAt: string; completedAt: string; retainedUntil: string; totalRows: number; items: CachedUpdateRow[];
    scannedRows: number; exhausted: boolean; searchIncomplete: boolean; nextCursor: string; cursorExpiresAt: string;
}
function record(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
    return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}
function integer(value: unknown, max = Number.MAX_SAFE_INTEGER): value is number { return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= max; }
function member(value: unknown, values: readonly string[]): boolean { return typeof value === 'string' && values.includes(value); }
function generation(value: unknown): value is string { return typeof value === 'string' && /^sample_[a-f0-9]{32}$/.test(value); }
function digest(value: unknown): value is string { return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value); }
function timestamp(value: unknown): value is string {
    return typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value) && Number.isFinite(Date.parse(value)) && Number(value.slice(0, 4)) >= 1970 && new Date(Date.parse(value)).toISOString().slice(0, 19) === value.slice(0, 19);
}
function binding(value: unknown): value is InventoryBinding { return record(value, ['sequence', 'generationId', 'manifestHash']) && inventorySequence(value.sequence) && generation(value.generationId) && digest(value.manifestHash); }
export function validCompleteUpdateManifest(value: unknown): value is CompleteUpdateManifest {
    if (!record(value, ['schemaVersion','scope','generationId','collectedAt','durationMs','release','metadata','comparisonCoverage','comparisonReason','installedCount','checkedCount','candidateCount','heldCount','unknownCount','chunkCount','canonicalRowBytes','rowsSha256']) || value.schemaVersion !== 'tracebolt.complete-cached-apt-updates.v1' || value.scope !== 'agent-visible-complete-known-cached-apt-candidate-rows' || !generation(value.generationId) || !integer(value.candidateCount,16384) || !integer(value.unknownCount,16384) || !integer(value.chunkCount,1024) || !integer(value.canonicalRowBytes,32 << 20) || !digest(value.rowsSha256)) return false;
    const preview = { schemaVersion:'tracebolt.cached-apt-updates.v1', scope:'agent-visible-dpkg-and-existing-apt-cache', generationId:value.generationId, collectedAt:value.collectedAt, durationMs:value.durationMs, release:value.release, metadata:value.metadata, coverage:value.candidateCount > 0 || value.unknownCount > 0 ? 'partial' : 'complete', reason:value.candidateCount > 0 ? 'item_limit' : value.unknownCount > 0 ? 'candidate_unknown' : 'none', installedCount:value.installedCount, checkedCount:value.checkedCount, candidateCount:value.candidateCount, heldCount:value.heldCount, unknownCount:value.unknownCount, truncated:value.candidateCount > 0, items:[] };
    if (!validCachedUpdatesSnapshot(preview) || (value.unknownCount === 0 ? value.comparisonCoverage !== 'complete' || value.comparisonReason !== 'none' : value.comparisonCoverage !== 'partial' || value.comparisonReason !== 'candidate_unknown')) return false;
    return value.candidateCount === 0 ? value.chunkCount === 0 && value.canonicalRowBytes === 0 && value.rowsSha256 === '172fd0ef0e5dcad6987433bf5815d9d77d4cb2ddd4ef403cfd451a316defa9af' : value.chunkCount > 0 && value.chunkCount <= value.candidateCount && value.candidateCount <= value.chunkCount * 128 && value.canonicalRowBytes >= value.candidateCount && value.canonicalRowBytes <= value.candidateCount * 2048 && value.canonicalRowBytes <= value.chunkCount * 65536;
}
export function validCompleteUpdateView(value: unknown, deviceId: string): value is CompleteUpdateView {
    if (!record(value, ['schemaVersion', 'deviceId', 'serverNow', 'collectionProfile', 'status', 'complete', 'transfer', 'failure']) || value.schemaVersion !== 'tracebolt.complete-update-view.v1' || value.deviceId !== deviceId || !/^agent_[A-Za-z0-9_-]{1,120}$/.test(deviceId) || !timestamp(value.serverNow) || !member(value.collectionProfile, ['', 'basic-readonly-v1', 'managed-operations-v1', 'managed-operations-v2', 'managed-operations-v3']) || !member(value.status, ['not_configured', 'awaiting', 'available', 'revoked', 'unavailable'])) return false;
    const complete = value.complete, transfer = value.transfer, failure = value.failure;
    if (complete !== null) {
        if (!record(complete, ['binding', 'manifest', 'state', 'completedAt', 'retainedUntil']) || !binding(complete.binding) || !validCompleteUpdateManifest(complete.manifest) || complete.binding.generationId !== complete.manifest.generationId || !member(complete.state, ['complete', 'expired']) || !timestamp(complete.completedAt) || !timestamp(complete.retainedUntil) || inventoryAge(complete.completedAt, complete.manifest.collectedAt) < 0 || inventoryAge(value.serverNow, complete.completedAt) < 0 || inventoryAge(complete.retainedUntil, complete.manifest.collectedAt) !== 86400000 || (complete.state === 'complete') !== (inventoryAge(complete.retainedUntil, value.serverNow) > 0)) return false;
    }
    if (transfer !== null) {
        if (!record(transfer, ['binding', 'state', 'declaredRows', 'acceptedRows', 'expectedChunks', 'acceptedChunks', 'collectedAt', 'startedAt', 'expiresAt']) || !binding(transfer.binding) || !member(transfer.state, ['pending', 'complete', 'expired', 'failed']) || !integer(transfer.declaredRows, 16384) || !integer(transfer.acceptedRows, transfer.declaredRows) || !integer(transfer.expectedChunks, 1024) || !integer(transfer.acceptedChunks, transfer.expectedChunks) || !timestamp(transfer.collectedAt) || !timestamp(transfer.startedAt) || !timestamp(transfer.expiresAt) || inventoryAge(transfer.startedAt, transfer.collectedAt) < 0 || inventoryAge(value.serverNow, transfer.startedAt) < 0 || inventoryAge(transfer.expiresAt, transfer.startedAt) < 0) return false;
        if (transfer.state === 'complete' && (transfer.acceptedRows !== transfer.declaredRows || transfer.acceptedChunks !== transfer.expectedChunks)) return false;
        if (transfer.state === 'pending' && inventoryAge(transfer.expiresAt, value.serverNow) <= 0) return false;
        if (complete !== null && BigInt((transfer.binding as InventoryBinding).sequence) < BigInt((complete as unknown as CompleteUpdateGeneration).binding.sequence)) return false;
    }
    if (failure !== null && (!record(failure, ['sequence', 'generationId', 'attemptedAt', 'receivedAt', 'reason']) || !inventorySequence(failure.sequence) || !generation(failure.generationId) || !timestamp(failure.attemptedAt) || !timestamp(failure.receivedAt) || inventoryAge(failure.receivedAt, failure.attemptedAt) < 0 || inventoryAge(value.serverNow, failure.receivedAt) < 0 || !member(failure.reason, ['not_supported', 'source_missing', 'source_invalid', 'source_changed', 'resource_limit', 'collection_failed']))) return false;
    if (value.collectionProfile !== 'managed-operations-v3') return value.status === 'not_configured' && complete === null && transfer === null && failure === null;
    if (value.status === 'not_configured') return complete === null && transfer === null && failure === null;
    if (value.status === 'awaiting') return complete === null;
    return value.status !== 'available' || complete !== null;
}
export function validCompleteUpdatePage(value: unknown, deviceId: string, selected: CompleteUpdateGeneration, search: string, cursor: string): value is CompleteUpdatePage {
    if (!record(value, ['schemaVersion', 'deviceId', 'serverNow', 'binding', 'collectedAt', 'completedAt', 'retainedUntil', 'totalRows', 'items', 'scannedRows', 'exhausted', 'searchIncomplete', 'nextCursor', 'cursorExpiresAt']) || value.schemaVersion !== 'tracebolt.complete-update-page.v1' || value.deviceId !== deviceId || !timestamp(value.serverNow) || !binding(value.binding) || !sameInventoryBinding(value.binding, selected.binding) || value.collectedAt !== selected.manifest.collectedAt || value.completedAt !== selected.completedAt || value.retainedUntil !== selected.retainedUntil || value.totalRows !== selected.manifest.candidateCount || !timestamp(value.cursorExpiresAt) || inventoryAge(value.serverNow, selected.completedAt) < 0 || inventoryAge(value.retainedUntil, value.serverNow) <= 0 || inventoryAge(value.cursorExpiresAt, value.serverNow) <= 0 || inventoryAge(value.retainedUntil, value.cursorExpiresAt) < 0 || inventoryAge(value.cursorExpiresAt, value.serverNow) > 900000 || !Array.isArray(value.items) || value.items.length > COMPLETE_UPDATES_PAGE_ROWS || !integer(value.scannedRows, COMPLETE_UPDATES_SCAN_ROWS) || value.scannedRows < value.items.length || value.scannedRows > selected.manifest.candidateCount || typeof value.exhausted !== 'boolean' || value.searchIncomplete !== (search.trim() !== '' && !value.exhausted) || typeof value.nextCursor !== 'string' || new TextEncoder().encode(value.nextCursor).byteLength > 1024 || (value.exhausted ? value.nextCursor !== '' : value.nextCursor === '' || value.nextCursor === cursor || value.scannedRows === 0)) return false;
    if (!search.trim() && value.items.length !== value.scannedRows) return false;
    let previous: CachedUpdateRow | null = null;
    for (const row of value.items) { if (!validCachedUpdateRow(row) || previous && (row.name < previous.name || row.name === previous.name && row.architecture <= previous.architecture) || search.trim() && !Object.values(row).join(' ').toLowerCase().includes(search.trim().toLowerCase())) return false; previous = row; }
    return true;
}
export function completeUpdatesGenerationVisible(view: CompleteUpdateView, elapsed: number): boolean {
    return Number.isFinite(elapsed) && elapsed >= 0 && view.status === 'available' && view.complete?.state === 'complete' && inventoryAge(view.complete.retainedUntil, view.serverNow) > elapsed;
}

// Pending is only current until both the original staging lease and the original
// capture retention permit it. Rendering never changes the manager's receipt.
export function completeUpdatesTransferExpired(view: CompleteUpdateView, elapsed: number): boolean {
    const transfer = view.transfer;
    return transfer?.state === 'pending' && Number.isFinite(elapsed) && elapsed >= 0 &&
        (inventoryAge(transfer.expiresAt, view.serverNow) <= elapsed || inventoryAge(view.serverNow, transfer.collectedAt) + elapsed >= 86400000);
}
