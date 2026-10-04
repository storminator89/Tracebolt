import type { CompletePackagePage, CompletePackageView } from './complete-packages-types';
import type { PackageRow } from './package-observations-types';

// Synthetic test data only; the production UI never imports these fixtures.
export const completeDevice = 'agent_complete_fixture';
export const completeNow = '2026-10-04T00:00:10Z';
export function completeRows(count = 350): PackageRow[] {
    return Array.from({ length: count }, (_, i) => ({ name: `fixture-${String(i).padStart(6, '0')}`, version: '1.0+b1', architecture: 'amd64', sourcePackage: `fixture-${String(i).padStart(6, '0')}`, sourceVersion: '1.0+b1', sourceMapping: 'binary-default', installState: 'installed' }));
}
export function completeView(count = 350): CompletePackageView {
    return {
        schemaVersion: 'tracebolt.complete-package-view.v1', deviceId: completeDevice, serverNow: completeNow, collectionProfile: 'managed-operations-v3', status: 'available',
        complete: { binding: { sequence: '9223372036854775807', generationId: `sample_${'a'.repeat(32)}`, manifestHash: 'b'.repeat(64) }, state: 'complete', completedAt: '2026-10-04T00:00:05Z', retainedUntil: '2026-10-05T00:00:00Z', manifest: { schemaVersion: 'tracebolt.complete-linux-packages.v1', scope: 'agent-visible-dpkg', generationId: `sample_${'a'.repeat(32)}`, collectedAt: '2026-10-04T00:00:00Z', durationMs: 2, release: { quality: 'healthy', reason: 'none', fields: { id: 'debian', versionId: '13', versionCodename: 'trixie' } }, observedCount: count, installedCount: count, chunkCount: Math.ceil(count / 128), canonicalRowBytes: count * 200, rowsSha256: count ? 'c'.repeat(64) : '25f4c92ff2c083fc7ad93865b91de92887fbd084b9fe543436e0ecd7703f4a61' } },
        transfer: null, failure: null,
    };
}
export function completePage(view: CompletePackageView, rows: PackageRow[], raw = ''): CompletePackagePage {
    const input = raw ? JSON.parse(raw) as { cursor: string; search: string; limit: number } : { cursor: '', search: '', limit: 100 };
    let index = input.cursor ? Number(input.cursor.slice(7)) : 0, scanned = 0;
    const items: PackageRow[] = [], search = input.search.trim().toLowerCase();
    for (; index < rows.length && scanned < 2048 && items.length < input.limit; index++) {
        const row = rows[index]; scanned++;
        if (!search || Object.values(row).join(' ').toLowerCase().includes(search)) items.push(row);
    }
    return { schemaVersion: 'tracebolt.complete-package-page.v1', deviceId: view.deviceId, serverNow: view.serverNow, binding: view.complete!.binding, collectedAt: view.complete!.manifest.collectedAt, completedAt: view.complete!.completedAt, retainedUntil: view.complete!.retainedUntil, totalRows: rows.length, items, scannedRows: scanned, exhausted: index === rows.length, searchIncomplete: Boolean(search) && index < rows.length, nextCursor: index === rows.length ? '' : `cursor_${index}`, cursorExpiresAt: '2026-10-04T00:15:10Z' };
}
