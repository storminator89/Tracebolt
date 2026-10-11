import { windowsView } from './windows-inventory-fixture';
import type { WindowsPatchContext } from './windows-patch-context-types';
/** Invented context only; no native read, local consent or update operation. */
export function windowsPatchContext(): WindowsPatchContext {
    const snapshot = windowsView().snapshot!;
    return { schemaVersion: 'tracebolt.windows-patch-context.v1', scope: 'windows-patch-context-v1', grantId: 'b'.repeat(32), generationId: snapshot.generationId, collectedAt: snapshot.collectedAt,
        os: { edition: { value: 'Windows 11 Pro', quality: 'observed' }, release: { value: '24H2', quality: 'observed' }, build: { value: '26100', quality: 'observed' }, revision: { value: '1000', quality: 'observed' } },
        reboot: { windowsUpdate: 'pending', servicing: 'clear', fileOperations: 'unavailable' },
        history: { quality: 'observed', reason: '', countExact: true, totalCount: 8, truncated: true, rows: [
            { index: 0, updateId: '00000001-0000-0000-0000-000000000001', revision: 1, title: 'Synthetic cumulative update', occurredAt: '2026-10-06T10:00:00Z', operation: 'installation', result: 'succeeded', hresult: '00000000', metadataTruncated: false },
            { index: 1, updateId: '00000001-0000-0000-0000-000000000002', revision: 2, title: 'Synthetic removed update', occurredAt: '2026-10-05T10:00:00Z', operation: 'uninstallation', result: 'failed', hresult: '80240022', metadataTruncated: true },
        ] } };
}
export const windowsPatchContextView = () => ({ ...windowsView(), patchContext: windowsPatchContext() });
