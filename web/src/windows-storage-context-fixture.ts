import { windowsView } from './windows-inventory-fixture';
import { windowsVolumes, fixtureVolumeId } from './windows-volumes-fixture';
import type { WindowsStorageContext, WindowsStorageGroup } from './windows-storage-context-types';
export function windowsStorageContext(): WindowsStorageContext {
    const snapshot = windowsView().snapshot!;
    return { schemaVersion: 'tracebolt.windows-storage-context.v1', scope: 'windows-storage-context-v1', grantId: '7'.repeat(32), generationId: snapshot.generationId, collectedAt: snapshot.collectedAt,
        drives: { quality: 'partial', reason: 'windows_storage_context_partial_result', rows: [
            { letter: 'C:', driveType: 'fixed', volumeGuid: fixtureVolumeId, quality: 'observed', reason: '' },
            { letter: 'E:', driveType: 'removable', volumeGuid: null, quality: 'denied', reason: 'windows_storage_context_access_denied' },
        ], observedCount: 2, countExact: true, complete: true, truncated: false },
        disks: { quality: 'partial', reason: 'windows_storage_context_partial_result', rows: [
            { index: 0, deviceId: { value: 'provider-local-04', quality: 'observed' }, friendlyName: { value: 'Fixture NVMe', quality: 'observed' }, healthStatus: 0, operationalStatus: [2], busType: 17, mediaType: 4, sizeBytes: '1099511627776' },
            { index: 1, deviceId: { value: null, quality: 'denied' }, friendlyName: { value: 'Fixture Spaces', quality: 'observed' }, healthStatus: null, operationalStatus: [32768], busType: 16, mediaType: null, sizeBytes: null },
        ], observedCount: 2, countExact: true, complete: true, truncated: false },
    };
}
export function windowsStorageContextView() {
    const storageContext = windowsStorageContext(), volumes = windowsVolumes();
    return { ...windowsView(), storageContext, volumes };
}
export function unavailableWindowsStorageGroup<T>(quality: 'unavailable' | 'denied' = 'unavailable', reason?: WindowsStorageGroup<T>['reason']): WindowsStorageGroup<T> {
    return { quality, reason: reason ?? (quality === 'denied' ? 'windows_storage_context_access_denied' : 'windows_storage_context_budget_exhausted'), rows: [], observedCount: 0, countExact: false, complete: false, truncated: false };
}
