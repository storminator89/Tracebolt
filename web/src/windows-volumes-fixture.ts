import type { WindowsVolumes } from './windows-volumes-types';
export const fixtureVolumeId = '\\\\?\\Volume{11111111-1111-1111-1111-111111111111}\\';
export function windowsVolumes(): WindowsVolumes {
    return { schemaVersion: 'tracebolt.windows-volumes.v1', scope: 'windows-visible-volumes-v1', grantId: 'd'.repeat(32), generationId: `sample_${'a'.repeat(32)}`, collectedAt: '2026-10-07T12:00:02Z', quality: 'observed', reason: '', complete: true, truncated: false, countExact: true, observedCount: 2, rows: [
        { volumeId: fixtureVolumeId, driveType: 'fixed', quality: 'observed', reason: '', capacity: { totalBytes: '9007199254740993', freeBytes: '18446744073709551615', availableBytes: '42' } },
        { volumeId: '\\\\?\\Volume{22222222-2222-2222-2222-222222222222}\\', driveType: 'removable', quality: 'denied', reason: 'windows_volumes_access_denied', capacity: null },
    ] };
}
