import { windowsStorageContextView } from './windows-storage-context-fixture';
import type { WindowsStorageIO, WindowsStorageIOMetric, WindowsStorageIOReason } from './windows-storage-io-types';
import { windowsStorageIOMetricKeys } from './windows-storage-io-types';

/** Invented provider values only. This never reads a Windows counter. */
export const observedWindowsStorageIOMetric = (value: number): WindowsStorageIOMetric => ({ value, quality: 'observed', reason: '' });
export const unavailableWindowsStorageIOMetric = (reason: Exclude<WindowsStorageIOReason, '' | 'windows_storage_io_partial_result'> = 'windows_storage_io_budget_exhausted'): WindowsStorageIOMetric => ({ value: null, quality: reason === 'windows_storage_io_access_denied' ? 'denied' : 'unavailable', reason });
export function windowsStorageIO(): WindowsStorageIO {
    const view = windowsStorageContextView();
    return { schemaVersion: 'tracebolt.windows-storage-io.v1', scope: 'windows-storage-io-v1', grantId: '4'.repeat(32), generationId: view.snapshot!.generationId, collectedAt: view.snapshot!.collectedAt,
        perfDisk: { quality: 'observed', reason: '', source: 'PDH PhysicalDisk(_Total)', sampleStartedAt: '2026-10-07T12:00:00.25Z', sampleEndedAt: '2026-10-07T12:00:01.25Z', intervalMilliseconds: 1000,
            readBytesPerSecond: observedWindowsStorageIOMetric(12582912), writeBytesPerSecond: observedWindowsStorageIOMetric(2097152), readOperationsPerSecond: observedWindowsStorageIOMetric(120.5), writeOperationsPerSecond: observedWindowsStorageIOMetric(24), readLatencySeconds: observedWindowsStorageIOMetric(0.00125), writeLatencySeconds: observedWindowsStorageIOMetric(0.0025), averageQueueLength: observedWindowsStorageIOMetric(1.75), currentQueueLength: observedWindowsStorageIOMetric(2) },
    };
}
export function summarizeWindowsStorageIO(value: WindowsStorageIO): WindowsStorageIO {
    const p = value.perfDisk, first = p.readBytesPerSecond;
    const same = windowsStorageIOMetricKeys.every(k => p[k].quality === first.quality && p[k].reason === first.reason);
    p.quality = same ? first.quality : 'partial'; p.reason = same ? first.reason : 'windows_storage_io_partial_result';
    return value;
}
export function unavailableWindowsStorageIO(reason: Exclude<WindowsStorageIOReason, '' | 'windows_storage_io_partial_result' | 'windows_storage_io_idle'> = 'windows_storage_io_budget_exhausted'): WindowsStorageIO {
    const value = windowsStorageIO();
    for (const k of windowsStorageIOMetricKeys) value.perfDisk[k] = unavailableWindowsStorageIOMetric(reason);
    Object.assign(value.perfDisk, { sampleStartedAt: null, sampleEndedAt: null, intervalMilliseconds: null });
    return summarizeWindowsStorageIO(value);
}
export function windowsStorageIOView() { return { ...windowsStorageContextView(), storageIO: windowsStorageIO() }; }
