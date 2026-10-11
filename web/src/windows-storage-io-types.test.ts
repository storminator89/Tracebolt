import goFixture from './windows-storage-io-go-fixture.json';
import { describe, expect, it } from 'vitest';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import { validWindowsInventoryView, type WindowsInventoryView } from './windows-inventory-types';
import { windowsStorageIO, windowsStorageIOView, unavailableWindowsStorageIO, unavailableWindowsStorageIOMetric, observedWindowsStorageIOMetric, summarizeWindowsStorageIO } from './windows-storage-io-fixture';
import { validWindowsStorageIO, usefulWindowsStorageIO, type WindowsStorageIO } from './windows-storage-io-types';

const valid = (value: unknown) => validWindowsStorageIO(value, windowsView().snapshot!, windowsNow);
describe('Windows PerfDisk aggregate contract', () => {
    it('accepts the exact canonical Go fixture with nanosecond timing', () => { expect(validWindowsStorageIO(goFixture, { ...windowsView().snapshot!, collectedAt: goFixture.collectedAt, generationId: goFixture.generationId }, '2026-10-11T12:35:00Z')).toBe(true); });
    it('accepts the independent source and current private view without a physical-disk join', () => { expect(valid(windowsStorageIO())).toBe(true); expect(validWindowsInventoryView(windowsStorageIOView(), windowsDeviceId)).toBe(true); });
    it('preserves observed zeros and undefined idle latency distinctly', () => {
        const v = windowsStorageIO(); v.perfDisk.readOperationsPerSecond = observedWindowsStorageIOMetric(0); v.perfDisk.readLatencySeconds = unavailableWindowsStorageIOMetric('windows_storage_io_idle'); summarizeWindowsStorageIO(v);
        expect(valid(v)).toBe(true); expect(usefulWindowsStorageIO(v)).toBe(true); v.perfDisk.readLatencySeconds = observedWindowsStorageIOMetric(0); expect(valid(v)).toBe(false);
    });
    it('accepts distinct unavailable causes and all-unavailable mixed partial sources', () => {
        for (const reason of ['windows_storage_io_access_denied', 'windows_storage_io_counter_missing', 'windows_storage_io_counter_reset', 'windows_storage_io_invalid_timebase', 'windows_storage_io_unsupported_platform', 'windows_storage_io_budget_exhausted'] as const) { const v = unavailableWindowsStorageIO(reason); expect(valid(v)).toBe(true); expect(usefulWindowsStorageIO(v)).toBe(false); }
        const v = unavailableWindowsStorageIO(); v.perfDisk.currentQueueLength = unavailableWindowsStorageIOMetric('windows_storage_io_counter_missing'); summarizeWindowsStorageIO(v); expect(v.perfDisk.quality).toBe('partial'); expect(valid(v)).toBe(true);
    });
    const invalid: [string, (v: WindowsStorageIO) => void][] = [
        ['unknown root', v => Object.assign(v, { diskId: 'private' })], ['unknown metric field', v => Object.assign(v.perfDisk.currentQueueLength, { healthy: true })], ['unknown source', v => Object.assign(v.perfDisk, { source: 'MSFT_PhysicalDisk' })], ['unknown reason', v => Object.assign(v.perfDisk.readBytesPerSecond, { reason: 'provider-error' })],
        ['numeric string', v => Object.assign(v.perfDisk.readBytesPerSecond, { value: '1' })], ['negative', v => { v.perfDisk.readBytesPerSecond.value = -1; }], ['negative zero', v => { v.perfDisk.readBytesPerSecond.value = -0; }], ['infinity', v => { v.perfDisk.readBytesPerSecond.value = Infinity; }], ['NaN', v => { v.perfDisk.readBytesPerSecond.value = NaN; }], ['denied retains value', v => { v.perfDisk.readBytesPerSecond.quality = 'denied'; }], ['unexplained missing', v => { v.perfDisk.readBytesPerSecond.value = null; }],
        ['observed metric without window', v => Object.assign(v.perfDisk, { sampleStartedAt: null, sampleEndedAt: null, intervalMilliseconds: null })], ['partial window', v => { v.perfDisk.sampleStartedAt = null; }], ['interval mismatch', v => { v.perfDisk.intervalMilliseconds = 1001; }], ['interval below minimum', v => { v.perfDisk.sampleEndedAt = '2026-10-07T12:00:01.249999999Z'; v.perfDisk.intervalMilliseconds = 999; }], ['interval above maximum', v => { v.perfDisk.sampleEndedAt = '2026-10-07T12:00:02.250000001Z'; v.perfDisk.intervalMilliseconds = 2000; }], ['sample before capture', v => { v.perfDisk.sampleStartedAt = '2026-10-07T11:59:59.25Z'; v.perfDisk.sampleEndedAt = '2026-10-07T12:00:00.25Z'; }],
        ['idle throughput', v => { v.perfDisk.readBytesPerSecond = unavailableWindowsStorageIOMetric('windows_storage_io_idle'); summarizeWindowsStorageIO(v); }], ['idle with positive ops', v => { v.perfDisk.readLatencySeconds = unavailableWindowsStorageIOMetric('windows_storage_io_idle'); summarizeWindowsStorageIO(v); }], ['latency with missing ops', v => { v.perfDisk.readOperationsPerSecond = unavailableWindowsStorageIOMetric(); summarizeWindowsStorageIO(v); }], ['wrong derived summary', v => { v.perfDisk.quality = 'partial'; v.perfDisk.reason = 'windows_storage_io_partial_result'; }],
        ['bad grant', v => { v.grantId = 'invalid'; }], ['wrong generation', v => { v.generationId = `sample_${'e'.repeat(32)}`; }], ['foreign capture', v => { v.collectedAt = '2026-10-07T11:59:59Z'; }],
    ];
    it.each(invalid)('rejects %s', (_label, mutate) => { const v = windowsStorageIO(); mutate(v); expect(valid(v)).toBe(false); });
    it('keeps sub-millisecond time precision and finite positive rates', () => { const v = windowsStorageIO(); v.perfDisk.sampleEndedAt = '2026-10-07T12:00:01.250999999Z'; expect(valid(v)).toBe(true); v.perfDisk.readBytesPerSecond.value = Number.MAX_VALUE; expect(valid(v)).toBe(true); });
    it('subtracts nanosecond endpoints before flooring across a millisecond boundary', () => { const v = windowsStorageIO(); v.perfDisk.sampleStartedAt = '2026-10-07T12:00:00.000999999Z'; v.perfDisk.sampleEndedAt = '2026-10-07T12:00:01.001000001Z'; v.perfDisk.intervalMilliseconds = 1000; expect(valid(v)).toBe(true); v.perfDisk.intervalMilliseconds = 1001; expect(valid(v)).toBe(false); v.perfDisk.intervalMilliseconds = 1000; v.collectedAt = '2026-10-07T12:00:00.000000001Z'; expect(valid(v)).toBe(false); });
    it('rejects reused grants, non-observation states, unknown view fields and expired data', () => {
        const v = windowsStorageIOView(); v.storageIO.grantId = v.storageContext.grantId; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false);
        for (const status of ['revoked', 'unavailable', 'awaiting', 'not_configured']) expect(validWindowsInventoryView({ ...windowsStorageIOView(), status, snapshot: null }, windowsDeviceId)).toBe(false);
        expect(validWindowsInventoryView({ ...windowsView(), storageIO: null }, windowsDeviceId)).toBe(false); expect(validWindowsInventoryView({ ...windowsView(), windowsStorageIO: windowsStorageIO() }, windowsDeviceId)).toBe(false);
        expect(validWindowsStorageIO(windowsStorageIO(), windowsView().snapshot!, '2026-10-08T12:00:00Z')).toBe(false);
    });
    it('retains only useful original-age IO under the current independent grant', () => {
        const view: WindowsInventoryView = windowsStorageIOView(), old = windowsStorageIO(); old.collectedAt = '2026-10-07T11:00:00Z'; old.generationId = `sample_${'e'.repeat(32)}`; old.perfDisk.sampleStartedAt = '2026-10-07T11:00:00.25Z'; old.perfDisk.sampleEndedAt = '2026-10-07T11:00:01.25Z'; view.retainedContext = { storageIO: old };
        expect(validWindowsInventoryView(view, windowsDeviceId)).toBe(true); old.grantId = 'f'.repeat(32); expect(validWindowsInventoryView(view, windowsDeviceId)).toBe(false); old.grantId = view.storageIO!.grantId;
        old.collectedAt = view.storageIO!.collectedAt; expect(validWindowsInventoryView(view, windowsDeviceId)).toBe(false);
        Object.assign(old, unavailableWindowsStorageIO(), { collectedAt: '2026-10-07T11:00:00Z', generationId: `sample_${'e'.repeat(32)}` }); expect(validWindowsInventoryView(view, windowsDeviceId)).toBe(false);
        delete view.storageIO; expect(validWindowsInventoryView(view, windowsDeviceId)).toBe(false);
    });
});
