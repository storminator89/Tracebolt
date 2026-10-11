import { describe, expect, it } from 'vitest';
import { windowsStorageContext, windowsStorageContextView, unavailableWindowsStorageGroup } from './windows-storage-context-fixture';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import { validWindowsStorageContext, usefulWindowsStorageContext, type WindowsStorageContext } from './windows-storage-context-types';
import { validWindowsInventoryView, type WindowsInventoryView } from './windows-inventory-types';
import { windowsHardwareContext } from './windows-hardware-context-fixture';
const valid = (v: unknown) => validWindowsStorageContext(v, windowsView().snapshot!, windowsNow);
describe('Bounded storage context contract', () => {
    it('accepts independent sources and old views without widening the old capacities', () => {
        expect(valid(windowsStorageContext())).toBe(true); expect(validWindowsInventoryView(windowsView(), windowsDeviceId)).toBe(true);
        const view = windowsStorageContextView(); expect(validWindowsInventoryView({ ...view, hardwareContext: windowsHardwareContext() }, windowsDeviceId)).toBe(true);
        expect(view.volumes.collectedAt).toBe('2026-10-07T12:00:02Z'); expect(view.storageContext.collectedAt).toBe('2026-10-07T12:00:00Z');
        expect(view.volumes.rows[0].capacity).toEqual({ totalBytes: '9007199254740993', freeBytes: '18446744073709551615', availableBytes: '42' });
        for (const key of ['drives', 'disks'] as const) for (const quality of ['denied', 'unavailable'] as const) { const v = windowsStorageContext(); Object.assign(v, { [key]: unavailableWindowsStorageGroup(quality) }); expect(valid(v)).toBe(true); }
    });
    it('keeps null unknown, actual zero, uint64 precision and future uint16 codes', () => {
        const v = windowsStorageContext(), row = v.disks.rows[0]; Object.assign(row, { healthStatus: null, busType: null, mediaType: null, sizeBytes: null, operationalStatus: [] }); expect(valid(v)).toBe(true);
        Object.assign(row, { healthStatus: 0, busType: 65535, mediaType: 65535, sizeBytes: '0', operationalStatus: [0, 65535] }); expect(valid(v)).toBe(true);
        row.sizeBytes = '18446744073709551615'; expect(valid(v)).toBe(true);
        row.deviceId.value = '😀'.repeat(32); row.friendlyName.value = '😀'.repeat(64); expect(valid(v)).toBe(true);
    });
    it('treats enumeration coverage independently of nullable or denied fields', () => {
        const v = windowsStorageContext(); for (const row of v.disks.rows) Object.assign(row, { deviceId: { value: null, quality: 'denied' }, friendlyName: { value: null, quality: 'unavailable' }, healthStatus: null, busType: null, mediaType: null, sizeBytes: null, operationalStatus: [] });
        expect(valid(v)).toBe(true); v.drives = unavailableWindowsStorageGroup(); expect(usefulWindowsStorageContext(v)).toBe(false);
        Object.assign(v.disks, { quality: 'observed', reason: '', rows: [], observedCount: 0 }); expect(valid(v)).toBe(true); expect(usefulWindowsStorageContext(v)).toBe(true);
        v.disks = unavailableWindowsStorageGroup(); expect(usefulWindowsStorageContext(v)).toBe(false);
    });
    const invalid: [string, (v: WindowsStorageContext) => void][] = [
        ['unknown root field', v => Object.assign(v, { serialNumber: 'forbidden' })], ['unknown group field', v => Object.assign(v.drives, { mountPaths: [] })], ['unknown disk field', v => Object.assign(v.disks.rows[0], { uniqueId: 'forbidden' })],
        ['unknown drive field', v => Object.assign(v.drives.rows[0], { diskNumber: 4 })], ['extra field quality member', v => Object.assign(v.disks.rows[0].deviceId, { source: 'guessed' })],
        ['oversized friendly name', v => { v.disks.rows[0].friendlyName.value = 'x'.repeat(129); }], ['oversized provider ID', v => { v.disks.rows[0].deviceId.value = 'x'.repeat(65); }],
        ['controls', v => { v.disks.rows[0].friendlyName.value = 'a\nb'; }], ['invalid surrogate', v => { v.disks.rows[0].friendlyName.value = '\ud800'; }], ['empty observed label', v => { v.disks.rows[0].deviceId.value = ''; }],
        ['denied field with value', v => { v.disks.rows[0].deviceId.quality = 'denied'; }], ['missing nullable scalar', v => { delete (v.disks.rows[0] as Partial<typeof v.disks.rows[0]>).healthStatus; }],
        ['numeric size', v => Object.assign(v.disks.rows[0], { sizeBytes: 123 })], ['uint64 overflow', v => { v.disks.rows[0].sizeBytes = '18446744073709551616'; }], ['leading zero bytes', v => { v.disks.rows[0].sizeBytes = '01'; }],
        ['negative zero status', v => { v.disks.rows[0].healthStatus = -0; }], ['fractional status', v => { v.disks.rows[0].healthStatus = 1.5; }], ['uint16 overflow', v => { v.disks.rows[0].busType = 65536; }],
        ['negative status', v => { v.disks.rows[0].mediaType = -1; }], ['null operational array', v => { v.disks.rows[0].operationalStatus = null as never; }], ['duplicate statuses', v => { v.disks.rows[0].operationalStatus = [2, 2]; }],
        ['too many statuses', v => { v.disks.rows[0].operationalStatus = Array.from({ length: 17 }, (_, i) => i); }], ['status array overflow', v => { v.disks.rows[0].operationalStatus = [65536]; }],
        ['row index gap', v => { v.disks.rows[0].index = 1; }], ['row index negative zero', v => { v.disks.rows[0].index = -0; }], ['unexplained partial', v => { v.disks.reason = ''; }],
        ['observed enumeration incomplete', v => { v.disks.quality = 'observed'; v.disks.complete = false; }], ['complete truncation', v => { v.disks.truncated = true; }], ['count contradicts rows', v => { v.disks.observedCount = 1; }],
        ['count too high', v => { v.disks.observedCount = 65; }], ['drive count too high', v => { v.drives.observedCount = 27; }], ['unknown reason', v => { v.disks.reason = 'private-error' as never; }],
        ['denied source rows', v => { v.disks.quality = 'denied'; v.disks.reason = 'windows_storage_context_access_denied'; }], ['null rows', v => { v.disks.rows = null as never; }],
        ['lowercase letter', v => { v.drives.rows[0].letter = 'c:'; }], ['drive path', v => { v.drives.rows[0].letter = 'C:\\'; }], ['duplicate letter', v => { v.drives.rows[1].letter = 'C:'; }],
        ['unsorted letters', v => { v.drives.rows.reverse(); }], ['unsupported remote type', v => { v.drives.rows[0].driveType = 'remote' as never; }], ['observed unknown type', v => { v.drives.rows[0].driveType = 'unknown'; }],
        ['observed missing mapping', v => { v.drives.rows[0].volumeGuid = null; }], ['denied mapping with value', v => { v.drives.rows[0].quality = 'denied'; }], ['GUID casing', v => { v.drives.rows[0].volumeGuid = '\\\\?\\Volume{AAAAAAAA-1111-1111-1111-111111111111}\\'; }],
        ['foreign volume path', v => { v.drives.rows[0].volumeGuid = '\\\\server\\share'; }], ['unavailable row access denied', v => { v.drives.rows[1].quality = 'unavailable'; }],
        ['observed denied drive fields', v => { v.drives.quality = 'observed'; v.drives.reason = ''; }], ['observed unknown disk fields', v => { v.disks.quality = 'observed'; v.disks.reason = ''; }], ['partial hides omission', v => { v.disks.observedCount = 3; v.disks.complete = false; }],
        ['generation mismatch', v => { v.generationId = `sample_${'8'.repeat(32)}`; }], ['time mismatch', v => { v.collectedAt = '2026-10-07T11:59:59Z'; }], ['bad grant', v => { v.grantId = 'invalid'; }], ['wrong scope', v => { v.scope = 'windows-visible-volumes-v1' as never; }],
    ];
    it.each(invalid)('rejects %s', (_label, mutate) => { const v = windowsStorageContext(); mutate(v); expect(valid(v)).toBe(false); });
    it('enforces native/transport bounds and encoded JSON byte cap', () => {
        const v = windowsStorageContext(); v.disks.rows = Array.from({ length: 32 }, (_, index) => ({ ...v.disks.rows[0], index })); Object.assign(v.disks, { observedCount: 64, quality: 'partial', reason: 'windows_storage_context_bounds', truncated: true, countExact: false, complete: false }); expect(valid(v)).toBe(true);
        v.disks.rows.push({ ...v.disks.rows[0], index: 32 }); expect(valid(v)).toBe(false); v.disks.rows.pop();
        for (const row of v.disks.rows) { row.deviceId = { value: '<'.repeat(64), quality: 'observed' }; row.friendlyName = { value: '😀'.repeat(64), quality: 'observed' }; } expect(valid(v)).toBe(false);
    });
    it('requires separate grant authority, exact capture, and bounded age', () => {
        const view = windowsStorageContextView(); view.storageContext.grantId = view.volumes.grantId; expect(validWindowsInventoryView(view, windowsDeviceId)).toBe(false);
        for (const status of ['revoked', 'unavailable', 'awaiting', 'not_configured']) expect(validWindowsInventoryView({ ...windowsStorageContextView(), status, snapshot: null }, windowsDeviceId)).toBe(false);
        expect(validWindowsInventoryView({ ...windowsView(), storageContext: null }, windowsDeviceId)).toBe(false);
        const v = windowsStorageContext(), snapshot = windowsView().snapshot!;
        expect(validWindowsStorageContext(v, snapshot, '2026-10-07T11:59:30Z')).toBe(true); expect(validWindowsStorageContext(v, snapshot, '2026-10-07T11:59:29.999999999Z')).toBe(false);
        expect(validWindowsStorageContext(v, snapshot, '2026-10-08T11:59:59.999999999Z')).toBe(true); expect(validWindowsStorageContext(v, snapshot, '2026-10-08T12:00:00Z')).toBe(false);
        v.collectedAt = '2026-10-07T12:00:00.000000001Z'; expect(valid(v)).toBe(false);
    });
    it('keeps a whole useful retained capture only with original age and current grant', () => {
        const v: WindowsInventoryView = windowsStorageContextView(), old = windowsStorageContext(); old.collectedAt = '2026-10-07T11:00:00Z'; old.generationId = `sample_${'b'.repeat(32)}`; v.retainedContext = { storageContext: old }; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(true);
        old.grantId = 'e'.repeat(32); expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false); old.grantId = v.storageContext!.grantId;
        old.drives = unavailableWindowsStorageGroup(); expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(true); old.disks = unavailableWindowsStorageGroup(); expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false);
        Object.assign(old.disks, { quality: 'observed', reason: '', complete: true, countExact: true }); expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(true);
        old.collectedAt = v.storageContext!.collectedAt; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false);
    });
    function unknownStorage() {
        const v = windowsStorageContext(); v.drives = unavailableWindowsStorageGroup();
        for (const row of v.disks.rows) Object.assign(row, { deviceId: { value: null, quality: 'unavailable' }, friendlyName: { value: null, quality: 'unavailable' }, sizeBytes: null, healthStatus: 5, busType: 0, mediaType: 0, operationalStatus: [] });
        return v;
    }
    it('admits unknown and future classification codes without counting them as useful retention', () => {
        const v = unknownStorage(); expect(valid(v)).toBe(true); expect(usefulWindowsStorageContext(v)).toBe(false);
        for (const healthStatus of [null, 3, 4, 5, 65535]) for (const busType of [null, 0, 14, 18, 65535]) for (const mediaType of [null, 0, 1, 2, 6, 65535]) {
            Object.assign(v.disks.rows[0], { healthStatus, busType, mediaType, operationalStatus: [0, 1, 19, 32768, 65535] });
            expect(valid(v)).toBe(true); expect(usefulWindowsStorageContext(v)).toBe(false);
        }
        const view: WindowsInventoryView = { ...windowsStorageContextView(), storageContext: unknownStorage() };
        expect(validWindowsInventoryView(view, windowsDeviceId)).toBe(true);
        const old = unknownStorage(); old.collectedAt = '2026-10-07T11:00:00Z'; old.generationId = `sample_${'b'.repeat(32)}`;
        view.retainedContext = { storageContext: old }; expect(validWindowsInventoryView(view, windowsDeviceId)).toBe(false);
        old.disks.rows[0].healthStatus = 0; expect(validWindowsInventoryView(view, windowsDeviceId)).toBe(true);
    });
    it('counts each known classification, actual label, size or mapping as independently useful', () => {
        const known = { healthStatus: [0, 1, 2], busType: [...Array.from({ length: 13 }, (_, i) => i + 1), 15, 16, 17], mediaType: [3, 4, 5] };
        for (const [field, values] of Object.entries(known)) for (const value of values) { const v = unknownStorage(); Object.assign(v.disks.rows[0], { [field]: value }); expect(valid(v)).toBe(true); expect(usefulWindowsStorageContext(v)).toBe(true); }
        for (let status = 2; status <= 18; status++) { const v = unknownStorage(); v.disks.rows[0].operationalStatus = [status]; expect(valid(v)).toBe(true); expect(usefulWindowsStorageContext(v)).toBe(true); }
        for (const field of ['deviceId', 'friendlyName'] as const) { const v = unknownStorage(); v.disks.rows[0][field] = { value: 'actual source label', quality: 'observed' }; expect(usefulWindowsStorageContext(v)).toBe(true); }
        const zero = unknownStorage(); zero.disks.rows[0].sizeBytes = '0'; expect(usefulWindowsStorageContext(zero)).toBe(true);
        const mapped = unknownStorage(); mapped.drives = windowsStorageContext().drives; expect(usefulWindowsStorageContext(mapped)).toBe(true);
    });

});
