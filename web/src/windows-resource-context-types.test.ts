import goFixture from './windows-resource-context-go-fixture.json';
import { describe, expect, it } from 'vitest';
import { windowsResourceContext, windowsResourceContextView, unavailableWindowsResourceContext } from './windows-resource-context-fixture';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import { validWindowsResourceContext, usefulWindowsResourceContext, windowsResourceBytes, windowsCommitRemaining, type WindowsResourceContext } from './windows-resource-context-types';
import { validWindowsInventoryView, type WindowsInventoryView } from './windows-inventory-types';
import { windowsHardwareContext } from './windows-hardware-context-fixture';
const valid = (v: unknown) => validWindowsResourceContext(v, windowsView().snapshot!, windowsNow);
describe('Bounded CPU and memory source contract', () => {
    it('accepts the native encoder fixture with exact greater-than-2^53 bytes', () => {
        const snapshot = { ...windowsView().snapshot!, generationId: goFixture.generationId, collectedAt: goFixture.collectedAt };
        expect(validWindowsResourceContext(goFixture, snapshot, goFixture.collectedAt)).toBe(true);
        expect(goFixture.installedMemory.installedBytes).toBe('9007199254742016');
        expect(goFixture.processors.totalCores).toBe(8);
    });
    it('accepts independent sources, default-off absence and existing hardware without changing old views', () => {
        expect(valid(windowsResourceContext())).toBe(true); expect(valid(unavailableWindowsResourceContext())).toBe(true);
        expect(validWindowsInventoryView(windowsView(), windowsDeviceId)).toBe(true);
        expect(validWindowsInventoryView({ ...windowsResourceContextView(), hardwareContext: windowsHardwareContext() }, windowsDeviceId)).toBe(true);
        for (const key of ['processors', 'installedMemory', 'memory', 'pagefiles'] as const) { const v = windowsResourceContext(); Object.assign(v, { [key]: unavailableWindowsResourceContext()[key] }); expect(valid(v)).toBe(true); }
    });
    it('keeps actual zero distinct from unknown and accepts uint64 bytes without numeric coercion', () => {
        const v = windowsResourceContext(); Object.assign(v.pagefiles, { count: 0, totalBytes: '0', totalInUseBytes: '0' }); v.memory.commitTotalBytes = v.memory.physicalAvailableBytes = '0'; expect(valid(v)).toBe(true);
        Object.assign(v.pagefiles, { count: 1, totalBytes: '18446744073709551615', totalInUseBytes: '9007199254740993' }); expect(valid(v)).toBe(true);
        Object.assign(v.memory, { commitTotalBytes: '9007199254740992', commitLimitBytes: '9007199254745088' }); expect(valid(v)).toBe(true); expect(windowsCommitRemaining(v.memory)).toBe('4096');
        expect(windowsResourceBytes('18446744073709551615', 'en')).toBe('16.0 EiB'); expect(windowsResourceBytes('33285996544', 'de')).toBe('31,0 GiB');
        expect(windowsCommitRemaining(unavailableWindowsResourceContext().memory)).toBeNull();
    });
    it('reports source rows without inferred topology, and only complete paired counts are summed', () => {
        const v = windowsResourceContext(); v.processors.rows.push(structuredClone(v.processors.rows[0])); v.processors.totalCores = 24; v.processors.totalLogicalProcessors = 48; expect(valid(v)).toBe(true);
        v.processors.rows[0].cores = { value: null, quality: 'denied' }; Object.assign(v.processors, { quality: 'partial', reason: 'windows_resource_context_partial_result', totalCores: null, totalLogicalProcessors: null }); expect(valid(v)).toBe(true);
        v.processors.totalLogicalProcessors = 48; expect(valid(v)).toBe(false);
        v.processors.totalLogicalProcessors = null; v.processors.rows[0].name = { value: null, quality: 'empty' }; expect(valid(v)).toBe(true);
        v.processors.rows[0].architecture = { value: null, quality: 'unavailable' }; expect(valid(v)).toBe(true);
    });
    const invalid: [string, (v: WindowsResourceContext) => void][] = [
        ['unknown root', v => Object.assign(v, { socketCount: 1 })], ['CPU identifier', v => Object.assign(v.processors.rows[0], { processorId: 'private' })], ['pagefile name', v => Object.assign(v.pagefiles, { name: 'private' })], ['unknown source', v => Object.assign(v.memory, { source: 'GlobalMemoryStatusEx' })],
        ['number bytes', v => Object.assign(v.memory, { commitTotalBytes: 4096 })], ['uint64 overflow', v => { v.pagefiles.totalBytes = '18446744073709551616'; }], ['leading zero', v => { v.pagefiles.totalBytes = '01'; }], ['negative bytes', v => { v.pagefiles.totalBytes = '-1'; }], ['exponent bytes', v => { v.pagefiles.totalBytes = '1e9'; }],
        ['unaligned installed RAM', v => { v.installedMemory.installedBytes = '1025'; }], ['zero installed RAM', v => { v.installedMemory.installedBytes = '0'; }], ['page alignment', v => { v.memory.commitTotalBytes = '4097'; }], ['invalid page size', v => { v.memory.pageSizeBytes = '3072'; }], ['page size too small', v => { v.memory.pageSizeBytes = '512'; }], ['page size too large', v => { v.memory.pageSizeBytes = '2147483648'; }], ['zero commit limit', v => { v.memory.commitLimitBytes = '0'; }], ['zero OS RAM', v => { v.memory.physicalTotalBytes = '0'; }], ['commit above limit', v => { v.memory.commitTotalBytes = '85899345920'; }], ['available above OS RAM', v => { v.memory.physicalAvailableBytes = '85899345920'; }],
        ['zero pagefiles positive allocation', v => { v.pagefiles.count = 0; }], ['pagefiles zero allocation', v => { v.pagefiles.totalBytes = v.pagefiles.totalInUseBytes = '0'; }], ['too many pagefiles', v => { v.pagefiles.count = 33; }], ['negative zero count', v => { v.pagefiles.count = -0; }], ['pagefile in use exceeds total', v => { v.pagefiles.totalInUseBytes = '85899345920'; }], ['partial memory source', v => Object.assign(v.memory, { quality: 'partial', reason: 'windows_resource_context_partial_result' })], ['denied retains values', v => Object.assign(v.memory, { quality: 'denied', reason: 'windows_resource_context_access_denied' })], ['unexplained source failure', v => Object.assign(v.memory, unavailableWindowsResourceContext().memory, { reason: '' })],
        ['long CPU name', v => { v.processors.rows[0].name.value = 'x'.repeat(129); }], ['control name', v => { v.processors.rows[0].name.value = 'a\nb'; }], ['invalid UTF16', v => { v.processors.rows[0].name.value = '\ud800'; }], ['unknown architecture', v => { v.processors.rows[0].architecture.value = 'future'; }], ['empty architecture', v => Object.assign(v.processors.rows[0].architecture, { value: null, quality: 'empty' })], ['zero cores', v => { v.processors.rows[0].cores.value = 0; }], ['count overflow', v => { v.processors.rows[0].cores.value = 65536; }], ['wrong aggregate', v => { v.processors.totalCores = 1; }], ['empty CPU rows', v => { v.processors.rows = []; }], ['too many CPU rows', v => { v.processors.rows = Array(5).fill(v.processors.rows[0]); }], ['partial without missing', v => Object.assign(v.processors, { quality: 'partial', reason: 'windows_resource_context_partial_result' })],
        ['partial wrong reason', v => { v.processors.rows[0].name = { value: null, quality: 'denied' }; Object.assign(v.processors, { quality: 'partial', reason: 'windows_resource_context_access_denied' }); }], ['denied wrong reason', v => Object.assign(v.installedMemory, { quality: 'denied', reason: 'windows_resource_context_budget_exhausted', installedBytes: null })], ['unknown reason', v => Object.assign(v.memory, unavailableWindowsResourceContext().memory, { reason: 'private-error' })],
        ['bad grant', v => { v.grantId = 'invalid'; }], ['generation mismatch', v => { v.generationId = `sample_${'8'.repeat(32)}`; }], ['time mismatch', v => { v.collectedAt = '2026-10-07T11:59:59Z'; }],
    ];
    it.each(invalid)('rejects %s', (_label, mutate) => { const v = windowsResourceContext(); mutate(v); expect(valid(v)).toBe(false); });
    it('enforces the HTML-escaped source size and complete collection cap', () => {
        const v = windowsResourceContext(); v.processors.rows = Array.from({ length: 4 }, () => structuredClone(v.processors.rows[0])); v.processors.totalCores = 48; v.processors.totalLogicalProcessors = 96; expect(valid(v)).toBe(true);
        for (const row of v.processors.rows) row.name.value = '😀'.repeat(64); expect(valid(v)).toBe(true);
        for (const row of v.processors.rows) row.name.value = '<'.repeat(128); expect(valid(v)).toBe(true);
        v.processors.rows.push(structuredClone(v.processors.rows[0])); expect(valid(v)).toBe(false);
    });
    it('keeps independent grant, capture and expiry authority', () => {
        const v = windowsResourceContextView(); v.resourceContext.grantId = windowsHardwareContext().grantId; expect(validWindowsInventoryView({ ...v, hardwareContext: windowsHardwareContext() }, windowsDeviceId)).toBe(false);
        for (const status of ['revoked', 'unavailable', 'awaiting', 'not_configured']) expect(validWindowsInventoryView({ ...windowsResourceContextView(), status, snapshot: null }, windowsDeviceId)).toBe(false);
        expect(validWindowsInventoryView({ ...windowsView(), resourceContext: null }, windowsDeviceId)).toBe(false);
        const s = windowsResourceContext(), snapshot = windowsView().snapshot!; expect(validWindowsResourceContext(s, snapshot, '2026-10-07T11:59:30Z')).toBe(true); expect(validWindowsResourceContext(s, snapshot, '2026-10-07T11:59:29.999999999Z')).toBe(false); expect(validWindowsResourceContext(s, snapshot, '2026-10-08T12:00:00Z')).toBe(false);
        s.collectedAt = '2026-10-07T12:00:00.000000001Z'; expect(valid(s)).toBe(false);
    });
    it('retains only useful original-age captures under current grant, including explicit absent pagefiles', () => {
        const view: WindowsInventoryView = windowsResourceContextView(), old = windowsResourceContext(); old.collectedAt = '2026-10-07T11:00:00Z'; old.generationId = `sample_${'c'.repeat(32)}`; view.retainedContext = { resourceContext: old }; expect(validWindowsInventoryView(view, windowsDeviceId)).toBe(true);
        old.grantId = 'e'.repeat(32); expect(validWindowsInventoryView(view, windowsDeviceId)).toBe(false); old.grantId = view.resourceContext!.grantId;
        old.collectedAt = view.resourceContext!.collectedAt; expect(validWindowsInventoryView(view, windowsDeviceId)).toBe(false);
        const unknown = unavailableWindowsResourceContext(); expect(usefulWindowsResourceContext(unknown)).toBe(false); Object.assign(unknown.pagefiles, { quality: 'observed', reason: '', count: 0, totalBytes: '0', totalInUseBytes: '0' }); expect(valid(unknown)).toBe(true); expect(usefulWindowsResourceContext(unknown)).toBe(true);
        unknown.collectedAt = '2026-10-07T11:00:00Z'; unknown.generationId = `sample_${'c'.repeat(32)}`; view.retainedContext = { resourceContext: unknown }; expect(validWindowsInventoryView(view, windowsDeviceId)).toBe(true);
        unknown.pagefiles = unavailableWindowsResourceContext().pagefiles; expect(validWindowsInventoryView(view, windowsDeviceId)).toBe(false);
    });
});
