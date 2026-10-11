import { describe, expect, it } from 'vitest';
import { windowsHardwareContext, windowsHardwareContextView } from './windows-hardware-context-fixture';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import { validWindowsHardwareContext, usefulWindowsHardwareContext, windowsFirmwareDate, type WindowsHardwareContext } from './windows-hardware-context-types';
import { validWindowsInventoryView, type WindowsInventoryView } from './windows-inventory-types';
import { windowsSessionContext } from './windows-session-context-fixture';
const valid = (v: unknown) => validWindowsHardwareContext(v, windowsView().snapshot!, windowsNow);
describe('Bounded hardware source contract', () => {
    it('accepts independently qualified sources and the exact private view', () => {
        expect(valid(windowsHardwareContext())).toBe(true);
        expect(validWindowsInventoryView({ ...windowsHardwareContextView(), sessionContext: windowsSessionContext() }, windowsDeviceId)).toBe(true);
        for (const kind of ['system', 'firmware', 'chassis', 'power'] as const) for (const quality of ['denied', 'unavailable'] as const) {
            const v = windowsHardwareContext(), source = v[kind]; source.quality = quality; source.reason = quality === 'denied' ? 'windows_hardware_context_access_denied' : 'windows_hardware_context_unavailable';
            if (kind === 'power') Object.assign(source, { acLineStatus: 'unknown', batteryPresence: 'unknown', charging: 'unknown', batteryPercent: null, estimatedSeconds: null });
            else for (const value of Object.values(source)) if (value && typeof value === 'object') Object.assign(value, { value: null, quality });
            expect(valid(v)).toBe(true);
        }
    });
    it('distinguishes absent, unknown and empty without inventing values', () => {
        const v = windowsHardwareContext(); Object.assign(v.power, { batteryPresence: 'absent', charging: 'unknown', batteryPercent: null }); expect(valid(v)).toBe(true);
        Object.assign(v.power, { batteryPresence: 'unknown', quality: 'partial', reason: 'windows_hardware_context_partial_result' }); expect(valid(v)).toBe(true);
        v.chassis.serialNumber = { value: null, quality: 'empty' }; expect(valid(v)).toBe(true);
    });
    it('accepts exact UTF-16 field limits, with BIOS and chassis serials kept separate', () => {
        const v = windowsHardwareContext(); v.system.model.value = '😀'.repeat(64); v.chassis.serialNumber.value = '😀'.repeat(32); v.firmware.serialNumber = { value: 'BIOS-LABEL', quality: 'observed' }; v.firmware.quality = 'observed'; v.firmware.reason = ''; expect(valid(v)).toBe(true);
    });
    const invalid: [string, (v: WindowsHardwareContext) => void][] = [
        ['unknown root field', v => Object.assign(v, { uniqueId: 'forbidden' })], ['unknown source field', v => Object.assign(v.system, { uuid: 'forbidden' })],
        ['wrong source', v => { v.firmware.source = 'Win32_ComputerSystemProduct' as never; }], ['wrong chassis source', v => { v.chassis.source = 'Win32_BIOS' as never; }],
        ['oversized label', v => { v.system.model.value = 'x'.repeat(129); }], ['oversized chassis serial', v => { v.chassis.serialNumber.value = 'x'.repeat(65); }],
        ['controls', v => { v.system.model.value = 'line\nline'; }], ['invalid surrogate', v => { v.system.model.value = '\ud800'; }], ['empty observed label', v => { v.system.model.value = ''; }],
        ['denied with value', v => { v.chassis.serialNumber.quality = 'denied'; }], ['empty with value', v => { v.system.model.quality = 'empty'; }], ['unexplained partial', v => { v.system.quality = 'partial'; }],
        ['invalid date', v => { v.firmware.releaseDate.value = '20260230000000.000000+000'; }], ['wildcard date', v => { v.firmware.releaseDate.value = '2026**********.******+***'; }],
        ['unknown date text', v => { v.firmware.releaseDate.value = 'not-a-date'; }], ['invalid time', v => { v.firmware.releaseDate.value = '20260101250000.000000+000'; }],
        ['percent over 100', v => { v.power.batteryPercent = 101; }], ['negative zero', v => { v.power.batteryPercent = -0; }], ['fractional percent', v => { v.power.batteryPercent = 1.2; }],
        ['native time sentinel', v => { v.power.estimatedSeconds = 4294967295; }], ['estimate while on AC', v => { v.power.estimatedSeconds = 3600; }], ['absent with percent', v => { v.power.batteryPresence = 'absent'; }],
        ['offline unknown estimate is not complete', v => { v.power.acLineStatus = 'offline'; }], ['unknown battery is not absent', v => { v.power.batteryPresence = 'unknown'; }],
        ['generation mismatch', v => { v.generationId = `sample_${'8'.repeat(32)}`; }], ['time mismatch', v => { v.collectedAt = '2026-10-07T11:59:59Z'; }], ['bad grant', v => { v.grantId = 'invalid'; }],
    ];
    it.each(invalid)('rejects %s', (_label, mutate) => { const v = windowsHardwareContext(); mutate(v); expect(valid(v)).toBe(false); });
    it('requires a separate grant, current authority and bounded original age', () => {
        const view = { ...windowsHardwareContextView(), sessionContext: windowsSessionContext() }; view.hardwareContext.grantId = view.sessionContext.grantId; expect(validWindowsInventoryView(view, windowsDeviceId)).toBe(false);
        const v = windowsHardwareContext(), snapshot = windowsView().snapshot!;
        expect(validWindowsHardwareContext(v, snapshot, '2026-10-07T11:59:30Z')).toBe(true);
        expect(validWindowsHardwareContext(v, snapshot, '2026-10-07T11:59:29.999999999Z')).toBe(false);
        expect(validWindowsHardwareContext(v, snapshot, '2026-10-08T11:59:59.999999999Z')).toBe(true);
        expect(validWindowsHardwareContext(v, snapshot, '2026-10-08T12:00:00Z')).toBe(false);
        const revoked = { ...windowsHardwareContextView(), status: 'revoked', snapshot: null }; expect(validWindowsInventoryView(revoked, windowsDeviceId)).toBe(false);
    });
    it('keeps retained captures under their original time and exact current grant', () => {
        const v: WindowsInventoryView = windowsHardwareContextView(), old = windowsHardwareContext(); old.collectedAt = '2026-10-07T11:00:00Z'; old.generationId = `sample_${'b'.repeat(32)}`; v.retainedContext = { hardwareContext: old }; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(true);
        old.grantId = 'e'.repeat(32); expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false); old.grantId = v.hardwareContext!.grantId;
        old.collectedAt = v.hardwareContext!.collectedAt; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false);
    });
    it('keeps all-unknown partial captures current without treating them as useful retained context', () => {
        const v = windowsHardwareContext();
        for (const kind of ['system', 'firmware', 'chassis'] as const) {
            const source = v[kind]; source.quality = 'partial'; source.reason = 'windows_hardware_context_partial_result';
            for (const field of Object.values(source)) if (field && typeof field === 'object') Object.assign(field, { value: null, quality: 'unavailable' });
        }
        Object.assign(v.power, { quality: 'partial', reason: 'windows_hardware_context_partial_result', acLineStatus: 'unknown', batteryPresence: 'unknown', charging: 'unknown', batteryPercent: null, estimatedSeconds: null });
        expect(valid(v)).toBe(true); expect(usefulWindowsHardwareContext(v)).toBe(false);
        const view = { ...windowsHardwareContextView(), hardwareContext: v }; expect(validWindowsInventoryView(view, windowsDeviceId)).toBe(true);
        const old = structuredClone(v); old.collectedAt = '2026-10-07T11:00:00Z'; old.generationId = `sample_${'b'.repeat(32)}`;
        const retained: WindowsInventoryView = { ...view, retainedContext: { hardwareContext: old } }; expect(validWindowsInventoryView(retained, windowsDeviceId)).toBe(false);
        old.power.batteryPresence = 'absent'; expect(usefulWindowsHardwareContext(old)).toBe(true); expect(validWindowsInventoryView(retained, windowsDeviceId)).toBe(true);
        old.power.batteryPresence = 'unknown'; old.system.model = { value: 'known model', quality: 'observed' }; expect(validWindowsInventoryView(retained, windowsDeviceId)).toBe(true);
    });
    it('formats exact dates without timezone-dependent day shifts or guessed days', () => {
        expect(windowsFirmwareDate('20260815013000.000000+120')).toBe('2026-08-15');
        expect(windowsFirmwareDate('20240229000000.000000-060')).toBe('2024-02-29');
        for (const value of [null, '20260229000000.000000+000', '2026**********.******+***', '20260815240000.000000+000']) expect(windowsFirmwareDate(value)).toBeNull();
    });
});
