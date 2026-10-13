import { describe, expect, it } from 'vitest';
import wire from './windows-complete-service-health-go-fixture.json';
import { completeHealthView } from './windows-service-health-complete-fixture';
import { validWindowsServiceHealthCompleteInventory, validWindowsServiceHealthCompleteName, validWindowsServiceHealthCompletePolicy, validWindowsServiceHealthCompleteSelection, validWindowsServiceHealthCompleteView, windowsServiceHealthCompleteStatus, windowsServiceHealthSourceFresh } from './windows-service-health-complete-types';
import type { WindowsServiceHealthCompleteView } from './windows-service-health-complete-types';
import { validWindowsServiceHealthView } from './windows-service-health-types';

describe('Go complete-source health contract', () => {
    it.each(['disabled', 'attention'] as const)('accepts exact Go %s DTO without extending v1', key => { const view = wire[key]; expect(validWindowsServiceHealthCompleteView(view, view.deviceId)).toBe(true); expect(validWindowsServiceHealthView(view, view.deviceId)).toBe(false); });
    it('accepts the Go paging-derived fresh selection fixture', () => { const view = completeHealthView(); expect(validWindowsServiceHealthCompleteView(view, view.deviceId)).toBe(true); expect(view.inventory!.observedCount).toBe(617); expect(view.inventory!.services).toEqual([]); });
    it('keeps native identity limits, including text excluded by the legacy preview', () => { expect(validWindowsServiceHealthCompleteName('界'.repeat(256))).toBe(true); expect(validWindowsServiceHealthCompleteName('🛠'.repeat(128))).toBe(true); expect(validWindowsServiceHealthCompleteName('A\tB')).toBe(true); expect(validWindowsServiceHealthCompleteName(' ')).toBe(true); expect(validWindowsServiceHealthCompleteName('界'.repeat(257))).toBe(false); expect(validWindowsServiceHealthCompleteName('a\0b')).toBe(false); expect(validWindowsServiceHealthCompleteSelection(Array.from({ length: 9 }, (_, i) => `Service${i}`), true)).toBe(false); });
    it('requires closed provenance on all observations and bounded selected evidence', () => {
        const original = structuredClone(wire.attention);
        for (const edit of [(v: any) => delete v.checks[0].observation.source, (v: any) => { v.inventory.source.sequence++; }, (v: any) => { v.inventory.source.path = 'hidden'; }, (v: any) => { v.inventory.services = Array.from({ length: 9 }, (_, i) => ({ ...v.inventory.services[0], name: `Service${i}` })); }, (v: any) => { v.inventory.services[0].name = 'NotSelected'; }, (v: any) => { v.policy.source.grantRevision++; }]) { const view = structuredClone(original); edit(view); expect(validWindowsServiceHealthCompleteView(view, view.deviceId)).toBe(false); }
    });
    it('accepts unavailable selected state without claiming it stopped', () => { const inventory = structuredClone(wire.attention.inventory); inventory.services[0].state = 'unknown'; expect(validWindowsServiceHealthCompleteInventory(inventory, wire.attention.serverNow)).toBe(true); });
    it('requires binding on configured names and rejects metadata-only v1 policy promotion', () => { expect(validWindowsServiceHealthCompletePolicy({ enabled: true, services: ['FixtureService'], revision: 1 })).toBe(false); expect(validWindowsServiceHealthCompletePolicy({ enabled: false, services: ['FixtureService'], revision: 1 })).toBe(false); expect(validWindowsServiceHealthCompletePolicy({ enabled: false, services: [], revision: 0 })).toBe(true); });
    it('uses 5-minute capture/receipt freshness and 2-minute evaluation freshness independently', () => {
        const view = structuredClone(wire.attention) as WindowsServiceHealthCompleteView;
        expect(windowsServiceHealthSourceFresh(view.inventory!.source, '2026-10-10T12:07:59Z')).toBe(true);
        expect(windowsServiceHealthSourceFresh(view.inventory!.source, '2026-10-10T12:08:00.001Z')).toBe(false);
        expect(windowsServiceHealthCompleteStatus(view, 120001)).toBe('unknown');
        view.serverNow = '2026-10-10T12:07:59Z'; view.evaluatedAt = view.serverNow;
        expect(validWindowsServiceHealthCompleteView(view, view.deviceId)).toBe(true);
        view.serverNow = '2026-10-10T12:08:00.001Z'; view.evaluatedAt = view.serverNow;
        expect(validWindowsServiceHealthCompleteView(view, view.deviceId)).toBe(false);
    });
    it('rejects provenance for another original device', () => { const view = structuredClone(wire.attention); view.deviceId = `agent_${'2'.repeat(32)}`; expect(validWindowsServiceHealthCompleteView(view, view.deviceId)).toBe(false); });
});
