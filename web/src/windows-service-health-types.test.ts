import wireFixture from '../../tests/fixtures/windows-service-health-view.json';
import { describe, expect, it } from 'vitest';
import { windowsDeviceId } from './windows-inventory-fixture';
import { windowsCapacityView } from './windows-capacity-fixture';
import { windowsServiceHealthIncident, windowsServiceHealthView } from './windows-service-health-fixture';
import { WINDOWS_SERVICE_HEALTH_VIEW_BYTES, compareWindowsServiceNames, validWindowsServiceHealthName, validWindowsServiceHealthSelection, validWindowsServiceHealthView, windowsServiceHealthChoices, windowsServiceHealthStatus } from './windows-service-health-types';
import type { WindowsServiceHealthView } from './windows-service-health-types';
describe('closed selected-service operator schema', () => {
    it('uses the separate bounded 512KiB view budget, not the 256KiB durable state budget', () => expect(WINDOWS_SERVICE_HEALTH_VIEW_BYTES).toBe(512 * 1024));
    it.each(Object.entries(wireFixture))('accepts exact Go evaluator-produced %s response', (_name, value) => expect(validWindowsServiceHealthView(value, value.deviceId)).toBe(true));
    it.each(['disabled', 'unknown', 'running', 'pending', 'attention'] as const)('accepts bounded %s fixture', status => expect(validWindowsServiceHealthView(windowsServiceHealthView(status), windowsDeviceId)).toBe(true));
    it('rejects another device, percentage envelope, unexpected private fields and arbitrary values', () => {
        for (const value of [null, [], false, 4, 'value', windowsCapacityView(), { ...windowsServiceHealthView(), credentialHash: 'secret' }, { ...windowsServiceHealthView(), deviceId: `agent_${'8'.repeat(32)}` }]) expect(validWindowsServiceHealthView(value, windowsDeviceId)).toBe(false);
    });
    it('preserves exact opaque casing/Unicode/spacing and matches canonical UTF-8 ordering', () => {
        for (const name of ['Spooler', 'spooler', ' Worker ü ', '💠']) expect(validWindowsServiceHealthName(name)).toBe(true);
        expect(compareWindowsServiceNames('\uE000', '💠')).toBeLessThan(0);
        expect(validWindowsServiceHealthSelection(['\uE000', '💠'], true)).toBe(true);
        expect(validWindowsServiceHealthSelection(['💠', '\uE000'], true)).toBe(false);
        for (const names of [[], ['Spooler', 'Spooler'], ['b', 'a'], [' '], ['a\n'], ['a\u202E'], ['a\uFFFD'], ['ü'.repeat(129)], Array.from({ length: 9 }, (_, i) => String(i))]) expect(validWindowsServiceHealthSelection(names, true)).toBe(false);
    });
    it.each([
        (v: WindowsServiceHealthView) => { v.checks = [null as never]; },
        (v: WindowsServiceHealthView) => { v.checks[0].name = 'Other'; },
        (v: WindowsServiceHealthView) => { v.checks[0].status = 'unknown'; },
        (v: WindowsServiceHealthView) => { v.checks[0].observation!.state = 'start_pending' as never; },
        (v: WindowsServiceHealthView) => { v.checks[0].observation!.sequence = 0; },
        (v: WindowsServiceHealthView) => { v.checks[0].observation!.collectedAt = '2026-10-07T12:00:11Z'; },
        (v: WindowsServiceHealthView) => { v.checks[0].observation!.receivedAt = '2026-10-07T11:58:09Z'; },
        (v: WindowsServiceHealthView) => { v.evaluatedAt = null; },
        (v: WindowsServiceHealthView) => { v.status = 'pending'; },
        (v: WindowsServiceHealthView) => { v.incidents = []; },
        (v: WindowsServiceHealthView) => { v.incidents[0].lastBadObservation.state = 'running'; },
        (v: WindowsServiceHealthView) => { v.incidents[0].policyRevision = 2; },
        (v: WindowsServiceHealthView) => { v.incidents[0].name = 'Other'; },
        (v: WindowsServiceHealthView) => { v.incidents.push({ ...v.incidents[0] }); },
        (v: WindowsServiceHealthView) => { v.inventory!.services.push(v.inventory!.services[0]); },
        (v: WindowsServiceHealthView) => { v.inventory!.receivedAt = '2026-10-07T11:58:09Z'; },
        (v: WindowsServiceHealthView) => { v.inventory!.quality = 'denied' as never; },
        (v: WindowsServiceHealthView) => { (v.inventory!.services[0] as unknown as Record<string, unknown>).pid = 12; },
    ])('rejects malformed or contradictory source/history/check %i', change => { const view = windowsServiceHealthView('attention'); change(view); expect(validWindowsServiceHealthView(view, windowsDeviceId)).toBe(false); });
    it('accepts unknown with retained open history and never claims recovery on policy closure', () => {
        const unknown = windowsServiceHealthView('unknown'); unknown.incidents = [windowsServiceHealthIncident()]; expect(validWindowsServiceHealthView(unknown, windowsDeviceId)).toBe(true);
        const disabled = windowsServiceHealthView(); disabled.policy.revision = 2; disabled.incidents = [windowsServiceHealthIncident('policy-changed')]; expect(validWindowsServiceHealthView(disabled, windowsDeviceId)).toBe(true); disabled.incidents[0].recoveryObservation = windowsServiceHealthIncident('running').recoveryObservation; expect(validWindowsServiceHealthView(disabled, windowsDeviceId)).toBe(false);
    });
    it('accepts running observation during recovery confirmation while the incident is still open', () => {
        const view = windowsServiceHealthView('attention'); view.checks[0].observation!.state = 'running'; view.inventory!.services[0].state = 'running'; expect(validWindowsServiceHealthView(view, windowsDeviceId)).toBe(true);
    });
    it('allows unique retained choices in partial coverage, case variants and pending chooser states', () => {
        const view = windowsServiceHealthView(); view.inventory!.quality = 'partial'; view.inventory!.complete = false; view.inventory!.truncated = true; view.inventory!.observedCount = 50; view.inventory!.services[0].state = 'start_pending'; expect(validWindowsServiceHealthView(view, windowsDeviceId)).toBe(true);
    });
    it('ages current state and chooser without rewriting retained history or source timestamps', () => {
        const view = windowsServiceHealthView('attention'), original = JSON.stringify(view); expect(windowsServiceHealthStatus(view, 110000)).toBe('attention'); expect(windowsServiceHealthChoices(view, 110000)).toHaveLength(3); expect(windowsServiceHealthStatus(view, 110001)).toBe('unknown'); expect(windowsServiceHealthChoices(view, 110001)).toHaveLength(0); expect(JSON.stringify(view)).toBe(original);
    });

    it('retains selected names as unknown checks while disabled, never as running checks', () => {
        const view = windowsServiceHealthView(); view.policy = { enabled: false, services: ['FixtureService'], revision: 2 }; view.checks = [{ name: 'FixtureService', status: 'unknown', observation: null }]; expect(validWindowsServiceHealthView(view, windowsDeviceId)).toBe(true); view.checks = []; expect(validWindowsServiceHealthView(view, windowsDeviceId)).toBe(false);
    });
    it.each(['missing-source', 'different-state', 'different-sequence', 'different-capture', 'different-receipt'] as const)('rejects a current check detached from its current source: %s', change => {
        const view = windowsServiceHealthView('running');
        if (change === 'missing-source') view.inventory = null;
        if (change === 'different-state') view.inventory!.services[0].state = 'paused';
        if (change === 'different-sequence') view.inventory!.sequence++;
        if (change === 'different-capture') view.inventory!.collectedAt = '2026-10-07T12:00:01Z';
        if (change === 'different-receipt') view.inventory!.receivedAt = '2026-10-07T12:00:02Z';
        expect(validWindowsServiceHealthView(view, windowsDeviceId)).toBe(false);
    });
    it('invalid elapsed time fails closed even while disabled', () => { for (const elapsed of [NaN, Infinity, -1]) { expect(windowsServiceHealthStatus(windowsServiceHealthView(), elapsed)).toBe('unknown'); expect(windowsServiceHealthChoices(windowsServiceHealthView(), elapsed)).toHaveLength(0); } });
});
