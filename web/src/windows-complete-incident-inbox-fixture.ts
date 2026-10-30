/** Synthetic recorder-generated API bytes. No native or host acceptance. */
import wire from './windows-complete-incident-go-fixture.json';
import { validWindowsCompleteIncidentInboxView } from './windows-complete-incident-inbox-types';
import type { WindowsCompleteIncidentInboxView } from './windows-complete-incident-inbox-types';
export const completeIncidentNow = wire.active.serverNow;
export function completeIncidentFixture(scene: keyof typeof wire = 'active', now?: string): WindowsCompleteIncidentInboxView {
    const delta = now ? Date.parse(now) - Date.parse(wire[scene].serverNow) : 0;
    const shift = (value: unknown): unknown => typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/.test(value) && now ? new Date(Date.parse(value) + delta).toISOString() : Array.isArray(value) ? value.map(shift) : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).map(([key, item]) => [key, shift(item)])) : value;
    const value = shift(structuredClone(wire[scene]));
    if (!validWindowsCompleteIncidentInboxView(value, 'active', 'all', 0)) throw new Error('Invalid Go complete incident fixture');
    return value;
}
