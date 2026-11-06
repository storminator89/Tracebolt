import { inventoryAge } from './complete-packages-types';
import { validWindowsMaintenanceTime } from './windows-maintenance-types';

export interface WindowsMaintenanceOccurrenceBounds { startsAt: string; endsAt: string }
const WEEK = 7 * 86400000;
/** Immutable UTC proposals. Local daylight-saving changes never move an occurrence. */
export function windowsMaintenanceWeeklyPlan(start: string, minutes: number, count: number): WindowsMaintenanceOccurrenceBounds[] | null {
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(start) || !Number.isInteger(minutes) || minutes < 1 || minutes > 1440 || !Number.isInteger(count) || count < 2 || count > 4) return null;
    const first = start + ':00Z';
    if (!validWindowsMaintenanceTime(first)) return null;
    const result = Array.from({ length: count }, (_, index) => {
        const starts = Date.parse(first) + index * WEEK;
        return { startsAt: new Date(starts).toISOString().replace('.000Z', 'Z'), endsAt: new Date(starts + minutes * 60000).toISOString().replace('.000Z', 'Z') };
    });
    return result.every(w => validWindowsMaintenanceTime(w.startsAt) && validWindowsMaintenanceTime(w.endsAt)) ? result : null;
}
export function validWindowsMaintenanceWeeklyBounds(windows: WindowsMaintenanceOccurrenceBounds[], now: string, age: number): boolean {
    if (!validWindowsMaintenanceTime(now) || !Number.isFinite(age) || age < 0 || age >= 120000 || windows.length < 2 || windows.length > 4) return false;
    const first = windows[0], duration = inventoryAge(first.endsAt, first.startsAt), lead = inventoryAge(first.startsAt, now) - age;
    return lead >= 60000 && lead <= WEEK && duration >= 60000 && duration <= 86400000 && inventoryAge(windows.at(-1)!.endsAt, now) - age <= 29 * 86400000 && windows.every((w, i) => validWindowsMaintenanceTime(w.startsAt) && validWindowsMaintenanceTime(w.endsAt) && inventoryAge(w.endsAt, w.startsAt) === duration && inventoryAge(w.startsAt, first.startsAt) === i * WEEK);
}
