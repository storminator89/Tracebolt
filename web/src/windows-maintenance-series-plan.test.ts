import { expect, it } from 'vitest';
import { validWindowsMaintenanceWeeklyBounds, windowsMaintenanceWeeklyPlan } from './windows-maintenance-series-plan';
const now = '2026-10-07T12:00:00Z';
it.each([2,3,4])('freezes %i exact seven-day UTC occurrences', count => {
    const plan = windowsMaintenanceWeeklyPlan('2026-10-07T12:01', 60, count)!;
    expect(plan).toHaveLength(count);
    expect(validWindowsMaintenanceWeeklyBounds(plan, now, 0)).toBe(true);
    for (let i=0;i<count;i++) {
        expect(Date.parse(plan[i].startsAt)-Date.parse(plan[0].startsAt)).toBe(i*7*86400000);
        expect(Date.parse(plan[i].endsAt)-Date.parse(plan[i].startsAt)).toBe(3600000);
    }
});
it('enforces finite count, valid calendar, whole-minute duration and first-start bounds', () => {
    for (const count of [0,1,5,2.5,Infinity]) expect(windowsMaintenanceWeeklyPlan('2026-10-07T12:01',60,count)).toBeNull();
    for (const duration of [0,1441,1.5,NaN]) expect(windowsMaintenanceWeeklyPlan('2026-10-07T12:01',duration,2)).toBeNull();
    expect(windowsMaintenanceWeeklyPlan('2026-02-30T12:01',60,2)).toBeNull();
    expect(windowsMaintenanceWeeklyPlan('2026-10-07T12:01Z',60,2)).toBeNull();
    expect(validWindowsMaintenanceWeeklyBounds(windowsMaintenanceWeeklyPlan('2026-10-07T12:00',1,2)!,now,0)).toBe(false);
    expect(validWindowsMaintenanceWeeklyBounds(windowsMaintenanceWeeklyPlan('2026-10-14T12:00',1440,4)!,now,0)).toBe(true);
    expect(validWindowsMaintenanceWeeklyBounds(windowsMaintenanceWeeklyPlan('2026-10-14T12:01',1,2)!,now,0)).toBe(false);
});
it('rejects stale reviews, altered spacing and mismatched duration', () => {
    const plan = windowsMaintenanceWeeklyPlan('2026-10-07T12:01',60,4)!;
    for (const age of [-1,1,120000,Infinity,NaN]) expect(validWindowsMaintenanceWeeklyBounds(plan,now,age)).toBe(false);
    plan[2].startsAt='2026-10-22T12:01:00Z';expect(validWindowsMaintenanceWeeklyBounds(plan,now,0)).toBe(false);
    const changed=windowsMaintenanceWeeklyPlan('2026-10-07T12:01',60,4)!;
    changed[1].endsAt='2026-10-14T14:01:00Z';expect(validWindowsMaintenanceWeeklyBounds(changed,now,0)).toBe(false);
});
it('keeps UTC weekly times through the daylight-saving boundary', () => {
    const plan=windowsMaintenanceWeeklyPlan('2026-10-23T12:00',60,2)!;
    const local=new Intl.DateTimeFormat('en-GB',{timeZone:'Europe/Berlin',hour:'2-digit',hourCycle:'h23',timeZoneName:'shortOffset'});
    expect(local.format(new Date(plan[0].startsAt))).toContain('14');
    expect(local.format(new Date(plan[1].startsAt))).toContain('13');
    expect(plan[1].startsAt).toBe('2026-10-30T12:00:00Z');
});
