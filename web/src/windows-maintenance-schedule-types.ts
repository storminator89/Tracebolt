import { inventoryAge } from './complete-packages-types';
import { validWindowsCapacityDeviceId } from './windows-capacity-types';
import { WINDOWS_MAINTENANCE_DOMAINS, validWindowsMaintenanceIntent, validWindowsMaintenanceKey, validWindowsMaintenanceTime } from './windows-maintenance-types';
import type { WindowsMaintenanceDomain, WindowsMaintenanceIntent } from './windows-maintenance-types';
export const WINDOWS_MAINTENANCE_SCHEDULE_BYTES = 256 * 1024;
export interface WindowsMaintenanceScheduleWindow { id: number; createdAt: string; startsAt: string; endsAt: string; cancelledAt: string | null; endedAt: string | null; intent: WindowsMaintenanceIntent }
export interface WindowsMaintenanceScheduleTarget { key: string; deviceId: string; domain: WindowsMaintenanceDomain; revision: number; changedAt: string | null; remainingSlots: number; retiredWindows: number; immediateActive: boolean; windows: WindowsMaintenanceScheduleWindow[] }
export interface WindowsMaintenanceScheduleView { schemaVersion: 'tracebolt.windows-maintenance-schedule.v1'; serverNow: string; authorityExpiresAt: string; targets: WindowsMaintenanceScheduleTarget[] }
export type WindowsMaintenanceScheduleStart = { key: string; revision: number; startsAt: string; endsAt: string; intent: WindowsMaintenanceIntent };
export type WindowsMaintenanceScheduleEnd = { key: string; revision: number; windowId: number };
const exact = (v: unknown, keys: string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const integer = (v: unknown, min = 0, max = Number.MAX_SAFE_INTEGER): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= min && v <= max;
const past = (v: unknown, now: string): v is string => validWindowsMaintenanceTime(v) && inventoryAge(now, v) >= 0;
function validWindow(v: unknown, now: string): v is WindowsMaintenanceScheduleWindow {
 if (!exact(v, ['id','createdAt','startsAt','endsAt','cancelledAt','endedAt','intent']) || !integer(v.id,1) || !past(v.createdAt,now) || !validWindowsMaintenanceTime(v.startsAt) || !validWindowsMaintenanceTime(v.endsAt) || !validWindowsMaintenanceIntent(v.intent)) return false;
 const lead=inventoryAge(v.startsAt,v.createdAt), duration=inventoryAge(v.endsAt,v.startsAt);
 return lead>=60000 && lead<=7*86400000 && duration>=60000 && duration<=86400000 && (v.cancelledAt===null || v.endedAt===null && past(v.cancelledAt,now) && inventoryAge(v.cancelledAt,v.createdAt)>=0 && inventoryAge(v.startsAt,v.cancelledAt)>0) && (v.endedAt===null || v.cancelledAt===null && past(v.endedAt,now) && inventoryAge(v.endedAt,v.startsAt)>=0 && inventoryAge(v.endsAt,v.endedAt)>0);
}
function validTarget(v:unknown,now:string):v is WindowsMaintenanceScheduleTarget {
 if(!exact(v,['key','deviceId','domain','revision','changedAt','retiredWindows','remainingSlots','immediateActive','windows']) || !validWindowsMaintenanceKey(v.key) || (typeof v.deviceId !== 'string' || !validWindowsCapacityDeviceId(v.deviceId)) || !(WINDOWS_MAINTENANCE_DOMAINS as readonly unknown[]).includes(v.domain) || !integer(v.revision) || !integer(v.retiredWindows) || !integer(v.remainingSlots,0,16) || typeof v.immediateActive!=='boolean' || !Array.isArray(v.windows) || v.windows.length!==Math.min(4,16-v.remainingSlots) || !v.windows.every(w=>validWindow(w,now)))return false;
 if(v.revision===0)return v.changedAt===null && v.remainingSlots===16 && v.retiredWindows===0;
 if(!past(v.changedAt,now)||v.windows.length===0)return false;
 const windows=v.windows as WindowsMaintenanceScheduleWindow[],latest=windows[0];
 if(v.changedAt!==(latest.cancelledAt??latest.endedAt??latest.createdAt)||v.revision!==latest.id+(latest.cancelledAt!==null||latest.endedAt!==null?1:0))return false;
 for(let i=1;i<windows.length;i++){const w=windows[i],newer=windows[i-1];if(newer.id!==w.id+(w.cancelledAt!==null||w.endedAt!==null?2:1)||inventoryAge(newer.createdAt,w.cancelledAt??w.endedAt??w.endsAt)<0)return false;}
 return true;
}
export function validWindowsMaintenanceScheduleView(v: unknown): v is WindowsMaintenanceScheduleView {
 if(!exact(v,['schemaVersion','serverNow','authorityExpiresAt','targets'])||v.schemaVersion!=='tracebolt.windows-maintenance-schedule.v1'||!validWindowsMaintenanceTime(v.serverNow)||!validWindowsMaintenanceTime(v.authorityExpiresAt)||inventoryAge(v.authorityExpiresAt,v.serverNow)<=0||!Array.isArray(v.targets)||v.targets.length>150||v.targets.length%6!==0||!v.targets.every(t=>validTarget(t,v.serverNow as string)))return false;
 const targets=v.targets as WindowsMaintenanceScheduleTarget[];
 if(new Set(targets.map(t=>t.key)).size!==targets.length)return false;
 for(let i=0;i<targets.length;i+=6){const group=targets.slice(i,i+6),id=group[0].deviceId;if(i>0&&targets[i-6].deviceId>=id||group.some((t,j)=>t.deviceId!==id||t.domain!==WINDOWS_MAINTENANCE_DOMAINS[j]))return false;const live=group.filter(t=>t.windows[0]&&['pending','active'].includes(windowsMaintenanceScheduleState(t.windows[0],v.serverNow as string,0)));if(live.some(t=>t.domain==='all')&&live.length>1||live.some(t=>t.immediateActive))return false;}
 return new TextEncoder().encode(JSON.stringify(v)).byteLength<=WINDOWS_MAINTENANCE_SCHEDULE_BYTES;
}
export function windowsMaintenanceScheduleState(w:WindowsMaintenanceScheduleWindow,now:string,age:number):'pending'|'active'|'ended'|'cancelled'|'expired'|'unknown'{
 if(!Number.isFinite(age)||age<0)return 'unknown';if(w.cancelledAt!==null)return 'cancelled';if(w.endedAt!==null)return 'ended';if(inventoryAge(w.endsAt,now)<=age)return 'expired';const untilStart=inventoryAge(w.startsAt,now);if(untilStart>0)return untilStart>age?'pending':'unknown';return 'active';
}
export function windowsMaintenanceScheduleCanStart(v:WindowsMaintenanceScheduleView,t:WindowsMaintenanceScheduleTarget,age:number):boolean{
 return Number.isFinite(age)&&age>=0&&t.remainingSlots>0&&!t.immediateActive&&t.revision<Number.MAX_SAFE_INTEGER&&!v.targets.some(c=>c.deviceId===t.deviceId&&(t.domain==='all'||c.domain==='all'||c.key===t.key)&&c.windows[0]&&['pending','active','unknown'].includes(windowsMaintenanceScheduleState(c.windows[0],v.serverNow,age)));
}
export function windowsMaintenanceScheduleBounds(start:string,minutes:number):{startsAt:string;endsAt:string}|null{
 if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(start)||![15,60,240].includes(minutes))return null;
 const startsAt=start+':00Z';if(!validWindowsMaintenanceTime(startsAt))return null;const endsAt=new Date(Date.parse(startsAt)+minutes*60000).toISOString().replace('.000Z','Z');return validWindowsMaintenanceTime(endsAt)?{startsAt,endsAt}:null;
}

/** A convenient proposal only. Saving still requires exact fixed-bound review. */
export function windowsMaintenanceScheduleSuggestedStart(now:string,age:number,hours=1):string|null {
 if(!validWindowsMaintenanceTime(now)||!Number.isFinite(age)||age<0||age>=120000||![1,4,24].includes(hours))return null;
 return new Date(Math.ceil((Date.parse(now)+age+hours*3600000)/60000)*60000).toISOString().slice(0,16);
}
