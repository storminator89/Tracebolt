import { inventoryAge } from './complete-packages-types';
import { validWindowsCapacityDeviceId } from './windows-capacity-types';
import { WINDOWS_MAINTENANCE_DOMAINS, validWindowsMaintenanceIntent, validWindowsMaintenanceKey, validWindowsMaintenanceTime } from './windows-maintenance-types';
import type { WindowsMaintenanceDomain, WindowsMaintenanceIntent } from './windows-maintenance-types';
import type { WindowsMaintenanceOccurrenceBounds } from './windows-maintenance-series-plan';
import { validWindowsMaintenanceWeeklyBounds } from './windows-maintenance-series-plan';
import { validWindowsMaintenanceScheduleView, windowsMaintenanceScheduleState } from './windows-maintenance-schedule-types';
import type { WindowsMaintenanceScheduleView } from './windows-maintenance-schedule-types';

export const WINDOWS_MAINTENANCE_SERIES_BYTES = 256 * 1024;
export interface WindowsMaintenanceSeriesOccurrence extends WindowsMaintenanceOccurrenceBounds { id: number; seriesId: number; createdAt: string; cancelledAt: string | null; endedAt: string | null; intent: WindowsMaintenanceIntent }
export interface WindowsMaintenanceSeriesTarget { key: string; deviceId: string; domain: WindowsMaintenanceDomain; revision: number; changedAt: string | null; remainingSlots: number; retiredOccurrences: number; immediateActive: boolean; legacyReserved: boolean; occurrences: WindowsMaintenanceSeriesOccurrence[] }
export interface WindowsMaintenanceSeriesView { schemaVersion: 'tracebolt.windows-maintenance-series.v1'; serverNow: string; authorityExpiresAt: string; targets: WindowsMaintenanceSeriesTarget[] }
export interface WindowsMaintenanceSeriesProposal { key: string; revision: number; intent: WindowsMaintenanceIntent; occurrences: WindowsMaintenanceOccurrenceBounds[] }
export interface WindowsMaintenanceSeriesReview extends WindowsMaintenanceSeriesProposal { schemaVersion: 'tracebolt.windows-maintenance-series-review.v1'; reviewToken: string; operationId: string; expiresAt: string; action: 'create' | 'cancel' | 'end'; occurrenceId: number }
export interface WindowsMaintenanceSeriesReceipt { schemaVersion: 'tracebolt.windows-maintenance-series-receipt.v1'; operationId: string; key: string; action: 'create' | 'cancel' | 'end'; revision: number; occurrenceIds: number[]; committedAt: string; expiresAt: string }
export const seriesExact = (v: unknown, keys: string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v,k));
const integer = (v: unknown, min=0, max=Number.MAX_SAFE_INTEGER): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= min && v <= max;
const past = (v: unknown, now: string): v is string => validWindowsMaintenanceTime(v) && inventoryAge(now,v) >= 0;
export const validWindowsMaintenanceSeriesOperationId = (v: unknown): v is string => typeof v==='string' && /^wms_[1-9][0-9]{0,15}_[a-f0-9]{32}$/.test(v);
export const windowsMaintenanceSeriesState = windowsMaintenanceScheduleState;
function validOccurrence(v: unknown, now: string): v is WindowsMaintenanceSeriesOccurrence {
    if (!seriesExact(v,['id','seriesId','createdAt','startsAt','endsAt','cancelledAt','endedAt','intent']) || !integer(v.id,1) || !integer(v.seriesId,1) || !past(v.createdAt,now) || !validWindowsMaintenanceTime(v.startsAt) || !validWindowsMaintenanceTime(v.endsAt) || !validWindowsMaintenanceIntent(v.intent)) return false;
    const lead=inventoryAge(v.startsAt,v.createdAt), duration=inventoryAge(v.endsAt,v.startsAt);
    return lead >= 60000 && lead <= 28*86400000 && duration >= 60000 && duration <= 86400000 && inventoryAge(v.endsAt,v.createdAt)<=29*86400000 && (v.cancelledAt === null || v.endedAt === null && past(v.cancelledAt,now) && inventoryAge(v.cancelledAt,v.createdAt)>=0 && inventoryAge(v.startsAt,v.cancelledAt)>0) && (v.endedAt===null || v.cancelledAt===null && past(v.endedAt,now) && inventoryAge(v.endedAt,v.startsAt)>=0 && inventoryAge(v.endsAt,v.endedAt)>0);
}
function validTarget(v: unknown, now: string): v is WindowsMaintenanceSeriesTarget {
    if (!seriesExact(v,['key','deviceId','domain','revision','changedAt','remainingSlots','retiredOccurrences','immediateActive','legacyReserved','occurrences']) || !validWindowsMaintenanceKey(v.key) || typeof v.deviceId!=='string' || !validWindowsCapacityDeviceId(v.deviceId) || !(WINDOWS_MAINTENANCE_DOMAINS as readonly unknown[]).includes(v.domain) || !integer(v.revision) || !integer(v.remainingSlots,0,16) || !integer(v.retiredOccurrences) || typeof v.immediateActive!=='boolean' || typeof v.legacyReserved!=='boolean' || !Array.isArray(v.occurrences) || v.occurrences.length>16-v.remainingSlots || !v.occurrences.every(w=>validOccurrence(w,now))) return false;
    if (v.revision===0) return v.changedAt===null && v.occurrences.length===0 && v.retiredOccurrences===0;
    if (!past(v.changedAt,now) || v.occurrences.length===0) return false;
    const rows=v.occurrences as WindowsMaintenanceSeriesOccurrence[];
    if (new Set(rows.map(w=>w.id)).size!==rows.length) return false;
    for (let i=0;i<rows.length;i++) { const row=rows[i]; if (row.seriesId>v.revision || row.id<=v.retiredOccurrences || row.id>v.retiredOccurrences+16-v.remainingSlots || i>0&&rows[i-1].id<=row.id || inventoryAge(v.changedAt,row.cancelledAt??row.endedAt??row.createdAt)<0) return false; }
    if(new Set(rows.filter(row=>['pending','active'].includes(windowsMaintenanceSeriesState(row,now,0))).map(row=>row.seriesId)).size>1)return false;
    const groups=new Map<number,WindowsMaintenanceSeriesOccurrence[]>();
    for(const row of rows) groups.set(row.seriesId,[...(groups.get(row.seriesId)??[]),row]);
    for(const group of groups.values()) {
        if(group.length>4)return false;
        const first=group[0];
        for(const row of group) if(row.createdAt!==first.createdAt || row.intent!==first.intent || inventoryAge(row.endsAt,row.startsAt)!==inventoryAge(first.endsAt,first.startsAt) || (row.id-first.id)*7*86400000!==inventoryAge(row.startsAt,first.startsAt) || Math.abs(row.id-first.id)>3)return false;
    }
    return true;
}
export function validWindowsMaintenanceSeriesView(v:unknown):v is WindowsMaintenanceSeriesView {
    if(!seriesExact(v,['schemaVersion','serverNow','authorityExpiresAt','targets']) || v.schemaVersion!=='tracebolt.windows-maintenance-series.v1' || !validWindowsMaintenanceTime(v.serverNow) || !validWindowsMaintenanceTime(v.authorityExpiresAt) || inventoryAge(v.authorityExpiresAt,v.serverNow)<=0 || !Array.isArray(v.targets) || v.targets.length>150 || v.targets.length%6!==0 || !v.targets.every(t=>validTarget(t,v.serverNow as string)))return false;
    const targets=v.targets as WindowsMaintenanceSeriesTarget[];
    if(new Set(targets.map(t=>t.key)).size!==targets.length)return false;
    for(let i=0;i<targets.length;i+=6) {
        const group=targets.slice(i,i+6),id=group[0].deviceId;
        if(i>0&&targets[i-6].deviceId>=id || group.some((t,j)=>t.deviceId!==id||t.domain!==WINDOWS_MAINTENANCE_DOMAINS[j]))return false;
        const live=group.filter(t=>t.occurrences.some(w=>['pending','active'].includes(windowsMaintenanceSeriesState(w,v.serverNow as string,0))));
        if(live.some(t=>t.domain==='all')&&live.length>1 || live.some(t=>t.immediateActive||t.legacyReserved))return false;
    }
    return new TextEncoder().encode(JSON.stringify(v)).byteLength<=WINDOWS_MAINTENANCE_SERIES_BYTES;
}
export function windowsMaintenanceSeriesCanStart(v:WindowsMaintenanceSeriesView,t:WindowsMaintenanceSeriesTarget,age:number,count:number):boolean {
    return Number.isFinite(age)&&age>=0&&age<120000&&count>=2&&count<=4&&t.remainingSlots>=count&&t.revision<Number.MAX_SAFE_INTEGER&&!t.immediateActive&&!t.legacyReserved&&!v.targets.some(c=>c.deviceId===t.deviceId&&(t.domain==='all'||c.domain==='all'||c.key===t.key)&&(c.occurrences.some(w=>['pending','active','unknown'].includes(windowsMaintenanceSeriesState(w,v.serverNow,age)))));
}
export function validWindowsMaintenanceSeriesReview(v:unknown,proposal:WindowsMaintenanceSeriesProposal,now:string,age:number,action:'create'|'cancel'|'end'='create',occurrenceId=0):v is WindowsMaintenanceSeriesReview {
    return seriesExact(v,['schemaVersion','reviewToken','operationId','expiresAt','key','revision','intent','occurrences','action','occurrenceId']) && v.schemaVersion==='tracebolt.windows-maintenance-series-review.v1' && v.action===action && v.occurrenceId===occurrenceId && typeof v.reviewToken==='string' && v.reviewToken.length>0&&v.reviewToken.length<=8192 && validWindowsMaintenanceSeriesOperationId(v.operationId) && validWindowsMaintenanceTime(v.expiresAt)&&inventoryAge(v.expiresAt,now)>age && v.key===proposal.key&&v.revision===proposal.revision&&v.intent===proposal.intent&&Array.isArray(v.occurrences)&&v.occurrences.length===proposal.occurrences.length&&v.occurrences.every((row,i)=>seriesExact(row,['startsAt','endsAt'])&&row.startsAt===proposal.occurrences[i].startsAt&&row.endsAt===proposal.occurrences[i].endsAt)&&(action!=='create'||validWindowsMaintenanceWeeklyBounds(proposal.occurrences,now,age));
}
export function validWindowsMaintenanceSeriesReceipt(v:unknown,review:Pick<WindowsMaintenanceSeriesReview,'operationId'|'key'|'action'|'revision'|'occurrenceId'|'occurrences'>):v is WindowsMaintenanceSeriesReceipt {
    if(!seriesExact(v,['schemaVersion','operationId','key','action','revision','occurrenceIds','committedAt','expiresAt']) || v.schemaVersion!=='tracebolt.windows-maintenance-series-receipt.v1' || v.operationId!==review.operationId || v.key!==review.key || v.action!==review.action || v.revision!==review.revision+1 || !validWindowsMaintenanceTime(v.committedAt) || !validWindowsMaintenanceTime(v.expiresAt) || inventoryAge(v.expiresAt,v.committedAt)!==86400000 || !Array.isArray(v.occurrenceIds) || v.occurrenceIds.length!==review.occurrences.length || !v.occurrenceIds.every(id=>integer(id,1)) || new Set(v.occurrenceIds).size!==v.occurrenceIds.length)return false;
    if(!validWindowsMaintenanceSeriesOperationId(v.operationId))return false;
    const issued=Number(v.operationId.split('_')[1]),committed=Date.parse(v.committedAt);
    if(!Number.isSafeInteger(issued)||committed<issued||committed>=issued+120000||v.occurrenceIds.some((id,i,ids)=>i>0&&(id as number)<=(ids[i-1] as number)))return false;
    return review.action==='create' || v.occurrenceIds[0]===review.occurrenceId;
}

/** Atomic modern read: v1 bytes remain unchanged; only these separate rows add series reservation/capacity. */
export interface WindowsMaintenanceSeriesLegacyView { schemaVersion: 'tracebolt.windows-maintenance-series-legacy.v1'; legacy: WindowsMaintenanceScheduleView; reservations: WindowsMaintenanceSeriesReservation[] }
export interface WindowsMaintenanceSeriesReservation { key: string; seriesReserved: boolean; remainingSlots: number }
export function validWindowsMaintenanceSeriesLegacyView(v:unknown):v is WindowsMaintenanceSeriesLegacyView {
    if(!seriesExact(v,['schemaVersion','legacy','reservations']) || v.schemaVersion!=='tracebolt.windows-maintenance-series-legacy.v1' || !validWindowsMaintenanceScheduleView(v.legacy) || !Array.isArray(v.reservations) || v.reservations.length!==v.legacy.targets.length)return false;
    const legacy=v.legacy;
    return v.reservations.every((r,i)=>seriesExact(r,['key','seriesReserved','remainingSlots'])&&r.key===legacy.targets[i].key&&typeof r.seriesReserved==='boolean'&&!(r.seriesReserved&&legacy.targets[i].windows.some(w=>['pending','active'].includes(windowsMaintenanceScheduleState(w,legacy.serverNow,0))))&&integer(r.remainingSlots,0,legacy.targets[i].remainingSlots))&&new TextEncoder().encode(JSON.stringify(v)).byteLength<=WINDOWS_MAINTENANCE_SERIES_BYTES;
}
