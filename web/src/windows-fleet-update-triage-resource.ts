import { useCallback, useEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, request } from './api';
import { hasLogoutIntent } from './auth';
import { inventoryAge } from './complete-packages-types';
import { validWindowsDeviceId, validWindowsInventoryView, WINDOWS_INVENTORY_VIEW_BYTES } from './windows-inventory-types';
import type { WindowsUpdates, WindowsUpdate } from './windows-updates-types';
import type { UpdateSelection } from './windows-update-jobs-types';

export const FLEET_UPDATE_READ_CONCURRENCY = 4;
export const FLEET_UPDATE_MAX_DEVICES = 50;
const READ_TIMEOUT_MS = 10000, BATCH_TIMEOUT_MS = 60000, RETENTION_MS = 300000;
type Anchor = { mono: number; wall: number };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
const elapsed = (a: Anchor) => {
 const mono = performance.now() - a.mono, wall = Date.now() - a.wall;
 return Number.isFinite(mono) && mono >= 0 && Number.isFinite(wall) && Math.abs(wall - mono) <= 1500 ? mono : Infinity;
};
export type FleetUpdateReport = {
 deviceId: string; updates?: WindowsUpdates; serverNow?: string; receivedAt?: string|null;
 status?: string; started?: Anchor; accepted?: Anchor;
};
function expiredReport(report: FleetUpdateReport): boolean {
 if (!report.updates || !report.started || !report.serverNow) return false;
 const age=inventoryAge(report.serverNow,report.updates.collectedAt)+elapsed(report.started);
 return !Number.isFinite(age)||age>=86400000;
}
export type FleetUpdateState = 'reporting' | 'partial' | 'stale' | 'unavailable';
export function fleetUpdateState(report: FleetUpdateReport): FleetUpdateState {
 const { updates, started, accepted, serverNow, receivedAt } = report;
 if (!updates || !started || !accepted || !serverNow || !receivedAt || !['observed', 'partial'].includes(updates.quality)) return 'unavailable';
 const age = inventoryAge(serverNow, updates.collectedAt) + elapsed(started), acceptedAge = elapsed(accepted);
 if (!Number.isFinite(age) || !Number.isFinite(acceptedAge) || age < 0 || age >= 86400000 || inventoryAge(updates.collectedAt, serverNow) > acceptedAge) return 'unavailable';
 if (report.status !== 'fresh' || age > 120000 || inventoryAge(serverNow, receivedAt) + elapsed(started) > 120000) return 'stale';
 return updates.quality === 'partial' || updates.truncated ? 'partial' : 'reporting';
}
export type FleetUpdateGroup = UpdateSelection & { reports: Array<{deviceId: string; row: WindowsUpdate}>; downloaded: number };
/** Metadata never establishes equivalence. Keep each device's original row and
 * capture/grant/generation evidence; only the exact WUA identity is grouped. */
export function groupFleetUpdates(reports: FleetUpdateReport[]): FleetUpdateGroup[] {
 const groups = new Map<string, FleetUpdateGroup>();
 for (const report of reports) {
  if (fleetUpdateState(report) === 'unavailable') continue;
  for (const row of report.updates!.rows) {
   const key = `${row.updateId}:${row.revision}`;
   let group = groups.get(key);
   if (!group) { group = { updateId: row.updateId, revision: row.revision, reports: [], downloaded: 0 }; groups.set(key, group); }
   if (group.reports.some(value => value.deviceId === report.deviceId)) continue;
   group.reports.push({deviceId: report.deviceId, row}); if (row.downloaded) group.downloaded++;
  }
 }
 return [...groups.values()].sort((a,b) => a.updateId.localeCompare(b.updateId) || a.revision - b.revision);
}
/** One deliberate bounded GET-only batch, never 50 polling inventory resources.
 * Full inventory DTOs are validated then discarded; only update evidence stays
 * in memory for at most five minutes, and never beyond its original 24h age. */
export function useFleetUpdateTriage(ids: string[], sessionKey: string, enabled: boolean, onClear: () => void, actor = '') {
 const key = JSON.stringify(ids.slice(0, FLEET_UPDATE_MAX_DEVICES)), scope = `${actor}:${sessionKey}:${enabled}:${key}`;
 const [data, setData] = useState<{scope: string; reports: FleetUpdateReport[]}|null>(null), [loading,setLoading] = useState(false), [,tick] = useState(0);
 const alive = useRef(false), locked = useRef(false), version = useRef(0), pending = useRef(new Set<AbortController>()), timers = useRef(new Set<number>()), retainedAt = useRef<Anchor|null>(null), retainedEpoch = useRef(0), clearCallback = useRef(onClear);
 clearCallback.current = onClear;
 const latestServer = useRef(new Map<string,{value:string;floor:string;accepted:Anchor}>());
 const clear = useCallback(() => {
  version.current++; for (const controller of pending.current) controller.abort(); pending.current.clear();
  for (const timer of timers.current) window.clearTimeout(timer); timers.current.clear(); retainedAt.current = null;
  if (alive.current) {setData(null); setLoading(false); clearCallback.current();}
 }, []);
 const read = useCallback(async () => {
  if (!enabled || !alive.current || locked.current || document.hidden || hasLogoutIntent() || !Number.isFinite(Date.parse(sessionKey))) return;
  clear();
  const targets: unknown = JSON.parse(key);
  if (!Array.isArray(targets) || !targets.length || targets.some(id => typeof id !== 'string' || !validWindowsDeviceId(id)) || new Set(targets).size !== targets.length) return;
  const token = version.current, epoch = getProtectedRequestEpoch(), batchStarted = capture(); let next = 0;
  retainedAt.current = batchStarted; retainedEpoch.current = epoch; setData({scope, reports: []}); setLoading(true);
  const active = () => {
   if (!alive.current || locked.current || token !== version.current) return false;
   if (epoch !== getProtectedRequestEpoch() || document.hidden || hasLogoutIntent()) {locked.current = true; clear(); return false;}
   if (!Number.isFinite(elapsed(batchStarted)) || Date.now() >= Date.parse(sessionKey)) {clear(); return false;}
   return true;
  };
  const batchTimer = window.setTimeout(clear, BATCH_TIMEOUT_MS); timers.current.add(batchTimer);
  const worker = async () => {
   while (next < targets.length && active()) {
    const deviceId = targets[next++] as string, started = capture(), controller = new AbortController(); pending.current.add(controller);
    let timeout: number | undefined;
    try {
     // Promise.race also bounds a transport which ignores abort. Such late bytes
     // cannot publish or start another read after the batch was cleared.
     const response = await Promise.race([
      request<unknown>(`/devices/${encodeURIComponent(deviceId)}/windows-inventory`, {signal:controller.signal}, WINDOWS_INVENTORY_VIEW_BYTES),
      new Promise<never>((_,reject)=>controller.signal.addEventListener('abort',()=>reject(new Error('Canceled')),{once:true})),
      new Promise<never>((_,reject) => {timeout=window.setTimeout(()=>{controller.abort();reject(new Error('timeout'));},READ_TIMEOUT_MS);timers.current.add(timeout);}),
     ]);
     if (!active() || controller.signal.aborted) return;
     if (!validWindowsInventoryView(response,deviceId) || elapsed(started) >= READ_TIMEOUT_MS) throw new Error('Invalid inventory');
     if(Date.parse(response.serverNow)>=Date.parse(sessionKey)){locked.current=true;clear();return;}
     const previous = latestServer.current.get(deviceId);
     if (previous && (inventoryAge(response.serverNow,previous.value) < 0 || inventoryAge(response.serverNow,previous.floor)+1500 < elapsed(previous.accepted))) throw new Error('Clock replay');
     latestServer.current.set(deviceId,previous?{...previous,value:response.serverNow}:{value:response.serverNow,floor:response.serverNow,accepted:capture()});
     const report: FleetUpdateReport = {deviceId, status:response.status, serverNow:response.serverNow, receivedAt:response.receivedAt, started, accepted:capture(), ...(response.updates?{updates:response.updates}:{})};
     setData(value=>value?.scope===scope?{scope,reports:[...value.reports,report]}:value);
    } catch (error) {
     if (!active()) return;
     if (error instanceof APIError && error.status === 401) {locked.current=true;clear();return;}
     setData(value=>value?.scope===scope?{scope,reports:[...value.reports,{deviceId}]}:value);
     // Do not release a timed-out transport's slot to another request. A
     // noncooperative transport must not increase outstanding concurrency.
     if(controller.signal.aborted)return;
    } finally {
     controller.abort(); pending.current.delete(controller); if(timeout!==undefined){window.clearTimeout(timeout);timers.current.delete(timeout);}
    }
   }
  };
  await Promise.all(Array.from({length:Math.min(FLEET_UPDATE_READ_CONCURRENCY,targets.length)},worker));
  window.clearTimeout(batchTimer);timers.current.delete(batchTimer);if(active())setLoading(false);
 }, [clear,enabled,key,scope,sessionKey]);
 useEffect(()=>{
  alive.current=true;locked.current=false;latestServer.current.clear();clear();
  const stop=()=>clear(),lock=()=>{locked.current=true;clear();},visibility=()=>{if(document.hidden)clear();};
  for(const event of ['blur','pagehide','popstate','hashchange'])window.addEventListener(event,stop);
  window.addEventListener(AUTH_REQUIRED_EVENT,lock);document.addEventListener('visibilitychange',visibility);
  const timer=window.setInterval(()=>{if(retainedAt.current){if(elapsed(retainedAt.current)>=RETENTION_MS||retainedEpoch.current!==getProtectedRequestEpoch()||hasLogoutIntent()||Date.now()>=Date.parse(sessionKey))clear();else {setData(value=>value&&value.reports.some(expiredReport)?{...value,reports:value.reports.map(report=>expiredReport(report)?{deviceId:report.deviceId}:report)}:value);tick(n=>n+1);}}},1000);
  return()=>{alive.current=false;clear();window.clearInterval(timer);for(const event of ['blur','pagehide','popstate','hashchange'])window.removeEventListener(event,stop);window.removeEventListener(AUTH_REQUIRED_EVENT,lock);document.removeEventListener('visibilitychange',visibility);};
 },[clear,scope,sessionKey]);
 const reports=enabled&&data?.scope===scope?data.reports.map(report=>expiredReport(report)?{deviceId:report.deviceId}:report):[];
 return {reports,groups:groupFleetUpdates(reports),loading:enabled&&loading,hasRead:enabled&&data?.scope===scope,read:()=>void read(),clear};
}
