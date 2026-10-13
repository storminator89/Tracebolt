import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { APIError, AUTH_REQUIRED_EVENT, abortProtectedRequests, request } from './api';
import { fleetUpdateState, groupFleetUpdates, useFleetUpdateTriage, FLEET_UPDATE_READ_CONCURRENCY } from './windows-fleet-update-triage-resource';
import { windowsUpdatesView } from './windows-updates-fixture';
import { WINDOWS_INVENTORY_VIEW_BYTES } from './windows-inventory-types';
vi.mock('./api',async original=>({...await original<typeof import('./api')>(),request:vi.fn()}));
const now='2026-10-07T12:00:10Z',expiry='2026-10-07T13:00:00Z';
const ids=Array.from({length:51},(_,i)=>`agent_${(i+1).toString(16).padStart(32,'0')}`);
const fixture=(id=ids[0])=>({...windowsUpdatesView(1),deviceId:id});
const flush=()=>act(async()=>{});
const hook=(targets=ids.slice(0,2))=>renderHook(()=>useFleetUpdateTriage(targets,expiry,true,vi.fn()));
beforeEach(()=>{vi.useFakeTimers();vi.setSystemTime(now);vi.mocked(request).mockReset().mockImplementation(async path=>fixture(path.split('/')[2]) as never)});
afterEach(()=>{cleanup();abortProtectedRequests();vi.useRealTimers();vi.restoreAllMocks()});
it('reads only on demand, uses bounded GETs, groups exact GUID/revision and preserves per-device metadata',async()=>{
 const a=fixture(ids[0]),b=fixture(ids[1]);b.updates.rows[0].title='Different vendor title';b.updates.rows[0].downloaded=false;
 b.updates.rows.push({...b.updates.rows[0],revision:11});b.updates.observedCount=2;
 vi.mocked(request).mockImplementation(async path=>(path.includes(ids[0])?a:b) as never);
 const {result}=hook();expect(request).not.toHaveBeenCalled();act(()=>result.current.read());await flush();
 expect(request).toHaveBeenCalledTimes(2);for(const [path,options,cap] of vi.mocked(request).mock.calls){expect(path).toMatch(/\/windows-inventory$/);expect(options?.method??'GET').toBe('GET');expect(cap).toBe(WINDOWS_INVENTORY_VIEW_BYTES)}
 expect(result.current.groups).toHaveLength(2);expect(result.current.groups[0].reports).toHaveLength(2);expect(result.current.groups[0].downloaded).toBe(1);expect(result.current.groups[1].reports).toHaveLength(1);expect(result.current.reports[1].updates).toMatchObject({generationId:b.updates.generationId,grantId:b.updates.grantId,collectedAt:b.updates.collectedAt});expect(result.current.reports[0]).not.toHaveProperty('snapshot');
});
it('bounds frozen devices, simultaneous reads and retained rows without polling',async()=>{
 const resolvers:Array<()=>void>=[];let live=0,maximum=0;
 vi.mocked(request).mockImplementation(path=>{live++;maximum=Math.max(maximum,live);return new Promise(resolve=>resolvers.push(()=>{live--;resolve(fixture(path.split('/')[2]))})) as never});
 const {result}=hook(ids);act(()=>result.current.read());expect(request).toHaveBeenCalledTimes(FLEET_UPDATE_READ_CONCURRENCY);
 while(resolvers.length){const batch=resolvers.splice(0);await act(async()=>batch.forEach(resolve=>resolve()));}
 expect(maximum).toBe(4);expect(request).toHaveBeenCalledTimes(50);expect(result.current.reports).toHaveLength(50);expect(result.current.loading).toBe(false);
 act(()=>vi.advanceTimersByTime(15000));expect(request).toHaveBeenCalledTimes(50);
});
it('keeps stale, partial, missing and invalid reports separate from an empty observed result',async()=>{
 const views=ids.slice(0,5).map(fixture);views[0].status='stale';views[0].serverNow='2026-10-07T12:03:00Z';views[1].updates.quality='partial';views[1].updates.reason='windows_updates_partial_result';views[2].updates.rows=[];views[2].updates.observedCount=0;
 vi.mocked(request).mockImplementation(async path=>{const index=ids.indexOf(path.split('/')[2]);if(index===3){const {updates,...missing}=views[3];void updates;return missing as never;}if(index===4)return {...views[4],unknown:'invalid'} as never;return views[index] as never});
 const {result}=hook(ids.slice(0,5));act(()=>result.current.read());await flush();
 expect(result.current.reports.map(fleetUpdateState)).toEqual(['stale','partial','reporting','unavailable','unavailable']);expect(result.current.groups[0].reports).toHaveLength(2);
});
it.each(['blur','pagehide','popstate','hashchange',AUTH_REQUIRED_EVENT,'cancel','unmount'])('clears accepted and late private rows on %s without starting queued reads',async event=>{
 const {result,unmount}=hook(ids.slice(0,8));let resolve!:(value:unknown)=>void;
 vi.mocked(request).mockResolvedValueOnce(fixture(ids[0])).mockImplementation(()=>new Promise(r=>{resolve=r}) as never);
 act(()=>result.current.read());await flush();expect(result.current.reports).toHaveLength(1);const calls=vi.mocked(request).mock.calls.length;
 act(()=>{if(event==='cancel')result.current.clear();else if(event==='unmount')unmount();else window.dispatchEvent(new Event(event))});await act(async()=>resolve(fixture(ids[1])));
 if(event!=='unmount'){expect(result.current.reports).toHaveLength(0);expect(result.current.groups).toHaveLength(0);expect(result.current.hasRead).toBe(false)}expect(request).toHaveBeenCalledTimes(calls);for(const [,options] of vi.mocked(request).mock.calls)expect(options!.signal!.aborted).toBe(true);
});
it('clears session replacement and rejects late response, then locks on unauthorized reads',async()=>{
 let resolve!:(value:unknown)=>void;vi.mocked(request).mockImplementation(()=>new Promise(r=>{resolve=r}) as never);
 const {result,rerender}=renderHook(({actor})=>useFleetUpdateTriage([ids[0]],expiry,true,vi.fn(),actor),{initialProps:{actor:'first'}});
 act(()=>result.current.read());rerender({actor:'second'});await act(async()=>resolve(fixture()));expect(result.current.reports).toHaveLength(0);
 vi.mocked(request).mockRejectedValue(new APIError('unauthorized',401));act(()=>result.current.read());await flush();act(()=>result.current.read());expect(request).toHaveBeenCalledTimes(2);expect(result.current.reports).toHaveLength(0);
});
it('times out ignored aborts without issuing queued requests or exceeding four outstanding transports',async()=>{
 vi.mocked(request).mockImplementation(()=>new Promise(()=>{}) as never);const {result}=hook(ids);act(()=>result.current.read());
 await act(async()=>vi.advanceTimersByTimeAsync(10000));expect(result.current.loading).toBe(false);expect(result.current.reports.map(fleetUpdateState)).toEqual(Array(4).fill('unavailable'));expect(request).toHaveBeenCalledTimes(4);
});
it('does not renew capture age and drops private rows on retention, epoch or clock loss',async()=>{
 const {result}=hook();act(()=>result.current.read());await flush();act(()=>vi.advanceTimersByTime(121000));expect(result.current.reports.map(fleetUpdateState)).toEqual(['stale','stale']);act(()=>vi.advanceTimersByTime(179000));expect(result.current.reports).toHaveLength(0);
 act(()=>result.current.read());await flush();expect(result.current.groups).toHaveLength(0); // unchanged manager clock cannot renew the cache
 vi.mocked(request).mockImplementation(async path=>({...fixture(path.split('/')[2]),serverNow:new Date().toISOString(),status:'stale'}) as never);act(()=>result.current.read());await flush();expect(result.current.reports).toHaveLength(2);act(()=>abortProtectedRequests());act(()=>vi.advanceTimersByTime(1000));expect(result.current.reports).toHaveLength(0);
 act(()=>result.current.read());await flush();act(()=>vi.setSystemTime(Date.now()-5000));act(()=>vi.advanceTimersByTime(1000));expect(result.current.reports).toHaveLength(0);
});
it('withholds future captures until acceptance time and never groups expired rows',async()=>{
 const view=fixture();view.status='stale';view.serverNow='2026-10-07T11:59:59Z';view.receivedAt=view.serverNow;vi.mocked(request).mockResolvedValue(view);const {result}=hook([ids[0]]);act(()=>result.current.read());await flush();expect(result.current.groups).toHaveLength(0);act(()=>vi.advanceTimersByTime(1000));expect(result.current.groups).toHaveLength(1);
 const report={...result.current.reports[0],serverNow:'2026-10-08T12:00:00Z'};expect(groupFleetUpdates([report])).toHaveLength(0);
});

it('purges the original update evidence at its 24-hour boundary, including collapsed source details',async()=>{
 const view=fixture();view.status='stale';view.serverNow='2026-10-08T11:59:59Z';vi.setSystemTime(view.serverNow);vi.mocked(request).mockResolvedValue(view);
 const {result}=renderHook(()=>useFleetUpdateTriage([ids[0]],'2026-10-08T13:00:00Z',true,vi.fn()));act(()=>result.current.read());await flush();expect(result.current.reports[0].updates).toBeDefined();expect(result.current.groups).toHaveLength(1);act(()=>vi.advanceTimersByTime(2000));expect(result.current.groups).toHaveLength(0);expect(result.current.reports).toEqual([{deviceId:ids[0]}]);
});

it('ends a slow but progressing batch at one minute and clears late results',async()=>{
 vi.mocked(request).mockImplementation(path=>new Promise(resolve=>window.setTimeout(()=>resolve(fixture(path.split('/')[2])),9000)) as never);const {result}=hook(ids);act(()=>result.current.read());await act(async()=>vi.advanceTimersByTimeAsync(60000));expect(result.current.hasRead).toBe(false);expect(result.current.reports).toHaveLength(0);const calls=vi.mocked(request).mock.calls.length;await act(async()=>vi.advanceTimersByTimeAsync(10000));expect(request).toHaveBeenCalledTimes(calls);expect(result.current.reports).toHaveLength(0);
});
