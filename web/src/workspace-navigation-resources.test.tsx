import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, APIError, AUTH_REQUIRED_EVENT, request } from './api';
import { useFleetIdentity } from './fleet-identity-resource';
import { useInvestigations } from './investigations-resource';
import { endpointView } from './endpoint-identity-fixtures';
import type { InvestigationScope, InvestigationsView } from './investigations-types';
vi.mock('./api', async original=>({...await original<typeof import('./api')>(),request:vi.fn()}));
const fleet=()=>{const v=endpointView();return {schemaVersion:'tracebolt.fleet-endpoint-identity.v1',serverNow:v.serverNow,items:[v]};};
const investigations=(scope:InvestigationScope='open'):InvestigationsView=>({schemaVersion:'tracebolt.investigations.v1',serverNow:'2026-10-07T12:00:00Z',scope,offset:0,total:0,counts:{open:0,recovered:0,closed:0,all:0},devices:[],items:[]});
const flush=()=>act(async()=>{await vi.advanceTimersByTimeAsync(0);});
type Props={enabled:boolean;session:string;revision:string;scope:InvestigationScope};
const initial:Props={enabled:true,session:'authorized-session',revision:'0',scope:'open'};
const sources=[{name:'fleet',view:()=>fleet(),use:(p:Props)=>useFleetIdentity(p.enabled,p.session,p.revision,true)},{name:'investigations',view:()=>investigations(),use:(p:Props)=>useInvestigations(p.enabled,p.session,p.revision,p.scope,0,true)}];
beforeEach(()=>{vi.useFakeTimers();vi.setSystemTime('2026-10-07T12:00:00Z');localStorage.clear();sessionStorage.clear();vi.spyOn(document,'visibilityState','get').mockReturnValue('visible');vi.mocked(request).mockReset();});
afterEach(()=>{cleanup();abortProtectedRequests();vi.useRealTimers();vi.restoreAllMocks();});
for(const source of sources)describe(`${source.name} workspace navigation snapshots`,()=>{
 it('retains original valid data during refresh, cancels navigation work and rejects its late response',async()=>{
  let oldResolve!:(v:unknown)=>void,newResolve!:(v:unknown)=>void,oldSignal!:AbortSignal;
  vi.mocked(request).mockResolvedValueOnce(source.view()).mockImplementationOnce((_p,o)=>{oldSignal=o!.signal as AbortSignal;return new Promise(resolve=>{oldResolve=resolve;});}).mockImplementationOnce(()=>new Promise(resolve=>{newResolve=resolve;}));
  const {result,rerender}=renderHook(p=>source.use(p),{initialProps:initial});await flush();const original=result.current.view;expect(original).not.toBeNull();
  rerender({...initial,revision:'1'});await flush();expect(result.current.view).toEqual(original);
  rerender({...initial,revision:'1',enabled:false});expect(oldSignal.aborted).toBe(true);expect(result.current.view).toBeNull();
  await act(async()=>{await vi.advanceTimersByTimeAsync(31000);});expect(request).toHaveBeenCalledTimes(2);
  rerender({...initial,revision:'1'});await flush();expect(result.current.view).toEqual(original);
  await act(async()=>oldResolve({...source.view(),serverNow:'2026-10-08T12:00:00Z'}));expect(result.current.view).toEqual(original);
  await act(async()=>newResolve(source.view()));expect(result.current.view).not.toBeNull();expect(request).toHaveBeenCalledTimes(3);
 });
 it('does not revive a snapshot after the 45-second navigation budget',async()=>{
  vi.mocked(request).mockResolvedValueOnce(source.view()).mockImplementation(()=>new Promise(()=>{}));const {result,rerender}=renderHook(p=>source.use(p),{initialProps:initial});await flush();expect(result.current.view).not.toBeNull();
  rerender({...initial,enabled:false});await act(async()=>{await vi.advanceTimersByTimeAsync(45001);});expect(request).toHaveBeenCalledTimes(1);
  rerender(initial);await flush();expect(result.current.view).toBeNull();expect(request).toHaveBeenCalledTimes(2);
 });
 it('clears paused snapshots on blur and never fetches until the view is active',async()=>{
  vi.mocked(request).mockResolvedValueOnce(source.view()).mockImplementation(()=>new Promise(()=>{}));const {result,rerender}=renderHook(p=>source.use(p),{initialProps:initial});await flush();rerender({...initial,enabled:false});
  act(()=>window.dispatchEvent(new Event('blur')));act(()=>window.dispatchEvent(new Event('focus')));expect(request).toHaveBeenCalledTimes(1);
  rerender(initial);await flush();expect(result.current.view).toBeNull();expect(request).toHaveBeenCalledTimes(2);
 });
 it('keeps access loss latched through route toggles until a different session',async()=>{
  vi.mocked(request).mockResolvedValue(source.view());const {result,rerender}=renderHook(p=>source.use(p),{initialProps:initial});await flush();rerender({...initial,enabled:false});
  act(()=>{abortProtectedRequests();window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT));});rerender(initial);await flush();expect(result.current.view).toBeNull();expect(request).toHaveBeenCalledTimes(1);
  rerender({...initial,session:'new-authorized-session'});await flush();expect(result.current.view).not.toBeNull();expect(request).toHaveBeenCalledTimes(2);
 });
 it('clears retained observations on a failed refresh or clock discontinuity',async()=>{
  vi.mocked(request).mockResolvedValueOnce(source.view()).mockRejectedValueOnce(new APIError('unavailable',503));const {result}=renderHook(p=>source.use(p),{initialProps:initial});await flush();act(()=>result.current.refresh());await flush();expect(result.current.view).toBeNull();
  vi.mocked(request).mockResolvedValue(source.view());act(()=>result.current.refresh());await flush();expect(result.current.view).not.toBeNull();vi.setSystemTime(Date.now()+10000);await act(async()=>{await vi.advanceTimersByTimeAsync(1000);});expect(result.current.view).toBeNull();const state=result.current;expect('error' in state?state.error:state.failure).toBe('clock');
 });
 it('refreshes a visible view in the background without changing original evidence time before response',async()=>{
  vi.mocked(request).mockResolvedValueOnce(source.view()).mockImplementation(()=>new Promise(()=>{}));const {result}=renderHook(p=>source.use(p),{initialProps:initial});await flush();const original=result.current.view;
  await act(async()=>{await vi.advanceTimersByTimeAsync(30000);});expect(request).toHaveBeenCalledTimes(2);expect(result.current.view).toEqual(original);
  await act(async()=>{await vi.advanceTimersByTimeAsync(10001);});expect(result.current.view).toBeNull();
 });
});
it('keeps investigation caches scoped to their exact filter and never shows another filter while reading',async()=>{
 vi.mocked(request).mockImplementation(async path=>investigations(new URL(path,'https://fixture.invalid').searchParams.get('scope') as InvestigationScope));
 const {result,rerender}=renderHook(p=>useInvestigations(p.enabled,p.session,p.revision,p.scope,0,true),{initialProps:initial});await flush();expect(result.current.view?.scope).toBe('open');
 rerender({...initial,scope:'recovered'});await flush();expect(result.current.view?.scope).toBe('recovered');
 vi.mocked(request).mockImplementation(()=>new Promise(()=>{}));rerender(initial);expect(result.current.view?.scope).toBe('open');
 rerender({...initial,scope:'closed'});expect(result.current.view).toBeNull();
});
it('never restores endpoint values after their original retention expires inside a cached fleet',async()=>{
 const value=fleet(),item=value.items[0];const nearEnd=new Date(Date.parse(item.expiresAt!)-500).toISOString();value.serverNow=nearEnd;item.serverNow=nearEnd;item.status='stale';
 vi.mocked(request).mockResolvedValueOnce(value).mockImplementation(()=>new Promise(()=>{}));const {result,rerender}=renderHook(p=>useFleetIdentity(p.enabled,p.session,p.revision,true),{initialProps:initial});await flush();expect(result.current.view?.items[0].latest).not.toBeNull();
 await act(async()=>{await vi.advanceTimersByTimeAsync(1001);});expect(result.current.view?.items[0].latest).toBeNull();
 rerender({...initial,enabled:false});rerender(initial);await flush();expect(result.current.view?.items[0].latest).toBeNull();expect(result.current.identities.get(item.deviceId)?.hostname).toBeNull();
});
for(const source of sources)for(const clockAdvance of [0,1])it(`${source.name} does not renew freshness for a ${clockAdvance}ms manager-clock advance across poll, route return and refresh`,async()=>{
 vi.mocked(request).mockResolvedValue(source.view());const {result,rerender}=renderHook(p=>source.use(p),{initialProps:initial});await flush();expect(result.current.view).not.toBeNull();
 const replay=source.view();replay.serverNow=new Date(Date.parse(replay.serverNow)+clockAdvance).toISOString();if(source.name==='fleet')for(const item of (replay as ReturnType<typeof fleet>).items)item.serverNow=replay.serverNow;vi.mocked(request).mockResolvedValue(replay);
 await act(async()=>{await vi.advanceTimersByTimeAsync(30000);});expect(result.current.view).not.toBeNull();expect(request).toHaveBeenCalledTimes(2);
 const sameTime=source.view();sameTime.serverNow=new Date(Date.parse(sameTime.serverNow)+clockAdvance*2).toISOString();if(source.name==='fleet')for(const item of (sameTime as ReturnType<typeof fleet>).items)item.serverNow=sameTime.serverNow;vi.mocked(request).mockResolvedValue(sameTime);
 rerender({...initial,enabled:false});await act(async()=>{await vi.advanceTimersByTimeAsync(14000);});rerender(initial);await flush();expect(result.current.view).not.toBeNull();
 await act(async()=>{await vi.advanceTimersByTimeAsync(1001);});expect(result.current.view).toBeNull();
 act(()=>result.current.refresh());await flush();expect(result.current.view).toBeNull();
 const newer=source.view();newer.serverNow=new Date(Date.parse(newer.serverNow)+60000).toISOString();if(source.name==='fleet')for(const item of (newer as ReturnType<typeof fleet>).items)item.serverNow=newer.serverNow;
 vi.mocked(request).mockResolvedValue(newer);act(()=>result.current.refresh());await flush();expect(result.current.view).not.toBeNull();
});

for(const source of sources)it(`${source.name} accepts a manager clock advancing with local elapsed time`,async()=>{
 const started=Date.now();vi.mocked(request).mockImplementation(async()=>{const view=source.view();view.serverNow=new Date(Date.parse(view.serverNow)+Date.now()-started).toISOString();if(source.name==='fleet')for(const item of (view as ReturnType<typeof fleet>).items)item.serverNow=view.serverNow;return view;});
 const {result}=renderHook(p=>source.use(p),{initialProps:initial});await flush();expect(result.current.view).not.toBeNull();await act(async()=>{await vi.advanceTimersByTimeAsync(60000);});expect(request).toHaveBeenCalledTimes(3);expect(result.current.view).not.toBeNull();expect(result.current.view?.serverNow).toBe(new Date(Date.parse(source.view().serverNow)+60000).toISOString());
});

it('invalidates other investigation pages when a successful read removes an authorized device',async()=>{
 const scoped=(scope:InvestigationScope)=>{const view=investigations(scope);view.devices=[{schemaVersion:'tracebolt.health-view.v1',deviceId:'agent_'+('a'.repeat(32)),serverNow:view.serverNow,evaluatedAt:null,status:'unknown',maintenanceUntil:null,monitoredServices:[],checks:[{key:'offline:contact',kind:'offline',target:'agent',state:'unknown',observedAt:null,value:null},{key:'filesystem:root',kind:'filesystem',target:'/',state:'unknown',observedAt:null,value:null}],incidents:[]}];return view;};
 vi.mocked(request).mockImplementation(async path=>scoped(new URL(path,'https://fixture.invalid').searchParams.get('scope') as InvestigationScope));const {result,rerender}=renderHook(p=>useInvestigations(p.enabled,p.session,p.revision,p.scope,0,true),{initialProps:initial});await flush();expect(result.current.view?.devices).toHaveLength(1);
 rerender({...initial,scope:'all'});await flush();expect(result.current.view?.devices).toHaveLength(1);
 vi.mocked(request).mockResolvedValueOnce(investigations());rerender(initial);await flush();expect(result.current.view?.devices).toHaveLength(0);
 vi.mocked(request).mockImplementation(()=>new Promise(()=>{}));rerender({...initial,scope:'all'});expect(result.current.view).toBeNull();
});
