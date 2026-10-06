import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import App from './App';
import { abortProtectedRequests } from './api';
import { emptyEndpointView } from './endpoint-identity-fixtures';
import { journalDevice as id, journalNow as now, journalSession, journalView } from './journal-fixtures';
import { setLocale } from './i18n';
import type { InvestigationScope, InvestigationsView } from './investigations-types';
import type { Device } from './types';
const json=(value:unknown,status=200)=>new Response(JSON.stringify(value),{status});
const metric={value:null,unit:'%',quality:'unknown' as const,source:'fixture',collectedAt:now};
const device:Device={id,name:'Fixture Linux',platform:'linux',os:'Linux',site:'',group:'',ip:null,status:'unknown',source:'lan',synthetic:false,lastSeen:now,agentVersion:'fixture',cpu:metric,memory:metric,disk:metric,uptime:'',tags:[],capabilities:[],evidence:[],trend:[],caseIds:[]};
function fixture():InvestigationsView{return {schemaVersion:'tracebolt.investigations.v1',serverNow:now,scope:'open',offset:0,total:1,counts:{open:1,recovered:0,closed:0,all:1},devices:[{schemaVersion:'tracebolt.health-view.v1',deviceId:id,serverNow:now,evaluatedAt:now,status:'attention',maintenanceUntil:null,monitoredServices:['fixture.service'],checks:[{key:'offline:contact',kind:'offline',target:'agent',state:'ok',observedAt:now,value:null},{key:'filesystem:root',kind:'filesystem',target:'/',state:'unknown',observedAt:null,value:null},{key:'service:fixture.service',kind:'service',target:'fixture.service',state:'open',observedAt:now,value:null}],incidents:[]}],items:[{deviceId:id,incident:{id:'health_0000000000000001',key:'service:fixture.service',kind:'service',target:'fixture.service',openedAt:now,lastObservedAt:now,resolvedAt:null,acknowledgedAt:null}}]};}
function server(mode='lan'){
 const fetch=vi.fn(async(url:string)=>{
  if(url==='/api/auth/session')return json(mode==='lan'?journalSession:{...journalSession,mode:'development',authenticated:false,authenticationRequired:false,csrfToken:null,expiresAt:null,expiresInSeconds:null});
  if(url==='/api/overview')return json({generatedAt:now,stats:{totalDevices:1,healthyDevices:0,attentionDevices:0,openCases:0,criticalCases:0},devices:[device],cases:[],activity:[]});
  if(url.startsWith('/api/investigations?')) { const scope=new URL(url,'https://localhost').searchParams.get('scope') as InvestigationScope; const value=fixture(); value.scope=scope; if(scope==='recovered'||scope==='closed') {value.total=0;value.items=[];} return json(value); }
  if(url===`/api/devices/${id}`)return json(device);
  if(url===`/api/devices/${id}/health`)return json({...fixture().devices[0],incidents:[fixture().items[0].incident]});
  if(url===`/api/devices/${id}/inventory/endpoint-identity`)return json({...emptyEndpointView(),deviceId:id});
  if(url===`/api/devices/${id}/journal`)return json(journalView('awaiting'));
  return json({},503);
 });vi.stubGlobal('fetch',fetch);return fetch;
}
beforeEach(()=>{sessionStorage.clear();localStorage.clear();setLocale('en',false);window.history.replaceState({},'', '/#/cases');vi.spyOn(document,'hasFocus').mockReturnValue(true);});
afterEach(()=>{cleanup();abortProtectedRequests();vi.unstubAllGlobals();vi.restoreAllMocks();});
const route=(value:string)=>act(()=>{window.history.replaceState({},'', `/${value.startsWith('#') ? value : `#${value}`}`);window.dispatchEvent(new Event('hashchange'));});
it('routes a real LAN investigation to its device Health, Details and exact-service logs without capturing logs',async()=>{
 const fetch=server();render(<App/>);await screen.findByText('fixture.service: service inactive');fireEvent.click(screen.getByText('Evidence & next check'));
 const health=screen.getByRole('link',{name:'Open Health & history'}).getAttribute('href')!;const details=screen.getByRole('link',{name:'Device details'}).getAttribute('href')!;const logs=screen.getByRole('link',{name:'Open service logs'}).getAttribute('href')!;
 route(health);await screen.findByRole('heading',{name:'Health & history'});expect(screen.getByRole('tab',{name:'Health & history'})).toHaveAttribute('aria-selected','true');
 route(details);await screen.findByText('Stable cryptographic device ID');expect(screen.getByRole('tab',{name:'Details'})).toHaveAttribute('aria-selected','true');
 route(logs);await screen.findByText('Awaiting a request');expect(screen.getByRole('tab',{name:'Logs'})).toHaveAttribute('aria-selected','true');
 fireEvent.click(document.querySelector('.journal-advanced summary')!);expect(screen.getByLabelText('Exact service unit')).toHaveValue('fixture.service');
 expect(fetch.mock.calls.some(([url])=>url.endsWith('/journal/create'))).toBe(false);
 route('/cases');await screen.findByText('fixture.service: service inactive');expect(screen.queryByText('Awaiting a request')).not.toBeInTheDocument();
});
it('uses durable counts on LAN Overview instead of the empty demo-case count',async()=>{
 window.history.replaceState({},'', '/#/overview');server();render(<App/>);await screen.findByText('fixture.service: service inactive');expect(screen.getByRole('button',{name:/Open investigations 1\s*Health warnings/})).toBeVisible();expect(screen.queryByText('No open investigations')).not.toBeInTheDocument();
});
it('does not fetch the new API or replace development cases',async()=>{
 const fetch=server('development');render(<App/>);await screen.findByRole('heading',{name:'Investigations',level:1});await waitFor(()=>expect(screen.getByText('There are no investigations in this view.')).toBeVisible());expect(fetch.mock.calls.some(([url])=>url.startsWith('/api/investigations'))).toBe(false);
});

it('resets a previous recovered filter when opening the Overview open-investigations shortcut',async()=>{
 const fetch=server();render(<App/>);await screen.findByText('fixture.service: service inactive');fireEvent.click(screen.getByRole('button',{name:'Recovered 0'}));await screen.findByText('No cases in this view');
 route('/overview');await screen.findByText('fixture.service: service inactive');fireEvent.click(screen.getByRole('button',{name:/Open investigations 1\s*Health warnings/}));await screen.findByRole('heading',{name:'Investigations',level:1});await screen.findByText('fixture.service: service inactive');expect(screen.getByRole('button',{name:'Open 1'})).toHaveAttribute('aria-pressed','true');
 expect(fetch.mock.calls.filter(([url])=>url.startsWith('/api/investigations')).at(-1)?.[0]).toBe('/api/investigations?scope=open&offset=0');
});

it('revalidates equivalent hash navigation instead of suspending forever',async()=>{
 window.history.replaceState({},'', '/');const fetch=server();render(<App/>);await screen.findByText('fixture.service: service inactive');const before=fetch.mock.calls.filter(([url])=>url.startsWith('/api/investigations')).length;
 route('/overview');await screen.findByText('fixture.service: service inactive');await waitFor(()=>expect(fetch.mock.calls.filter(([url])=>url.startsWith('/api/investigations')).length).toBe(before+1));
});

it('survives a rapid real hash roundtrip whose final route equals the starting route',async()=>{
 window.history.replaceState({},'', '/#/overview');server();render(<App/>);await screen.findByText('fixture.service: service inactive');
 await act(async()=>{window.location.hash='/cases';window.location.hash='/overview';await new Promise(resolve=>setTimeout(resolve,20));});
 expect(screen.getByText('fixture.service: service inactive')).toBeVisible();fireEvent.click(screen.getByRole('button',{name:/Open investigations 1\s*Health warnings/}));await screen.findByRole('heading',{name:'Investigations',level:1});await screen.findByText('fixture.service: service inactive');fireEvent.click(screen.getByRole('button',{name:'Refresh investigations'}));await screen.findByText('fixture.service: service inactive');
});

it.each(['health','logs'])('falls back from an unavailable %s deep link after reading device metadata',async(tab)=>{
 window.history.replaceState({},'', `/#/devices/${id}/${tab}`);const fetch=server('development');render(<App/>);await screen.findByRole('heading',{name:'Fixture Linux',level:1});await waitFor(()=>expect(screen.getByRole('tab',{name:'Overview'})).toHaveAttribute('aria-selected','true'));expect(screen.queryByRole('tab',{name:tab==='health'?'Health & history':'Logs'})).not.toBeInTheDocument();expect(fetch.mock.calls.some(([url])=>url.endsWith('/journal/create'))).toBe(false);
});
