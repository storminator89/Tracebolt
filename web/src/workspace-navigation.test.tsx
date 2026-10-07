import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import App from './App';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT } from './api';
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
  if(url==='/api/capabilities')return json({mode:'lan',syntheticFleet:false,realCollector:'Fixture',remoteEnrollment:false,shellExecution:false,aiConnected:false,persistence:'Fixture',limitations:[]});
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

it('retains the same current open investigation query across sidebar Overview navigation',async()=>{
 const fetch=server();render(<App/>);await screen.findByText('fixture.service: service inactive');
 const shell=document.querySelector('.app-shell'),sidebar=document.querySelector('.sidebar'),topbar=document.querySelector('.topbar');
 const before=fetch.mock.calls.filter(([url])=>url.startsWith('/api/investigations')).length;
 route('/overview');await screen.findByRole('heading',{name:'Overview',level:1});
 expect(screen.getByText('fixture.service: service inactive')).toBeVisible();
 expect(fetch.mock.calls.filter(([url])=>url.startsWith('/api/investigations'))).toHaveLength(before);
 expect(document.querySelector('.app-shell')).toBe(shell);expect(document.querySelector('.sidebar')).toBe(sidebar);expect(document.querySelector('.topbar')).toBe(topbar);
 expect(fetch.mock.calls.filter(([url])=>url==='/api/overview')).toHaveLength(1);expect(fetch.mock.calls.filter(([url])=>url==='/api/auth/session')).toHaveLength(1);
});
it('restores each top-level view scroll and keeps retained workspace state out of a revoked session',async()=>{
 server();render(<App/>);await screen.findByText('fixture.service: service inactive');const main=screen.getByRole('main');main.scrollTop=320;
 route('/devices');await screen.findByRole('heading',{name:'Devices',level:1});expect(main.scrollTop).toBe(0);main.scrollTop=175;
 fireEvent.change(screen.getByLabelText('Search devices'),{target:{value:'Fixture'}});
 route('/cases');await screen.findByRole('heading',{name:'Investigations',level:1});expect(main.scrollTop).toBe(320);
 route('/devices');await screen.findByLabelText('Search devices');expect(main.scrollTop).toBe(175);expect(screen.getByLabelText('Search devices')).toHaveValue('Fixture');
 act(()=>{abortProtectedRequests();window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT));});
 expect(document.querySelector('.app-shell')).toBeNull();expect(screen.queryByText('fixture.service: service inactive')).not.toBeInTheDocument();
});

it('keeps the known case badge on Devices and reports actual recent readiness in Settings',async()=>{
 const fetch=server();render(<App/>);await screen.findByText('fixture.service: service inactive');const badge=document.querySelector('.nav-badge');expect(badge).toHaveTextContent('1');
 route('/devices');await screen.findByLabelText('Search devices');expect(document.querySelector('.nav-badge')).toBe(badge);
 route('/settings');await screen.findByText('Rule-based investigations');const row=screen.getByText('Rule-based investigations').closest('.capability-line')!;
 expect(row).toHaveTextContent('Health: agent contact, root filesystem and selected services.');expect(row).toHaveTextContent('Available');expect(row).not.toHaveTextContent('Not available');
 expect(fetch.mock.calls.filter(([url])=>url.startsWith('/api/investigations'))).toHaveLength(1);
});
it('labels unobserved Settings health readiness unknown without starting a background feature read',async()=>{
 window.history.replaceState({},'', '/#/settings');const fetch=server();render(<App/>);await screen.findByText('Rule-based investigations');
 expect(screen.getByText('Rule-based investigations').closest('.capability-line')).toHaveTextContent('Status unknown');
 expect(fetch.mock.calls.some(([url])=>url.startsWith('/api/investigations'))).toBe(false);
});
