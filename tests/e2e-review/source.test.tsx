/** Supplemental DOM/source tests. These are not browser or screenshot evidence. */
import { beforeEach, afterEach, describe, expect, it, vi } from '../../web/node_modules/vitest/dist/index.js';
import { cleanup, render, screen, fireEvent, waitFor } from '../../web/node_modules/@testing-library/react/dist/index.js';
import App from '../../web/src/App';
import { defaultFilters, filterDevices, decodeRouteId, csvCell, noteBytes } from '../../web/src/utils';
import { applicationStatusFixture, applicationHTTPStatusFixture, applicationMixedStatusFixture } from './application-checks-browser.mjs';
import { applicationObservationAge, projectApplicationCheck, validApplicationChecksView } from '../../web/src/application-checks-types';
const at='2026-10-03T12:00:00Z';
const metric={value:25,unit:'%',quality:'healthy',source:'synthetic-fixture',collectedAt:at};
const device={id:'review-device',name:'REVIEW-DEMO',platform:'windows',os:'Windows demo',site:'Synthetic',group:'Review',ip:null,status:'critical',source:'synthetic',synthetic:true,lastSeen:at,agentVersion:'demo',cpu:metric,memory:metric,disk:metric,uptime:'demo',tags:[],capabilities:[],evidence:[],trend:[],caseIds:[]};
const overview={product:'Tracebolt',mode:'local-development',generatedAt:at,devices:[device],cases:[],activity:[],stats:{totalDevices:1,healthyDevices:0,attentionDevices:1,unknownDevices:0,openCases:0,criticalCases:0}};
const response=(body:any,status=200)=>Promise.resolve(new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json'}}));
const devSession={mode:'development',authenticationRequired:false,authenticated:false,csrfToken:'fixture-csrf',serverNow:at,expiresAt:null,expiresInSeconds:null,transport:'http',insecureTestMode:false,transportWarning:null};
const fetchMock=(handler:any)=>vi.fn((url:any,...args:any[])=>String(url).endsWith('/auth/session')?response(devSession):handler(url,...args));
beforeEach(()=>{localStorage.clear();location.hash='/devices';vi.stubGlobal('fetch',fetchMock(()=>response(overview)));});
afterEach(()=>{cleanup();vi.unstubAllGlobals();});
describe('Independent source/DOM regressions',()=>{
 it('combined attention retains critical and attention while excluding unknown',()=>{
  const devices=[device,{...device,id:'b',status:'attention'},{...device,id:'c',status:'unknown'},{...device,id:'d',status:'healthy'}];
  expect(filterDevices(devices as any,{...defaultFilters,status:'needs-attention'}).map(d=>d.status)).toEqual(['critical','attention']);
 });
 it('route parser rejects malformed percent encoding without throwing',()=>{expect(decodeRouteId('%E0%A4%A')).toBeUndefined();});
 it('CSV neutralizes formula starters and quote escaping',()=>{for(const value of ['=1+1','+1','-1','@SUM(A1)','  =1','\t=1']) expect(csvCell(value).startsWith('"\'')).toBe(true);expect(csvCell('a"b')).toBe('"a""b"');});
 it('notes count UTF-8 bytes explicitly',()=>{expect(noteBytes('é😀')).toBe(6);});
 it('skip-to-content preserves inventory route and moves DOM focus',async()=>{render(<App/>);await screen.findByRole('heading',{name:'Geräte',exact:true,level:1});fireEvent.click(screen.getByRole('link',{name:'Zum Inhalt'}));expect(location.hash).toBe('#/devices');expect(document.activeElement?.id).toBe('main-content');});
 it('initial API failure presents explicit failure with no fake inventory',async()=>{vi.stubGlobal('fetch',fetchMock(()=>response({error:{message:'controlled unavailable'}},503)));render(<App/>);expect(await screen.findByRole('alert')).toHaveTextContent('keine Ersatz-Demodaten');expect(screen.queryByText('REVIEW-DEMO')).toBeNull();});
 it('literal name markup is never interpreted as HTML',async()=>{const payload='<img src=x onerror="window.reviewXss=1">';vi.stubGlobal('fetch',fetchMock(()=>response({...overview,devices:[{...device,name:payload}]})));const {container}=render(<App/>);expect(await screen.findByText(payload)).toBeInTheDocument();expect(container.querySelector('img')).toBeNull();});
 it('help modal owns Escape before the device page returns to the focused inventory',async()=>{
  vi.stubGlobal('fetch',fetchMock((url:string)=>response(url.includes('/devices/')?device:overview)));
  render(<App/>);await screen.findByRole('heading',{name:'Geräte',exact:true,level:1});fireEvent.click(screen.getByRole('button',{name:'REVIEW-DEMO: Details öffnen'}));
  const detail=await screen.findByRole('region',{name:'Gerät REVIEW-DEMO'});expect(detail).toHaveFocus();expect(screen.queryByRole('dialog')).toBeNull();expect(document.querySelector('.inventory-panel')).toBeNull();
  fireEvent.keyDown(window,{key:'?'});await screen.findByRole('dialog',{name:'Tastenkürzel'});
  fireEvent.keyDown(document,{key:'Escape'});await waitFor(()=>expect(screen.queryByRole('dialog')).toBeNull());
  expect(screen.getByRole('region',{name:'Gerät REVIEW-DEMO'})).toBeInTheDocument();expect(location.hash).toBe('#/devices/review-device');
  fireEvent.keyDown(document,{key:'Escape'});await waitFor(()=>expect(screen.queryByRole('region',{name:'Gerät REVIEW-DEMO'})).toBeNull());
  expect(location.hash).toBe('#/devices');expect(document.activeElement?.id).toBe('main-content');
 });
 it('malformed saved-view shape must not crash the inventory',async()=>{localStorage.setItem('local-rmm-saved-view',JSON.stringify({...defaultFilters,query:null}));render(<App/>);await screen.findByRole('heading',{name:'Geräte',exact:true,level:1});fireEvent.click(screen.getByRole('button',{name:'Gespeicherte Ansicht'}));await waitFor(()=>expect(screen.getByRole('heading',{name:'Geräte',exact:true,level:1})).toBeInTheDocument());});
});

describe('Hosted application-status fault-injection contract',()=>{
 it('uses valid retained DTOs with independent HTTP outcomes and verified-leaf expiry',()=>{
  const view=applicationStatusFixture();expect(validApplicationChecksView(view)).toBe(true);expect(view.maxAgeSeconds).toBe(85);
  expect(view.items.map(row=>[row.httpStatus,row.tls.state])).toEqual([[204,'expiring'],[503,'valid'],[204,'expired'],[null,'unknown']]);
  const expired=view.items[2];expect(Date.parse(expired.observedAt)).toBeLessThan(Date.parse(expired.tls.expiresAt));expect(Date.parse(expired.tls.expiresAt)).toBeLessThan(Date.parse(view.serverNow));
  for(const row of view.items){expect(applicationObservationAge(view,row,0)).toBe(65000);expect(projectApplicationCheck(view,row,0)).toEqual(row);}
  const plain=applicationHTTPStatusFixture(),mixed=applicationMixedStatusFixture();
  for(const fixture of [plain,mixed]){
   expect(validApplicationChecksView(fixture)).toBe(true);expect(fixture.maxAgeSeconds).toBe(fixture.intervalSeconds+(fixture.items.length+1)*5);
   for(const row of fixture.items){expect(applicationObservationAge(fixture,row,0)).toBe(65000);expect(projectApplicationCheck(fixture,row,0)).toEqual(row);}
  }
  expect(plain.items.map(row=>[row.targetScheme,row.tls.state])).toEqual([['https','expiring'],['http','not_applicable']]);
  expect(mixed.items.map(row=>[row.kind,row.reason])).toEqual([['dns','dns_resolved'],['tcp','tcp_connected'],['http','http_2xx']]);
  for(const row of mixed.items.slice(0,2))expect(Object.keys(row).sort()).toEqual(['id','kind','observedAt','reason','state']);
 });
 it('cannot portray a leaf as verified when it was already expired at the original observation',()=>{
  const view=applicationStatusFixture();view.items[2].observedAt=view.serverNow;expect(validApplicationChecksView(view)).toBe(false);
  for(const index of [0,1]){
   const mixed=applicationMixedStatusFixture();mixed.items[index]={...mixed.items[index],tls:{state:'valid',expiresAt:'2026-12-01T12:00:00Z'}};
   expect(validApplicationChecksView(mixed)).toBe(false);
  }
  const crossed=applicationMixedStatusFixture();crossed.items[0].reason='tcp_connected';expect(validApplicationChecksView(crossed)).toBe(false);
 });
 it('ages the unchanged browser fixture past the real stale boundary without changing observation times',()=>{
  const view=applicationStatusFixture();
  for(const row of view.items){expect(projectApplicationCheck(view,row,20000).state).toBe(row.state);expect(projectApplicationCheck(view,row,21000)).toEqual({...row,state:'unknown',reason:'stale',httpStatus:null,tls:{state:'unknown',expiresAt:null}});expect(applicationObservationAge(view,row,21000)).toBe(86000);}
  for(const fixture of [applicationHTTPStatusFixture(),applicationMixedStatusFixture()]){
   const boundaryMs=fixture.maxAgeSeconds*1000-65000;
   for(const row of fixture.items){
    expect(projectApplicationCheck(fixture,row,boundaryMs)).toEqual(row);
    const stale=projectApplicationCheck(fixture,row,boundaryMs+1000);
    expect(stale).toMatchObject({state:'unknown',reason:'stale',observedAt:row.observedAt});
    expect(applicationObservationAge(fixture,row,boundaryMs+1000)).toBe((fixture.maxAgeSeconds+1)*1000);
    if(row.kind==='dns'||row.kind==='tcp')expect(Object.keys(stale).sort()).toEqual(['id','kind','observedAt','reason','state']);
    else expect(stale).toMatchObject({httpStatus:null,tls:{state:row.targetScheme==='http'?'not_applicable':'unknown',expiresAt:null}});
   }
  }
 });
});
