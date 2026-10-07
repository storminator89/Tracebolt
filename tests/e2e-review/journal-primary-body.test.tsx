/** Primary-consumer instrumentation plus actual React/API decoder regressions.
 * Synthetic fetch streams only; this does not claim Chromium acceptance. */
import { act, cleanup, fireEvent, render, screen, waitFor } from '../../web/node_modules/@testing-library/react/dist/index.js';
import { afterEach, beforeEach, describe, expect, it, vi } from '../../web/node_modules/vitest/dist/index.js';
import { installJournalPrimaryBody } from './journal-primary-body.mjs';
import { abortProtectedRequests } from '../../web/src/api';
import { AuthBoundary } from '../../web/src/auth';
import { JournalPanel } from '../../web/src/journal';
import { journalDevice, journalPage, journalSession, journalSessionExpiry, journalView } from '../../web/src/journal-fixtures';
import { JOURNAL_PAGE_BYTES } from '../../web/src/journal-types';
import { serviceRows, systemPage, systemView } from '../../web/src/system-inventory-fixtures';
import { SYSTEM_PAGE_BYTES } from '../../web/src/system-inventory-types';
import { setLocale } from '../../web/src/i18n';

const root=`/api/devices/${journalDevice}/journal`,url=()=>new URL(root+'/query',location.href).href;
const systemRoot=`/api/devices/${journalDevice}/inventory/system`;
const json=(body:unknown)=>new Response(JSON.stringify(body));
const page=(offset:number)=>journalPage(Array.from({length:100},(_,i)=>`Synthetic primary row ${offset+i}`),'',offset,205);
let uninstall:(()=>void)|undefined;
const observer=()=>globalThis.__traceboltJournalBody;
beforeEach(()=>{expect(JOURNAL_PAGE_BYTES).toBe(65536);setLocale('en',false);localStorage.clear();sessionStorage.clear();});
afterEach(()=>{cleanup();uninstall?.();uninstall=undefined;abortProtectedRequests();vi.unstubAllGlobals();vi.restoreAllMocks();});

describe('journal fixture primary-consumer observation',()=>{
 it.each(['valid','malformed','invalid identity','disconnect','abort','oversized','declared oversized'])('observes the real service picker reader and preserves fail-closed handling for %s streams',async outcome=>{
  expect(SYSTEM_PAGE_BYTES).toBe(262144);
  const view={...systemView(3,0),deviceId:journalDevice},services=serviceRows(3);
  let held:ReadableStreamDefaultController<Uint8Array>,signal:AbortSignal,response:Response,value:ReturnType<typeof systemPage>,readerSpy:ReturnType<typeof vi.fn>,cancelled=false;
  const fetch=vi.fn(async(path:string,init?:RequestInit)=>{
   if(path==='/api/auth/session')return json({...journalSession,transport:'http',insecureTestMode:true,transportWarning:'unencrypted_lan_test'});
   if(path==='/api/session')return json({csrfToken:'synthetic-csrf'});
   if(path===root)return json(journalView('awaiting'));
   if(path===systemRoot)return json(view);
   if(path!==systemRoot+'/query')throw new Error('Unexpected synthetic route');
   value=systemPage(view,services,[],String(init?.body));if(outcome==='invalid identity')value.deviceId=`agent_${'b'.repeat(32)}`;
   signal=init!.signal!;
   const stream=new ReadableStream<Uint8Array>({start(controller){held=controller;},cancel(){cancelled=true;}});
   signal.addEventListener('abort',()=>{if(!cancelled)try{held.error(new DOMException('Synthetic abort','AbortError'));}catch{}},{once:true});
   response=new Response(stream,outcome==='declared oversized'?{headers:{'Content-Length':String(SYSTEM_PAGE_BYTES+1)}}:undefined);
   readerSpy=vi.spyOn(stream,'getReader');vi.spyOn(response,'clone').mockImplementation(()=>{throw new Error('Secondary body consumer is forbidden');});
   return response;
  });vi.stubGlobal('fetch',fetch);uninstall=installJournalPrimaryBody({url:url()});
  // Settle the initial session/status effects before interacting: the awaiting
  // text can commit before the journal reset effect that closes the picker.
  await act(async()=>{render(<AuthBoundary><JournalPanel deviceId={journalDevice} insecureTestMode={true} sessionKey={journalSessionExpiry}/></AuthBoundary>);});
  await screen.findByText('Awaiting a request');expect(fetch.mock.calls.some(([path])=>path.startsWith(systemRoot))).toBe(false);
  const picker=screen.getByRole('button',{name:'Choose observed service'});expect(picker).toBeEnabled();
  const token=observer().arm('services');fireEvent.click(picker);
  expect(screen.getByRole('dialog',{name:'Choose observed service'})).toBeVisible();await waitFor(()=>expect(held).toBeDefined());
  expect(observer().take(token)).toBeNull();
  if(outcome==='declared oversized'){
   await screen.findByRole('alert');expect(cancelled).toBe(true);expect(readerSpy).not.toHaveBeenCalled();expect(observer().state(token)).toBe('cancelled');
  }else{
   const bytes=new TextEncoder().encode(JSON.stringify(value!)),split=Math.floor(bytes.length/2);
   await act(async()=>{held.enqueue(bytes.slice(0,split));});expect(observer().state(token)).toBe('reading');expect(observer().take(token)).toBeNull();expect(screen.queryByRole('list')).not.toBeInTheDocument();
   await act(async()=>{
    if(outcome==='abort')fireEvent.click(screen.getByRole('button',{name:'Close service picker'}));
    else if(outcome==='disconnect')held.error(new TypeError('Synthetic disconnect'));
    else if(outcome==='oversized')held.enqueue(new Uint8Array(SYSTEM_PAGE_BYTES+1));
    else{held.enqueue(bytes.slice(split,outcome==='malformed'?bytes.length-1:undefined));held.close();}
   });
   expect(readerSpy).toHaveBeenCalledTimes(1);expect(response!.clone).not.toHaveBeenCalled();
   if(outcome==='valid'){
    await screen.findByRole('button',{name:`Use ${services[2].name}`});expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button',{name:`Use ${services[0].name}`}));expect(screen.queryByRole('region',{name:'Observed services'})).not.toBeInTheDocument();
    expect(screen.getByLabelText('Exact service unit')).toHaveValue(services[0].name);expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
    const captured=observer().take(token);expect(captured).toEqual({status:200,body:value!});expect(Object.isFrozen(captured.body.services[0])).toBe(true);expect(observer().take(token)).toBeNull();
   }else if(outcome==='invalid identity'){
    await screen.findByRole('alert');expect(screen.queryByRole('list')).not.toBeInTheDocument();expect(observer().take(token)?.body.deviceId).toBe(value!.deviceId);
   }else{
    if(outcome==='abort'){expect(signal!.aborted).toBe(true);expect(screen.queryByRole('region',{name:'Observed services'})).not.toBeInTheDocument();}
    else await screen.findByRole('alert');
    expect(screen.queryByRole('list')).not.toBeInTheDocument();expect(observer().take(token)).toBeNull();expect(observer().state(token)).not.toBe('complete');if(outcome==='oversized')expect(cancelled).toBe(true);
   }
  }
  expect(fetch.mock.calls.filter(([path])=>path===systemRoot)).toHaveLength(1);expect(fetch.mock.calls.filter(([path])=>path===systemRoot+'/query')).toHaveLength(1);
  expect(fetch.mock.calls.some(([path])=>path===root+'/query'||path.endsWith('/create')||path.endsWith('/cancel'))).toBe(false);
 });

 it.each(['valid','malformed','invalid identity','disconnect','abort','oversized','declared oversized'])('preserves the real reader and fail-closed UI for %s streams',async outcome=>{
  let held:ReadableStreamDefaultController<Uint8Array>,signal:AbortSignal,response:Response,readerSpy:ReturnType<typeof vi.fn>,cancelled=false;
  const fetch=vi.fn(async(path:string,init?:RequestInit)=>{
   if(path==='/api/auth/session')return json({...journalSession,transport:'http',insecureTestMode:true,transportWarning:'unencrypted_lan_test'});
   if(path==='/api/session')return json({csrfToken:'synthetic-csrf'});
   if(path===root)return json(journalView());
   if(path!==root+'/query')throw new Error('Unexpected synthetic route');
   const input=JSON.parse(String(init?.body));if(input.offset===0)return json(page(0));
   signal=init!.signal!;
   const stream=new ReadableStream<Uint8Array>({start(controller){held=controller;},cancel(){cancelled=true;}});
   signal.addEventListener('abort',()=>{if(!cancelled)try{held.error(new DOMException('Synthetic abort','AbortError'));}catch{}},{once:true});
   response=new Response(stream,outcome==='declared oversized'?{headers:{'Content-Length':String(JOURNAL_PAGE_BYTES+1)}}:undefined);
   readerSpy=vi.spyOn(stream,'getReader');vi.spyOn(response,'clone').mockImplementation(()=>{throw new Error('Secondary body consumer is forbidden');});
   return response;
  });vi.stubGlobal('fetch',fetch);uninstall=installJournalPrimaryBody({url:url()});
  render(<JournalPanel deviceId={journalDevice} insecureTestMode={true} sessionKey={journalSessionExpiry}/>);await screen.findByText('Synthetic primary row 99');
  expect(observer().state(0)).toBe('missing');const token=observer().arm();
  fireEvent.click(screen.getByRole('button',{name:'Next'}));await waitFor(()=>expect(held).toBeDefined());
  expect(observer().take(token)).toBeNull();
  if(outcome==='declared oversized'){
   await screen.findByRole('alert');expect(cancelled).toBe(true);expect(readerSpy).not.toHaveBeenCalled();expect(observer().state(token)).toBe('cancelled');
  }else{
   const value=page(100);if(outcome==='invalid identity')value.identity={...value.identity,id:'journal_'+'e'.repeat(32)};
   const bytes=new TextEncoder().encode(JSON.stringify(value)),split=Math.floor(bytes.length/2);
   await act(async()=>{held.enqueue(bytes.slice(0,split));});
   expect(observer().state(token)).toBe('reading');expect(observer().take(token)).toBeNull();expect(screen.queryByRole('table')).not.toBeInTheDocument();expect(screen.getByRole('status')).toHaveTextContent('Reading journal status');
   await act(async()=>{
    if(outcome==='abort')window.dispatchEvent(new Event('pagehide'));
    else if(outcome==='disconnect')held.error(new TypeError('Synthetic disconnect'));
    else if(outcome==='oversized')held.enqueue(new Uint8Array(JOURNAL_PAGE_BYTES+1));
    else{held.enqueue(bytes.slice(split,outcome==='malformed'?bytes.length-1:undefined));held.close();}
   });
   expect(readerSpy).toHaveBeenCalledTimes(1);expect(response!.clone).not.toHaveBeenCalled();
   if(outcome==='valid'){
    await screen.findByText('Synthetic primary row 199');expect(screen.queryByRole('alert')).not.toBeInTheDocument();expect(signal!.aborted).toBe(false);
    const captured=observer().take(token);expect(captured).toEqual({status:200,body:value});expect(Object.isFrozen(captured.body)).toBe(true);expect(Object.isFrozen(captured.body.identity)).toBe(true);expect(Object.isFrozen(captured.body.rows[0])).toBe(true);
    expect(()=>{captured.body.identity.sequence='999';}).toThrow();expect(observer().take(token)).toBeNull();
   }else if(outcome==='invalid identity'){
    await screen.findByRole('alert');expect(screen.queryByRole('table')).not.toBeInTheDocument();
    // Complete JSON is not proof of application acceptance: the production
    // validator must reject this body and the browser's UI checks must fail.
    expect(observer().take(token)?.body.identity.id).toBe(value.identity.id);
   }else{
    if(outcome==='abort'){expect(signal!.aborted).toBe(true);expect(screen.getByRole('status')).toHaveTextContent('Content paused');}
    else await screen.findByRole('alert');
    expect(screen.queryByRole('table')).not.toBeInTheDocument();expect(observer().take(token)).toBeNull();expect(observer().state(token)).not.toBe('complete');
    if(outcome==='oversized')expect(cancelled).toBe(true);
   }
  }
  expect(fetch.mock.calls.filter(([path])=>path===root+'/query')).toHaveLength(2);
  expect(fetch.mock.calls.some(([path])=>path.endsWith('/create')||path.endsWith('/cancel'))).toBe(false);
 });

 it('does not consume ahead, clone a response, or observe credentials and other routes',async()=>{
  const response=new Response('{"fixture":true}'),fetch=vi.fn(async()=>response);vi.stubGlobal('fetch',fetch);uninstall=installJournalPrimaryBody({url:url()});
  const token=observer().arm();expect(await globalThis.fetch('/api/auth/session')).toBe(response);expect(observer().state(token)).toBe('armed');
  const returned=await globalThis.fetch(root+'/query',{method:'POST'});expect(returned).toBe(response);expect(response.bodyUsed).toBe(false);expect(observer().state(token)).toBe('reading');expect(observer().take(token)).toBeNull();
  const reader=response.body!.getReader();await reader.read();expect(observer().state(token)).toBe('reading');await reader.read();reader.releaseLock();expect(observer().take(token)).toEqual({status:200,body:{fixture:true}});
 });

 it('discards superseded observations and keeps the next primary response separate',async()=>{
  const responses=[new Response('{"fixture":1}'),new Response('{"fixture":2}')];let index=0;
  vi.stubGlobal('fetch',vi.fn(async()=>responses[index++]));uninstall=installJournalPrimaryBody({url:url()});const old=observer().arm();const first=await globalThis.fetch(root+'/query',{method:'POST'});const token=observer().arm();const second=await globalThis.fetch(root+'/query',{method:'POST'});
  for(const response of [first,second]){const reader=response.body!.getReader();await reader.read();await reader.read();reader.releaseLock();}
  expect(observer().take(old)).toBeNull();expect(observer().take(token)).toEqual({status:200,body:{fixture:2}});
 });

 it('forwards the original stream rejection rather than replacing it with diagnostic errors',async()=>{
  let stream:ReadableStreamDefaultController<Uint8Array>;const failure=new TypeError('Synthetic original disconnect');
  const response=new Response(new ReadableStream<Uint8Array>({start(controller){stream=controller;}}));vi.stubGlobal('fetch',vi.fn(async()=>response));
  uninstall=installJournalPrimaryBody({url:url()});const token=observer().arm();const returned=await globalThis.fetch(root+'/query',{method:'POST'}),reader=returned.body!.getReader(),pending=reader.read();stream!.error(failure);
  await expect(pending).rejects.toBe(failure);expect(observer().state(token)).toBe('failed');expect(observer().take(token)).toBeNull();reader.releaseLock();
 });

 it('rejects duplicate matching requests instead of substituting another response',async()=>{
  vi.stubGlobal('fetch',vi.fn(async()=>new Response('{"fixture":true}')));uninstall=installJournalPrimaryBody({url:url()});const token=observer().arm();
  const first=await globalThis.fetch(root+'/query',{method:'POST'});await globalThis.fetch(root+'/query',{method:'POST'});const reader=first.body!.getReader();await reader.read();await reader.read();reader.releaseLock();
  expect(observer().state(token)).toBe('duplicate');expect(observer().take(token)).toBeNull();
 });

 it('keeps the service observation scoped to one exact device POST without reading other responses',async()=>{
  vi.stubGlobal('fetch',vi.fn(async()=>new Response('{"fixture":true}')));uninstall=installJournalPrimaryBody({url:url()});expect(()=>observer().arm('auth')).toThrow();const token=observer().arm('services');
  for(const [path,method]of [[systemRoot,'GET'],[systemRoot+'/query','GET'],[root+'/query','POST'],[systemRoot.replace(journalDevice,`agent_${'b'.repeat(32)}`)+'/query','POST'],['/api/auth/session','GET'],['/api/session','GET']]){
   const response=await globalThis.fetch(path,{method});expect(response.bodyUsed).toBe(false);expect(observer().state(token)).toBe('armed');
  }
  const first=await globalThis.fetch(systemRoot+'/query',{method:'POST'});await globalThis.fetch(systemRoot+'/query',{method:'POST'});const reader=first.body!.getReader();await reader.read();await reader.read();reader.releaseLock();expect(observer().state(token)).toBe('duplicate');expect(observer().take(token)).toBeNull();
 });

 it.each([['journal',65536],['services',262144],['overview',262144]] as const)('retains the exact %s byte cap',async(scope,maximum)=>{
  vi.stubGlobal('fetch',vi.fn(async()=>new Response('"'+'x'.repeat(maximum-2)+'"')));uninstall=installJournalPrimaryBody({url:url()});
  const route=scope==='journal'?root+'/query':scope==='services'?systemRoot+'/query':overviewRoot+'/query',token=observer().arm(scope),response=await globalThis.fetch(route,{method:'POST',body:scope==='overview'?'{}':undefined}),reader=response.body!.getReader();
  while(!(await reader.read()).done){}reader.releaseLock();expect(observer().take(token)?.body).toHaveLength(maximum-2);
  vi.stubGlobal('fetch',vi.fn(async()=>new Response('"'+'x'.repeat(maximum-1)+'"')));uninstall();uninstall=installJournalPrimaryBody({url:url()});
  const oversized=observer().arm(scope),tooLarge=await globalThis.fetch(route,{method:'POST',body:scope==='overview'?'{}':undefined}),largeReader=tooLarge.body!.getReader();while(!(await largeReader.read()).done){}largeReader.releaseLock();expect(observer().state(oversized)).toBe('oversized');expect(observer().take(oversized)).toBeNull();
 });
});

import { CompleteOverviewPanel } from '../../web/src/complete-overview';
import { overviewPage, overviewView, processRows } from '../../web/src/complete-overview-fixtures';
import { OVERVIEW_PAGE_BYTES } from '../../web/src/complete-overview-types';
const overviewRoot=`/api/devices/${journalDevice}/inventory/overview`;

describe('complete overview fixture primary-consumer observation',()=>{
 it.each(['valid','terminal inspector abort','malformed','invalid identity','disconnect','abort','oversized','declared oversized'])('binds the exact literal-search primary request and preserves UI handling for %s',async outcome=>{
  expect(OVERVIEW_PAGE_BYTES).toBe(262144);
  const view={...overviewView(205,0),deviceId:journalDevice},processes=processRows(205),search='nEeDlE[.*]';
  for(const index of [0,100,200])processes[index].process!.name=`Needle[.*] fixture ${index}`;
  let held:ReadableStreamDefaultController<Uint8Array>,signal:AbortSignal,response:Response,value:ReturnType<typeof overviewPage>,readerSpy:ReturnType<typeof vi.fn>,cancelled=false;
  const fetch=vi.fn(async(path:string,init?:RequestInit)=>{
   if(path==='/api/auth/session')return json({...journalSession,transport:'http',insecureTestMode:true,transportWarning:'unencrypted_lan_test'});
   if(path==='/api/session')return json({csrfToken:'synthetic-csrf'});
   if(path===overviewRoot)return json(view);
   if(path!==overviewRoot+'/query')throw new Error('Unexpected synthetic route');
   value=overviewPage(view,processes,[],String(init?.body));
   if(JSON.parse(String(init?.body)).search==='')return json(value);
   if(outcome==='invalid identity')value.deviceId=`agent_${'b'.repeat(32)}`;
   signal=init!.signal!;
   const stream=new ReadableStream<Uint8Array>({start(controller){held=controller;},cancel(){cancelled=true;}});
   signal.addEventListener('abort',()=>{if(!cancelled)try{held.error(new DOMException('Synthetic abort','AbortError'));}catch{}},{once:true});
   response=new Response(stream,outcome==='declared oversized'?{headers:{'Content-Length':String(OVERVIEW_PAGE_BYTES+1)}}:undefined);
   readerSpy=vi.spyOn(stream,'getReader');vi.spyOn(response,'clone').mockImplementation(()=>{throw new Error('Secondary body consumer is forbidden');});return response;
  });vi.stubGlobal('fetch',fetch);uninstall=installJournalPrimaryBody({url:url()});
  await act(async()=>{render(<AuthBoundary><CompleteOverviewPanel deviceId={journalDevice} section="processes"/></AuthBoundary>);});await screen.findByRole('table');
  fireEvent.change(screen.getByRole('searchbox',{name:'Search this section'}),{target:{value:search}});expect(screen.queryByRole('table')).not.toBeInTheDocument();
  const token=observer().arm('overview');fireEvent.click(screen.getByRole('button',{name:'Search'}));await waitFor(()=>expect(held).toBeDefined());expect(observer().take(token)).toBeNull();
  if(outcome==='declared oversized'){
   await screen.findByRole('alert');expect(cancelled).toBe(true);expect(readerSpy).not.toHaveBeenCalled();expect(observer().state(token)).toBe('cancelled');
  }else{
   const bytes=new TextEncoder().encode(JSON.stringify(value!)),split=Math.floor(bytes.length/2);
   await act(async()=>{held.enqueue(bytes.slice(0,split));});expect(observer().state(token)).toBe('reading');expect(observer().take(token)).toBeNull();expect(screen.queryByRole('table')).not.toBeInTheDocument();
   await act(async()=>{
    if(outcome==='abort')window.dispatchEvent(new Event('pagehide'));
    else if(outcome==='disconnect')held.error(new TypeError('Synthetic disconnect'));
    else if(outcome==='oversized')held.enqueue(new Uint8Array(OVERVIEW_PAGE_BYTES+1));
    else{held.enqueue(bytes.slice(split,outcome==='malformed'?bytes.length-1:undefined));held.close();}
   });
   expect(readerSpy).toHaveBeenCalledTimes(1);expect(response!.clone).not.toHaveBeenCalled();
   if(outcome==='valid'||outcome==='terminal inspector abort'){
    await screen.findByText('Needle[.*] fixture 200');expect(document.querySelectorAll('.complete-overview tbody tr')).toHaveLength(3);expect(screen.queryByRole('alert')).not.toBeInTheDocument();expect(signal!.aborted).toBe(false);expect(cancelled).toBe(false);
    if(outcome==='terminal inspector abort'){
     // Controlled ordering regression, not a claim to reproduce Chromium:
     // the app has already read and validated all bytes when a separate terminal
     // inspector reports abort. Do not require that second body reader to succeed.
     const terminalFailure=new Error('Synthetic terminal inspector: net::ERR_ABORTED');
     const inspector={json:vi.fn(async()=>{throw terminalFailure;})};await expect(inspector.json()).rejects.toBe(terminalFailure);
     expect(observer().state(token)).toBe('complete');expect(screen.getByRole('table')).toBeVisible();
    }
    const captured=observer().take(token),raw=fetch.mock.calls.filter(([path])=>path===overviewRoot+'/query').at(-1)![1]!.body;
    expect(captured).toEqual({status:200,body:value!,requestBody:raw});expect(JSON.parse(captured.requestBody)).toEqual({section:'processes',generationId:view.processes.complete!.binding.generationId,cursor:'',search,limit:100});
    expect(captured.body.binding).toEqual(view.processes.complete!.binding);expect(captured.body.collectedAt).toBe(view.processes.complete!.manifest.collectedAt);expect(captured.body.retainedUntil).toBe(view.processes.complete!.retainedUntil);expect(captured.body.items).toHaveLength(3);expect(Object.isFrozen(captured.body.items[0])).toBe(true);expect(observer().take(token)).toBeNull();
   }else if(outcome==='invalid identity'){
    await screen.findByRole('alert');expect(screen.queryByRole('table')).not.toBeInTheDocument();expect(observer().take(token)?.body.deviceId).toBe(value!.deviceId);
   }else{
    if(outcome==='abort')expect(signal!.aborted).toBe(true);else await screen.findByRole('alert');
    expect(screen.queryByRole('table')).not.toBeInTheDocument();expect(observer().take(token)).toBeNull();expect(observer().state(token)).not.toBe('complete');
   }
  }
  expect(fetch.mock.calls.filter(([path])=>path===overviewRoot+'/query')).toHaveLength(2);expect(fetch.mock.calls.some(([path])=>path.includes('/journal')||path.includes('/service-actions'))).toBe(false);
 });

 it('observes only the armed exact overview POST and rejects duplicates or unsupported request bodies',async()=>{
  vi.stubGlobal('fetch',vi.fn(async()=>json({fixture:true})));uninstall=installJournalPrimaryBody({url:url()});let token=observer().arm('overview');
  for(const [path,method]of [[overviewRoot,'GET'],[overviewRoot+'/query','GET'],[overviewRoot+'/query?unexpected=1','POST'],[root+'/query','POST'],[systemRoot+'/query','POST'],[overviewRoot.replace(journalDevice,`agent_${'b'.repeat(32)}`)+'/query','POST'],['/api/auth/session','GET'],['/api/session','GET']]){
   const response=await globalThis.fetch(path,{method,body:method==='POST'?'{}':undefined});expect(response.bodyUsed).toBe(false);expect(observer().state(token)).toBe('armed');
  }
  const first=await globalThis.fetch(overviewRoot+'/query',{method:'POST',body:'{"cursor":""}'});expect(first.bodyUsed).toBe(false);await globalThis.fetch(overviewRoot+'/query',{method:'POST',body:'{"cursor":"different"}'});const reader=first.body!.getReader();while(!(await reader.read()).done){}reader.releaseLock();expect(observer().state(token)).toBe('duplicate');expect(observer().take(token)).toBeNull();
  for(const body of [undefined,new Uint8Array([1]),'x'.repeat(2049)]){
   token=observer().arm('overview');const response=await globalThis.fetch(overviewRoot+'/query',{method:'POST',body});expect(response.bodyUsed).toBe(false);expect(observer().state(token)).toBe('invalid-request');expect(observer().take(token)).toBeNull();
  }
 });
});

import { approveServiceAction, previewServiceAction, InvalidServiceActionResponse } from '../../web/src/service-action-api';
import { actionAccess, actionDevice, actionActor, actionJobView, actionPreview, actionSession, actionView } from '../../web/src/service-action-fixtures';
import { SERVICE_ACTION_VIEW_BYTES } from '../../web/src/service-action-types';
const actionRoot=`/api/devices/${actionDevice}/service-actions`;
const primaryActionAccess={...actionAccess,insecureTestMode:true},primaryActionSession={...actionSession,transport:'http',insecureTestMode:true,transportWarning:'unencrypted_lan_test'};
const primaryActionPreview=()=>({...actionPreview(),transportProfile:'disposable-http-test' as const});

describe.each(['preview','approve'] as const)('service-action %s primary observation',operation=>{
 it.each(['valid','terminal inspector abort','malformed','invalid identity','disconnect','abort','oversized','declared oversized'])('preserves the real named/CSRF/DTO reader and exact one-shot request for %s',async outcome=>{
  expect(SERVICE_ACTION_VIEW_BYTES).toBe(32768);
  const scope=operation==='preview'?'actionPreview':'actionApprove',value=operation==='preview'?{...actionView(),preview:primaryActionPreview()}:actionJobView();
  if(outcome==='invalid identity')value.deviceId=`agent_${'e'.repeat(32)}`;
  let held:ReadableStreamDefaultController<Uint8Array>,response:Response,readerSpy:ReturnType<typeof vi.fn>,cancelled=false;
  const controller=new AbortController(),fetch=vi.fn(async(path:string,init?:RequestInit)=>{
   if(path==='/api/auth/session')return json(primaryActionSession);
   if(path==='/api/session')return json({csrfToken:'synthetic-csrf'});
   if(path!==actionRoot+'/'+operation)throw new Error('Unexpected synthetic route');
   const stream=new ReadableStream<Uint8Array>({start(target){held=target;},cancel(){cancelled=true;}});
   init!.signal!.addEventListener('abort',()=>{if(!cancelled)try{held.error(new DOMException('Synthetic abort','AbortError'));}catch{}},{once:true});
   response=new Response(stream,outcome==='declared oversized'?{headers:{'Content-Length':String(SERVICE_ACTION_VIEW_BYTES+1)}}:undefined);readerSpy=vi.spyOn(stream,'getReader');vi.spyOn(response,'clone').mockImplementation(()=>{throw new Error('Secondary body consumer is forbidden');});return response;
  });vi.stubGlobal('fetch',fetch);uninstall=installJournalPrimaryBody({url:new URL(`/api/devices/${actionDevice}/journal/query`,location.href).href});
  const token=observer().arm(scope),pending=(operation==='preview'?previewServiceAction(actionDevice,'fixture.service',primaryActionAccess,controller.signal):approveServiceAction(actionDevice,primaryActionPreview(),primaryActionAccess,controller.signal)).then(result=>({result,error:null}),error=>({result:null,error}));
  await waitFor(()=>expect(held).toBeDefined());expect(observer().take(token)).toBeNull();
  const raw=fetch.mock.calls.at(-1)![1]!.body as string;
  expect(fetch.mock.calls.map(([path])=>path)).toEqual(['/api/auth/session','/api/session',actionRoot+'/'+operation]);
  expect(fetch.mock.calls.at(-1)![1]).toMatchObject({method:'POST',credentials:'same-origin',headers:{'X-CSRF-Token':'synthetic-csrf'}});
  expect(JSON.parse(raw)).toEqual(operation==='preview'?{unit:'fixture.service'}:{previewId:actionPreview().id,previewDigest:actionPreview().digest});
  const bytes=new TextEncoder().encode(JSON.stringify(value));
  if(outcome!=='declared oversized'){
   const split=Math.floor(bytes.length/2);held.enqueue(bytes.slice(0,split));await waitFor(()=>expect(observer().state(token)).toBe('reading'));expect(observer().take(token)).toBeNull();
   if(outcome==='abort')controller.abort();
   else if(outcome==='disconnect')held.error(new TypeError('Synthetic disconnect'));
   else if(outcome==='oversized')held.enqueue(new Uint8Array(SERVICE_ACTION_VIEW_BYTES+1));
   else{held.enqueue(bytes.slice(split,outcome==='malformed'?bytes.length-1:undefined));held.close();}
  }
  const result=await pending;
  if(outcome==='valid'||outcome==='terminal inspector abort'){
   expect(result.error).toBeNull();expect(result.result).toEqual(value);expect(readerSpy!).toHaveBeenCalledTimes(1);expect(response!.clone).not.toHaveBeenCalled();expect(cancelled).toBe(false);
   if(outcome==='terminal inspector abort'){
    // Controlled ordering only: the real primary API validator already accepted
    // these bytes. This does not infer acceptance in the historical browser run.
    const terminal=new Error('Synthetic terminal inspector body-data-missing / aborted'),inspector={body:vi.fn(async()=>{throw terminal;})};await expect(inspector.body()).rejects.toBe(terminal);expect(observer().state(token)).toBe('complete');
   }
   expect(observer().take(token)).toEqual({status:200,body:value,requestBody:raw,bytes:bytes.length});expect(observer().take(token)).toBeNull();
  }else{
   expect(result.result).toBeNull();expect(result.error).not.toBeNull();
   if(outcome==='invalid identity'){expect(result.error).toBeInstanceOf(InvalidServiceActionResponse);expect(observer().take(token)?.body).toEqual(value);}
   else{expect(observer().take(token)).toBeNull();expect(observer().state(token)).not.toBe('complete');}
   if(outcome==='declared oversized'){expect(cancelled).toBe(true);expect(readerSpy!).not.toHaveBeenCalled();}
  }
  expect(fetch.mock.calls.filter(([path])=>path===actionRoot+'/'+operation)).toHaveLength(1);expect(fetch).toHaveBeenCalledTimes(3);
 });

 it.each(['actor','capability','expiry'] as const)('never sends an armed action when %s authorization changes',async changed=>{
  const session={...primaryActionSession,...(changed==='actor'?{actorId:`operator_${'f'.repeat(32)}`}:changed==='capability'?{capabilities:['read']}:{expiresAt:'2026-10-05T14:00:00Z'})};
  const fetch=vi.fn(async()=>json(session));vi.stubGlobal('fetch',fetch);uninstall=installJournalPrimaryBody({url:new URL(`/api/devices/${actionDevice}/journal/query`,location.href).href});const token=observer().arm(operation==='preview'?'actionPreview':'actionApprove');
  await expect(operation==='preview'?previewServiceAction(actionDevice,'fixture.service',primaryActionAccess,new AbortController().signal):approveServiceAction(actionDevice,primaryActionPreview(),primaryActionAccess,new AbortController().signal)).rejects.toMatchObject({status:401});expect(fetch).toHaveBeenCalledTimes(1);expect(observer().state(token)).toBe('armed');expect(observer().take(token)).toBeNull();expect(actionActor).toBe(actionAccess.actorId);
 });
});

it.each(['actionPreview','actionApprove'] as const)('bounds and isolates the exact %s observer without consuming credentials or another action',async scope=>{
 const target=`/api/devices/${journalDevice}/service-actions/${scope==='actionPreview'?'preview':'approve'}`,other=target.endsWith('/preview')?target.replace(/preview$/,'approve'):target.replace(/approve$/,'preview');
 vi.stubGlobal('fetch',vi.fn(async()=>new Response('"'+'x'.repeat(32766)+'"')));uninstall=installJournalPrimaryBody({url:url()});let token=observer().arm(scope);
 for(const [path,method]of [[target,'GET'],[other,'POST'],[target+'?extra=1','POST'],[target.replace(journalDevice,`agent_${'e'.repeat(32)}`),'POST'],['/api/auth/session','GET'],['/api/session','GET'],[root+'/query','POST']]){const response=await globalThis.fetch(path,{method,body:method==='POST'?'{}':undefined});expect(response.bodyUsed).toBe(false);expect(observer().state(token)).toBe('armed');}
 const response=await globalThis.fetch(target,{method:'POST',body:'{}'});expect(response.bodyUsed).toBe(false);const reader=response.body!.getReader();while(!(await reader.read()).done){}reader.releaseLock();const captured=observer().take(token);expect(captured.bytes).toBe(32768);expect(captured.body).toHaveLength(32766);expect(captured.requestBody).toBe('{}');
 token=observer().arm(scope);const first=await globalThis.fetch(target,{method:'POST',body:'{}'});await globalThis.fetch(target,{method:'POST',body:'{"other":true}'});const read=first.body!.getReader();while(!(await read.read()).done){}read.releaseLock();expect(observer().state(token)).toBe('duplicate');expect(observer().take(token)).toBeNull();
 token=observer().arm(scope);const tooLong=await globalThis.fetch(target,{method:'POST',body:'x'.repeat(2049)});expect(tooLong.bodyUsed).toBe(false);expect(observer().state(token)).toBe('invalid-request');expect(observer().take(token)).toBeNull();
});
