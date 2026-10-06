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
  render(<AuthBoundary><JournalPanel deviceId={journalDevice} insecureTestMode={true} sessionKey={journalSessionExpiry}/></AuthBoundary>);
  await screen.findByText('Awaiting a request');expect(fetch.mock.calls.some(([path])=>path.startsWith(systemRoot))).toBe(false);
  const token=observer().arm('services');fireEvent.click(screen.getByRole('button',{name:'Choose observed service'}));await waitFor(()=>expect(held).toBeDefined());
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
  fireEvent.click(screen.getByRole('button',{name:'Next page'}));await waitFor(()=>expect(held).toBeDefined());
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
    if(outcome==='abort'){expect(signal!.aborted).toBe(true);expect(screen.getByRole('status')).toHaveTextContent('Log content is paused');}
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

 it.each([['journal',65536],['services',262144]] as const)('retains the exact %s byte cap',async(scope,maximum)=>{
  vi.stubGlobal('fetch',vi.fn(async()=>new Response('"'+'x'.repeat(maximum-2)+'"')));uninstall=installJournalPrimaryBody({url:url()});
  const route=scope==='journal'?root+'/query':systemRoot+'/query',token=observer().arm(scope),response=await globalThis.fetch(route,{method:'POST'}),reader=response.body!.getReader();
  while(!(await reader.read()).done){}reader.releaseLock();expect(observer().take(token)?.body).toHaveLength(maximum-2);
  vi.stubGlobal('fetch',vi.fn(async()=>new Response('"'+'x'.repeat(maximum-1)+'"')));uninstall();uninstall=installJournalPrimaryBody({url:url()});
  const oversized=observer().arm(scope),tooLarge=await globalThis.fetch(route,{method:'POST'}),largeReader=tooLarge.body!.getReader();while(!(await largeReader.read()).done){}largeReader.releaseLock();expect(observer().state(oversized)).toBe('oversized');expect(observer().take(oversized)).toBeNull();
 });
});
