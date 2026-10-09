/** Production bounded decoder + UI, synthetic streams only; not browser evidence. */
import {act,cleanup,fireEvent,render,screen,waitFor} from '../../web/node_modules/@testing-library/react/dist/index.js';
import {afterEach,beforeEach,describe,expect,it,vi} from '../../web/node_modules/vitest/dist/index.js';
import {installEnrollmentPrimaryBody} from './enrollment-primary-body.mjs';
import {EnrollmentSection} from '../../web/src/enrollment';
import {abortProtectedRequests,AUTH_REQUIRED_EVENT,mutate} from '../../web/src/api';
import {setLocale} from '../../web/src/i18n';
const secret='A'.repeat(43),invite='invite_'+'1'.repeat(32),url=()=>new URL('/api/enrollment/invitations',location.href).href;
const observer=()=> (globalThis as any).__traceboltEnrollmentBody;
let uninstall:(()=>void)|undefined;
const json=(value:unknown,status=200)=>new Response(JSON.stringify(value),{status,headers:{'Content-Type':'application/json'}});
function creation(){
 const now=Math.floor(Date.now()/1000),fingerprint='ab'.repeat(32);
 const snapshot={version:'tracebolt.enrollment-state.v2',binding:{instanceID:'manager_'+'2'.repeat(32),origin:location.origin,profile:'http-test',collectionProfile:'basic-readonly-v1',issuerFingerprint:'c'.repeat(64)},invitationID:invite,createRequestID:'request_'+'3'.repeat(32),platform:'linux',revision:1,state:'created',createdAt:now,deadlineAt:now+600,updatedAt:now,claim:{claimID:'claim_'+'4'.repeat(32),requestID:'request_'+'5'.repeat(32),keyFingerprint:fingerprint,csrHash:'c'.repeat(64),claimHash:'d'.repeat(64),comparisonCode:'12ab'.repeat(8),at:now},approval:{requestID:'',deviceID:'',keyFingerprint:fingerprint,at:0},intent:{intentID:'',requestID:'',serialHex:'',templateVersion:'',deviceID:'',keyFingerprint:'',notBefore:0,notAfter:0,at:0},issuance:{requestID:'',certificateHash:'',at:0},activation:{requestID:'',at:0},termination:{requestID:'',from:'',at:0}};
 return {serverNow:new Date().toISOString(),schemaVersion:'tracebolt.enrollment-invitation.v2',snapshot,invitationSecret:secret,bootstrap:{schemaVersion:'tracebolt.enrollment-bootstrap.v2',managerInstanceId:snapshot.binding.instanceID,profile:'http-test',enrollmentOrigin:location.origin,agentOrigin:'http://localhost:9443',collectionProfile:snapshot.binding.collectionProfile,invitationId:invite,serverCaPem:'',issuerRootPem:'-----BEGIN CERTIFICATE-----\nUk9PVF9DRVJUSUZJQ0FURQ==\n-----END CERTIFICATE-----',issuerPem:'-----BEGIN CERTIFICATE-----\nSVNTVUVSX0NFUlRJRklDQVRF\n-----END CERTIFICATE-----'}};
}
beforeEach(()=>{setLocale('en',false);history.replaceState({},'', '/#/devices');localStorage.clear();sessionStorage.clear();});
afterEach(()=>{cleanup();uninstall?.();uninstall=undefined;abortProtectedRequests();vi.restoreAllMocks();vi.unstubAllGlobals();});

describe('primary decoder and actual enrollment UI',()=>{
 for(const outcome of ['valid','abort','disconnect','truncated','malformed','invalid UTF8','declared oversized','oversized','invalid DTO','invalid bootstrap'] as const)it(outcome,async()=>{
  let held!:ReadableStreamDefaultController<Uint8Array>,signal!:AbortSignal,response!:Response,readerSpy:any,cancelled=false;
  const value=creation();if(outcome==='invalid DTO')value.snapshot.platform='darwin';if(outcome==='invalid bootstrap')value.bootstrap.issuerPem+='\n'+secret;
  const fetch=vi.fn(async(path:string,init?:RequestInit)=>{
   if(path==='/api/session')return json({csrfToken:'synthetic-csrf'});
   if(path==='/api/enrollment')return json({serverNow:new Date().toISOString(),schemaVersion:'tracebolt.enrollment-operator.v2',enabled:true,platforms:['linux'],recordLimit:25,items:[]});
   expect(path).toBe('/api/enrollment/invitations');expect(init?.method).toBe('POST');value.serverNow=new Date().toISOString();signal=init!.signal!;
   const stream=new ReadableStream<Uint8Array>({start(controller){held=controller;},cancel(){cancelled=true;}});
   signal.addEventListener('abort',()=>{try{held.error(new DOMException('Synthetic abort','AbortError'));}catch{}},{once:true});readerSpy=vi.spyOn(stream,'getReader');
   response=new Response(stream,{status:201,...(outcome==='declared oversized'?{headers:{'Content-Length':'262145'}}:{})});vi.spyOn(response,'clone').mockImplementation(()=>{throw new Error('Second reader forbidden');});return response;
  });vi.stubGlobal('fetch',fetch);uninstall=installEnrollmentPrimaryBody({url:url()});
  render(<EnrollmentSection onChanged={()=>{}} onDevice={()=>{}} deviceIds={[]}/>);await waitFor(()=>expect(screen.getByRole('button',{name:'Add device',exact:true})).toBeEnabled());fireEvent.click(screen.getByRole('button',{name:'Add device',exact:true}));
  const token=observer().arm();fireEvent.click(screen.getByRole('button',{name:'Create invitation',exact:true}));await waitFor(()=>expect(held).toBeDefined());
  if(outcome==='declared oversized')await screen.findByRole('alert');else{
   const bytes=new TextEncoder().encode(JSON.stringify(value)),split=Math.floor(bytes.length/2);await act(async()=>{held.enqueue(bytes.slice(0,split));});expect(observer().state(token)).toBe('reading');expect(observer().take(token)).toBeNull();
   await act(async()=>{
    if(outcome==='abort')fireEvent.keyDown(document,{key:'Escape'});else if(outcome==='disconnect')held.error(new TypeError('Synthetic disconnect'));
    else if(outcome==='oversized')held.enqueue(new Uint8Array(262145));else if(outcome==='malformed'){held.enqueue(new TextEncoder().encode('not-json'));held.close();}
    else if(outcome==='invalid UTF8'){held.enqueue(new Uint8Array([255]));held.close();}else{held.enqueue(bytes.slice(split,outcome==='truncated'?bytes.length-1:undefined));held.close();}
   });
  }
  if(outcome==='valid'){
   const input=await screen.findByLabelText('One-time invitation secret');expect(input).toHaveAttribute('type','password');expect(input).toHaveValue(secret);expect(observer().state(token)).toBe('complete');
   const captured=observer().take(token);expect(captured.status).toBe(201);expect(captured.body).toEqual(value);expect(Object.isFrozen(captured.body.bootstrap)).toBe(true);expect(observer().take(token)).toBeNull();fireEvent.keyDown(document,{key:'Escape'});expect(screen.queryByLabelText('One-time invitation secret')).toBeNull();
  }else{
   if(outcome==='abort'){expect(signal.aborted).toBe(true);expect(observer().state(token)).toBe('aborted');}else await screen.findByRole('alert');expect(screen.queryByLabelText('One-time invitation secret')).toBeNull();
   if(outcome==='invalid DTO'||outcome==='invalid bootstrap'){
    // EOF/JSON does not imply application acceptance: helper mask checks fail.
    expect(observer().state(token)).toBe('complete');expect(observer().take(token).body).toEqual(value);
   }else{expect(observer().state(token)).not.toBe('complete');expect(observer().take(token)).toBeNull();}
  }
  expect(fetch.mock.calls.filter(([path])=>path==='/api/enrollment/invitations')).toHaveLength(1);expect(response.clone).not.toHaveBeenCalled();expect(readerSpy).toHaveBeenCalledTimes(outcome==='declared oversized'?0:1);
  if(outcome==='declared oversized'||outcome==='oversized')expect(cancelled).toBe(true);expect(JSON.stringify({...localStorage,...sessionStorage})).not.toContain(secret);
 });
});
async function consume(response:Response){const reader=response.body!.getReader();for(;;){const part=await reader.read();if(part.done)break;}reader.releaseLock();}
async function observedFetch(){return globalThis.fetch('/api/enrollment/invitations',{method:'POST',body:'{"requestId":"synthetic"}'});}
function install(value:unknown=creation()){const response=json(value,201),fetch=vi.fn(async()=>response);vi.stubGlobal('fetch',fetch);uninstall=installEnrollmentPrimaryBody({url:url()});return {response,fetch,value};}
it('preserves original Response with no prefetch or clone',async()=>{const f=install(),token=observer().arm(),returned=await observedFetch();expect(returned).toBe(f.response);expect(returned.bodyUsed).toBe(false);expect(observer().take(token)).toBeNull();await consume(returned);expect(observer().take(token).body).toEqual(f.value);expect(f.fetch).toHaveBeenCalledTimes(1);});
for(const event of ['pagehide','hashchange',AUTH_REQUIRED_EVENT,'hidden'] as const)it(`clears secret capture on ${event}`,async()=>{
 install();const token=observer().arm();await consume(await observedFetch());expect(observer().state(token)).toBe('complete');if(event==='hidden'){vi.spyOn(document,'visibilityState','get').mockReturnValue('hidden');document.dispatchEvent(new Event('visibilitychange'));}else window.dispatchEvent(new Event(event));
 expect(observer().state(token)).toBe('invalidated');expect(observer().take(token)).toBeNull();expect(JSON.stringify(observer().snapshot(token))).not.toContain(secret);
});
it('abort after EOF before take destroys complete capture',async()=>{install();const token=observer().arm(),controller=new AbortController();const response=await fetch('/api/enrollment/invitations',{method:'POST',body:'{}',signal:controller.signal});await consume(response);expect(observer().state(token)).toBe('complete');controller.abort();expect(observer().state(token)).toBe('aborted');expect(observer().take(token)).toBeNull();expect(observer().snapshot(token).signalAborted).toBe(true);});
it('duplicate POST cannot recover either response',async()=>{const responses=[json(creation(),201),json(creation(),201)];let index=0;vi.stubGlobal('fetch',vi.fn(async()=>responses[index++]));uninstall=installEnrollmentPrimaryBody({url:url()});const token=observer().arm(),first=await observedFetch(),second=await observedFetch();await consume(first);await consume(second);expect(observer().state(token)).toBe('duplicate');expect(observer().take(token)).toBeNull();expect(index).toBe(2);});
it('rejects unrelated or credentialed observer destinations',()=>{for(const target of ['https://localhost/api/enrollment/invitations','http://example.org/api/enrollment/invitations','http://user:pass@localhost/api/enrollment/invitations','http://localhost/api/enrollment/invitations?secret=x','http://localhost/api/enrollment/invitations#x','http://localhost/api/other'])expect(()=>installEnrollmentPrimaryBody({url:target})).toThrow('Invalid synthetic enrollment observation scope');});
it('other methods, paths and origins remain untouched',async()=>{const fetch=vi.fn(async()=>json({safe:true}));vi.stubGlobal('fetch',fetch);uninstall=installEnrollmentPrimaryBody({url:url()});const token=observer().arm();for(const [path,method]of [['/api/enrollment/invitations','GET'],['/api/enrollment/other','POST'],['http://other.invalid/api/enrollment/invitations','POST']])await consume(await globalThis.fetch(path,{method,body:method==='POST'?'{}':undefined}));expect(observer().state(token)).toBe('armed');expect(observer().take(token)).toBeNull();expect(fetch).toHaveBeenCalledTimes(3);});
it('uninstall destroys capture and restores fetch',async()=>{const f=install();observer().arm();await consume(await observedFetch());uninstall!();uninstall=undefined;expect(observer()).toBeUndefined();expect(globalThis.fetch).toBe(f.fetch);});
it('actual mutate rejects protected abort without recovering an observed response',async()=>{
 let held!:ReadableStreamDefaultController<Uint8Array>;const controller=new AbortController();const fetch=vi.fn(async(path:string,init?:RequestInit)=>{if(path==='/api/session')return json({csrfToken:'synthetic'});const stream=new ReadableStream<Uint8Array>({start(value){held=value;}});init!.signal!.addEventListener('abort',()=>held.error(new DOMException('Synthetic abort','AbortError')),{once:true});return new Response(stream,{status:201});});
 vi.stubGlobal('fetch',fetch);uninstall=installEnrollmentPrimaryBody({url:url()});const token=observer().arm(),result=mutate('/enrollment/invitations',{requestId:'synthetic'},controller.signal).then(value=>({value,error:null}),error=>({value:null,error}));await waitFor(()=>expect(held).toBeDefined());held.enqueue(new TextEncoder().encode('{"partial":'));abortProtectedRequests();const completed=await result;expect(completed.value).toBeNull();expect(completed.error).toMatchObject({name:'AbortError'});expect(observer().state(token)).toBe('aborted');expect(observer().take(token)).toBeNull();expect(fetch.mock.calls.filter(([path])=>path==='/api/enrollment/invitations')).toHaveLength(1);
});
it('reader failure preserves the original error and discards partial private bytes',async()=>{
 let held!:ReadableStreamDefaultController<Uint8Array>;const original=new Error('INERT_PRIVATE_FAILURE');const response=new Response(new ReadableStream<Uint8Array>({start(value){held=value;}}),{status:201});vi.stubGlobal('fetch',vi.fn(async()=>response));uninstall=installEnrollmentPrimaryBody({url:url()});const token=observer().arm(),returned=await observedFetch(),reader=returned.body!.getReader();held.enqueue(new TextEncoder().encode(secret));await reader.read();const pending=reader.read();held.error(original);await expect(pending).rejects.toBe(original);expect(observer().state(token)).toBe('failed');expect(observer().take(token)).toBeNull();expect(JSON.stringify(observer().snapshot(token))).not.toContain(secret);
});
it('unusable request bodies and absent response streams never become complete',async()=>{
 for(const body of [undefined,new Uint8Array([1]),'x'.repeat(2049)]){
  install();const token=observer().arm(),response=await fetch('/api/enrollment/invitations',{method:'POST',body:body as any});await consume(response);expect(observer().state(token)).toBe('invalid-request');expect(observer().take(token)).toBeNull();uninstall!();uninstall=undefined;
 }
 vi.stubGlobal('fetch',vi.fn(async()=>new Response(null,{status:201})));uninstall=installEnrollmentPrimaryBody({url:url()});const token=observer().arm();await observedFetch();expect(observer().state(token)).toBe('missing-body');expect(observer().take(token)).toBeNull();
});
it('superseded capture cannot restore late private bytes or replace the next response',async()=>{
 let held!:ReadableStreamDefaultController<Uint8Array>;const first=new Response(new ReadableStream<Uint8Array>({start(value){held=value;}}),{status:201}),second=json({newCapture:true},201);let count=0;vi.stubGlobal('fetch',vi.fn(async()=>count++===0?first:second));uninstall=installEnrollmentPrimaryBody({url:url()});const old=observer().arm(),original=await observedFetch(),pending=consume(original),fresh=observer().arm();held.enqueue(new TextEncoder().encode(JSON.stringify({invitationSecret:secret})));held.close();await pending;expect(observer().take(old)).toBeNull();await consume(await observedFetch());expect(observer().take(fresh).body).toEqual({newCapture:true});expect(count).toBe(2);
});
