/** Production bounded decoder + UI, synthetic streams only; not browser evidence. */
import {act,cleanup,fireEvent,render,screen,waitFor,within} from '../../web/node_modules/@testing-library/react/dist/index.js';
import {afterEach,beforeEach,describe,expect,it,vi} from '../../web/node_modules/vitest/dist/index.js';
import {installEnrollmentPrimaryBody} from './enrollment-primary-body.mjs';
import {EnrollmentSection} from '../../web/src/enrollment';
import {abortProtectedRequests,AUTH_REQUIRED_EVENT,mutate} from '../../web/src/api';
import {setLocale} from '../../web/src/i18n';
import {validSnapshot} from '../../web/src/enrollment-types';
import enrollmentBrowserSource from './enrollment-browser.mjs?raw';
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

for(const event of ['pagehide','hashchange',AUTH_REQUIRED_EVENT,'hidden'] as const)it(`invalidation before first POST stays terminal: ${event}`,async()=>{
 const f=install(),token=observer().arm();
 if(event==='hidden'){vi.spyOn(document,'visibilityState','get').mockReturnValue('hidden');document.dispatchEvent(new Event('visibilitychange'));}else window.dispatchEvent(new Event(event));
 expect(observer().state(token)).toBe('invalidated');
 const response=await observedFetch();expect(response).toBe(f.response);await consume(response);
 expect(observer().state(token)).toBe('invalidated');expect(observer().take(token)).toBeNull();expect(observer().snapshot(token).eof).toBe(false);expect(f.fetch).toHaveBeenCalledTimes(1);
});
it('clear before the first POST stays missing and explicit rearm starts a separate capture',async()=>{
 const responses=[json(creation(),201),json(creation(),201)],original=vi.fn(async()=>responses.shift()!);vi.stubGlobal('fetch',original);uninstall=installEnrollmentPrimaryBody({url:url()});
 const old=observer().arm();observer().clear();await consume(await observedFetch());expect(observer().state(old)).toBe('missing');expect(observer().take(old)).toBeNull();
 const next=observer().arm();expect(next).not.toBe(old);await consume(await observedFetch());expect(observer().state(next)).toBe('complete');expect(observer().take(next)?.status).toBe(201);expect(observer().take(old)).toBeNull();expect(original).toHaveBeenCalledTimes(2);
});

it('repeated creation clicks use one production POST/reader and clear the accepted masked secret',async()=>{
 const value=creation();let held!:ReadableStreamDefaultController<Uint8Array>,readerSpy:any,response!:Response;
 const original=vi.fn(async(path:string)=>{
  if(path==='/api/session')return json({csrfToken:'synthetic'});
  if(path==='/api/enrollment')return json({serverNow:new Date().toISOString(),schemaVersion:'tracebolt.enrollment-operator.v2',enabled:true,platforms:['linux'],recordLimit:25,items:[]});
  expect(path).toBe('/api/enrollment/invitations');value.serverNow=new Date().toISOString();const body=new ReadableStream<Uint8Array>({start(controller){held=controller;}});readerSpy=vi.spyOn(body,'getReader');response=new Response(body,{status:201});vi.spyOn(response,'clone');vi.spyOn(response,'json');return response;
 });vi.stubGlobal('fetch',original);uninstall=installEnrollmentPrimaryBody({url:url()});
 render(<EnrollmentSection onChanged={()=>{}} onDevice={()=>{}} deviceIds={[]}/>);await waitFor(()=>expect(screen.getByRole('button',{name:'Add device',exact:true})).toBeEnabled());fireEvent.click(screen.getByRole('button',{name:'Add device',exact:true}));
 const token=observer().arm(),button=screen.getByRole('button',{name:'Create invitation',exact:true});fireEvent.click(button,{detail:1});fireEvent.click(button,{detail:2});fireEvent.doubleClick(button,{detail:2});await waitFor(()=>expect(held).toBeDefined());expect(button).toBeDisabled();expect(observer().take(token)).toBeNull();expect(screen.queryByLabelText('One-time invitation secret')).toBeNull();
 expect(original.mock.calls.filter(([path])=>path==='/api/enrollment/invitations')).toHaveLength(1);
 await act(async()=>{held.enqueue(new TextEncoder().encode(JSON.stringify(value)));held.close();});const input=await screen.findByLabelText('One-time invitation secret');expect(input).toHaveAttribute('type','password');expect(input).toHaveValue(secret);expect(observer().snapshot(token)).toMatchObject({requests:1,status:201,eof:true,signalAborted:false,phase:'complete'});expect(observer().take(token).body).toEqual(value);expect(observer().take(token)).toBeNull();expect(readerSpy).toHaveBeenCalledTimes(1);expect(response.clone).not.toHaveBeenCalled();expect(response.json).not.toHaveBeenCalled();
 expect(JSON.stringify({...localStorage,...sessionStorage})).not.toContain(secret);expect(location.href).not.toContain(secret);fireEvent.keyDown(document,{key:'Escape'});expect(screen.queryByLabelText('One-time invitation secret')).toBeNull();
});
for(const [initial,action,label,status] of [['created','canceled','Cancel invitation','Canceled'],['claimed_pending','rejected','Reject','Rejected'],['activated','revoked','Revoke identity','Revoked']] as const)for(const outcome of ['valid','wrong terminal state','HTTP failure'] as const)it(`production terminal UI ${action}: ${outcome}`,async()=>{
 const item=creation().snapshot;item.state=initial;item.revision=2;item.intent.notAfter=item.deadlineAt;
 if(initial==='activated')item.approval.deviceID='agent_'+'6'.repeat(32);
 let held!:ReadableStreamDefaultController<Uint8Array>,submitted:any;
 const original=vi.fn(async(path:string,init?:RequestInit)=>{
  if(path==='/api/session')return json({csrfToken:'synthetic'});
  if(path==='/api/enrollment')return json({serverNow:new Date().toISOString(),schemaVersion:'tracebolt.enrollment-operator.v2',enabled:true,platforms:['linux'],recordLimit:25,items:[item]});
  expect(path).toBe(`/api/enrollment/${invite}/terminate`);expect(init?.method).toBe('POST');submitted=JSON.parse(String(init?.body));return new Response(new ReadableStream<Uint8Array>({start(controller){held=controller;}}),{status:outcome==='HTTP failure'?403:200});
 });vi.stubGlobal('fetch',original);
 render(<EnrollmentSection onChanged={()=>{}} onDevice={()=>{}} deviceIds={[]}/>);fireEvent.click(await screen.findByRole('button',{name:/^Invitations/}));fireEvent.click(screen.getByRole('button',{name:`Review invitation ${invite}`,exact:true}));const dialog=screen.getByRole('dialog',{name:'Review invitation',exact:true});
 fireEvent.click(within(dialog).getByRole('button',{name:label,exact:true}));const group=within(dialog).getByRole('group',{name:'Confirm termination',exact:true});expect(submitted).toBeUndefined();
 fireEvent.click(within(group).getByRole('button',{name:'Back',exact:true}));expect(submitted).toBeUndefined();expect(within(dialog).queryByRole('group',{name:'Confirm termination',exact:true})).toBeNull();
 fireEvent.click(within(dialog).getByRole('button',{name:label,exact:true}));const confirmation=within(dialog).getByRole('button',{name:'Confirm termination',exact:true});fireEvent.click(confirmation);fireEvent.click(confirmation);await waitFor(()=>expect(held).toBeDefined());expect(confirmation).toBeDisabled();expect(dialog.querySelector('.enrollment-created-meta')).not.toHaveTextContent(status);
 const committed={...item,state:outcome==='wrong terminal state'?'approved':action,revision:3,termination:{requestID:submitted.requestId,from:initial,at:item.updatedAt}};await act(async()=>{held.enqueue(new TextEncoder().encode(JSON.stringify(committed)));held.close();});if(outcome!=='valid'){await within(dialog).findByRole('alert');expect(dialog.querySelector('.enrollment-created-meta')).not.toHaveTextContent(status);expect(original.mock.calls.filter(([path])=>path.endsWith('/terminate'))).toHaveLength(1);return;}await waitFor(()=>expect(dialog.querySelector('.enrollment-created-meta')).toHaveTextContent(status));expect(within(dialog).queryByRole('group',{name:'Confirm termination',exact:true})).toBeNull();expect(within(dialog).queryByRole('button',{name:label,exact:true})).toBeNull();expect(within(dialog).queryByRole('button',{name:'Approve device',exact:true})).toBeNull();
 expect(original.mock.calls.filter(([path])=>path.endsWith('/terminate'))).toHaveLength(1);expect(submitted).toMatchObject({expectedRevision:2,action});expect(item.deadlineAt).toBe(committed.deadlineAt);expect(item.claim.keyFingerprint).toBe(committed.claim.keyFingerprint);expect(item.claim.comparisonCode).toBe(committed.claim.comparisonCode);
});

// Execute the browser helper itself with actual production UI/decoder and inert
// streams. A rejected POST may trigger the app's existing reconciliation GET;
// terminal-looking reconciled UI must never hide invalid primary evidence.
for(const [initial,action,label,rendered] of [['created','canceled','Cancel invitation','Canceled'],['claimed_pending','rejected','Reject','Rejected'],['activated','revoked','Revoke identity','Revoked']] as const)for(const field of ['valid','version','platform','binding.instanceID','binding.origin','binding.profile','binding.collectionProfile','binding.issuerFingerprint','claim.keyFingerprint','claim.comparisonCode'] as const)it(`actual termination helper ${action}: ${field} with reconciliation`,async()=>{
 const item=creation().snapshot;item.state=initial;item.revision=2;item.intent.notAfter=item.deadlineAt;let terminal:any=null,posts=0,reads=0,bodyReads=0,primaryReader:any,responseWait:(value:any)=>void=()=>{};
 const original=vi.fn(async(path:string,init?:RequestInit)=>{
  if(path==='/api/session')return json({csrfToken:'synthetic'});
  if(path==='/api/enrollment'){reads++;return json({serverNow:new Date().toISOString(),schemaVersion:'tracebolt.enrollment-operator.v2',enabled:true,platforms:['linux'],recordLimit:25,items:[terminal||item]});}
  expect(path).toBe(`/api/enrollment/${invite}/terminate`);posts++;
  const requested=JSON.parse(String(init?.body));terminal={...structuredClone(item),revision:3,state:action,termination:{requestID:requested.requestId,from:initial,at:item.updatedAt}};
  const invalid=structuredClone(terminal);
  if(field!=='valid'){const [section,key]=field.split('.');if(key)invalid[section][key]='INERT_WRONG_PRIMARY_FIELD';else invalid[section]='INERT_WRONG_PRIMARY_FIELD';}
  if(field!=='version'&&field!=='binding.profile')expect(validSnapshot(invalid)).toBe(true);
  const response=json(invalid);primaryReader=vi.spyOn(response.body!,'getReader');vi.spyOn(response,'clone').mockImplementation(()=>{throw new Error('Secondary reader forbidden');});queueMicrotask(()=>responseWait({json(){bodyReads++;throw new Error('Secondary CDP body unavailable');},status:()=>200,url:()=>location.origin+path,request:()=>({method:()=> 'POST',url:()=>location.origin+path,postData:()=>String(init?.body)})}));return response;
 });vi.stubGlobal('fetch',original);uninstall=installEnrollmentPrimaryBody({url:url()});
 render(<EnrollmentSection onChanged={()=>{}} onDevice={()=>{}} deviceIds={[]}/>);fireEvent.click(await screen.findByRole('button',{name:/^Invitations/}));fireEvent.click(screen.getByRole('button',{name:`Review invitation ${invite}`,exact:true}));
 function locator(get:()=>HTMLElement[]){return {get,async click(){expect(get()).toHaveLength(1);fireEvent.click(get()[0]);},getByRole(role:any,options:any){return locator(()=>get().flatMap(node=>within(node).queryAllByRole(role,options)));},locator(selector:string){return locator(()=>get().flatMap(node=>[...node.querySelectorAll(selector)] as HTMLElement[]));}};}
 const page={getByRole(role:any,options:any){return locator(()=>screen.queryAllByRole(role,options));},evaluate(fn:any,arg:any){return Promise.resolve(fn(arg));},waitForResponse(predicate:any){return new Promise(resolve=>{responseWait=value=>{expect(predicate(value)).toBe(true);resolve(value);};});}};
 const checks:any=(value:any)=>({toBe(want:any){expect(value).toBe(want);},async toBeVisible(){await waitFor(()=>expect(value.get()).toHaveLength(1));},async toContainText(want:string){await waitFor(()=>{expect(value.get()).toHaveLength(1);expect(value.get()[0]).toHaveTextContent(want);});},async toHaveCount(want:number){await waitFor(()=>expect(value.get()).toHaveLength(want));}});
 checks.poll=(fn:any)=>({not:{async toMatch(pattern:RegExp){await waitFor(async()=>expect(await fn()).not.toMatch(pattern));}}});
 // Git may check this source out as CRLF on Windows. Extract the same helper
 // body on either platform; reject a missing delimiter instead of compiling
 // the remainder of the browser module (which includes top-level await).
 const source=enrollmentBrowserSource.replace(/\r\n/g,'\n'),start=source.indexOf('async function terminate('),end=source.indexOf('\n\ntry{',start);
 expect(start).toBeGreaterThanOrEqual(0);expect(end).toBeGreaterThan(start);
 const helper=Function('expect','validSnapshot','base','mark','transportDiagnostics','let terminationPrimaryFailure=null,terminationTransportFailure=null;'+source.slice(start,end)+';return terminate;')(checks,validSnapshot,location.origin,()=>{},{capture:()=>({operation:'other',category:'other'})});
 const result=helper(page,label,item).then(()=>({error:null}),error=>({error}));const completed=await result;
 if(field==='valid')expect(completed.error).toBeNull();else expect(completed.error).not.toBeNull();
 await waitFor(()=>expect(screen.getByRole('dialog').querySelector('.enrollment-created-meta')).toHaveTextContent(rendered));
 expect(posts).toBe(1);expect(reads).toBe(field==='valid'?1:2);expect(bodyReads).toBe(0);expect(primaryReader).toHaveBeenCalledTimes(1);expect(screen.queryByRole('group',{name:'Confirm termination'})).toBeNull();expect(observer().state(1)).toBe('missing');
});

const terminalURL=()=>`/api/enrollment/${invite}/terminate`;
const terminalBody=(action='canceled')=>JSON.stringify({requestId:'request_'+'7'.repeat(32),expectedRevision:2,action});
function armTerminal(action='canceled'){return observer().armTermination({invitationID:invite,action});}
async function terminalFetch(signal?:AbortSignal,body=terminalBody(),path=terminalURL()){return fetch(path,{method:'POST',body,signal});}
for(const outcome of ['abort','failure','malformed','invalid UTF8','truncated','oversized','cancelled','missing-body'] as const)it(`termination primary ${outcome} cannot be consumed`,async()=>{
 let held!:ReadableStreamDefaultController<Uint8Array>;const controller=new AbortController();
 const response=outcome==='missing-body'?new Response(null,{status:200}):new Response(new ReadableStream<Uint8Array>({start(value){held=value;}}),{status:200});
 const original=vi.fn(async()=>response);vi.stubGlobal('fetch',original);uninstall=installEnrollmentPrimaryBody({url:url()});const token=armTerminal(),returned=await terminalFetch(controller.signal);
 if(outcome!=='missing-body'){
  const reader=returned.body!.getReader();if(outcome==='cancelled')await reader.cancel();else if(outcome==='abort'){controller.abort();held.close();await reader.read();}
  else if(outcome==='failure'){const pending=reader.read();held.error(new Error('INERT_PRIVATE_FAILURE'));await expect(pending).rejects.toThrow('INERT_PRIVATE_FAILURE');}
  else{held.enqueue(outcome==='oversized'?new Uint8Array(262145):outcome==='invalid UTF8'?new Uint8Array([255]):new TextEncoder().encode(outcome==='truncated'?'{"x":1':'not-json'));held.close();await reader.read();await reader.read();}
 }
 expect(observer().state(token)).not.toBe('complete');expect(observer().take(token)).toBeNull();expect(original).toHaveBeenCalledTimes(1);expect(JSON.stringify(observer().snapshot(token))).not.toContain('INERT_PRIVATE_FAILURE');
});
for(const event of ['pagehide','hashchange',AUTH_REQUIRED_EVENT,'hidden','abort','clear'] as const)for(const when of ['before request','during read','after EOF'] as const)it(`termination cleanup ${event} ${when}`,async()=>{
 let held!:ReadableStreamDefaultController<Uint8Array>;const response=new Response(new ReadableStream<Uint8Array>({start(value){held=value;}}),{status:200}),controller=new AbortController(),original=vi.fn(async()=>response);
 vi.stubGlobal('fetch',original);uninstall=installEnrollmentPrimaryBody({url:url()});const token=armTerminal();
 const invalidate=()=>{if(event==='abort')controller.abort();else if(event==='clear')observer().clear();else if(event==='hidden'){vi.spyOn(document,'visibilityState','get').mockReturnValue('hidden');document.dispatchEvent(new Event('visibilitychange'));}else window.dispatchEvent(new Event(event));};
 if(when==='before request')invalidate();const returned=await terminalFetch(controller.signal),reader=returned.body!.getReader();held.enqueue(new TextEncoder().encode('{"private":"'+secret+'"}'));await reader.read();
 if(when==='during read')invalidate();held.close();await reader.read();if(when==='after EOF'){expect(observer().state(token)).toBe('complete');invalidate();}
 expect(observer().take(token)).toBeNull();expect(observer().state(token)).not.toBe('complete');expect(JSON.stringify(observer().snapshot(token))).not.toContain(secret);expect(original).toHaveBeenCalledTimes(1);
});
it('termination arm matches only its exact action and bounded request',async()=>{
 for(const body of [terminalBody('rejected'),'{}','not-json',JSON.stringify({requestId:'bad',expectedRevision:2,action:'canceled'}),JSON.stringify({requestId:'request_'+'7'.repeat(32),expectedRevision:0,action:'canceled'}),new Uint8Array([1]),'x'.repeat(2049)]){
  const original=vi.fn(async()=>json({state:'canceled'}));vi.stubGlobal('fetch',original);uninstall=installEnrollmentPrimaryBody({url:url()});const token=armTerminal();await consume(await terminalFetch(undefined,body as any));expect(observer().state(token)).toBe('invalid-request');expect(observer().take(token)).toBeNull();expect(original).toHaveBeenCalledTimes(1);uninstall!();uninstall=undefined;
 }
});
it('termination duplicate and wrong invitation cannot provide primary success',async()=>{
 const original=vi.fn(async()=>json({state:'canceled'}));vi.stubGlobal('fetch',original);uninstall=installEnrollmentPrimaryBody({url:url()});const token=armTerminal();
 await consume(await terminalFetch(undefined,terminalBody(),terminalURL().replace(invite,'invite_'+'f'.repeat(32))));expect(observer().state(token)).toBe('armed');expect(observer().take(token)).toBeNull();
 await consume(await terminalFetch());expect(observer().state(token)).toBe('complete');await consume(await terminalFetch());expect(observer().state(token)).toBe('duplicate');expect(observer().take(token)).toBeNull();expect(original).toHaveBeenCalledTimes(3);
});
it('invalid termination arm clears prior capture without widening creation scope',async()=>{
 const original=vi.fn(async()=>json(creation(),201));vi.stubGlobal('fetch',original);uninstall=installEnrollmentPrimaryBody({url:url()});const created=observer().arm();await consume(await observedFetch());expect(observer().state(created)).toBe('complete');
 for(const scope of [{invitationID:'../invitations',action:'canceled'},{invitationID:invite,action:'approved'},{invitationID:invite+'?x',action:'rejected'},{}])expect(()=>observer().armTermination(scope)).toThrow('Invalid synthetic termination observation scope');
 expect(observer().take(created)).toBeNull();const next=observer().arm();await consume(await observedFetch());expect(observer().take(next).status).toBe(201);
});
