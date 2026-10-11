import assert from 'node:assert/strict';
import fs from 'node:fs';
import {EventEmitter} from 'node:events';
import {createBrowserTransportDiagnostics} from './browser-transport-diagnostics.mjs';
import test from 'node:test';
import {createBrowserInvitation,invitationCreationStage} from './enrollment-create-diagnostics.mjs';
const secret='INERT_PRIVATE_RESPONSE_ERROR_URL_AND_SECRET_SENTINEL';
const phases=['open dialog','arm primary reader','submit','await response','response status','await primary reader','primary reader complete','primary response binding','response schema','secret type','masked field','masked value'];
function fixture(failAt){
 const stages=[],events=[],secrets=[],details=[];let writes=0,clears=0,reads=0;
 const requestBody='{"requestId":"synthetic"}',created={schemaVersion:'tracebolt.enrollment-invitation.v2',invitationSecret:secret};
 const failure=new Error(secret);
 const observer={
  arm(){events.push('arm');if(failAt==='arm primary reader')throw failure;return 1;},
  state(){return failAt==='primary reader complete'?'aborted':'complete';},
  snapshot(){return {phase:observer.state(),eof:true,signalAborted:false,requests:1};},
  take(){events.push('take');return {status:201,requestBody:failAt==='primary response binding'?'other':requestBody,body:failAt==='response schema'?{...created,schemaVersion:secret}:failAt==='secret type'?{...created,invitationSecret:null}:created};},
  clear(){clears++;},
 };
 const response={status:()=>failAt==='response status'?403:201,request:()=>({postData:()=>requestBody}),body(){reads++;throw new Error('Secondary inspector bytes unavailable');}};
 const page={
  getByRole(role,{name,exact}){assert.equal(role,'button');assert.equal(exact,true);return {async click(){if(name==='Add device'){events.push('open');if(failAt==='open dialog')throw failure;}else{assert.equal(name,'Create invitation');events.push('submit');writes++;if(failAt==='submit')throw failure;}},async dblclick(){assert.equal(name,'Create invitation');events.push('double-submit');writes++;if(failAt==='submit')throw failure;}};},
  waitForResponse(predicate){events.push('register');assert.equal(predicate({url:()=> 'http://127.0.0.1:19889/api/enrollment/invitations',request:()=>({method:()=> 'POST'})}),true);return failAt==='await response'?new Promise((resolve,reject)=>setImmediate(()=>reject(failure))):Promise.resolve(response);},
  async evaluate(fn,arg){const previous=globalThis.window;try{globalThis.window={__traceboltEnrollmentBody:observer};return await fn(arg);}finally{if(previous===undefined)delete globalThis.window;else globalThis.window=previous;}},
  getByLabel(name,{exact}){assert.equal(name,'One-time invitation secret');assert.equal(exact,true);return {async inputValue(){return failAt==='masked value'?'different':secret;}};},
 };
 const expect=value=>({toBe(expected){assert.equal(value,expected);},async toHaveAttribute(name,expected){assert.equal(name,'type');assert.equal(expected,'password');events.push('mask');if(failAt==='masked field')throw failure;}});
 expect.poll=callback=>({not:{async toMatch(pattern){if(failAt==='await primary reader')throw failure;assert.doesNotMatch(await callback(),pattern);}}});
 return {stages,events,secrets,details,observer,response,failure,page,run:(invocation='single',extra={})=>createBrowserInvitation(page,{base:'http://127.0.0.1:19889',mark:value=>stages.push(value),expect,secrets,invocation,recordPrimaryFailure:value=>details.push(value),...extra}),writes:()=>writes,clears:()=>clears,reads:()=>reads};
}

test('stage labels stay closed without coercing hostile values',()=>{
 const hostile={toString(){throw new Error(secret);}};
 for(const call of ['single','first','second',secret,hostile,null])for(const phase of [...phases,secret,hostile,null]){
  const value=invitationCreationStage(call,phase);assert.equal(value.includes(secret),false);
  assert.ok(['single','first','second'].some(invocation=>[...phases,'unknown'].includes(value.replace(`create invitation ${invocation}: `,''))));
 }
});
for(const invocation of ['single','first','second'])test(`${invocation} requires primary success and masked equality without a second body retrieval`,async()=>{
 const f=fixture();assert.deepEqual(await f.run(invocation),{schemaVersion:'tracebolt.enrollment-invitation.v2',invitationSecret:secret});
 assert.deepEqual(f.stages,phases.map(phase=>invitationCreationStage(invocation,phase)));
 assert.deepEqual(f.events,['open','arm','register','submit','take','mask']);assert.equal(f.writes(),1);assert.equal(f.reads(),0);assert.equal(f.clears(),1);assert.deepEqual(f.secrets,[secret]);assert.deepEqual(f.details,[]);
});
for(const invocation of ['first','second'])for(const phase of phases)test(`${invocation} fails closed at ${phase} without replay and clears observation`,async()=>{
 const f=fixture(phase);await assert.rejects(f.run(invocation));assert.equal(f.stages.at(-1),invitationCreationStage(invocation,phase));
 assert.equal(f.writes(),['open dialog','arm primary reader'].includes(phase)?0:1);assert.equal(f.reads(),0);assert.equal(f.clears(),1);
 assert.equal(JSON.stringify({stages:f.stages,details:f.details}).includes(secret),false);
});
for(const phase of ['aborted','failed','invalid','cancelled','oversized','invalidated','duplicate','missing'])test(`primary ${phase} never becomes success`,async()=>{
 const f=fixture();f.observer.state=()=>phase;await assert.rejects(f.run());assert.equal(f.writes(),1);assert.equal(f.reads(),0);assert.deepEqual(f.secrets,[]);assert.equal(f.clears(),1);
});
test('null consumption and mismatched status cannot pass binding',async()=>{
 for(const value of [null,{status:200,requestBody:'synthetic',body:{}}]){const f=fixture();f.observer.take=()=>value;await assert.rejects(f.run());assert.deepEqual(f.secrets,[]);assert.equal(f.writes(),1);assert.equal(f.clears(),1);}
});
test('diagnostic failures preserve original failure',async()=>{
 const f=fixture('masked field');await assert.rejects(f.run('single',{recordPrimaryFailure(){throw new Error(secret);},transportDiagnostics:{capture(){throw new Error(secret);}}}),error=>error===f.failure);assert.equal(f.clears(),1);assert.equal(f.writes(),1);
});
test('runner retains first/second route calls, redaction, gates and per-case reset',()=>{
 const source=fs.readFileSync(new URL('./enrollment-browser.mjs',import.meta.url),'utf8');
 assert.match(source,/context.addInitScript\(installEnrollmentPrimaryBody,\{url:base\+'\/api\/enrollment\/invitations'\}\)/);
 assert.match(source,/create\(page,'first'\)/);assert.match(source,/create\(page,'second'\)/);
 assert.match(source,/creationTransportFailure=null;creationPrimaryFailure=null/);
 assert.match(source,/error:'Assertion failed; secret-bearing diagnostics intentionally withheld\.'/);
 assert.match(source,/process\.exitCode=fatal\|\|runtimeErrorCount\|\|results\.some\(r=>r\.status==='FAIL'\)\?1:0/);
 const helper=fs.readFileSync(new URL('./enrollment-create-diagnostics.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(helper,/response\.(?:body|json|text|finished)\(|\.clone\(|setTimeout|setInterval|console\./);
 assert.match(helper,/input.inputValue\(\)===created.invitationSecret/);
 assert.match(helper,/finally\{[\s\S]*__traceboltEnrollmentBody.clear\(\)/);
});

test('held double-click submission retains all primary, binding, mask and cleanup gates',async()=>{
 const f=fixture();let release,entered;const held=new Promise(resolve=>release=resolve),submitted=new Promise(resolve=>entered=resolve);
 const pending=f.run('single',{submit:async button=>{await button.dblclick();entered();await held;}});
 await submitted;assert.deepEqual(f.events,['open','arm','register','double-submit']);assert.equal(f.writes(),1);assert.equal(f.clears(),0);assert.deepEqual(f.secrets,[]);
 release();await pending;assert.deepEqual(f.events,['open','arm','register','double-submit','take','mask']);assert.equal(f.reads(),0);assert.equal(f.clears(),1);assert.deepEqual(f.secrets,[secret]);
});
for(const phase of ['submit','response status','await primary reader','primary reader complete','primary response binding','response schema','secret type','masked field','masked value'])test(`double-click submission fails closed at ${phase}`,async()=>{
 const f=fixture(phase);await assert.rejects(f.run('single',{submit:button=>button.dblclick()}));assert.equal(f.writes(),1);assert.equal(f.reads(),0);assert.equal(f.clears(),1);assert.equal(f.stages.at(-1),invitationCreationStage('single',phase));assert.equal(JSON.stringify({stages:f.stages,details:f.details}).includes(secret),false);
});
test('quarantined double-click uses the shared primary reader and preserves strict assertions',()=>{
 const source=fs.readFileSync(new URL('./enrollment-browser.mjs',import.meta.url),'utf8');
 const start=source.indexOf("  await check('One creation request"),end=source.indexOf("  await check('Native claim comparison",start);assert.ok(start>0&&end>start);const scenario=source.slice(start,end);
 assert.match(scenario,/create\(page,'single',async button=>/);assert.match(scenario,/button\.dblclick\(\)/);assert.match(scenario,/expect\(button\)\.toBeDisabled\(\)/);assert.match(scenario,/expect\(posts\)\.toBe\(1\)/);assert.match(scenario,/finally\{release\(\);\}/);assert.match(scenario,/finally\{release\(\);await page\.unroute\('\*\*\/api\/enrollment\/invitations'\);\}/);
 assert.doesNotMatch(scenario,/\.json\(\)|waitForResponse|\.clone\(/);
 for(const retained of ['public bootstrap export','raw.includes(created.invitationSecret)',"raw.includes('PRIVATE KEY')",'JSON.stringify(created.bootstrap)',"toHaveAttribute('type','text')","toHaveAttribute('type','password')",'checkClean(page)',"terminate(page,'Cancel invitation')",".state).toBe('canceled')"])assert.ok(scenario.includes(retained),retained);
 const original=source.slice(source.indexOf('async function terminate('),source.indexOf('\ntry{'));assert.match(original,/responseStatus=response\.status\(\);expect\(responseStatus\)\.toBe\(200\)/);assert.match(original,/committed\.state\)\.toBe\(expected\[0\]\)/);assert.match(original,/toContainText\(expected\[1\]\)/);assert.match(original,/expect\(confirmation\)\.toHaveCount\(0\)/);
 assert.match(source,/const includeQuarantined=process\.env\.TRACEBOLT_REVIEW_QUARANTINED==='1'/);assert.match(source,/status:'SKIPPED'/);assert.match(source,/runtimeErrorCount===0&&results\.length===13&&results\.every/);
});

function deferred(){let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return {promise,resolve,reject};}
const nextTurn=()=>new Promise(resolve=>setImmediate(resolve));
function delayedResponse(f){const pending=deferred(),register=f.page.waitForResponse;f.page.waitForResponse=predicate=>{register(predicate);return pending.promise;};return pending;}
function outcome(promise){const state={};state.done=promise.then(value=>{state.value=value;state.settled=true;},error=>{state.error=error;state.settled=true;});return state;}
for(const kind of ['synchronous callback','rejected callback','failed click'])test(`${kind} clears immediately and observes a late response rejection`,async()=>{
 const f=fixture(kind==='failed click'?'submit':undefined),response=delayedResponse(f);
 const submit=kind==='synchronous callback'?()=>{throw f.failure;}:kind==='rejected callback'?()=>Promise.reject(f.failure):undefined;
 const result=outcome(f.run('single',{submit}));await nextTurn();assert.equal(result.settled,true);assert.equal(result.error,f.failure);assert.equal(f.clears(),1);assert.deepEqual(f.secrets,[]);
 const stages=[...f.stages];response.reject(new Error(secret));await nextTurn();await nextTurn();assert.deepEqual(f.stages,stages);assert.equal(f.clears(),1);assert.equal(f.reads(),0);assert.equal(f.writes(),kind==='failed click'?1:0);assert.equal(JSON.stringify({stages:f.stages,details:f.details}).includes(secret),false);
});
for(const late of ['resolve','reject'])test(`response rejection clears a held submit before its late ${late}`,async()=>{
 const f=fixture(),response=delayedResponse(f),held=deferred(),entered=deferred();
 const result=outcome(f.run('single',{submit:async button=>{await button.dblclick();entered.resolve();await held.promise;}}));await entered.promise;
 response.reject(f.failure);await nextTurn();assert.equal(result.settled,true);assert.equal(result.error,f.failure);assert.equal(f.clears(),1);assert.deepEqual(f.secrets,[]);assert.equal(f.events.includes('take'),false);
 const stages=[...f.stages];held[late](new Error(secret));await nextTurn();await nextTurn();assert.deepEqual(f.stages,stages);assert.equal(f.clears(),1);assert.equal(f.reads(),0);assert.equal(f.writes(),1);assert.equal(JSON.stringify({stages:f.stages,details:f.details}).includes(secret),false);
});
test('successful response cannot pass while submit is held or turn its later failure into success',async()=>{
 const f=fixture(),held=deferred(),entered=deferred();const result=outcome(f.run('single',{submit:async button=>{await button.dblclick();entered.resolve();await held.promise;}}));await entered.promise;await nextTurn();assert.equal(result.settled,undefined);assert.equal(f.events.includes('take'),false);assert.deepEqual(f.secrets,[]);
 held.reject(f.failure);await result.done;assert.equal(result.error,f.failure);assert.equal(f.clears(),1);assert.equal(f.events.includes('take'),false);assert.equal(f.reads(),0);assert.equal(f.writes(),1);
});
test('completed submission cannot pass before the actual response succeeds',async()=>{
 const f=fixture(),response=delayedResponse(f);const result=outcome(f.run());await nextTurn();assert.equal(result.settled,undefined);assert.equal(f.events.includes('take'),false);assert.equal(f.clears(),0);assert.deepEqual(f.secrets,[]);
 response.resolve(f.response);await result.done;assert.equal(result.error,undefined);assert.equal(result.value.invitationSecret,secret);assert.deepEqual(f.stages,phases.map(phase=>invitationCreationStage('single',phase)));assert.equal(f.writes(),1);assert.equal(f.reads(),0);assert.equal(f.clears(),1);
});
test('synchronous submit-locator failure also observes a late response rejection',async()=>{
 const f=fixture(),response=delayedResponse(f),get=f.page.getByRole;f.page.getByRole=(role,options)=>{if(options.name==='Create invitation')throw f.failure;return get(role,options);};const result=outcome(f.run());await nextTurn();assert.equal(result.error,f.failure);assert.equal(result.settled,true);assert.equal(f.clears(),1);response.reject(new Error(secret));await nextTurn();assert.equal(f.writes(),0);assert.equal(f.reads(),0);assert.deepEqual(f.secrets,[]);
});
test('actual held-scenario cleanup releases and unregisters its route after early response failure',async()=>{
 const source=fs.readFileSync(new URL('./enrollment-browser.mjs',import.meta.url),'utf8');const start=source.indexOf("   const page=await pageAt();let release,entered;"),end=source.indexOf("   mark('public bootstrap export')",start);assert.ok(start>0&&end>start);
 const f=fixture(),response=delayedResponse(f),held=deferred(),entered=deferred();let routeHandler,continued=0,unregistered=0;
 f.page.route=async(pattern,handler)=>{assert.equal(pattern,'**/api/enrollment/invitations');routeHandler=handler;};
 f.page.unroute=async pattern=>{assert.equal(pattern,'**/api/enrollment/invitations');unregistered++;};
 const get=f.page.getByRole;f.page.getByRole=(role,options)=>{const button=get(role,options);if(options.name!=='Create invitation')return button;return {...button,async dblclick(){await button.dblclick();void routeHandler({async continue(){continued++;}});entered.resolve();await held.promise;}};};
 const expect=value=>({toBe(expected){assert.equal(value,expected);},async toBeDisabled(){}});
 const run=Function('pageAt','create','expect',`return (async()=>{${source.slice(start,end)}})();`);
 const result=outcome(run(async()=>f.page,(_page,invocation,submit)=>f.run(invocation,{submit}),expect));await entered.promise;assert.equal(continued,0);assert.equal(unregistered,0);
 response.reject(f.failure);await nextTurn();assert.equal(result.settled,true);assert.equal(result.error,f.failure);assert.equal(f.clears(),1);assert.equal(continued,1);assert.equal(unregistered,1);assert.deepEqual(f.secrets,[]);
 const stages=[...f.stages];held.resolve();await nextTurn();assert.equal(f.clears(),1);assert.equal(continued,1);assert.equal(unregistered,1);assert.deepEqual(f.stages,stages);assert.equal(f.writes(),1);assert.equal(f.reads(),0);
});
function terminalFixture({submit,status=200,committed='canceled',rendered='Canceled',label='Cancel invitation',failAt,message=secret,capture}={}){
 const source=fs.readFileSync(new URL('./enrollment-browser.mjs',import.meta.url),'utf8'),helper=source.slice(source.indexOf('async function terminate('),source.indexOf('\ntry{'));
 const pending=deferred(),events=[],stages=[],failure=new Error(message);let writes=0,reads=0,captures=0,statusReads=0;
 const fail=phase=>{if(failAt===phase)throw failure;};
 const request={failure:()=>({errorText:'net::ERR_ABORTED'}),url:()=>`http://127.0.0.1/${secret}`};
 const response={request:()=>request,status(){statusReads++;fail('status');return status;},async json(){reads++;fail('body');return {state:committed,privateValue:secret};}};
 const confirmation={getByRole(role,options){assert.equal(role,'button');assert.deepEqual(options,{name:'Confirm termination',exact:true});fail('submit locator');return {click(){events.push('submit');writes++;fail('submit');return submit?submit():Promise.resolve();}};}};
 const context=new EventEmitter(),browser=Object.assign(new EventEmitter(),{version:()=> '134.0.6998.0',isConnected:()=>true});
 const page=Object.assign(new EventEmitter(),{
  context:()=>context,viewportSize:()=>({width:1440,height:1000}),isClosed:()=>false,
  getByRole(role,options){
   if(role==='button'){assert.equal(options.name,label);return {async click(){events.push('open');fail('open');}};}
   if(role==='group'){assert.equal(options.name,'Confirm termination');return confirmation;}
   assert.equal(role,'dialog');assert.equal(options.name,'Review invitation');return {locator(selector){assert.equal(selector,'.enrollment-created-meta');return rendered;}};
  },
  waitForResponse(predicate){events.push('register');fail('registration');assert.equal(predicate({request:()=>({method:()=> 'POST'}),url:()=> 'http://127.0.0.1:19889/api/enrollment/invite_synthetic/terminate'}),true);return pending.promise;},
 });
 const expect=value=>({toBe(expected){assert.equal(value,expected);},async toBeVisible(){assert.equal(value,confirmation);fail('confirmation');},async toContainText(expected){events.push('rendered');fail('rendered');assert.equal(value,expected);},async toHaveCount(expected){assert.equal(value,confirmation);assert.equal(expected,0);fail('closed');events.push('closed');}});
 const diagnostics=createBrowserTransportDiagnostics(page,browser),transportDiagnostics={capture(...args){captures++;return capture?capture(...args):diagnostics.capture(...args);}};
 const extracted=Function('expect','mark','base','transportDiagnostics','let terminationTransportFailure=null;'+helper+';return {terminate,detail:()=>terminationTransportFailure};')(expect,value=>stages.push(value),'http://127.0.0.1:19889',transportDiagnostics);
 return {pending,response,request,page,context,browser,diagnostics,events,stages,failure,detail:extracted.detail,captures:()=>captures,statusReads:()=>statusReads,writes:()=>writes,reads:()=>reads,run:()=>extracted.terminate(page,label)};
}
for(const kind of ['synchronous','asynchronous'])test(`terminal ${kind} click failure observes the later response rejection`,async()=>{
 const failure=new Error(secret),f=terminalFixture({submit:()=>{if(kind==='synchronous')throw failure;return Promise.reject(failure);}}),result=outcome(f.run());await nextTurn();assert.equal(result.settled,true);assert.equal(result.error,failure);f.pending.reject(new Error(secret));await nextTurn();assert.equal(f.writes(),1);assert.equal(f.reads(),0);assert.equal(f.events.includes('rendered'),false);
});
for(const late of ['resolve','reject'])test(`terminal response failure rejects while click is held and observes late ${late}`,async()=>{
 const held=deferred(),f=terminalFixture({submit:()=>held.promise}),result=outcome(f.run());await nextTurn();f.pending.reject(f.failure);await nextTurn();assert.equal(result.settled,true);assert.equal(result.error,f.failure);assert.equal(f.reads(),0);const stages=[...f.stages];held[late](new Error(secret));await nextTurn();assert.deepEqual(f.stages,stages);assert.equal(f.writes(),1);assert.equal(f.events.includes('rendered'),false);
});
for(const first of ['response','submit'])test(`terminal ${first}-first success retains actual HTTP, committed and rendered checks`,async()=>{
 const held=deferred(),f=terminalFixture({submit:()=>held.promise}),result=outcome(f.run());await nextTurn();if(first==='response')f.pending.resolve(f.response);else held.resolve();await nextTurn();assert.equal(result.settled,undefined);assert.equal(f.reads(),0);assert.equal(f.events.includes('rendered'),false);if(first==='response')held.resolve();else f.pending.resolve(f.response);await result.done;assert.equal(result.error,undefined);assert.equal(f.writes(),1);assert.equal(f.reads(),1);assert.deepEqual(f.events,['open','register','submit','rendered','closed']);
});
for(const invalid of [{status:409},{committed:'rejected'},{rendered:'Not committed'}])test(`terminal acceptance rejects mismatched ${Object.keys(invalid)[0]}`,async()=>{
 const f=terminalFixture(invalid),result=outcome(f.run());await nextTurn();f.pending.resolve(f.response);await result.done;assert.ok(result.error);assert.equal(f.writes(),1);assert.equal(f.events.includes('closed'),false);
});

const terminalStages=['open termination confirmation','await committed termination response','submit termination','verify termination response status','read committed termination body','verify committed termination state','verify rendered terminal state'];
function safeTerminalEvidence(f){
 const report={stage:f.stages.at(-1),error:'Assertion failed; secret-bearing diagnostics intentionally withheld.',terminationTransportFailure:f.detail()};
 assert.ok(f.stages.every(stage=>terminalStages.includes(stage)));
 assert.equal(JSON.stringify(report).includes(secret),false);
 return report;
}
for(const [failAt,phase,writes,reads] of [
 ['open','open termination confirmation',0,0],['confirmation','open termination confirmation',0,0],
 ['registration','await committed termination response',0,0],['submit locator','submit termination',0,0],['submit','submit termination',1,0],
 ['status','verify termination response status',1,0],['body','read committed termination body',1,1],
 ['rendered','verify rendered terminal state',1,1],['closed','verify rendered terminal state',1,1],
])test(`terminal ${failAt} failure has a finite exact stage and preserves the original error`,async()=>{
 const f=terminalFixture({failAt}),result=outcome(f.run());f.pending.resolve(f.response);await result.done;
 assert.equal(result.error,f.failure);assert.equal(f.stages.at(-1),phase);assert.equal(f.writes(),writes);assert.equal(f.reads(),reads);assert.equal(f.captures(),1);
 assert.equal(f.detail().operation,failAt==='body'?'response-body':'other');safeTerminalEvidence(f);
});
for(const status of [401,409,429,503])test(`terminal HTTP ${status} remains a hard failure before the body read`,async()=>{
 const f=terminalFixture({status}),result=outcome(f.run());f.pending.resolve(f.response);await result.done;
 assert.ok(result.error);assert.equal(f.detail().httpStatus,status);assert.equal(f.statusReads(),1);assert.equal(f.stages.at(-1),'verify termination response status');assert.equal(f.writes(),1);assert.equal(f.reads(),0);assert.equal(f.events.includes('rendered'),false);safeTerminalEvidence(f);
});
test('terminal wrong committed state remains failure without exporting the body or state value',async()=>{
 const f=terminalFixture({committed:secret}),result=outcome(f.run());f.pending.resolve(f.response);await result.done;
 assert.ok(result.error);assert.equal(f.stages.at(-1),'verify committed termination state');assert.equal(f.writes(),1);assert.equal(f.reads(),1);assert.equal(f.events.includes('rendered'),false);safeTerminalEvidence(f);
});
test('terminal malformed JSON remains the original body-read failure',async()=>{
 const f=terminalFixture(),failure=new SyntaxError(secret);f.response.json=async()=>{throw failure;};const result=outcome(f.run());f.pending.resolve(f.response);await result.done;
 assert.equal(result.error,failure);assert.equal(f.stages.at(-1),'read committed termination body');assert.equal(f.detail().operation,'response-body');assert.equal(f.detail().category,'other');assert.equal(f.writes(),1);assert.equal(f.events.includes('rendered'),false);safeTerminalEvidence(f);
});
test('terminal transport snapshot is bounded and captured before cleanup, without a second body read',async()=>{
 const f=terminalFixture({failAt:'body',message:`Protocol error (Network.getResponseBody): No data found for resource with given identifier\n${secret}`});
 f.page.emit('requestfailed',f.request);const result=outcome(f.run());f.pending.resolve(f.response);await result.done;
 assert.equal(result.error,f.failure);assert.equal(f.reads(),1);assert.equal(f.writes(),1);assert.equal(f.captures(),1);
 assert.deepEqual(f.detail(),{operation:'response-body',category:'body-data-missing',pageClosed:false,pageCrashed:false,contextClosed:false,browserDisconnected:false,browserConnected:true,requestState:'failed',requestFailure:'aborted',configuredViewport:{width:1440,height:1000},preCaptureLayout:null,elapsedMs:null,browserVersion:'134.0.6998.0',httpStatus:200});
 const before=JSON.stringify(safeTerminalEvidence(f));f.page.emit('close');f.context.emit('close');f.browser.emit('disconnected');f.diagnostics.dispose();assert.equal(JSON.stringify(safeTerminalEvidence(f)),before);
});
for(const failAt of ['submit','body','rendered'])test(`terminal ${failAt} original error survives a throwing diagnostic`,async()=>{
 const f=terminalFixture({failAt,capture(){throw new Error(secret);}}),result=outcome(f.run());f.pending.resolve(f.response);await result.done;
 assert.equal(result.error,f.failure);assert.equal(f.captures(),1);assert.equal(f.detail(),null);assert.equal(f.writes(),1);safeTerminalEvidence(f);
});
for(const first of ['response','submit'])test(`terminal same-turn ${first}-first settlements retain the original Promise.all error and stage`,async()=>{
 const held=deferred(),f=terminalFixture({submit:()=>held.promise}),responseFailure=new Error(secret),submitFailure=new Error(secret),original=outcome(Promise.all([f.pending.promise,Promise.resolve().then(()=>held.promise)])),result=outcome(f.run());await nextTurn();
 if(first==='response'){f.pending.reject(responseFailure);held.reject(submitFailure);}else{held.reject(submitFailure);f.pending.reject(responseFailure);}
 await result.done;await original.done;assert.equal(result.error,original.error);assert.equal(f.stages.at(-1),original.error===responseFailure?'await committed termination response':'submit termination');assert.equal(f.captures(),1);assert.equal(f.writes(),1);assert.equal(f.reads(),0);safeTerminalEvidence(f);
});
for(const first of ['response','submit'])for(const late of ['resolve','reject'])test(`terminal ${first} failure cannot be relabeled by a late ${late} or emit a second snapshot`,async()=>{
 const held=deferred(),f=terminalFixture({submit:()=>held.promise}),result=outcome(f.run());await nextTurn();
 if(first==='response')f.pending.reject(f.failure);else held.reject(f.failure);
 await result.done;assert.equal(result.error,f.failure);assert.equal(f.stages.at(-1),first==='response'?'await committed termination response':'submit termination');const before=JSON.stringify({stages:f.stages,...safeTerminalEvidence(f)});
 if(first==='response')held[late](new Error(secret));else f.pending[late](late==='resolve'?f.response:new Error(secret));await nextTurn();await nextTurn();
 assert.equal(JSON.stringify({stages:f.stages,...safeTerminalEvidence(f)}),before);assert.equal(f.captures(),1);assert.equal(f.writes(),1);assert.equal(f.reads(),0);assert.equal(f.events.includes('rendered'),false);
});
for(const [label,committed,rendered] of [['Cancel invitation','canceled','Canceled'],['Reject','rejected','Rejected'],['Revoke identity','revoked','Revoked']])test(`terminal ${label} retains exact committed, rendered and dismissal assertions`,async()=>{
 const f=terminalFixture({label,committed,rendered}),result=outcome(f.run());f.pending.resolve(f.response);await result.done;
 assert.equal(result.error,undefined);assert.deepEqual(f.stages,terminalStages);assert.deepEqual(f.events,['open','register','submit','rendered','closed']);assert.equal(f.writes(),1);assert.equal(f.reads(),1);assert.equal(f.statusReads(),1);assert.equal(f.captures(),0);assert.equal(f.detail(),null);
});
test('terminal unsupported action cannot click or disclose its supplied value',async()=>{
 const f=terminalFixture({label:secret});await assert.rejects(f.run(),error=>error.message==='UNSUPPORTED_TEST_ACTION');assert.equal(f.writes(),0);assert.equal(f.reads(),0);assert.deepEqual(f.events,[]);assert.equal(f.captures(),0);
});
test('actual case reporting resets terminal evidence, withholds raw errors and cleans up after the snapshot',async()=>{
 const source=fs.readFileSync(new URL('./enrollment-browser.mjs',import.meta.url),'utf8'),check=source.slice(source.indexOf('async function check('),source.indexOf('async function terminate('));
 const events=[],logs=[],detail={operation:'response-body',category:'body-data-missing'};
 const f=Function('events','logs',`
  const includeQuarantined=true,quarantinedNames=new Set(),results=[],secrets=[];
  let currentTest='',stage='',creationTransportFailure=null,creationPrimaryFailure=null,terminationTransportFailure=null;
  let transportDiagnostics,context;
  const console={log:value=>logs.push(value)};
  async function start(){events.push('start');transportDiagnostics={dispose(){events.push('dispose');}};context={async close(){events.push('close');}};}
  async function stop(){events.push('stop');}
  ${check}
  return {check,results,snapshot(value){events.push('capture');terminationTransportFailure=value;stage='read committed termination body';}};
 `)(events,logs);
 await f.check('inert first',async()=>{f.snapshot(detail);throw new Error(secret);});
 await f.check('inert second',async()=>{throw new Error(secret);});
 assert.equal(f.results.length,2);assert.equal(f.results[0].status,'FAIL');assert.equal(f.results[1].status,'FAIL');assert.deepEqual(f.results[0].terminationTransportFailure,detail);assert.equal('terminationTransportFailure' in f.results[1],false);
 assert.deepEqual(events,['start','capture','dispose','close','stop','start','dispose','close','stop']);assert.equal(JSON.stringify({results:f.results,logs}).includes(secret),false);
});
test('terminal diagnostics retain the existing selected inert suite and fail-closed full browser gate',()=>{
 const source=fs.readFileSync(new URL('./enrollment-browser.mjs',import.meta.url),'utf8'),workflow=fs.readFileSync(new URL('../../.github/workflows/validate.yml',import.meta.url),'utf8');
 const manifest=JSON.parse(fs.readFileSync(new URL('./inert-suites.json',import.meta.url),'utf8'));
 assert.ok(manifest.entries.includes('enrollment-create-diagnostics.test.mjs'));assert.ok(workflow.split('\n').some(line=>line.trim().startsWith('node --test ')&&line.split(/\s+/).includes('tests/e2e-review/enrollment-create-diagnostics.test.mjs')));
 assert.equal([...source.matchAll(/await check\('/g)].length,13);assert.match(source,/creationTransportFailure=null;creationPrimaryFailure=null;terminationTransportFailure=null/);
 assert.match(workflow,/r.summary,\{passed:13,failed:0,skipped:0,fullEnrollmentAcceptance:true,setupFailure:false\}/);
 const helper=source.slice(source.indexOf('async function terminate('),source.indexOf('\ntry{'));
 assert.doesNotMatch(helper,/setTimeout|setInterval|waitForTimeout|\.clone\(|page\.evaluate|console\.|response\.(?:body|text|finished)\(/);
 assert.equal([...helper.matchAll(/response\.json\(/g)].length,1);assert.match(helper,/\[response\]=await Promise\.all\(\[responsePending,clickPending\]\)/);
 assert.match(source,/process\.exitCode=fatal\|\|runtimeErrorCount\|\|results\.some\(r=>r\.status==='FAIL'\)\?1:0/);
});

test('terminal diagnostic status is only a finite HTTP integer, never a coerced response value',async()=>{
 const hostile={toString(){throw new Error(secret);}};
 for(const status of [100,599,0,99,600,200.5,Infinity,NaN,secret,null,undefined,hostile]){
  const f=terminalFixture();f.response.status=()=>status;const result=outcome(f.run());f.pending.resolve(f.response);await result.done;
  assert.ok(result.error);assert.equal(f.stages.at(-1),'verify termination response status');assert.equal(f.detail().httpStatus,Number.isInteger(status)&&status>=100&&status<=599?status:null);assert.equal(f.reads(),0);assert.equal(f.writes(),1);safeTerminalEvidence(f);
 }
});
test('terminal missing or throwing status has no invented diagnostic HTTP result',async()=>{
 for(const failAt of ['registration','submit','status']){
  const f=terminalFixture({failAt}),result=outcome(f.run());f.pending.resolve(f.response);await result.done;
  assert.equal(result.error,f.failure);assert.equal(f.detail().httpStatus,null);assert.equal(f.statusReads(),failAt==='status'?1:0);safeTerminalEvidence(f);
 }
});
