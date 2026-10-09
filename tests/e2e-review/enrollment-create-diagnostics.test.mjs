import assert from 'node:assert/strict';
import fs from 'node:fs';
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
  getByRole(role,{name,exact}){assert.equal(role,'button');assert.equal(exact,true);return {async click(){if(name==='Add device'){events.push('open');if(failAt==='open dialog')throw failure;}else{assert.equal(name,'Create invitation');events.push('submit');writes++;if(failAt==='submit')throw failure;}}};},
  waitForResponse(predicate){events.push('register');assert.equal(predicate({url:()=> 'http://127.0.0.1:19889/api/enrollment/invitations',request:()=>({method:()=> 'POST'})}),true);return failAt==='await response'?new Promise((resolve,reject)=>setImmediate(()=>reject(failure))):Promise.resolve(response);},
  async evaluate(fn,arg){const previous=globalThis.window;try{globalThis.window={__traceboltEnrollmentBody:observer};return await fn(arg);}finally{if(previous===undefined)delete globalThis.window;else globalThis.window=previous;}},
  getByLabel(name,{exact}){assert.equal(name,'One-time invitation secret');assert.equal(exact,true);return {async inputValue(){return failAt==='masked value'?'different':secret;}};},
 };
 const expect=value=>({toBe(expected){assert.equal(value,expected);},async toHaveAttribute(name,expected){assert.equal(name,'type');assert.equal(expected,'password');events.push('mask');if(failAt==='masked field')throw failure;}});
 expect.poll=callback=>({not:{async toMatch(pattern){if(failAt==='await primary reader')throw failure;assert.doesNotMatch(await callback(),pattern);}}});
 return {stages,events,secrets,details,observer,response,failure,run:(invocation='single',extra={})=>createBrowserInvitation(page,{base:'http://127.0.0.1:19889',mark:value=>stages.push(value),expect,secrets,invocation,recordPrimaryFailure:value=>details.push(value),...extra}),writes:()=>writes,clears:()=>clears,reads:()=>reads};
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
