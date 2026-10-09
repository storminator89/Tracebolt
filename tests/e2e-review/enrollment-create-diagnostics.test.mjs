import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import {createBrowserInvitation,invitationCreationStage} from './enrollment-create-diagnostics.mjs';

const privateValue='INERT_PRIVATE_RESPONSE_ERROR_URL_AND_SECRET_SENTINEL';
const phases=['open dialog','submit','await response','response status','parse response','response schema','secret type','masked field'];
function fixture(failAt){
 const stages=[],events=[],secrets=[];
 let writes=0,reads=0,predicate;
 const created={schemaVersion:'tracebolt.enrollment-invitation.v2',invitationSecret:privateValue};
 const fail=phase=>{if(failAt===phase)throw new Error(privateValue);};
 const response={status(){events.push('status');return failAt==='response status'?403:201;},async json(){reads++;events.push('json');fail('parse response');return failAt==='response schema'?{...created,schemaVersion:privateValue}:failAt==='secret type'?{...created,invitationSecret:{privateValue}}:created;}};
 const page={
  getByRole(role,options){
   assert.equal(role,'button');assert.equal(options.exact,true);
   assert.ok(['Add device','Create invitation'].includes(options.name));
   return {async click(){if(options.name==='Add device'){events.push('open');fail('open dialog');}else{writes++;events.push('submit');fail('submit');}}};
  },
  waitForResponse(match){events.push('register');predicate=match;return failAt==='await response'?new Promise((resolve,reject)=>setImmediate(()=>reject(new Error(privateValue)))):Promise.resolve(response);},
  getByLabel(label,options){assert.equal(label,'One-time invitation secret');assert.deepEqual(options,{exact:true});return {inertInput:true};},
 };
 const expect=value=>({toBe(expected){assert.equal(value,expected);},async toHaveAttribute(name,expected){assert.deepEqual(value,{inertInput:true});assert.equal(name,'type');assert.equal(expected,'password');events.push('mask');fail('masked field');}});
 return {stages,events,secrets,created,run:invocation=>createBrowserInvitation(page,{base:'http://127.0.0.1:19889',mark:stage=>stages.push(stage),expect,secrets,invocation}),writes:()=>writes,reads:()=>reads,predicate:()=>predicate};
}

test('stage labels are a closed vocabulary, with no string coercion or private values',()=>{
 const hostile={toString(){throw new Error(privateValue);}};
 for(const invocation of ['single','first','second',privateValue,hostile,null,Infinity]){
  for(const phase of [...phases,privateValue,hostile,null,Infinity]){
   const label=invitationCreationStage(invocation,phase);
   assert.match(label,/^create invitation (single|first|second): (open dialog|submit|await response|response status|parse response|response schema|secret type|masked field|unknown)$/);
   assert.equal(label.includes(privateValue),false);
  }
 }
});

for(const invocation of ['single','first','second'])test(`successful ${invocation} creation preserves one write, pre-click waiter and masking`,async()=>{
 const f=fixture();assert.equal(await f.run(invocation),f.created);
 assert.deepEqual(f.stages,phases.map(phase=>invitationCreationStage(invocation,phase)));
 assert.deepEqual(f.events,['open','register','submit','status','json','mask']);
 assert.equal(f.writes(),1);assert.deepEqual(f.secrets,[privateValue]);
 const match=f.predicate();const response=(url,method)=>({url:()=>url,request:()=>({method:()=>method})});
 assert.equal(match(response('http://127.0.0.1:19889/api/enrollment/invitations','POST')),true);
 assert.equal(match(response('http://127.0.0.1:19889/api/enrollment/invitations','GET')),false);
 assert.equal(match(response('http://127.0.0.1:19889/api/enrollment/invitations/other','POST')),false);
 assert.equal(match(response('http://another.invalid/api/enrollment/invitations','POST')),false);
});

for(const invocation of ['first','second'])for(const phase of phases)test(`${invocation} failure at ${phase} remains a failure with finite diagnostics and no retry`,async()=>{
 const f=fixture(phase);await assert.rejects(f.run(invocation));
 assert.equal(f.stages.at(-1),invitationCreationStage(invocation,phase));
 assert.deepEqual(f.stages,phases.slice(0,phases.indexOf(phase)+1).map(value=>invitationCreationStage(invocation,value)));
 assert.equal(JSON.stringify(f.stages).includes(privateValue),false);
 assert.equal(f.writes(),phase==='open dialog'?0:1);
 if(phase==='response status')assert.equal(f.reads(),0);
 assert.deepEqual(f.secrets,phase==='masked field'?[privateValue]:[]);
});

test('browser runner wires distinct route calls and retains redacted failure reporting',()=>{
 const source=fs.readFileSync(new URL('./enrollment-browser.mjs',import.meta.url),'utf8');
 assert.match(source,/async function create\(page,invocation='single'\)\{return createBrowserInvitation\(page,\{base,mark,expect,secrets,invocation\}\);\}/);
 const begin=source.indexOf("await check('Route dismissal and protected-session loss");
 const scenario=source.slice(begin,source.indexOf('\n  });',begin));
 assert.equal((scenario.match(/create\(page,'first'\)/g)||[]).length,1);
 assert.equal((scenario.match(/create\(page,'second'\)/g)||[]).length,1);
 assert.ok(scenario.indexOf("create(page,'first')")<scenario.indexOf("location.hash='/settings'"));
 assert.ok(scenario.indexOf("page.goto(`${base}/#/devices`)")<scenario.indexOf("create(page,'second')"));
 assert.match(scenario,/await expect\(page\.getByRole\('dialog'\)\)\.toHaveCount\(0\)/);
 assert.match(scenario,/await expect\(page\.locator\('\.app-shell'\)\)\.toHaveCount\(0\)/);
 assert.match(scenario,/await checkClean\(page\)/);
 assert.match(source,/catch\{results\.push\(\{name,status:'FAIL',stage,durationMs:Date\.now\(\)-begin,error:'Assertion failed; secret-bearing diagnostics intentionally withheld\.'/);
 assert.match(source,/process\.exitCode=fatal\|\|runtimeErrorCount\|\|results\.some\(r=>r\.status==='FAIL'\)\?1:0/);
});
