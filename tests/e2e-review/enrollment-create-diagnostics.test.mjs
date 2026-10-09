import assert from 'node:assert/strict';
import fs from 'node:fs';
import {EventEmitter} from 'node:events';
import {createBrowserTransportDiagnostics} from './browser-transport-diagnostics.mjs';
import test from 'node:test';
import {createBrowserInvitation,invitationCreationStage} from './enrollment-create-diagnostics.mjs';

const privateValue='INERT_PRIVATE_RESPONSE_ERROR_URL_AND_SECRET_SENTINEL';
const phases=['open dialog','submit','await response','response status','retrieve response bytes','decode response JSON','response schema','secret type','masked field'];
function fixture(failAt){
 const stages=[],events=[],secrets=[];
 let writes=0,reads=0,predicate;
 const created={schemaVersion:'tracebolt.enrollment-invitation.v2',invitationSecret:privateValue};
 const fail=phase=>{if(failAt===phase)throw new Error(privateValue);};
 const response={status(){events.push('status');return failAt==='response status'?403:201;},async body(){reads++;events.push('body');fail('retrieve response bytes');return Buffer.from(failAt==='decode response JSON'?privateValue:JSON.stringify(failAt==='response schema'?{...created,schemaVersion:privateValue}:failAt==='secret type'?{...created,invitationSecret:{privateValue}}:created));}};
 const page=Object.assign(new EventEmitter(),{
  getByRole(role,options){
   assert.equal(role,'button');assert.equal(options.exact,true);
   assert.ok(['Add device','Create invitation'].includes(options.name));
   return {async click(){if(options.name==='Add device'){events.push('open');fail('open dialog');}else{writes++;events.push('submit');fail('submit');}}};
  },
  waitForResponse(match){events.push('register');predicate=match;return failAt==='await response'?new Promise((resolve,reject)=>setImmediate(()=>reject(new Error(privateValue)))):Promise.resolve(response);},
  getByLabel(label,options){assert.equal(label,'One-time invitation secret');assert.deepEqual(options,{exact:true});return {inertInput:true};},
 });
 const expect=value=>({toBe(expected){assert.equal(value,expected);},async toHaveAttribute(name,expected){assert.deepEqual(value,{inertInput:true});assert.equal(name,'type');assert.equal(expected,'password');events.push('mask');fail('masked field');}});
 return {page,response,stages,events,secrets,created,run:(invocation,extra={})=>createBrowserInvitation(page,{base:'http://127.0.0.1:19889',mark:stage=>stages.push(stage),expect,secrets,invocation,...extra}),writes:()=>writes,reads:()=>reads,predicate:()=>predicate};
}

test('stage labels are a closed vocabulary, with no string coercion or private values',()=>{
 const hostile={toString(){throw new Error(privateValue);}};
 for(const invocation of ['single','first','second',privateValue,hostile,null,Infinity]){
  for(const phase of [...phases,privateValue,hostile,null,Infinity]){
   const label=invitationCreationStage(invocation,phase);
   assert.match(label,/^create invitation (single|first|second): (open dialog|submit|await response|response status|retrieve response bytes|decode response JSON|response schema|secret type|masked field|unknown)$/);
   assert.equal(label.includes(privateValue),false);
  }
 }
});

for(const invocation of ['single','first','second'])test(`successful ${invocation} creation preserves one write, pre-click waiter and masking`,async()=>{
 const f=fixture();assert.deepEqual(await f.run(invocation),f.created);
 assert.deepEqual(f.stages,phases.map(phase=>invitationCreationStage(invocation,phase)));
 assert.deepEqual(f.events,['open','register','submit','status','body','mask']);
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
 assert.match(source,/async function create\(page,invocation='single'\)\{return createBrowserInvitation\(page,\{base,mark,expect,secrets,invocation,transportDiagnostics,recordTransportFailure:detail=>\{creationTransportFailure=detail;\}\}\);\}/);
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

function observe(f){
 const context=new EventEmitter(),browser=new EventEmitter(),request={failure:()=>null};
 Object.assign(browser,{isConnected:()=>true,version:()=> '145.0.7632.6'});
 Object.assign(f.page,{context:()=>context,isClosed:()=>false,viewportSize:()=>({width:1440,height:1000})});
 f.response.request=()=>request;
 return {context,browser,request,diagnostics:createBrowserTransportDiagnostics(f.page,browser)};
}

for(const [message,category] of [
 ['Protocol error (Network.getResponseBody): No resource with given identifier found','body-resource-missing'],
 ['Protocol error (Network.getResponseBody): No data found for resource with given identifier','body-data-missing'],
 ['Protocol error (Network.getResponseBody): Request content was evicted from inspector cache','body-buffer-evicted'],
 ['Protocol error (Network.getResponseBody): private detail','body-protocol-other'],
 ['Target page, context or browser has been closed','target-closed'],
 ['Target crashed','target-crashed'],
 [privateValue,'other'],
])test(`retrieval failure records ${category} without raw data, extra reads or mutation replay`,async()=>{
 const f=fixture(),o=observe(f),original=new Error(message+'\n'+privateValue),details=[];
 let reads=0;
 f.response.body=async()=>{reads++;f.page.emit('requestfinished',o.request);throw original;};
 await assert.rejects(f.run('second',{transportDiagnostics:o.diagnostics,recordTransportFailure:value=>details.push(value)}),error=>error===original);
 assert.equal(reads,1);assert.equal(f.writes(),1);assert.deepEqual(f.secrets,[]);
 assert.equal(f.stages.at(-1),'create invitation second: retrieve response bytes');
 assert.equal(details.length,1);assert.equal(details[0].operation,'response-body');assert.equal(details[0].category,category);
 assert.equal(details[0].requestState,'finished');assert.equal(details[0].requestFailure,'none');
 assert.equal(details[0].pageClosed,false);assert.equal(details[0].browserConnected,true);
 assert.equal(JSON.stringify(details).includes(privateValue),false);
 f.page.emit('close');o.context.emit('close');o.browser.emit('disconnected');
 assert.equal(details[0].pageClosed,false);assert.equal(details[0].contextClosed,false);assert.equal(details[0].browserDisconnected,false);
 o.diagnostics.dispose();for(const target of [f.page,o.context,o.browser])assert.deepEqual(target.eventNames(),[]);
});

test('request failure snapshot belongs to the creation response and precedes teardown',async()=>{
 const f=fixture(),o=observe(f),original=new Error(privateValue),details=[];
 o.request.failure=()=>({errorText:'net::ERR_ABORTED'});
 f.response.body=async()=>{f.page.emit('requestfailed',o.request);throw original;};
 await assert.rejects(f.run('first',{transportDiagnostics:o.diagnostics,recordTransportFailure:value=>details.push(value)}),error=>error===original);
 assert.equal(details[0].requestState,'failed');assert.equal(details[0].requestFailure,'aborted');
 assert.equal(details[0].category,'other');assert.equal(details[0].pageClosed,false);
 assert.equal(f.writes(),1);o.diagnostics.dispose();
});

test('malformed or empty JSON stays a decode failure without transport misclassification',async()=>{
 for(const body of ['',privateValue,'{"invitationSecret":"'+privateValue+'",']){
  const f=fixture(),details=[];let reads=0;
  f.response.body=async()=>{reads++;return Buffer.from(body);};
  await assert.rejects(f.run('first',{transportDiagnostics:{capture(){throw new Error('must not capture');}},recordTransportFailure:value=>details.push(value)}),SyntaxError);
  assert.equal(f.stages.at(-1),'create invitation first: decode response JSON');
  assert.deepEqual(details,[]);assert.deepEqual(f.secrets,[]);assert.equal(reads,1);assert.equal(f.writes(),1);
 }
});

test('diagnostic capture or recording errors cannot mask the original body failure',async()=>{
 const original=new Error(privateValue);
 for(const transportDiagnostics of [undefined,{capture(){throw new Error('capture '+privateValue);}},{capture(){return {category:'other'};}}]){
  const f=fixture();let reads=0;
  f.response.body=async()=>{reads++;throw original;};
  await assert.rejects(f.run('single',{transportDiagnostics,recordTransportFailure(){throw new Error('record '+privateValue);}}),error=>error===original);
  assert.equal(reads,1);assert.equal(f.writes(),1);assert.equal(f.stages.at(-1),'create invitation single: retrieve response bytes');
 }
});

test('success never emits transport diagnostics and keeps the same private response',async()=>{
 const f=fixture(),details=[];
 assert.deepEqual(await f.run('single',{transportDiagnostics:{capture(){throw new Error('must not capture');}},recordTransportFailure:value=>details.push(value)}),f.created);
 assert.deepEqual(details,[]);assert.equal(f.reads(),1);assert.equal(f.writes(),1);assert.deepEqual(f.secrets,[privateValue]);
});

test('runner scopes transport snapshots per case and removes passive monitors before cleanup',()=>{
 const source=fs.readFileSync(new URL('./enrollment-browser.mjs',import.meta.url),'utf8');
 assert.match(source,/transportDiagnostics=createBrowserTransportDiagnostics\(page,browser\)/);
 assert.match(source,/currentTest=name;stage='fixture setup';creationTransportFailure=null/);
 assert.match(source,/creationTransportFailure\?\{transportFailure:creationTransportFailure\}:\{\}/);
 assert.match(source,/finally\{transportDiagnostics\?\.dispose\(\);transportDiagnostics=null;if\(context\)await context.close\(\)/);
 const helper=fs.readFileSync(new URL('./enrollment-create-diagnostics.mjs',import.meta.url),'utf8');
 assert.equal((helper.match(/await response\.body\(\)/g)||[]).length,1);
 assert.match(helper,/throw error;\n \}\n step\('decode response JSON'\)/);
 assert.doesNotMatch(helper,/console\.|response\.finished\(|setTimeout|setInterval|\.evaluate\(|\.headers\(|\.postData\(|\.text\(|\.json\(/);
});
