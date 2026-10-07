import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createPackageUpdatesFixture,packageUpdatesWireFixtures,packageUpdatesNamedSession,packageUpdatesRoute,packageUpdatesCaseName,packageUpdatesFixtureDisclosure,packageUpdatesFailureStage} from './package-updates-browser.mjs';
const base='http://127.0.0.1:19886',anchor='2026-10-07T01:00:00.000Z',requestId='update_'+'c'.repeat(32);
const read=path=>fs.readFileSync(new URL(path,import.meta.url),'utf8');
const prepare=f=>({requestId,packages:f.selection});
const approve=f=>({requestId,previewDigest:f.project().preview.digest});
function session(f,now){return {mode:'lan',transport:'http',insecureTestMode:true,transportWarning:'unencrypted_lan_test',authenticationRequired:true,authenticated:true,csrfToken:'public-fixture-csrf',serverNow:new Date(now).toISOString(),expiresAt:new Date(Date.parse(anchor)+60000).toISOString(),expiresInSeconds:55,loginMode:'shared',actorId:null,capabilities:['read']};}
function setup(){let current=Date.parse(anchor)+5000;const fixture=createPackageUpdatesFixture({anchor,now:()=>current}),state={unexpected:[],external:[],loginRequests:0,namedReads:0};const handle=packageUpdatesRoute({base,fixture,state,now:()=>current});return {fixture,state,handle,now:()=>current,advance:value=>{current+=value;}};}
async function route(s,path,{method='GET',body=null,csrf='public-fixture-csrf',contentType='application/json',auth}={}){
 const calls=[],raw=body===null?null:typeof body==='string'?body:JSON.stringify(body);
 await s.handle({request:()=>({url:()=>path.startsWith('http')?path:base+path,method:()=>method,postData:()=>raw,postDataJSON:()=>JSON.parse(raw),allHeaders:async()=>({'content-type':contentType,'x-csrf-token':csrf})}),fetch:async()=>{calls.push({kind:'fetch'});const value=path==='/api/session'?{csrfToken:'public-fixture-csrf'}:auth??session(s.fixture,s.now());return {status:()=>200,json:async()=>value};},fulfill:async value=>calls.push({kind:'fulfill',...value}),continue:async()=>calls.push({kind:'continue'}),abort:async reason=>calls.push({kind:'abort',reason})});return calls;
}
const last=value=>value.at(-1);
async function preflight(s){await route(s,s.fixture.prefix);await route(s,'/api/auth/session');await route(s,'/api/session');}

test('public Go projections remain unchanged and every exposed workflow/inventory view passes production TypeScript decoders',()=>{
 const raw=packageUpdatesWireFixtures(),f=createPackageUpdatesFixture({anchor}),offset=Date.parse(anchor)-Date.parse(raw.idle.serverNow);
 assert.deepEqual(raw,JSON.parse(read('../../web/src/package-update-go-fixtures.json')));
 for(const name of ['unavailable','idle','preview_ready','needs_intervention']){
  const value=f.project(name);assert.notEqual(value.executionMode,'native');assert.equal(Date.parse(value.serverNow)-Date.parse(raw[name].serverNow),offset);
  if(value.preview){assert.deepEqual(value.preview.items,raw[name].preview.items);assert.equal(value.preview.digest,raw[name].preview.digest);assert.equal(value.preview.actorId,raw[name].preview.actorId);assert.equal(value.preview.transportProfile,'disposable-http-test');assert.equal(Date.parse(value.preview.expiresAt)-Date.parse(raw[name].preview.expiresAt),offset);assert.equal(Date.parse(value.preview.expiresAt)-Date.parse(value.job.createdAt),60000);}
 }
 assert.equal(f.complete.status,'not_configured');assert.equal(f.complete.complete,null);assert.equal(f.cached.latest.metadata.refresh,'not_attempted');assert.deepEqual(f.cached.latest.items.map(({name,architecture})=>({name,architecture})),f.selection);
 assert.equal(f.cached.latest.items[0].candidateVersion,raw.preview_ready.preview.items[0].toVersion);
 assert.throws(()=>f.project('native_succeeded'));raw.preview_ready.preview.items[0].name='changed';assert.equal(packageUpdatesWireFixtures().preview_ready.preview.items[0].name,'sample-bin');
});

test('receiver keeps unavailable explicit, prepares only exact identities, and binds a single unknown result to request and digest',()=>{
 const f=createPackageUpdatesFixture();assert.equal(f.phase,'unavailable');assert.throws(()=>f.handle('POST',f.prefix+'/prepare',prepare(f)));f.loadSimulation();
 for(const body of [{...prepare(f),extra:true},{...prepare(f),packages:[{name:'other',architecture:'amd64'}]},{...prepare(f),packages:[{...f.selection[0],toVersion:'1.0-2'}]},{...prepare(f),requestId:'update_'+'0'.repeat(32)},{...prepare(f),packages:[...f.selection,...f.selection]}])assert.throws(()=>f.handle('POST',f.prefix+'/prepare',body));
 const review=f.handle('POST',f.prefix+'/prepare',prepare(f));assert.equal(review.job.state,'preview_ready');assert.equal(review.preview.requestId,requestId);assert.equal(f.counts.prepare,1);
 for(const body of [{...approve(f),extra:true},{...approve(f),requestId:'update_'+'d'.repeat(32)},{...approve(f),previewDigest:'sha256:'+'0'.repeat(64)}])assert.throws(()=>f.handle('POST',f.prefix+'/approve',body));
 const unknown=f.handle('POST',f.prefix+'/approve',approve(f));assert.equal(unknown.job.state,'needs_intervention');assert.equal(unknown.available,false);assert.equal(unknown.job.result.packages[0].outcome,'unknown');assert.equal(unknown.job.result.packages[0].observedVersion,null);assert.equal(unknown.job.result.reboot.state,'unknown');assert.equal(unknown.job.result.reboot.source,'simulation');assert.equal(f.counts.approve,1);
 assert.deepEqual(f.handle('GET',`${f.prefix}/jobs/${requestId}`,null),unknown);
 for(const path of [f.prefix+'/prepare',f.prefix+'/approve',f.prefix+'/execute',f.prefix+'/install'])assert.throws(()=>f.handle('POST',path,prepare(f)));
 assert.throws(()=>f.handle('GET',`${f.prefix}/jobs/update_${'d'.repeat(32)}`,null));assert.throws(()=>f.loadSimulation());
});

test('original preview expiry is never renewed for approval or another request',()=>{
 let now=Date.parse(anchor)+5000;const f=createPackageUpdatesFixture({anchor,now:()=>now});f.loadSimulation();const reviewed=f.handle('POST',f.prefix+'/prepare',prepare(f));now=Date.parse(reviewed.preview.expiresAt);
 assert.throws(()=>f.handle('POST',f.prefix+'/approve',approve(f)));assert.equal(f.counts.approve,0);assert.deepEqual(f.handle('GET',f.prefix,null).preview,reviewed.preview);assert.throws(()=>f.handle('POST',f.prefix+'/prepare',{...prepare(f),requestId:'update_'+'d'.repeat(32)}));
});

test('named capabilities are a fixture-only display proxy preserving actual session/CSRF clocks and expiry',()=>{
 const s=setup(),original=session(s.fixture,s.now()),proxy=packageUpdatesNamedSession(original,s.fixture.actor);
 assert.deepEqual(proxy,{...original,loginMode:'named',actorId:s.fixture.actor,capabilities:['read','plan_updates','execute_updates']});assert.equal(original.loginMode,'shared');
 for(const change of [{authenticated:false},{transport:'https'},{insecureTestMode:false},{csrfToken:''},{expiresAt:original.serverNow}])assert.throws(()=>packageUpdatesNamedSession({...original,...change},s.fixture.actor));
});

test('all package writes terminate in exact fixtures after fresh status, named access and one-use live CSRF reads',async()=>{
 const s=setup(),f=s.fixture;f.loadSimulation();await preflight(s);
 const prepared=await route(s,f.prefix+'/prepare',{method:'POST',body:prepare(f)});assert.equal(last(prepared).kind,'fulfill');assert.equal(prepared.some(x=>['continue','fetch'].includes(x.kind)),false);assert.equal(JSON.parse(last(prepared).body).job.state,'preview_ready');
 assert.equal(last(await route(s,f.prefix+'/approve',{method:'POST',body:approve(f)})).kind,'abort');
 await preflight(s);const approved=await route(s,f.prefix+'/approve',{method:'POST',body:approve(f)});assert.equal(last(approved).kind,'fulfill');assert.equal(approved.some(x=>['continue','fetch'].includes(x.kind)),false);assert.equal(JSON.parse(last(approved).body).job.result.reason,'runner_state_unknown');assert.deepEqual(f.counts,{reads:2,prepare:1,approve:1});
});

test('wrong CSRF, changed status order, expired admission, expired sessions and extra fields abort before any synthetic write',async()=>{
 for(const scenario of ['csrf','content-type','status-order','deadline','session-expiry','extra','query']){
  const s=setup(),f=s.fixture;f.loadSimulation();await preflight(s);const options={method:'POST',body:prepare(f)};let path=f.prefix+'/prepare';
  if(scenario==='csrf')options.csrf='different';if(scenario==='content-type')options.contentType='text/plain';if(scenario==='status-order')await route(s,f.prefix);if(scenario==='deadline')s.advance(10000);if(scenario==='session-expiry')s.advance(55000);if(scenario==='extra')options.body={...prepare(f),command:'forbidden'};if(scenario==='query')path+='?force=true';
  const calls=await route(s,path,options);assert.equal(last(calls).kind,'abort',scenario);assert.equal(calls.some(x=>['continue','fetch'].includes(x.kind)),false,scenario);assert.equal(f.counts.prepare,0,scenario);
 }
});

test('unexpected, external and native/action/provider requests always abort; only one login and same-origin static GETs pass',async()=>{
 const s=setup(),f=s.fixture;
 for(const [path,method,body] of [[f.prefix+'/execute','POST',{}],[f.prefix+'/install','POST',{}],[f.prefix+'/prepare','POST',prepare(f)],['/api/ai/config','POST',{}],['/api/enrollment','POST',{}],[`/api/devices/${f.device}/service-actions/approve`,'POST',{}],['/api/unrecognized','GET',null],['/api/auth/logout','POST',{}],['https://example.invalid/api/session','GET',null],[f.prefix+'?native=true','GET',null]]){
  const calls=await route(s,path,{method,body});assert.equal(last(calls).kind,'abort');assert.equal(calls.some(x=>['continue','fetch'].includes(x.kind)),false);
 }
 assert.equal(last(await route(s,'/assets/index.js')).kind,'continue');assert.equal(last(await route(s,'/api/auth/login',{method:'POST',body:{}})).kind,'continue');assert.equal(last(await route(s,'/api/auth/login',{method:'POST',body:{}})).kind,'abort');assert.equal(f.counts.prepare,0);assert.equal(f.counts.approve,0);
});

test('one additive diagnostic hosted case discloses projections and covers localized desktop/mobile unavailable, selection, review and unknown screenshots',()=>{
 const runner=read('./lan-browser.mjs'),source=read('./package-updates-browser.mjs');assert.equal((runner.match(/await check\(/g)||[]).length,25);assert.equal((runner.match(/await check\(packageUpdatesCaseName/g)||[]).length,1);assert.match(runner,/name===packageUpdatesCaseName\?\{stage:packageUpdatesFailureStage\(\)\}/);assert.match(read('../../.github/workflows/validate.yml'),/node --test .*package-updates-fixtures.test.mjs/);
 assert.match(packageUpdatesCaseName,/Synthetic/);assert.equal(packageUpdatesFailureStage(),'setup');assert.match(packageUpdatesFixtureDisclosure,/Named operator capabilities are an intercepted display proxy only/);assert.match(packageUpdatesFixtureDisclosure,/No actual preparation, install, grant, provider request, key entry or native operation/);assert.match(packageUpdatesFixtureDisclosure,/No native acceptance or signed-plan proof/);
 for(const name of ['unavailable','selection','review','unknown'])assert.ok(source.includes(`gallery('${name}'`));assert.match(source,/for\(const locale of \['en','de'\]\)for\(const width of \[1440,390\]\)/);assert.match(source,/synthetic-package-capture-label/);assert.match(source,/input\[type="password"\]/);assert.match(source,/headers\['x-csrf-token'\]===csrf/);assert.doesNotMatch(source,/ignoreHTTPSErrors|chromium\.launch|child_process|execFile|spawn\(/);
});
