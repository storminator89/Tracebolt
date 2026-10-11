/** Inert controller and browser-contract checks only. No browser/server launch. */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createWindowsServiceActionsFixture,windowsServiceActionsRoute,exerciseWindowsServiceActions,windowsServiceActionsDisclosure,windowsServiceActionsCaseName,requireWindowsServiceActionsEvidence} from './windows-service-actions-browser.mjs';
const base='http://127.0.0.1:19890';
const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8');
function setup(){
 const fixture=createWindowsServiceActionsFixture(),state={blocked:[],external:[]},handler=windowsServiceActionsRoute({base,fixture,state}),prefix='/api/devices/'+fixture.device.id;
 const invoke=async(path,{method='GET',raw=null,headers={},origin=base}={})=>{let result;await handler({request:()=>({url:()=>origin+path,method:()=>method,postData:()=>raw,headers:()=>headers}),fulfill:async value=>{result={...value,value:JSON.parse(value.body)};},abort:async value=>{result={abort:value};},continue:async()=>{result={continued:true};}});return result;};
 const headers={'x-csrf-token':fixture.session.csrfToken,origin:base,'content-type':'application/json'};
 return {fixture,state,invoke,prefix,headers,action:prefix+'/windows-service-actions'};
}
test('existing Go vectors drive exact review, one synthetic approval and immutable saved result across reads',async()=>{
 const f=setup(),p=f.fixture.preview.preview;
 const ready=await f.invoke(f.action);assert.equal(ready.value.job,null);
 const preview=await f.invoke(f.action+'/preview',{method:'POST',raw:JSON.stringify({target:'FixtureService',operation:'restart'}),headers:f.headers});assert.deepEqual(preview.value,f.fixture.preview);assert.equal(f.fixture.counts.approve,0);
 const approved=await f.invoke(f.action+'/approve',{method:'POST',raw:JSON.stringify({previewId:p.id,previewDigest:p.digest}),headers:f.headers});assert.deepEqual(approved.value,f.fixture.approved);
 const first=(await f.invoke(f.action)).value,second=(await f.invoke(f.action)).value;assert.deepEqual(first,f.fixture.complete);assert.deepEqual(second,first);assert.equal(first.job.startDeadline,p.expiresAt);assert.deepEqual(first.job.identity,approved.value.job.identity);assert.equal(first.job.result.runningObserved,true);assert.deepEqual(f.fixture.counts,{preview:1,approve:1,status:3});assert.deepEqual(f.state,{blocked:[],external:[]});
 // Readback does not expose a mutable alias to the controller's saved value.
 first.job.target='changed';assert.equal((await f.invoke(f.action)).value.job.target,'FixtureService');
 for(const action of ['preview','approve'])assert.deepEqual(await f.invoke(f.action+'/'+action,{method:'POST',raw:action==='preview'?JSON.stringify({target:'FixtureService',operation:'restart'}):JSON.stringify({previewId:p.id,previewDigest:p.digest}),headers:f.headers}),{abort:'blockedbyclient'});
 assert.equal(f.fixture.counts.approve,1);assert.match(windowsServiceActionsDisclosure,/in-memory fixture only/);assert.match(windowsServiceActionsDisclosure,/No real login, durable manager\/broker write, SCM control/);
});
test('synthetic fixtures keep timestamp and numeric deadline binding when shifted',()=>{
 const f=createWindowsServiceActionsFixture('2027-01-01T00:00:00Z');assert.equal(f.preview.preview.createdAt,'2027-01-01T00:00:00.000Z');assert.equal(f.complete.job.result.deadline,Date.parse(f.complete.job.startDeadline)/1000);assert.equal(f.inventory.deviceId,f.device.id);assert.equal(f.session.actorId,f.preview.preview.actorId);
 for(const at of ['invalid','2026-10-11T10:00:00.001Z'])assert.throws(()=>createWindowsServiceActionsFixture(at),/clock/);
});
test('action route rejects wrong method, body, CSRF, Origin, query, alias, replay and approval-before-preview',async()=>{
 const f=setup(),p=f.fixture.preview.preview,preview=JSON.stringify({target:'FixtureService',operation:'restart'}),approve=JSON.stringify({previewId:p.id,previewDigest:p.digest});
 assert.deepEqual(await f.invoke(f.action+'/approve',{method:'POST',headers:f.headers,raw:approve}),{abort:'blockedbyclient'});
 for(const patch of [{method:'GET'},{method:'PUT'},{headers:{}},{headers:{...f.headers,'x-csrf-token':'wrong'}},{headers:{...f.headers,origin:'https://outside.invalid'}},{headers:{...f.headers,'content-type':'text/plain'}},{raw:'{}'},{raw:null},{raw:' '.repeat(1025)},{raw:JSON.stringify({target:'Spooler',operation:'restart'})},{raw:JSON.stringify({target:'FixtureService',operation:'stop'})},{raw:'{"target":"FixtureService","operation":"restart","operation":"restart"}'}])assert.deepEqual(await f.invoke(f.action+'/preview',{method:'POST',headers:f.headers,raw:preview,...patch}),{abort:'blockedbyclient'});
 for(const suffix of ['/preview/','/preview?x=1','/approve/extra','/%70review','/execute','/setup'])assert.deepEqual(await f.invoke(f.action+suffix,{method:'POST',headers:f.headers,raw:preview}),{abort:'blockedbyclient'});
 assert.deepEqual(await f.invoke(f.action+'?x=1'),{abort:'blockedbyclient'});assert.deepEqual(await f.invoke(f.action,{raw:'{}'}),{abort:'blockedbyclient'});assert.deepEqual(await f.invoke(f.action,{origin:'https://outside.invalid'}),{abort:'blockedbyclient'});
 assert.deepEqual(f.fixture.counts,{preview:0,approve:0,status:0});
});
test('approval requires the exact reviewed ID and digest, preserving the pending preview after rejection',async()=>{
 const f=setup(),p=f.fixture.preview.preview;
 await f.invoke(f.action+'/preview',{method:'POST',headers:f.headers,raw:JSON.stringify({target:'FixtureService',operation:'restart'})});
 for(const raw of [JSON.stringify({previewId:p.id,previewDigest:'sha256:'+'0'.repeat(64)}),JSON.stringify({previewId:'action_'+'9'.repeat(32),previewDigest:p.digest}),JSON.stringify({previewId:p.id,previewDigest:p.digest,approved:true}),' '+JSON.stringify({previewId:p.id,previewDigest:p.digest})])assert.deepEqual(await f.invoke(f.action+'/approve',{method:'POST',headers:f.headers,raw}),{abort:'blockedbyclient'});
 assert.equal(f.fixture.counts.approve,0);const accepted=await f.invoke(f.action+'/approve',{method:'POST',headers:f.headers,raw:JSON.stringify({previewId:p.id,previewDigest:p.digest})});assert.equal(accepted.value.job.identity.jobId,p.id);assert.equal(f.fixture.counts.approve,1);
});
test('all unexpected API writes are blocked while unrelated read scopes remain explicitly unavailable',async()=>{
 const f=setup();for(const method of ['POST','PUT','PATCH','DELETE'])for(const path of ['/api/auth/login',f.prefix+'/windows-services/policy',f.prefix+'/windows-inventory/grant','/api/unrecognized'])assert.deepEqual(await f.invoke(path,{method,headers:f.headers,raw:'{}'}),{abort:'blockedbyclient'});
 assert.equal((await f.invoke(f.prefix+'/windows-services')).status,503);assert.deepEqual(await f.invoke('/assets/app.js'),{continued:true});
 const query={search:'',sort:'name-asc',limit:100,cursor:''};const result=await f.invoke(f.prefix+'/windows-full-services/query',{method:'POST',headers:f.headers,raw:JSON.stringify(query)});assert.equal(result.value.status,'not_configured');assert.equal(result.value.complete,null);
 for(const change of [{headers:{}},{raw:JSON.stringify({...query,limit:101})},{method:'GET'}])assert.deepEqual(await f.invoke(f.prefix+'/windows-full-services/query',{method:'POST',headers:f.headers,raw:JSON.stringify(query),...change}),{abort:'blockedbyclient'});
});
test('only exact loopback origins are usable without any request',()=>{
 for(const base of ['https://127.0.0.1:19890','http://localhost:19890','http://example.invalid','http://127.0.0.1:19890/path','http://user:pass@127.0.0.1:19890','invalid'])assert.throws(()=>windowsServiceActionsRoute({base,fixture:createWindowsServiceActionsFixture(),state:{blocked:[],external:[]}}));
});
test('opening the default Processes tab is an authenticated read and never grants a process scope',async()=>{
 const f=setup(),query={search:'',sort:'pid-asc',limit:100,cursor:''};
 const result=await f.invoke(f.prefix+'/windows-full-processes/query',{method:'POST',headers:f.headers,raw:JSON.stringify(query)});
 assert.equal(result.status,200);assert.equal(result.value.schemaVersion,'tracebolt.windows-full-processes-page.v1');
 assert.equal(result.value.deviceId,f.fixture.device.id);assert.equal(result.value.status,'not_configured');
 assert.equal(result.value.authorityUntil,null);assert.equal(result.value.grantId,null);assert.equal(result.value.complete,null);assert.deepEqual(result.value.rows,[]);
 assert.deepEqual(f.state,{blocked:[],external:[]});assert.deepEqual(f.fixture.counts,{preview:0,approve:0,status:0});
});
test('synthetic process read rejects unauthenticated, malformed or action-shaped requests',async()=>{
 const query={search:'',sort:'pid-asc',limit:100,cursor:''};
 for(const change of [f=>({method:'GET'}),f=>({headers:{}}),f=>({headers:{...f.headers,'x-csrf-token':'wrong'}}),f=>({headers:{...f.headers,origin:'https://outside.invalid'}}),f=>({headers:{...f.headers,'content-type':'text/plain'}}),f=>({raw:JSON.stringify({...query,limit:101})}),f=>({raw:JSON.stringify({...query,grant:true})}),f=>({raw:'{"search":"","sort":"pid-asc","limit":100,"cursor":"","limit":100}'})]){
  const f=setup(),result=await f.invoke(f.prefix+'/windows-full-processes/query',{method:'POST',headers:f.headers,raw:JSON.stringify(query),...change(f)});
  assert.deepEqual(result,{abort:'blockedbyclient'});assert.equal(f.state.blocked.length,1);assert.deepEqual(f.fixture.counts,{preview:0,approve:0,status:0});
 }
 for(const suffix of ['/query?private=1','/query/extra','/enable']){
  const f=setup();assert.deepEqual(await f.invoke(f.prefix+'/windows-full-processes'+suffix,{method:'POST',headers:f.headers,raw:JSON.stringify(query)}),{abort:'blockedbyclient'});
 }
});
const sourceSha='a'.repeat(40),evidence=()=>['en','de'].flatMap(locale=>[1440,390].map(width=>({file:`synthetic-windows-service-actions-${width}-${locale}.png`,sourceSha,test:windowsServiceActionsCaseName,locale,viewport:{width,height:width===390?844:1000},fullPage:false,publicSafe:true,fixtureDisclosure:windowsServiceActionsDisclosure})));
test('completion requires exactly four captured source-bound locale/viewport evidence entries',()=>{
 assert.deepEqual(requireWindowsServiceActionsEvidence(evidence(),sourceSha),{screens:4,durableStoreAcceptance:false,nativeAcceptance:false});
 for(const mutate of [rows=>rows.pop(),rows=>rows.push(rows[0]),rows=>{rows[1]=rows[0];},rows=>{rows[0].sourceSha='b'.repeat(40);},rows=>{rows[0].locale='de';},rows=>{rows[0].viewport.height=844;},rows=>{rows[0].fullPage=true;},rows=>{rows[0].publicSafe=false;},rows=>{rows[0].fixtureDisclosure='native';},rows=>{rows[0].test='other';}]){const rows=evidence();mutate(rows);assert.throws(()=>requireWindowsServiceActionsEvidence(rows,sourceSha));}
 assert.throws(()=>requireWindowsServiceActionsEvidence(evidence(),null));
});
test('hosted hook and inert import preserve existing roots and budgets, and cannot silently skip captures',()=>{
 const workflow=read('../../.github/workflows/validate.yml'),manifest=JSON.parse(read('./inert-suites.json')),runner=read('./windows-service-actions-runner.mjs'),helper=read('./windows-service-actions-browser.mjs');
 assert.ok(manifest.imported.includes('windows-service-actions-fixtures.test.mjs'));assert.ok(!manifest.entries.includes('windows-service-actions-fixtures.test.mjs'));assert.match(read('./windows-inventory-fixtures.test.mjs'),/import '\.\/windows-service-actions-fixtures\.test\.mjs'/);
 assert.match(workflow,/run: node tests\/e2e-review\/windows-service-actions-runner\.mjs/);for(const item of ['results','manifest'])assert.ok(workflow.includes(`            artifacts/review/windows-service-actions-${item}.json\n`));
 assert.equal((read('./lan-browser.mjs').match(/await check\(/g)||[]).length,27);assert.equal((read('./enrollment-browser.mjs').match(/await check\('/g)||[]).length,13);
 assert.match(runner,/requireWindowsServiceActionsEvidence\(screenshots,sourceSha\)/);assert.match(runner,/120000/);assert.match(runner,/for\(const locale of \['en','de'\]\)for\(const width of \[1440,390\]\)/);assert.match(runner,/if\(errors\|\|apiRequests\|\|variants.length!==4\)/);assert.doesNotMatch(runner,/CHROMIUM_PATH|executablePath|ignoreHTTPSErrors|grantPermissions|execFile|spawn\(|go build|setDefaultTimeout/);
 for(const hook of ["stage='review'","stage='approve'","stage='saved-status'","stage='reload'","stage='capture'","button.click();button.click();","await page.reload()","toHaveAttribute('datetime',deadline)","toBeHidden()","toBeVisible()","toBeInViewport()"] )assert.ok(helper.includes(hook),hook);
 assert.doesNotMatch(helper,/chromium\.launch|createServer|writeFile|execFile|spawn\(|fetch\(|page\.request|newContext\(/);
 assert.equal(typeof exerciseWindowsServiceActions,'function');
});
