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
 assert.match(workflow,/run: \|\n          node tests\/e2e-review\/windows-service-actions-runner\.mjs\n          node tests\/e2e-review\/windows-update-retirement-browser\.mjs --check-evidence/);for(const item of ['results','manifest'])assert.ok(workflow.includes(`            artifacts/review/windows-service-actions-${item}.json\n`));
 assert.equal((read('./lan-browser.mjs').match(/await check\(/g)||[]).length,27);assert.equal((read('./enrollment-browser.mjs').match(/await check\('/g)||[]).length,13);
 assert.match(runner,/requireWindowsServiceActionsEvidence\(screenshots,sourceSha\)/);assert.match(runner,/120000/);assert.match(runner,/for\(const locale of \['en','de'\]\)for\(const width of \[1440,390\]\)/);assert.match(runner,/if\(errors\|\|apiRequests\|\|variants.length!==4\)/);assert.doesNotMatch(runner,/CHROMIUM_PATH|executablePath|ignoreHTTPSErrors|grantPermissions|execFile|spawn\(|go build|setDefaultTimeout/);
 for(const hook of ["stage='review'","stage='approve'","stage='saved-status'","stage='reload'","stage='capture'","button.click();button.click();","await page.reload()","toHaveAttribute('datetime',deadline)","toBeHidden()","toBeVisible()","toBeInViewport()"] )assert.ok(helper.includes(hook),hook);
 assert.doesNotMatch(helper,/chromium\.launch|createServer|writeFile|execFile|spawn\(|fetch\(|page\.request|newContext\(/);
 assert.equal(typeof exerciseWindowsServiceActions,'function');
});


import {createWindowsServiceActionHistoryFixture,windowsServiceActionHistoryRoute,windowsServiceActionHistoryCaseName,requireWindowsServiceActionHistoryEvidence} from './windows-service-action-history-browser.mjs';
test('retained history routes only the bounded same-identity GET vectors and never approve',async()=>{
 const fixture=createWindowsServiceActionHistoryFixture(),state={blocked:[],external:[]},handler=windowsServiceActionHistoryRoute({base,fixture,state}),prefix='/api/devices/'+fixture.device.id+'/windows-service-actions/history';
 const invoke=async(path,method='GET',raw=null)=>{let result;await handler({request:()=>({url:()=>base+path,method:()=>method,postData:()=>raw,headers:()=>({})}),fulfill:async value=>{result=JSON.parse(value.body);},abort:async value=>{result={abort:value};}});return result;};
 assert.deepEqual(await invoke(prefix),fixture.history);assert.deepEqual(await invoke(prefix+'/'+fixture.details[0].job.identity.jobId),fixture.details[0]);
 for(const [path,method,raw] of [[prefix,'POST','{}'],[prefix,'GET','{}'],[prefix+'?cursor=old','GET',null],[prefix+'/action_'+ 'f'.repeat(32),'GET',null]])assert.deepEqual(await invoke(path,method,raw),{abort:'blockedbyclient'});
 assert.deepEqual(fixture.historyCounts,{list:1,detail:1});assert.equal(fixture.counts.approve,0);assert.equal(fixture.counts.preview,0);
});
test('history requires four distinct source-bound screenshots through the existing hosted gate',()=>{
 const rows=evidence().map(row=>({...row,file:row.file.replace('service-actions','service-action-history'),test:windowsServiceActionHistoryCaseName}));
 assert.deepEqual(requireWindowsServiceActionHistoryEvidence(rows,sourceSha),{screens:4,nativeAcceptance:false});assert.throws(()=>requireWindowsServiceActionHistoryEvidence(rows.slice(1),sourceSha));assert.throws(()=>requireWindowsServiceActionHistoryEvidence(rows,'b'.repeat(40)));
 const runner=read('./windows-service-actions-runner.mjs');assert.match(runner,/requireWindowsServiceActionHistoryEvidence\(historyScreenshots,sourceSha\)/);assert.match(runner,/historyVariants.length!==4/);assert.match(runner,/historyStorage.includes\(detail.job.identity.jobId\)/);
});

import {createWindowsUpdateJobsFixture,windowsUpdateJobsRoute,exerciseWindowsUpdateJobs,windowsUpdateJobsCaseName,windowsUpdateJobsDisclosure,requireWindowsUpdateJobsEvidence,requireWindowsUpdateWorklistDetails,windowsUpdateJobsOrigin} from './windows-update-jobs-browser.mjs';
function updateSetup(){
 const base=windowsUpdateJobsOrigin,fixture=createWindowsUpdateJobsFixture(),state={blocked:[],external:[]},handler=windowsUpdateJobsRoute({base,fixture,state}),prefix='/api/devices/'+fixture.device.id+'/windows-update-jobs';
 const headers={'x-csrf-token':fixture.session.csrfToken,origin:base,'content-type':'application/json'};
 const invokePath=async(path,{method='GET',raw=null,headers:sent=headers,origin=base}={})=>{let result;await handler({request:()=>({url:()=>origin+path,method:()=>method,postData:()=>raw,headers:()=>sent}),fulfill:async value=>{result=JSON.parse(value.body);},abort:async value=>{result={abort:value};},continue:async()=>{result={continued:true};}});return result;};
 const invoke=(suffix='',options)=>invokePath(prefix+suffix,options);
 return {fixture,state,invoke,invokePath,headers};
}
test('update browser fixture requires asynchronous readiness review and one explicit exact approval',async()=>{
 const f=updateSetup(),id='update_'+'9'.repeat(32),post=raw=>({method:'POST',raw:JSON.stringify(raw)});
 assert.equal((await f.invoke()).job,null);assert.deepEqual(f.fixture.session.capabilities,['read','windows_update_install']);assert.equal(f.fixture.session.insecureTestMode,false);
 assert.equal((await f.invoke('/request',post({requestId:id,...f.fixture.selection}))).job.state,'requested');
 const ready=await f.invoke();assert.equal(ready.job.state,'preview');assert.equal(f.fixture.updateCounts.preview,0);const approval={previewId:id,previewDigest:ready.job.preview.digest,acknowledged:true};
 assert.deepEqual(await f.invoke('/approve',post(approval)),{abort:'blockedbyclient'});
 assert.equal((await f.invoke('/preview',post({requestId:id}))).job.preview.id,id);
 assert.deepEqual(await f.invoke('/approve',post({...approval,acknowledged:false})),{abort:'blockedbyclient'});
 assert.equal((await f.invoke('/approve',post(approval))).job.state,'approved');
 const result=await f.invoke();assert.equal(result.job.result.outcome,'succeeded');assert.equal(result.job.result.rebootRequired,'yes');assert.deepEqual(await f.invoke(),result);
 assert.deepEqual(await f.invoke('/approve',post(approval)),{abort:'blockedbyclient'});assert.deepEqual(f.fixture.updateCounts,{request:1,preview:1,approve:1,status:4});
 result.job.selection.revision++;assert.deepEqual((await f.invoke()).job.selection,f.fixture.selection);assert.equal(f.fixture.counts.approve,0);assert.equal(f.fixture.counts.preview,0);
});
test('update synthetic routing never permits a host operation or malformed request',async()=>{
 const request={requestId:'update_'+'9'.repeat(32),updateId:'00000001-0000-0000-0000-000000000001',revision:10};
 for(const change of [{method:'GET'},{headers:{}},{raw:'{}'},{raw:JSON.stringify({...request,revision:11})},{raw:JSON.stringify({...request,force:true})},{raw:' '.repeat(1025)},{origin:'https://outside.invalid'}]){
  const f=updateSetup();assert.deepEqual(await f.invoke('/request',{method:'POST',raw:JSON.stringify(request),...change}),{abort:'blockedbyclient'});assert.equal(f.fixture.updateCounts.request,0);
 }
 for(const suffix of ['/install','/claim','/report','/download','/reboot','/approve?x=1','/request/','/%72equest']){const f=updateSetup();assert.deepEqual(await f.invoke(suffix,{method:'POST',raw:JSON.stringify(request)}),{abort:'blockedbyclient'});}
});
test('existing hosted gate requires twelve update review/result/worklist screenshots without new runner or budget',()=>{
 const rows=['review','result','worklist'].flatMap(kind=>['en','de'].flatMap(locale=>[1440,390].map(width=>({file:`synthetic-windows-update-jobs-${kind}-${width}-${locale}.png`,sourceSha,test:windowsUpdateJobsCaseName,locale,viewport:{width,height:width===390?844:1000},fullPage:false,publicSafe:true,fixtureDisclosure:windowsUpdateJobsDisclosure}))));
 assert.deepEqual(requireWindowsUpdateJobsEvidence(rows,sourceSha),{screens:12,nativeAcceptance:false});
 for(const mutate of [r=>r.pop(),r=>r.push(r[0]),r=>{r[0].sourceSha='b'.repeat(40);},r=>{r[0].fixtureDisclosure='native';},r=>{r[0].viewport.width=800;},r=>{r[0].viewport.height=844;},r=>{r[0].fullPage=true;},r=>{r[0].publicSafe=false;},r=>{r[0].test='other';},r=>{r[0].locale='de';},r=>{r[8]=r[0];}]){const changed=structuredClone(rows);mutate(changed);assert.throws(()=>requireWindowsUpdateJobsEvidence(changed,sourceSha));}
 const runner=read('./windows-service-actions-runner.mjs'),helper=read('./windows-update-jobs-browser.mjs');assert.match(runner,/requireWindowsUpdateJobsEvidence\(updateScreenshots,sourceSha\)/);assert.match(runner,/updateVariants.length!==4/);assert.match(runner,/120000/);assert.match(runner,/updateStorage.includes\(value\)/);assert.match(runner,/requireWindowsUpdateWorklistDetails\(updateDetails\)/);assert.ok(runner.indexOf('requireWindowsUpdateWorklistDetails(updateDetails)')<runner.indexOf('updateVariants.push'));assert.match(runner,/review\|result\|worklist/);assert.match(runner,/expect\(updateFixture.secondPostAttempts\).toEqual\(\{request:0,preview:0,approve:0,other:0\}\)/);
 for(const hook of ["stage='request'","stage='review'","stage='approve'","stage='saved-result'","stage='reload'","button.click();button.click();","not.toBeChecked()","toBeDisabled()","capture('review')","capture('result')","synthetic-windows-update-jobs-worklist-","await worklist.evaluate(el=>el.scrollIntoView","toBeInViewport({ratio:1})","secondDevicePOSTs","frozenTargetCount:2"])assert.ok(helper.includes(hook),hook);
 assert.doesNotMatch(helper,/chromium\.launch|createServer|writeFile|execFile|spawn\(|fetch\(|page\.request|newContext\(/);assert.match(windowsUpdateJobsDisclosure,/No actual TLS authority/);assert.equal(typeof exerciseWindowsUpdateJobs,'function');
});

test('update HTTPS fixture is wholly intercepted without certificate exceptions or network continuation',async()=>{
 const fixture=createWindowsUpdateJobsFixture();
 for(const origin of [base,'https://127.0.0.1:19890','https://outside.invalid'])assert.throws(()=>windowsUpdateJobsRoute({base:origin,fixture,state:{blocked:[],external:[]}}));
 let assetPath=null,continued=false;const handler=windowsUpdateJobsRoute({base:windowsUpdateJobsOrigin,fixture,state:{blocked:[],external:[]},asset:async(_route,path)=>{assetPath=path;}});
 await handler({request:()=>({url:()=>windowsUpdateJobsOrigin+'/assets/app.js',method:()=> 'GET',postData:()=>null,headers:()=>({})}),continue:async()=>{continued=true;}});
 assert.equal(assetPath,'/assets/app.js');assert.equal(continued,false);
 const helper=read('./windows-update-jobs-browser.mjs'),runner=read('./windows-service-actions-runner.mjs');assert.match(helper,/const open=async\(\)=>\{await page.getByRole\('tab',\{name:de\?'Inventar':'Inventory',exact:true\}\).click\(\);await page.getByRole\('tab',\{name:'Updates'/);assert.doesNotMatch(helper,/route\.continue|route\.fetch/);assert.match(runner,/base:windowsUpdateJobsOrigin/);assert.match(runner,/await route.fulfill\(\{status:200,contentType:contentTypes\[path.extname\(file\)\],body:await fs.readFile\(file\)\}\)/);assert.doesNotMatch(runner,/ignoreHTTPSErrors|grantPermissions|executablePath/);
});


test('two admitted synthetic Windows targets expose distinct bound inventory and saved current/history/exact reads',async()=>{
 const f=updateSetup(),fixture=f.fixture,second='/api/devices/'+fixture.secondDevice.id,first='/api/devices/'+fixture.device.id,id='update_'+'9'.repeat(32),post=value=>({method:'POST',raw:JSON.stringify(value)});
 const overview=await f.invokePath('/api/overview');assert.equal(overview.stats.totalDevices,2);assert.equal(overview.stats.unknownDevices,2);assert.deepEqual(overview.devices.map(d=>d.id),[fixture.device.id,fixture.secondDevice.id]);
 for(const device of overview.devices){assert.match(device.id,/^agent_[a-f0-9]{32}$/);assert.equal(device.platform,'windows');assert.equal(device.source,'lan');assert.equal(device.synthetic,false);assert.match(device.name,/SYNTHETIC/);assert.ok(device.capabilities.some(c=>c.id==='agent_identity'&&c.status==='supported'));assert.deepEqual(await f.invokePath('/api/devices/'+device.id),device);assert.equal((await f.invokePath('/api/devices/'+device.id+'/windows-inventory')).deviceId,device.id);}
 assert.notEqual(fixture.selection.updateId,fixture.secondSelection.updateId);assert.notEqual(fixture.selection.revision,fixture.secondSelection.revision);
 await f.invoke('/request',post({requestId:id,...fixture.selection}));const ready=await f.invoke();await f.invoke('/preview',post({requestId:id}));await f.invoke('/approve',post({previewId:id,previewDigest:ready.job.preview.digest,acknowledged:true}));const result=await f.invoke();
 const firstHistory=await f.invoke('?history=1'),firstExact=await f.invoke('?jobId='+id);assert.deepEqual(firstExact,result);assert.equal(firstHistory.deviceId,fixture.device.id);assert.equal(firstHistory.jobs[0].id,id);assert.equal(firstHistory.jobs[0].result.outcome,'succeeded');
 const pending=await f.invokePath(second+'/windows-update-jobs'),history=await f.invokePath(second+'/windows-update-jobs?history=1'),exact=await f.invokePath(second+'/windows-update-jobs?jobId='+fixture.secondSavedID);
 assert.deepEqual(exact,pending);assert.equal(pending.deviceId,fixture.secondDevice.id);assert.equal(pending.available,false);assert.equal(pending.reason,'job_pending_or_intervention');assert.equal(pending.job.id,fixture.secondSavedID);assert.equal(pending.job.state,'claimed');assert.equal(pending.job.result,null);assert.equal(pending.job.preview,null);assert.deepEqual(pending.job.selection,fixture.secondSelection);assert.equal(history.deviceId,fixture.secondDevice.id);assert.equal(history.jobs.length,1);assert.equal(history.jobs[0].id,fixture.secondSavedID);assert.equal(history.jobs[0].state,'claimed');assert.equal(history.jobs[0].result,null);assert.equal(history.jobs[0].claimedAt,Date.parse(fixture.now)/1000-10);assert.equal(history.remainingCapacity,31);
 assert.deepEqual(fixture.secondUpdateReads,{current:1,history:1,exact:1});assert.deepEqual(fixture.secondUpdateCounts,{request:0,preview:0,approve:0,status:2});assert.deepEqual(fixture.secondPostAttempts,{request:0,preview:0,approve:0,other:0});assert.deepEqual(f.state,{blocked:[],external:[]});
 pending.job.state='complete';history.jobs[0].selection.revision=999;exact.job.result={outcome:'succeeded'};assert.equal((await f.invokePath(second+'/windows-update-jobs')).job.state,'claimed');assert.equal((await f.invokePath(second+'/windows-update-jobs?history=1')).jobs[0].selection.revision,11);assert.equal((await f.invokePath(second+'/windows-update-jobs?jobId='+fixture.secondSavedID)).job.result,null);
 for(const path of [first+'/windows-update-jobs?jobId='+fixture.secondSavedID,second+'/windows-update-jobs?jobId='+id,second+'/windows-update-jobs?jobId=update_'+'c'.repeat(32),second+'/windows-update-jobs?history=1&jobId='+fixture.secondSavedID,second+'/windows-update-jobs?jobId='+fixture.secondSavedID+'&jobId='+fixture.secondSavedID,second+'/windows-update-jobs/?history=1',second+'/windows-update-jobs?history=01',second+'/windows-update-jobs/preview'])assert.deepEqual(await f.invokePath(path),{abort:'blockedbyclient'});
 assert.equal(fixture.updateCounts.request,1);assert.equal(fixture.updateCounts.preview,1);assert.equal(fixture.updateCounts.approve,1);assert.deepEqual(fixture.secondPostAttempts,{request:0,preview:0,approve:0,other:0});
});

test('second target rejects every POST and mutation verb while accepted mutation counters remain zero',async()=>{
 const f=updateSetup(),fixture=f.fixture,path='/api/devices/'+fixture.secondDevice.id+'/windows-update-jobs';
 for(const op of ['request','preview','approve'])for(const method of ['POST','PUT','PATCH','DELETE'])assert.deepEqual(await f.invokePath(path+'/'+op,{method,raw:JSON.stringify(op==='request'?{requestId:'update_'+'9'.repeat(32),...fixture.secondSelection}:op==='preview'?{requestId:fixture.secondSavedID}:{previewId:fixture.secondSavedID,previewDigest:fixture.digest,acknowledged:true})}),{abort:'blockedbyclient'});
 for(const suffix of ['','/request?x=1','/install','/claim','/report','/download','/reboot','/%72equest','/request/'])assert.deepEqual(await f.invokePath(path+suffix,{method:'POST',raw:'{}'}),{abort:'blockedbyclient'});
 assert.deepEqual(await f.invokePath('/api/devices/'+fixture.secondDevice.id+'/windows-inventory',{method:'POST',raw:'{}'}),{abort:'blockedbyclient'});
 assert.deepEqual(fixture.secondUpdateCounts,{request:0,preview:0,approve:0,status:0});assert.deepEqual(fixture.updateCounts,{request:0,preview:0,approve:0,status:0});assert.equal(fixture.secondPostAttempts.request,2);assert.equal(fixture.secondPostAttempts.preview,1);assert.equal(fixture.secondPostAttempts.approve,1);assert.equal(fixture.secondPostAttempts.other,9);assert.equal(Object.values(fixture.secondPostAttempts).reduce((sum,n)=>sum+n,0),13);
 assert.equal((await f.invokePath(path)).job.state,'claimed');assert.equal((await f.invokePath(path+'?jobId='+fixture.secondSavedID)).job.result,null);
});

test('hosted variant gate requires frozen two-target independent readback and zero attempted or accepted second-device writes',()=>{
 const details={frozenTargetCount:2,frozenWorklistReadback:true,exactSavedHistory:true,independentResultReadback:true,independentPendingReadback:true,compactWorklistCapture:true,secondDeviceMutations:{request:0,preview:0,approve:0},secondDevicePOSTs:0,nativeAcceptance:false};
 assert.deepEqual(requireWindowsUpdateWorklistDetails(details),{frozenTargets:2,secondDevicePOSTs:0,nativeAcceptance:false});
 for(const key of Object.keys(details)){const partial=structuredClone(details);delete partial[key];assert.throws(()=>requireWindowsUpdateWorklistDetails(partial));}
 for(const patch of [{frozenTargetCount:1},{frozenTargetCount:3},{frozenWorklistReadback:false},{exactSavedHistory:false},{independentResultReadback:false},{independentPendingReadback:false},{compactWorklistCapture:false},{secondDevicePOSTs:1},{nativeAcceptance:true}])assert.throws(()=>requireWindowsUpdateWorklistDetails({...details,...patch}));
 for(const op of ['request','preview','approve'])assert.throws(()=>requireWindowsUpdateWorklistDetails({...details,secondDeviceMutations:{...details.secondDeviceMutations,[op]:1}}));
 assert.throws(()=>requireWindowsUpdateWorklistDetails({...details,secondDeviceMutations:{...details.secondDeviceMutations,other:0}}));assert.throws(()=>requireWindowsUpdateWorklistDetails(null));
 const helper=read('./windows-update-jobs-browser.mjs');assert.ok(helper.indexOf("await capture('result')")<helper.indexOf("stage='worklist'"));assert.match(helper,/await expect\(choices.getByRole\('checkbox'\)\).toHaveCount\(2\)/);assert.match(helper,/await expect\(worklist.locator\('\.windows-update-jobs'\)\).toHaveCount\(0\)/);assert.match(helper,/await expect\(secondSummary\).not.toContainText\(resultText\)/);assert.match(helper,/document.documentElement.scrollWidth<=innerWidth\+1/);assert.doesNotMatch(helper,/setViewportSize|addStyleTag|chromium\.launch|createServer|writeFile|execFile|spawn\(|fetch\(|page\.request|newContext\(/);
});
