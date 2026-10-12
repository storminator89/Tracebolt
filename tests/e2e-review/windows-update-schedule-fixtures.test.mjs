/** Inert scheduling controller and hosted-source contracts. Never launches a browser/server. */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createWindowsUpdateJobsFixture,requireWindowsUpdateJobsEvidence,windowsUpdateJobsOrigin} from './windows-update-jobs-browser.mjs';
import {createWindowsUpdateScheduleFixture,windowsUpdateScheduleRoute,exerciseWindowsUpdateSchedule,windowsUpdateScheduleCaseName,windowsUpdateScheduleDisclosure,windowsUpdateScheduleFailureStage,requireWindowsUpdateScheduleEvidence} from './windows-update-schedule-browser.mjs';
const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8'),id='update_'+'9'.repeat(32);
function setup(){
 const base=windowsUpdateJobsOrigin,fixture=createWindowsUpdateScheduleFixture(),state={blocked:[],external:[]},prefix='/api/devices/'+fixture.device.id+'/windows-update-jobs';
 const headers={'x-csrf-token':fixture.session.csrfToken,origin:base,'content-type':'application/json'};
 let assetPath=null,continued=false;
 const handler=windowsUpdateScheduleRoute({base,fixture,state,asset:async(_route,path)=>{assetPath=path;}});
 const invokePath=async(path,{method='GET',raw=null,headers:sent=headers,origin=base}={})=>{let result;await handler({request:()=>({url:()=>origin+path,method:()=>method,postData:()=>raw,headers:()=>sent}),fulfill:async value=>{result={status:value.status,value:JSON.parse(value.body)};},abort:async value=>{result={abort:value};},continue:async()=>{continued=true;}});return result;};
 return {fixture,state,headers,prefix,invokePath,invoke:(suffix='',options)=>invokePath(prefix+suffix,options),assetState:()=>({assetPath,continued})};
}
const post=body=>({method:'POST',raw:JSON.stringify(body)}),approval=f=>({previewId:id,previewDigest:f.fixture.digest,acknowledged:true,...f.fixture.scheduleWindow}),cancel=f=>({scheduleId:id,scheduleDigest:f.fixture.scheduleDigest});
async function reviewed(f){
 assert.equal((await f.invoke('/request',post({requestId:id,...f.fixture.selection}))).value.job.state,'requested');
 assert.equal((await f.invoke()).value.job.state,'preview');
 assert.equal((await f.invoke('/preview',post({requestId:id}))).value.job.preview.id,id);
}

test('schedule fixture adds explicit authority without changing the manual fixture',()=>{
 const manual=createWindowsUpdateJobsFixture(),scheduled=createWindowsUpdateScheduleFixture();
 assert.deepEqual(manual.session.capabilities,['read','windows_update_install']);assert.equal(Object.hasOwn(manual.updateView(),'schedulingAvailable'),false);
 assert.deepEqual(scheduled.session.capabilities,['read','windows_update_install','windows_update_schedule']);assert.equal(scheduled.updateView().schedulingAvailable,true);
 assert.equal(scheduled.session.transport,'https');assert.equal(scheduled.session.insecureTestMode,false);assert.equal(windowsUpdateScheduleFailureStage(),'setup');assert.deepEqual(scheduled.scheduleCounts,{schedule:0,cancel:0,immediateInstallWrites:0});
});
test('prospective review saves exactly one window and cancellation preserves the spent lifetime slot',async()=>{
 const f=setup();await reviewed(f);
 const saved=(await f.invoke('/schedule',post(approval(f)))).value;assert.equal(saved.job.state,'scheduled');assert.equal(saved.available,false);assert.equal(saved.job.preview,null);assert.equal(saved.job.result,null);assert.deepEqual(saved.job.selection,f.fixture.selection);
 assert.deepEqual(saved.job.schedule,{version:'tracebolt.windows-selected-update-schedule.v1',digest:f.fixture.scheduleDigest,approvedAt:Date.parse(f.fixture.now)/1000,...f.fixture.scheduleWindow,permitIssuedAt:0,revoked:false});
 assert.deepEqual((await f.invoke('?jobId='+id)).value,saved);assert.equal((await f.invoke('?history=1')).value.remainingCapacity,31);assert.equal((await f.invoke('?history=1')).value.jobs[0].approvedAt,0);
 const canceled=(await f.invoke('/cancel-schedule',post(cancel(f)))).value;assert.equal(canceled.job.state,'schedule_canceled');assert.equal(canceled.available,true);assert.deepEqual(canceled.job.schedule,saved.job.schedule);
 assert.deepEqual((await f.invoke()).value,canceled);assert.deepEqual((await f.invoke('?jobId='+id)).value,canceled);assert.equal((await f.invoke('?history=1')).value.remainingCapacity,31);
 assert.deepEqual(f.fixture.scheduleCounts,{schedule:1,cancel:1,immediateInstallWrites:0});assert.equal(f.fixture.updateCounts.request,1);assert.equal(f.fixture.updateCounts.preview,1);assert.equal(f.fixture.updateCounts.approve,0);assert.deepEqual(f.state,{blocked:[],external:[]});
 // Replies are copies and cannot rewrite the immutable synthetic evidence.
 canceled.job.schedule.endAt++;saved.job.selection.revision++;assert.equal(f.fixture.savedSchedule().job.schedule.endAt,f.fixture.scheduleWindow.endAt);assert.deepEqual(f.fixture.savedSchedule().job.selection,f.fixture.selection);
});
test('scheduling cannot skip readiness or explicit reopening and rejects unchecked prospective consent',async()=>{
 const f=setup();assert.deepEqual(await f.invoke('/schedule',post(approval(f))),{abort:'blockedbyclient'});
 await f.invoke('/request',post({requestId:id,...f.fixture.selection}));assert.deepEqual(await f.invoke('/schedule',post(approval(f))),{abort:'blockedbyclient'});
 await f.invoke();assert.deepEqual(await f.invoke('/schedule',post(approval(f))),{abort:'blockedbyclient'});
 await f.invoke('/preview',post({requestId:id}));assert.deepEqual(await f.invoke('/schedule',post({...approval(f),acknowledged:false})),{abort:'blockedbyclient'});
 assert.deepEqual(f.fixture.scheduleCounts,{schedule:0,cancel:0,immediateInstallWrites:0});assert.equal(f.fixture.updateCounts.approve,0);
});
test('prospective scope is exact ID, digest, canonical acknowledgement and fixed bounded UTC window',async()=>{
 const f=setup();await reviewed(f);const body=approval(f),canonical=JSON.stringify(body);
 const malformed=[{...body,previewId:'update_'+'8'.repeat(32)},{...body,previewDigest:'sha256:'+'0'.repeat(64)},{...body,actorId:f.fixture.session.actorId},{...body,startAt:body.startAt-60},{...body,endAt:body.endAt+60},{...body,endAt:body.startAt},{...body,startAt:body.startAt+86400},{...body,acknowledged:1}].map(JSON.stringify);
 for(const raw of [...malformed,' '+canonical,canonical.replace('"acknowledged":true','"acknowledged":true,"acknowledged":true'),canonical.replace('"startAt":'+body.startAt,'"startAt":"'+body.startAt+'"')])assert.deepEqual(await f.invoke('/schedule',{method:'POST',raw}),{abort:'blockedbyclient'});
 assert.equal(f.fixture.scheduleCounts.schedule,0);assert.equal((await f.invoke('/schedule',post(body))).value.job.state,'scheduled');
 assert.deepEqual(await f.invoke('/schedule',post(body)),{abort:'blockedbyclient'});assert.equal(f.fixture.scheduleCounts.schedule,1);
});
test('new routes reject methods, missing trust headers, aliases, extra queries and external requests',async()=>{
 for(const suffix of ['/schedule','/cancel-schedule'])for(const change of [{method:'GET'},{method:'PUT'},{raw:null},{raw:' '.repeat(1025)},{headers:{}},{headers:{origin:windowsUpdateJobsOrigin}},{origin:'https://outside.invalid'}]){
  const f=setup();await reviewed(f);if(suffix==='/cancel-schedule')await f.invoke('/schedule',post(approval(f)));
  assert.deepEqual(await f.invoke(suffix,{...post(suffix==='/schedule'?approval(f):cancel(f)),...change}),{abort:'blockedbyclient'});assert.equal(f.fixture.scheduleCounts.cancel,0);
 }
 for(const suffix of ['/schedule?x=1','/schedule/','/%73chedule','/cancel-schedule?x=1','/cancel-schedule/','/schedule/execute','/revoke-scheduling']){const f=setup();assert.deepEqual(await f.invoke(suffix,post(approval(f))),{abort:'blockedbyclient'});}
});
test('cancellation requires the exact saved schedule and cannot repeat or manufacture a permit',async()=>{
 const f=setup();await reviewed(f);assert.deepEqual(await f.invoke('/cancel-schedule',post(cancel(f))),{abort:'blockedbyclient'});await f.invoke('/schedule',post(approval(f)));
 for(const body of [{...cancel(f),scheduleId:'update_'+'8'.repeat(32)},{...cancel(f),scheduleDigest:f.fixture.digest},{...cancel(f),force:true}])assert.deepEqual(await f.invoke('/cancel-schedule',post(body)),{abort:'blockedbyclient'});
 const result=await f.invoke('/cancel-schedule',post(cancel(f)));assert.equal(result.value.job.state,'schedule_canceled');assert.equal(result.value.job.schedule.permitIssuedAt,0);assert.equal(result.value.job.result,null);
 assert.deepEqual(await f.invoke('/cancel-schedule',post(cancel(f))),{abort:'blockedbyclient'});assert.deepEqual(f.fixture.scheduleCounts,{schedule:1,cancel:1,immediateInstallWrites:0});
});
test('immediate approval and all native/action-shaped writes are blocked in the schedule case',async()=>{
 const f=setup();await reviewed(f);assert.deepEqual(await f.invoke('/approve',post({previewId:id,previewDigest:f.fixture.digest,acknowledged:true})),{abort:'blockedbyclient'});assert.equal(f.fixture.scheduleCounts.immediateInstallWrites,1);assert.equal(f.fixture.updateCounts.approve,0);
 for(const suffix of ['/install','/claim','/report','/download','/reboot','/grant','/execute'])assert.deepEqual(await f.invoke(suffix,post(approval(f))),{abort:'blockedbyclient'});
 assert.equal(f.fixture.scheduleCounts.schedule,0);assert.equal(f.fixture.savedSchedule(),null);
});
test('existing GET/readiness/asset routing stays wholly intercepted with exact job queries',async()=>{
 const f=setup();const session=(await f.invokePath('/api/auth/session')).value;assert.deepEqual(session.capabilities,['read','windows_update_install','windows_update_schedule']);await f.invokePath('/assets/app.js');assert.deepEqual(f.assetState(),{assetPath:'/assets/app.js',continued:false});
 await reviewed(f);await f.invoke('/schedule',post(approval(f)));assert.equal((await f.invoke('?history=1')).value.jobs[0].schedule.digest,f.fixture.scheduleDigest);
 for(const query of ['?jobId=update_'+'8'.repeat(32),'?history=1&history=1','?jobId='+id+'&force=1'])assert.deepEqual(await f.invoke(query),{abort:'blockedbyclient'});
 for(const base of ['http://127.0.0.1:19890','https://outside.invalid','https://windows-update-jobs.invalid/path'])assert.throws(()=>windowsUpdateScheduleRoute({base,fixture:f.fixture,state:f.state}));
});
const sourceSha='a'.repeat(40),evidence=()=>['review','pending','canceled'].flatMap(kind=>['en','de'].flatMap(locale=>[1440,390].map(width=>({file:`synthetic-windows-update-schedule-${kind}-${width}-${locale}.png`,sourceSha,test:windowsUpdateScheduleCaseName,locale,viewport:{width,height:width===390?844:1000},publicSafe:true,fullPage:false,fixtureDisclosure:windowsUpdateScheduleDisclosure}))));
test('schedule acceptance requires twelve distinct exact source-bound locale and viewport captures',()=>{
 assert.deepEqual(requireWindowsUpdateScheduleEvidence(evidence(),sourceSha),{screens:12,nativeAcceptance:false});
 for(const mutate of [r=>r.pop(),r=>r.push(r[0]),r=>{r[1]=r[0];},r=>{r[0].file='synthetic-windows-update-jobs-review-1440-en.png';},r=>{r[0].sourceSha='b'.repeat(40);},r=>{r[0].locale='de';},r=>{r[0].viewport.width=800;},r=>{r[0].viewport.height=844;},r=>{r[0].fullPage=true;},r=>{r[0].publicSafe=false;},r=>{r[0].fixtureDisclosure='native';},r=>{r[0].test='other';}]){const rows=evidence();mutate(rows);assert.throws(()=>requireWindowsUpdateScheduleEvidence(rows,sourceSha));}
 assert.throws(()=>requireWindowsUpdateScheduleEvidence(evidence(),null));assert.throws(()=>requireWindowsUpdateScheduleEvidence(evidence(),'b'.repeat(40)));assert.throws(()=>requireWindowsUpdateJobsEvidence(evidence(),sourceSha));
});
test('schedule source uses the existing genuine screenshot helper, locked runner and unchanged 120-second budget',()=>{
 const runner=read('./windows-service-actions-runner.mjs'),helper=read('./windows-update-schedule-browser.mjs'),manifest=JSON.parse(read('./inert-suites.json'));
 assert.ok(manifest.imported.includes('windows-update-schedule-fixtures.test.mjs'));assert.ok(!manifest.entries.includes('windows-update-schedule-fixtures.test.mjs'));assert.match(read('./windows-inventory-fixtures.test.mjs'),/import '\.\/windows-update-schedule-fixtures\.test\.mjs'/);
 assert.match(runner,/await page.screenshot\(\{path:path.join\(out,name\+'\.png'\),fullPage:false,animations:'disabled'\}\)/);assert.match(runner,/requireWindowsUpdateScheduleEvidence\(scheduleScreenshots,sourceSha\)/);assert.match(runner,/scheduleVariants.length!==4/);assert.match(runner,/scheduleState.blocked\)\.toEqual\(\[\]\)/);assert.match(runner,/scheduleState.external\)\.toEqual\(\[\]\)/);assert.match(runner,/scheduleStorage.includes\(value\)/);assert.match(runner,/\.\.\.updateScreenshots/);assert.match(runner,/\.\.\.scheduleScreenshots/);
 assert.equal((runner.match(/120000/g)||[]).length,1);assert.match(runner,/requireWindowsUpdateJobsEvidence\(updateScreenshots,sourceSha\)/);assert.match(runner,/updateVariants.length!==4/);
 assert.doesNotMatch(runner,/CHROMIUM_PATH|executablePath|ignoreHTTPSErrors|grantPermissions|execFile|spawn\(|go build|setDefaultTimeout/);assert.doesNotMatch(helper,/chromium\.launch|createServer|writeFile|execFile|spawn\(|fetch\(|page\.request|newContext\(|route\.continue|route\.fetch|setTimeout/);
 for(const hook of ["stage='review'","stage='pending'","stage='cancel'","stage='reload'","not.toBeChecked()","toBeDisabled()","capture('review',scheduleDetails)","capture('pending')","capture('canceled')","await page.reload()","exactSaved()","toBeInViewport()","immediateInstallWrites"])assert.ok(helper.includes(hook),hook);
 assert.equal((helper.match(/button.click\(\);button.click\(\);/g)||[]).length,2);assert.match(windowsUpdateScheduleDisclosure,/in-memory fixture/);assert.match(windowsUpdateScheduleDisclosure,/Zero immediate-install writes/);assert.match(windowsUpdateScheduleDisclosure,/No actual TLS authority/);assert.equal(typeof exerciseWindowsUpdateSchedule,'function');
});
