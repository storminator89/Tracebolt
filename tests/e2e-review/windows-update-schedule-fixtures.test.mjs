/** Inert scheduling controller and hosted-source contracts. Never launches a browser/server. */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {createWindowsUpdateJobsFixture,requireWindowsUpdateJobsEvidence,windowsUpdateJobsOrigin} from './windows-update-jobs-browser.mjs';
import {createWindowsUpdateScheduleFixture,windowsUpdateScheduleRoute,exerciseWindowsUpdateSchedule,windowsUpdateScheduleCaseName,windowsUpdateScheduleDisclosure,windowsUpdateScheduleFailureStage,requireWindowsUpdateScheduleEvidence,windowsBackgroundUpdateScheduleCaseName,windowsBackgroundUpdateScheduleDisclosure,requireWindowsBackgroundUpdateScheduleEvidence,createWindowsFleetUpdateScheduleFixture,exerciseWindowsFleetUpdateSchedule,windowsFleetUpdateScheduleCaseName,windowsFleetUpdateScheduleDisclosure,windowsFleetUpdateScheduleScenes,windowsFleetUpdateTriageRow,requireWindowsFleetUpdateScheduleEvidence,requireWindowsFleetUpdateScheduleDetails} from './windows-update-schedule-browser.mjs';
const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8'),id='update_'+'9'.repeat(32);
function setup(profile='standalone',fixture=createWindowsUpdateScheduleFixture(profile)){
 const base=windowsUpdateJobsOrigin,state={blocked:[],external:[]},prefix='/api/devices/'+fixture.device.id+'/windows-update-jobs';
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

test('fresh combined fixture preserves standalone and manual-background profile boundaries',async()=>{
 const standalone=createWindowsUpdateScheduleFixture(),manual=createWindowsUpdateJobsFixture(),f=setup('background');
 for(const value of [standalone.updateView(),manual.updateView()])for(const field of ['backgroundScheduling','backgroundExecutor','coordinated','executorObservedAt','mutation'])assert.equal(Object.hasOwn(value,field),false);
 assert.equal(standalone.scheduleProfile,'standalone');assert.equal(f.fixture.scheduleProfile,'background');
 const view=(await f.invoke()).value;assert.equal(view.backgroundScheduling,true);assert.equal(view.backgroundExecutor,true);assert.equal(view.coordinated,true);assert.equal(view.schedulingAvailable,true);assert.equal(view.executorAvailability,'verified_recent');assert.equal(view.executorObservedAt,view.mutationCapturedAt);assert.deepEqual(view.mutation,{active:true,blocked:false,phase:'idle',revision:'1',retained:0});
 assert.deepEqual(f.fixture.session.capabilities,['read','windows_update_install','windows_update_schedule']);
 for(const profile of [null,false,true,'manual','combined',{},1])assert.throws(()=>createWindowsUpdateScheduleFixture(profile));
});
test('combined background reserves once with separate exact approval, saved window and cancellation readback',async()=>{
 const f=setup('background');assert.deepEqual(await f.invoke('/schedule',post(approval(f))),{abort:'blockedbyclient'});await reviewed(f);
 for(const body of [{...approval(f),acknowledged:false},{...approval(f),endAt:f.fixture.scheduleWindow.endAt+60},{...approval(f),previewDigest:'sha256:'+'0'.repeat(64)}])assert.deepEqual(await f.invoke('/schedule',post(body)),{abort:'blockedbyclient'});
 const saved=(await f.invoke('/schedule',post(approval(f)))).value;assert.equal(saved.backgroundScheduling,true);assert.equal(saved.job.state,'scheduled');assert.equal(saved.job.preview,null);assert.equal(saved.job.result,null);assert.equal(saved.job.schedule.permitIssuedAt,0);assert.deepEqual(saved.job.selection,f.fixture.selection);
 assert.deepEqual(saved.job.schedule,{version:'tracebolt.windows-selected-update-schedule.v1',digest:f.fixture.scheduleDigest,approvedAt:Date.parse(f.fixture.now)/1000,...f.fixture.scheduleWindow,permitIssuedAt:0,revoked:false});
 assert.deepEqual((await f.invoke('?jobId='+id)).value,saved);assert.equal((await f.invoke('?history=1')).value.remainingCapacity,31);
 assert.deepEqual(await f.invoke('/schedule',post(approval(f))),{abort:'blockedbyclient'});
 const canceled=(await f.invoke('/cancel-schedule',post(cancel(f)))).value;assert.equal(canceled.backgroundScheduling,true);assert.equal(canceled.job.state,'schedule_canceled');assert.deepEqual(canceled.job.schedule,saved.job.schedule);assert.deepEqual(canceled.mutation,saved.mutation);assert.equal(canceled.executorObservedAt,saved.executorObservedAt);
 assert.deepEqual((await f.invoke()).value,canceled);assert.equal((await f.invoke('?history=1')).value.remainingCapacity,31);assert.deepEqual(await f.invoke('/cancel-schedule',post(cancel(f))),{abort:'blockedbyclient'});
 assert.deepEqual(f.fixture.scheduleCounts,{schedule:1,cancel:1,immediateInstallWrites:0});assert.equal(f.fixture.updateCounts.request,1);assert.equal(f.fixture.updateCounts.preview,1);assert.equal(f.fixture.updateCounts.approve,0);assert.deepEqual(f.state.external,[]);
});
const backgroundEvidence=()=>['status','review','pending','canceled'].flatMap(kind=>['en','de'].flatMap(locale=>[1440,390].map(width=>({file:`synthetic-windows-background-update-schedule-${kind}-${width}-${locale}.png`,sourceSha,test:windowsBackgroundUpdateScheduleCaseName,locale,viewport:{width,height:width===390?844:1000},publicSafe:true,fullPage:false,fixtureDisclosure:windowsBackgroundUpdateScheduleDisclosure}))));
test('combined evidence requires separate source-bound status and UTC approval captures in every locale and viewport',()=>{
 assert.deepEqual(requireWindowsBackgroundUpdateScheduleEvidence(backgroundEvidence(),sourceSha),{screens:16,nativeAcceptance:false});
 for(const mutate of [r=>r.pop(),r=>r.push(r[0]),r=>{r[1]=r[0];},r=>{r[0].file='synthetic-windows-update-schedule-review-1440-en.png';},r=>{r[0].sourceSha='b'.repeat(40);},r=>{r[0].locale='de';},r=>{r[0].viewport.width=800;},r=>{r[0].viewport.height=844;},r=>{r[0].fullPage=true;},r=>{r[0].publicSafe=false;},r=>{r[0].fixtureDisclosure=windowsUpdateScheduleDisclosure;},r=>{r[0].test=windowsUpdateScheduleCaseName;}]){const rows=backgroundEvidence();mutate(rows);assert.throws(()=>requireWindowsBackgroundUpdateScheduleEvidence(rows,sourceSha));}
 assert.throws(()=>requireWindowsBackgroundUpdateScheduleEvidence(backgroundEvidence(),null));assert.throws(()=>requireWindowsBackgroundUpdateScheduleEvidence(evidence(),sourceSha));assert.throws(()=>requireWindowsUpdateScheduleEvidence(backgroundEvidence(),sourceSha));
});
test('hosted combined supplement preserves earlier gates, real screenshot helper and exact bounded runner',()=>{
 const runner=read('./windows-service-actions-runner.mjs'),helper=read('./windows-update-schedule-browser.mjs');
 assert.ok(runner.includes("for(const scheduleProfile of ['standalone','background'])"));assert.match(runner,/createWindowsUpdateScheduleFixture\(scheduleProfile\)/);assert.match(runner,/requireWindowsBackgroundUpdateScheduleEvidence\(backgroundScheduleScreenshots,sourceSha\)/);assert.match(runner,/backgroundScheduleVariants.length!==4/);assert.match(runner,/\.\.\.backgroundScheduleScreenshots/);assert.match(runner,/backgroundScheduleVariants:passed\?backgroundScheduleVariants:\[\]/);
 for(const hook of ["capture('status')","capture('review',scheduleDetails)","capture('pending',jobStatus)","capture('canceled')","await manual.check();await expect(ack).not.toBeChecked();await expect(approve).toBeDisabled();await manual.uncheck()","await expect(executor).toBeInViewport()","await expect(shared).toBeInViewport()","Approved UTC windows","Availability not checked live","separately activated background update service and observer","No download, license acceptance, reboot or retry"])assert.ok(helper.includes(hook),hook);
 assert.equal((runner.match(/120000/g)||[]).length,1);assert.match(runner,/requireWindowsUpdateScheduleEvidence\(scheduleScreenshots,sourceSha\)/);assert.match(runner,/requireWindowsUpdateJobsEvidence\(updateScreenshots,sourceSha\)/);
 // The dedicated manual-background coexistence case remains a required independent gate.
 assert.match(read('./windows-mutation-coexistence-browser.mjs'),/Background update service · Manual approvals only/);assert.match(read('./windows-mutation-coexistence-fixtures.test.mjs'),/schedulingAvailable/);
 assert.match(windowsBackgroundUpdateScheduleDisclosure,/Fresh combined-background scheduling profile/);assert.match(windowsBackgroundUpdateScheduleDisclosure,/availability is not checked live/);
});


test('fleet scheduling fixture keeps two exact independent bindings and a fixed common UTC window',()=>{
 const f=createWindowsFleetUpdateScheduleFixture(),first=f.updateView(),second=f.secondUpdateView(),history=f.secondUpdateHistory();
 assert.equal(first.deviceId,f.device.id);assert.equal(first.job,null);assert.equal(first.backgroundScheduling,true);
 assert.equal(second.deviceId,f.secondDevice.id);assert.notEqual(second.deviceId,first.deviceId);assert.equal(second.schedulingAvailable,false);assert.equal(second.schedulingRevoked,true);assert.equal(second.job.state,'schedule_blocked');assert.equal(second.job.reason,'schedule_authority_revoked');assert.equal(second.job.schedule.revoked,true);assert.equal(second.job.schedule.permitIssuedAt,0);
 assert.deepEqual(second.job.selection,f.secondSelection);assert.notDeepEqual(second.job.selection,f.selection);assert.equal(second.job.schedule.startAt,f.scheduleWindow.startAt);assert.equal(second.job.schedule.endAt,f.scheduleWindow.endAt);assert.notEqual(second.job.schedule.digest,f.scheduleDigest);
 assert.equal(history.remainingCapacity,31);assert.equal(history.jobs[0].id,f.secondSavedID);assert.deepEqual(history.jobs[0].schedule,second.job.schedule);assert.equal(history.jobs[0].approvedAt,0);assert.equal(history.jobs[0].claimedAt,0);
 second.job.schedule.endAt++;history.jobs[0].schedule.revoked=false;assert.equal(f.secondUpdateView().job.schedule.endAt,f.scheduleWindow.endAt);assert.equal(f.secondUpdateHistory().jobs[0].schedule.revoked,true);
 assert.deepEqual(f.secondPostAttempts,{request:0,preview:0,approve:0,other:0});assert.deepEqual(f.scheduleCounts,{schedule:0,cancel:0,immediateInstallWrites:0});
});
test('one synthetic fleet approval never advances or replaces the other saved device schedule',async()=>{
 const f=setup('background',createWindowsFleetUpdateScheduleFixture()),secondPath='/api/devices/'+f.fixture.secondDevice.id+'/windows-update-jobs';
 const before=(await f.invokePath(secondPath)).value;await reviewed(f);
 assert.deepEqual(await f.invoke('/schedule',post({...approval(f),endAt:f.fixture.scheduleWindow.endAt+60})),{abort:'blockedbyclient'});
 const saved=(await f.invoke('/schedule',post(approval(f)))).value;assert.equal(saved.job.state,'scheduled');assert.deepEqual(saved.job.selection,f.fixture.selection);assert.equal(saved.job.schedule.startAt,f.fixture.scheduleWindow.startAt);assert.equal(saved.job.schedule.endAt,f.fixture.scheduleWindow.endAt);
 assert.deepEqual((await f.invoke('?jobId='+id)).value,saved);assert.deepEqual((await f.invokePath(secondPath+'?jobId='+f.fixture.secondSavedID)).value,before);assert.equal((await f.invokePath(secondPath+'?history=1')).value.jobs[0].state,'schedule_blocked');
 assert.deepEqual(f.fixture.scheduleCounts,{schedule:1,cancel:0,immediateInstallWrites:0});assert.deepEqual(f.fixture.secondPostAttempts,{request:0,preview:0,approve:0,other:0});assert.deepEqual(f.fixture.secondUpdateCounts,{request:0,preview:0,approve:0,status:2});assert.deepEqual(f.state.external,[]);assert.equal(f.assetState().continued,false);
});
test('fleet peer mutation routes stay rejected and counted rather than gaining authority from selection',async()=>{
 const f=setup('background',createWindowsFleetUpdateScheduleFixture()),secondPath='/api/devices/'+f.fixture.secondDevice.id+'/windows-update-jobs';
 for(const operation of ['request','preview','approve','schedule','cancel-schedule','revoke-scheduling'])assert.deepEqual(await f.invokePath(secondPath+'/'+operation,post({})),{abort:'blockedbyclient'});
 assert.deepEqual(f.fixture.secondPostAttempts,{request:1,preview:1,approve:1,other:3});assert.deepEqual(f.fixture.scheduleCounts,{schedule:0,cancel:0,immediateInstallWrites:0});assert.equal(f.fixture.updateCounts.request,0);assert.equal(f.fixture.secondUpdateView().job.state,'schedule_blocked');
 for(const query of ['?jobId='+id,'?history=1&extra=1'])assert.deepEqual(await f.invokePath(secondPath+query),{abort:'blockedbyclient'});
});
const fleetEvidence=()=>windowsFleetUpdateScheduleScenes.flatMap(kind=>['en','de'].flatMap(locale=>[1440,390].map(width=>({file:`synthetic-windows-fleet-update-schedule-${kind}-${width}-${locale}.png`,sourceSha,test:windowsFleetUpdateScheduleCaseName,locale,viewport:{width,height:width===390?844:1000},publicSafe:true,fullPage:false,fixtureDisclosure:windowsFleetUpdateScheduleDisclosure}))));
test('fleet captures require exactly three distinct scenes in both locales and viewports at the exact source',()=>{
 assert.deepEqual(windowsFleetUpdateScheduleScenes,['cached-triage','shared-window-review','per-device-summary']);assert.equal(Object.isFrozen(windowsFleetUpdateScheduleScenes),true);assert.deepEqual(requireWindowsFleetUpdateScheduleEvidence(fleetEvidence(),sourceSha),{screens:12,nativeAcceptance:false});
 for(const mutate of [r=>r.pop(),r=>r.push(r[0]),r=>{r[1]=r[0];},r=>{r[0].file='synthetic-windows-update-schedule-review-1440-en.png';},r=>{r[0].sourceSha='b'.repeat(40);},r=>{r[0].locale='de';},r=>{r[0].viewport.width=800;},r=>{r[0].viewport.height=844;},r=>{r[0].fullPage=true;},r=>{r[0].publicSafe=false;},r=>{r[0].fixtureDisclosure=windowsBackgroundUpdateScheduleDisclosure;},r=>{r[0].test=windowsBackgroundUpdateScheduleCaseName;}]){const rows=fleetEvidence();mutate(rows);assert.throws(()=>requireWindowsFleetUpdateScheduleEvidence(rows,sourceSha));}
 assert.throws(()=>requireWindowsFleetUpdateScheduleEvidence(fleetEvidence().filter(row=>!row.file.includes('cached-triage')),sourceSha));
 assert.throws(()=>requireWindowsFleetUpdateScheduleEvidence(fleetEvidence(),null));assert.throws(()=>requireWindowsFleetUpdateScheduleEvidence(backgroundEvidence(),sourceSha));assert.throws(()=>requireWindowsBackgroundUpdateScheduleEvidence(fleetEvidence(),sourceSha));
});
test('common-window scenes are additive to the existing intercepted gate without new timeout or weaker original checks',()=>{
 const runner=read('./windows-service-actions-runner.mjs'),helper=read('./windows-update-schedule-browser.mjs'),workflow=read('../../.github/workflows/validate.yml');
 assert.equal(typeof exerciseWindowsFleetUpdateSchedule,'function');assert.match(runner,/windowsFleetUpdateScheduleScenes.some\(scene=>/);assert.match(runner,/requireWindowsFleetUpdateScheduleDetails\(fleetDetails\)/);assert.match(runner,/createWindowsFleetUpdateScheduleFixture\(\)/);assert.match(runner,/requireWindowsFleetUpdateScheduleEvidence\(fleetScheduleScreenshots,sourceSha\)/);assert.match(runner,/fleetScheduleVariants.length!==4/);assert.match(runner,/\.\.\.fleetScheduleScreenshots/);assert.match(runner,/fleetState.blocked\)\.toEqual\(\[\]\)/);assert.match(runner,/fleetState.external\)\.toEqual\(\[\]\)/);assert.match(runner,/fleetStorage.includes\(value\)/);
 assert.equal((runner.match(/120000/g)||[]).length,1);for(const check of ['requireWindowsServiceActionsEvidence','requireWindowsServiceActionHistoryEvidence','requireWindowsUpdateJobsEvidence','requireWindowsUpdateScheduleEvidence','requireWindowsBackgroundUpdateScheduleEvidence','requireWindowsSoftwareJobsEvidence'])assert.ok(runner.includes(check+'('));
 for(const hook of ["capture('cached-triage',triage)","await readCached.click()","Reports read: 2/2 · Partial / truncated: 0 · Stale: 0 · Unavailable: 0","Gemeldet: 1 · Heruntergeladen: 1 · Herstellerschweregrad: Kritisch","await expect(row.locator('details')).not.toHaveAttribute('open')","await expect(triage.getByRole('status')).toBeInViewport({ratio:1})","await reviewPair(fixture.selection).click()","await showAll.click()","expect(fixture.fleetInventoryReads).toEqual({first:0,second:0})","expect(fixture.fleetInventoryReads).toEqual({first:1,second:1})","expect(fixture.fleetInventoryReads).toEqual({first:2,second:1})","await expect(panel.getByRole('combobox')).toHaveCount(0)","capture('shared-window-review',schedule)","capture('per-device-summary',worklist.locator('.windows-fleet-update-list'))","await expect(ack).not.toBeChecked();await expect(approve).toBeDisabled()","await expect(summary).toBeInViewport({ratio:1})","expect(fixture.secondUpdateCounts.status).toBe(0)","expect(fixture.updateReads.exact).toBeGreaterThan(0)"])assert.ok(helper.includes(hook),hook);
 assert.match(workflow,/node tests\/e2e-review\/windows-service-actions-runner.mjs/);assert.match(workflow,/artifacts\/review\/synthetic-\*\.png/);assert.match(workflow,/artifacts\/review\/windows-service-actions-manifest.json/);
 assert.match(windowsFleetUpdateScheduleDisclosure,/second device.*GETs only/);assert.match(windowsFleetUpdateScheduleDisclosure,/no real API request or mutation/);assert.doesNotMatch(helper,/chromium\.launch|createServer|writeFile|execFile|spawn\(|fetch\(|page\.request|newContext\(|route\.continue|route\.fetch|setTimeout/);
});


test('fleet cached triage reads exact inventory GETs without readiness, peer mutation or refreshed capture time',async()=>{
 const f=setup('background',createWindowsFleetUpdateScheduleFixture()),firstPath='/api/devices/'+f.fixture.device.id+'/windows-inventory',secondPath='/api/devices/'+f.fixture.secondDevice.id+'/windows-inventory';
 assert.deepEqual(f.fixture.fleetInventoryReads,{first:0,second:0});
 const first=(await f.invokePath(firstPath)).value,second=(await f.invokePath(secondPath)).value;
 assert.deepEqual(f.fixture.fleetInventoryReads,{first:1,second:1});assert.equal(first.deviceId,f.fixture.device.id);assert.equal(second.deviceId,f.fixture.secondDevice.id);
 assert.deepEqual(first.updates.rows[0].kbArticleIds,['KB1000000']);assert.deepEqual(second.updates.rows[0].kbArticleIds,first.updates.rows[0].kbArticleIds);assert.equal(second.updates.rows[0].title,first.updates.rows[0].title);
 assert.notEqual(second.updates.rows[0].updateId,first.updates.rows[0].updateId);assert.notEqual(second.updates.rows[0].revision,first.updates.rows[0].revision);
 assert.deepEqual((await f.invokePath(firstPath)).value,first);assert.deepEqual(f.fixture.fleetInventoryReads,{first:2,second:1});
 assert.equal(first.updates.collectedAt,f.fixture.now);assert.equal(second.updates.collectedAt,f.fixture.now);assert.equal(first.updates.cacheFreshness,'unknown');
 assert.equal(f.fixture.updateCounts.request,0);assert.equal(f.fixture.updateCounts.preview,0);assert.equal(f.fixture.updateCounts.approve,0);
 assert.deepEqual(f.fixture.updateReads,{current:0,history:0,exact:0});assert.deepEqual(f.fixture.secondUpdateReads,{current:0,history:0,exact:0});assert.deepEqual(f.fixture.secondPostAttempts,{request:0,preview:0,approve:0,other:0});assert.deepEqual(f.fixture.scheduleCounts,{schedule:0,cancel:0,immediateInstallWrites:0});assert.deepEqual(f.state,{blocked:[],external:[]});
});
test('fleet inventory read counters exclude invalid method, origin, query and body attempts',async()=>{
 for(const target of ['device','secondDevice'])for(const change of [{method:'POST'},{method:'PUT'},{raw:'{}'},{origin:'https://outside.invalid'}]){
  const f=setup('background',createWindowsFleetUpdateScheduleFixture()),path='/api/devices/'+f.fixture[target].id+'/windows-inventory';
  assert.deepEqual(await f.invokePath(path,change),{abort:'blockedbyclient'});assert.deepEqual(f.fixture.fleetInventoryReads,{first:0,second:0});assert.equal(f.fixture.updateCounts.request,0);assert.equal(f.fixture.scheduleCounts.schedule,0);
 }
 for(const target of ['device','secondDevice']){
  const f=setup('background',createWindowsFleetUpdateScheduleFixture());assert.deepEqual(await f.invokePath('/api/devices/'+f.fixture[target].id+'/windows-inventory?refresh=1'),{abort:'blockedbyclient'});assert.deepEqual(f.fixture.fleetInventoryReads,{first:0,second:0});
 }
});
const fleetDetails=()=>({explicitCachedRead:true,cachedReadGETOnly:true,exactPairsKeptSeparate:true,selectedReportingDevicesOnly:true,freshSelectedInventoryRead:true,fixedExactSelection:true,showAllFrozenDevices:true,compactCachedTriageCapture:true,visibleTriageCounts:true,cachedInventoryReads:2,exactTriagePairs:2,sharedWindowExact:true,explicitUncheckedPerDeviceApproval:true,noAutomaticNextDevice:true,independentSavedStates:true,exactSavedReadback:true,syntheticScheduleRequests:1,secondDeviceMutationRequests:0,immediateInstallWrites:0,requestsToRealAPI:0,nativeAcceptance:false});
test('fleet behavioral gate rejects omitted or altered triage boundaries even with a complete image manifest',()=>{
 assert.deepEqual(requireWindowsFleetUpdateScheduleDetails(fleetDetails()),{cachedInventoryReads:2,exactTriagePairs:2,syntheticScheduleRequests:1,secondDeviceMutationRequests:0,nativeAcceptance:false});
 for(const key of Object.keys(fleetDetails())){
  const missing=fleetDetails();delete missing[key];assert.throws(()=>requireWindowsFleetUpdateScheduleDetails(missing),key);
  const altered=fleetDetails();altered[key]=typeof altered[key]==='boolean'?!altered[key]:altered[key]+1;assert.throws(()=>requireWindowsFleetUpdateScheduleDetails(altered),key);
 }
 for(const invalid of [null,undefined,false,[],{}])assert.throws(()=>requireWindowsFleetUpdateScheduleDetails(invalid));
});

// Inert actual production DOM and installed Playwright locator/selector semantics.
// No browser, layout, screenshot, listener, network or native acceptance claim.
test('fleet triage exact-pair row selectors stay relative to each row in EN/DE',async()=>{
 const require=createRequire(new URL('../../web/package.json',import.meta.url)),{JSDOM}=require('jsdom');
 const playwrightRoot=path.dirname(require.resolve('playwright-core/package.json'));
 const {source}=require(path.join(playwrightRoot,'lib/generated/injectedScriptSource.js'));
 const {Locator}=require(path.join(playwrightRoot,'lib/client/locator.js'));
 const {getByRoleSelector}=require(path.join(playwrightRoot,'lib/utils/isomorphic/locatorUtils.js'));
 const built=await require('esbuild').build({stdin:{contents:`
  import {createRoot} from 'react-dom/client';
  import {WindowsFleetUpdateTriage} from './windows-fleet-update-triage';
  import {groupFleetUpdates} from './windows-fleet-update-triage-resource';
  import {setLocale} from './i18n';
  window.mount=(fixture,locale)=>{
   setLocale(locale,false);
   const reports=[fixture.inventory,fixture.secondInventory].map(value=>({...value,started:{mono:performance.now(),wall:Date.now()},accepted:{mono:performance.now(),wall:Date.now()}}));
   createRoot(document.getElementById('root')).render(<WindowsFleetUpdateTriage devices={[fixture.device,fixture.secondDevice]} selected={null} onSelect={()=>{}} triage={{reports,groups:groupFleetUpdates(reports),hasRead:true,loading:false,read:()=>{},clear:()=>{}}}/>);
  };`,resolveDir:fileURLToPath(new URL('../../web/src/',import.meta.url)),loader:'tsx'},outdir:'inert-memory-only',bundle:true,platform:'browser',format:'iife',jsx:'automatic',define:{'process.env.NODE_ENV':'"production"'},write:false,logLevel:'silent'});
 assert.ok(exerciseWindowsFleetUpdateSchedule.toString().includes('windowsFleetUpdateTriageRow(triageRows,page,selection,locale)'));
 for(const locale of ['en','de']){
  const fixture=createWindowsFleetUpdateScheduleFixture();
  const dom=new JSDOM('<!doctype html><html><body><section class="windows-fleet-update-worklist"><div id="root"></div></section></body></html>',{url:'https://synthetic.invalid',runScripts:'outside-only',pretendToBeVisual:true});
  try{
   const window=dom.window;window.fetch=()=>{throw new Error('Inert selector regression forbids requests')};Object.assign(window,{TextEncoder,TextDecoder,structuredClone});
   window.eval(built.outputFiles.find(file=>file.path.endsWith('.js')).text);window.mount(fixture,locale);
   for(let attempt=0;attempt<100&&!window.document.querySelector('.windows-fleet-update-triage-list>li');attempt++)await new Promise(resolve=>setTimeout(resolve,10));
   // JSDOM lacks pseudo-element styles; this fixture defines no pseudo content.
   const computed=window.getComputedStyle.bind(window);window.getComputedStyle=element=>computed(element);
   window.module={exports:{}};window.eval(source+'\nthis.injected=new InjectedScript(window,{isUnderTest:true,sdkLanguage:"javascript",testIdAttributeName:"data-testid",stableRafCount:1,browserName:"chromium",customEngines:[]});');
   const frame={_platform:{}},page={getByRole:(role,options)=>new Locator(frame,getByRoleSelector(role,options))};
   const triage=new Locator(frame,'.windows-fleet-update-worklist').locator('.windows-fleet-update-triage'),rows=triage.locator('.windows-fleet-update-triage-list > li');
   const query=locator=>window.injected.querySelectorAll(window.injected.parseSelector(locator._selector),window.document);
   assert.equal(query(rows).length,2);
   const matched=[];
   for(const selection of [fixture.selection,fixture.secondSelection]){
    const options={name:(locale==='de'?'Meldende Geräte prüfen':'Review reporting devices')+`: ${selection.updateId} · rev. ${selection.revision}`,exact:true};
    assert.equal(query(triage.getByRole('button',options)).length,1);
    assert.equal(query(rows.filter({has:triage.getByRole('button',options)})).length,0,'Original ancestor-scoped locator must reproduce zero rows');
    const found=query(windowsFleetUpdateTriageRow(rows,page,selection,locale));assert.equal(found.length,1);
    assert.equal(found[0].querySelector('button').getAttribute('aria-label'),options.name);
    assert.ok(found[0].textContent.includes('KB1000000'));assert.equal(found[0].querySelector('details').open,false);matched.push(found[0]);
    const absent={...selection,revision:selection.revision+100};assert.equal(query(windowsFleetUpdateTriageRow(rows,page,absent,locale)).length,0);
   }
   assert.notEqual(matched[0],matched[1],'Same display metadata must retain two exact-pair rows');
  }finally{dom.window.close();}
 }
});
