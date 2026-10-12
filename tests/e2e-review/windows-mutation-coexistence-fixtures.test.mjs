/** Inert read-only route and hosted-evidence contracts. No browser is launched. */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createWindowsMutationCoexistenceFixture,windowsMutationCoexistenceRoute,windowsMutationCoexistenceOrigin,windowsMutationCoexistenceCaseName,windowsMutationCoexistenceDisclosure,requireWindowsMutationCoexistenceDetails,requireWindowsMutationCoexistenceEvidence,requireWindowsMutationCoexistenceReport} from './windows-mutation-coexistence-browser.mjs';
const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8');
function setup(owner){
 const fixture=createWindowsMutationCoexistenceFixture(owner),base=windowsMutationCoexistenceOrigin,prefix='/api/devices/'+fixture.device.id,state={blocked:[],external:[]},headers={'x-csrf-token':fixture.session.csrfToken,origin:base,'content-type':'application/json'};let assetPath=null,continued=false;
 const handler=windowsMutationCoexistenceRoute({base,fixture,state,asset:async(_,path)=>{assetPath=path;}});
 const invoke=async(path,{method='GET',raw=null,headers:sent=headers,origin=base}={})=>{let result;await handler({request:()=>({url:()=>origin+path,method:()=>method,postData:()=>raw,headers:()=>sent}),fulfill:async value=>{result={status:value.status,value:JSON.parse(value.body)};},abort:async value=>{result={abort:value};},continue:async()=>{continued=true;}});return result;};
 return {fixture,prefix,state,headers,invoke,assetState:()=>({assetPath,continued})};
}

test('both exact coordinated views share the original blocker and retain outcomes after release',()=>{
 for(const domain of ['managed_msi','cached_wua']){
  const f=createWindowsMutationCoexistenceFixture(domain),before=f.coexistenceSaved('software'),update=f.coexistenceSaved('updates');
  assert.equal(before.coordinated,true);assert.equal(update.coordinated,true);assert.deepEqual(before.mutation,update.mutation);assert.equal(before.mutation.domain,domain);assert.equal(before.mutation.jobId,f.coexistenceJob);assert.equal(before.mutation.phase,'completion_recorded');assert.equal(before.mutation.recovery,'exact_terminal_receipt');
  assert.equal(before.result.attempted,domain==='managed_msi');assert.equal(update.job.result.attempted,domain==='cached_wua');assert.equal(before.readiness,null);assert.equal(update.job.preview,null);assert.equal(update.available,false);assert.equal(before.canReview,false);
  const original=structuredClone(before.result),originalUpdate=structuredClone(update.job.result);before.mutation.jobId='changed';before.result.outcome='changed';assert.notEqual(f.coexistenceSaved('software').result.outcome,'changed');
  f.coexistenceSetPhase('released');const after=f.coexistenceSaved('software'),afterUpdate=f.coexistenceSaved('updates');assert.deepEqual(after.result,original);assert.deepEqual(afterUpdate.job.result,originalUpdate);assert.deepEqual(after.mutation,afterUpdate.mutation);assert.equal(after.mutation.blocked,false);assert.equal(after.mutation.phase,'idle');assert.equal(after.mutation.retained,1);assert.equal(Object.hasOwn(after.mutation,'domain'),false);assert.equal(Object.hasOwn(after.mutation,'jobId'),false);
  assert.throws(()=>f.coexistenceSetPhase('blocked'));assert.throws(()=>f.coexistenceSetPhase('released'));assert.throws(()=>f.coexistenceSaved('other'));
 }
 assert.throws(()=>createWindowsMutationCoexistenceFixture('service_actions'));
});

test('read-only routes mount independent MSI and update status, exact saved job and history',async()=>{
 const f=setup(),msi=f.prefix+'/windows-managed-msi',updates=f.prefix+'/windows-update-jobs';
 const a=(await f.invoke(msi)).value,b=(await f.invoke(updates)).value;assert.deepEqual(a.mutation,b.mutation);
 assert.deepEqual((await f.invoke(updates+'?jobId='+f.fixture.savedID())).value,b);assert.equal((await f.invoke(updates+'?history=1')).value.jobs[0].id,f.fixture.savedID());
 f.fixture.coexistenceSetPhase('released');assert.equal((await f.invoke(msi)).value.mutation.blocked,false);assert.equal((await f.invoke(updates)).value.mutation.blocked,false);
 assert.deepEqual(f.fixture.coexistenceCounts,{softwareReads:2,updateReads:3,historyReads:1,mutationWrites:0,secondTargetWrites:0});assert.deepEqual(f.state,{blocked:[],external:[]});
});

test('no fixture write can approve, install, release, reset or operate a second target',async()=>{
 const f=setup();
 for(const [domain,ops] of [['windows-managed-msi',['reserve','upload','complete','deliver','review','review-coordinated','approve','release','unlock','recover']],['windows-update-jobs',['request','preview','approve','schedule','release','unlock','recover']],['windows-service-actions',['approve']],['windows-software-jobs',['approve']]]){
  for(const op of ops)assert.deepEqual(await f.invoke(f.prefix+'/'+domain+'/'+op,{method:'POST',raw:'{}'}),{abort:'blockedbyclient'});
 }
 for(const method of ['POST','PUT','PATCH','DELETE'])assert.deepEqual(await f.invoke('/api/devices/'+f.fixture.secondDevice.id+'/windows-managed-msi/approve',{method,raw:'{}'}),{abort:'blockedbyclient'});
 assert.equal(f.fixture.coexistenceCounts.secondTargetWrites,4);assert.equal(f.fixture.coexistenceCounts.mutationWrites,23);assert.equal(f.fixture.coexistencePhase(),'blocked');assert.deepEqual(f.fixture.managedAttempts,{reserve:0,upload:0,complete:0,deliver:0,review:0,approve:0});assert.equal(f.fixture.updateCounts.approve,0);assert.equal(f.fixture.softwareCounts.approve,0);
});

test('status routes reject aliases, body-bearing reads, header drift and foreign origins',async()=>{
 const f=setup(),paths=[f.prefix+'/windows-managed-msi/',f.prefix+'/windows-managed-msi?x=1',f.prefix+'/windows-managed-msi/recover',f.prefix+'/windows-update-jobs/',f.prefix+'/windows-update-jobs?history=01',f.prefix+'/windows-update-jobs?jobId=update_'+'f'.repeat(32),'/api/devices/'+f.fixture.secondDevice.id+'/windows-update-jobs'];
 for(const p of paths)assert.deepEqual(await f.invoke(p),{abort:'blockedbyclient'});
 const p=f.prefix+'/windows-managed-msi';assert.deepEqual(await f.invoke(p,{raw:'{}'}),{abort:'blockedbyclient'});assert.deepEqual(await f.invoke(p,{origin:'https://outside.invalid'}),{abort:'blockedbyclient'});
 for(const k of ['content-encoding','range','content-range','content-disposition','forwarded','proxy-authorization','x-forwarded-host'])assert.deepEqual(await f.invoke(p,{headers:{...f.headers,[k]:'invalid'}}),{abort:'blockedbyclient'});
 assert.equal(f.fixture.coexistenceCounts.softwareReads,0);assert.equal(f.fixture.coexistenceCounts.updateReads,0);
});

test('bounded inventory-query POST remains read-only and asset traffic never escapes',async()=>{
 const f=setup(),query={search:'',sort:'name-asc',limit:100,cursor:''};
 assert.equal((await f.invoke(f.prefix+'/windows-full-software/query',{method:'POST',raw:JSON.stringify(query)})).value.status,'not_configured');
 assert.deepEqual(await f.invoke(f.prefix+'/windows-full-software/query',{method:'POST',raw:JSON.stringify({...query,limit:10000})}),{abort:'blockedbyclient'});
 await f.invoke('/assets/app.js');assert.deepEqual(f.assetState(),{assetPath:'/assets/app.js',continued:false});assert.equal(f.fixture.coexistenceCounts.mutationWrites,0);
});

const sha='a'.repeat(40),evidence=()=>['software','updates'].flatMap(surface=>['blocked','released'].flatMap(phase=>['en','de'].flatMap(locale=>[1440,390].map(width=>({file:`synthetic-windows-mutation-coexistence-${surface}-${phase}-${width}-${locale}.png`,sourceSha:sha,test:windowsMutationCoexistenceCaseName,locale,viewport:{width,height:width===390?844:1000},publicSafe:true,fullPage:false,fixtureDisclosure:windowsMutationCoexistenceDisclosure,sha256:'b'.repeat(64)})))));
const details=()=>({softwareMounted:true,updatesMounted:true,blockedSharedOwner:true,exactRecoveryReadback:true,compactSummary:true,releasedReadback:true,originalOutcomesRetained:true,reloadReadback:true,backgroundRecentEvidence:true,backgroundUnknownAvailability:true,manualOnly:true,readOnly:true,softwareReads:6,updateReads:6,mutationWrites:0,secondTargetWrites:0,realAPIRequests:0,nativeAcceptance:false});
const manifest=()=>({sourceSha:sha,screenshots:evidence()});
const report=()=>({sourceSha:sha,createdAt:'2026-10-12T00:00:00.000Z',name:windowsMutationCoexistenceCaseName,status:'PASS',stage:'complete',scope:windowsMutationCoexistenceDisclosure,variants:['en','de'].flatMap(locale=>[1440,390].map(width=>({locale,width,...details()}))),runtimeErrorCount:0,requestsToRealAPI:0,browserAcceptance:true,durableStoreAcceptance:false,nativeAcceptance:false,secretsExported:false,realTelemetryExported:false});

test('sixteen exact-source screenshots cover both mounted views, phases, locales and widths',()=>{
 assert.deepEqual(requireWindowsMutationCoexistenceEvidence(evidence(),sha),{screens:16,readOnly:true,nativeAcceptance:false});
 for(const change of [r=>r.pop(),r=>r.push(r[0]),r=>{r[1]=r[0]},r=>{r[0].sourceSha='c'.repeat(40)},r=>{r[0].file=r[0].file.replace('software','updates')},r=>{r[0].locale='de'},r=>{r[0].viewport.height=844},r=>{r[0].viewport.scale=1},r=>{r[0].fullPage=true},r=>{r[0].publicSafe=false},r=>{r[0].fixtureDisclosure='native accepted'},r=>{r[0].test='other'},r=>{r[0].sha256='wrong'},r=>{r[0].extra=true}]){const rows=evidence();change(rows);assert.throws(()=>requireWindowsMutationCoexistenceEvidence(rows,sha));}
 assert.throws(()=>requireWindowsMutationCoexistenceEvidence(evidence(),'bad'));
});

test('behavior evidence requires both actual mounts, recovery readback, reload and zero writes',()=>{
 assert.deepEqual(requireWindowsMutationCoexistenceDetails(details()),{readOnly:true,nativeAcceptance:false});
 for(const key of Object.keys(details())){const d=details();delete d[key];assert.throws(()=>requireWindowsMutationCoexistenceDetails(d));}
 for(const patch of [{softwareMounted:false},{updatesMounted:false},{exactRecoveryReadback:false},{compactSummary:false},{readOnly:false},{softwareReads:1},{updateReads:0},{mutationWrites:1},{secondTargetWrites:1},{realAPIRequests:1},{nativeAcceptance:true},{extra:true}])assert.throws(()=>requireWindowsMutationCoexistenceDetails({...details(),...patch}));
});

test('hosted report root and manifest fail closed on omissions, drift or unsafe claims',()=>{
 assert.deepEqual(requireWindowsMutationCoexistenceReport(report(),manifest(),sha),{variants:4,screens:16,readOnly:true,nativeAcceptance:false});
 for(const key of Object.keys(report())){const r=report();delete r[key];assert.throws(()=>requireWindowsMutationCoexistenceReport(r,manifest(),sha));}
 for(const patch of [{sourceSha:'c'.repeat(40)},{createdAt:'invalid'},{name:'other'},{status:'FAIL'},{stage:'blocked'},{scope:'native accepted'},{runtimeErrorCount:1},{requestsToRealAPI:1},{browserAcceptance:false},{durableStoreAcceptance:true},{nativeAcceptance:true},{secretsExported:true},{realTelemetryExported:true},{extra:true}])assert.throws(()=>requireWindowsMutationCoexistenceReport({...report(),...patch},manifest(),sha));
 for(const change of [v=>v.pop(),v=>{v[1]=v[0]},v=>{v[0].width=800},v=>{v[0].mutationWrites=1}]){const r=report();change(r.variants);assert.throws(()=>requireWindowsMutationCoexistenceReport(r,manifest(),sha));}
 for(const change of [m=>{delete m.sourceSha},m=>{m.sourceSha='c'.repeat(40)},m=>{m.extra=true},m=>{m.screenshots.pop()}]){const m=manifest();change(m);assert.throws(()=>requireWindowsMutationCoexistenceReport(report(),m,sha));}
});

test('additive hosted source uses production validators, both mounted panes and no network fallback',()=>{
 const helper=read('./windows-mutation-coexistence-browser.mjs'),runner=read('./windows-mutation-coexistence-runner.mjs');
 assert.doesNotMatch(helper,/chromium\.launch|createServer|writeFile|execFile|spawn\(|fetch\(|page\.request|newContext\(|route\.continue|route\.fetch|setTimeout|addStyleTag|setViewportSize/);
 assert.doesNotMatch(runner,/createServer|route\.continue|route\.fetch|fetch\(|page\.request|ignoreHTTPSErrors|executablePath/);
 for(const gate of ['validManagedView(value,fixture.device.id)','validUpdateJobView(value,fixture.device.id,fixture.session.actorId)','validUpdateJobHistory(history,fixture.device.id,fixture.session.actorId)','validMutationStatus(shared.mutation)',"'.managed-msi-panel':'.windows-update-jobs'","'.windows-mutation-status'",'not.toContainText(fixture.coexistenceJob)','toContainText(fixture.coexistenceJob)','await page.reload()','originalOutcomesRetained:true'])assert.ok(helper.includes(gate),gate);
 for(const gate of ["serviceWorkers:'block'",'state.blocked).toEqual([])','state.external).toEqual([])','stored.includes(value)','requireWindowsMutationCoexistenceReport(makeReport(true),{sourceSha,screenshots},sourceSha)','file.startsWith(realDist+path.sep)','fullPage:false'])assert.ok(runner.includes(gate),gate);
 assert.equal((runner.match(/120000/g)||[]).length,1);
 const workflow=read('../../.github/workflows/validate.yml'),suites=JSON.parse(read('./inert-suites.json'));
 for(const name of ['windows-managed-msi-fixtures.test.mjs','windows-mutation-coexistence-fixtures.test.mjs']){assert.ok(suites.entries.includes(name));assert.ok(workflow.includes('node --test tests/e2e-review/'+name));}
 for(const name of ['windows-managed-msi-runner.mjs','windows-mutation-coexistence-runner.mjs'])assert.ok(workflow.includes('node tests/e2e-review/'+name));
 assert.ok(workflow.includes('requireWindowsMutationCoexistenceReport'));assert.ok(workflow.includes('windows-mutation-coexistence-results.json'));assert.ok(workflow.includes('windows-mutation-coexistence-manifest.json'));
});


test('background hosted fixture keeps signed recency separate from configuration and saved results',()=>{
 const legacy=createWindowsMutationCoexistenceFixture();
 for(const field of ['backgroundExecutor','executorAvailability','executorObservedAt'])assert.equal(Object.hasOwn(legacy.coexistenceSaved('updates'),field),false);
 for(const owner of ['managed_msi','cached_wua']){
  const f=createWindowsMutationCoexistenceFixture(owner,true),recent=f.coexistenceSaved('updates'),original=structuredClone(recent.job.result);
  assert.equal(recent.backgroundExecutor,true);assert.equal(recent.executorAvailability,'verified_recent');assert.equal(recent.executorObservedAt,recent.mutationCapturedAt);assert.equal(recent.mutation.active,true);assert.equal(Object.hasOwn(recent,'schedulingAvailable'),false);assert.equal(Object.hasOwn(recent.job,'schedule'),false);
  f.coexistenceSetPhase('released');const unknown=f.coexistenceSaved('updates');assert.equal(unknown.backgroundExecutor,true);assert.equal(unknown.executorAvailability,'unknown');assert.equal(Object.hasOwn(unknown,'executorObservedAt'),false);assert.deepEqual(unknown.job.result,original);assert.equal(f.coexistenceCounts.mutationWrites,0);
 }
 assert.throws(()=>createWindowsMutationCoexistenceFixture('managed_msi','true'));
 const helper=read('./windows-mutation-coexistence-browser.mjs'),runner=read('./windows-mutation-coexistence-runner.mjs');
 for(const gate of ['.windows-update-executor-status','backgroundRecentEvidence:true','backgroundUnknownAvailability:true','manualOnly:true',"'Schedule this update'","'Revoke scheduling'"])assert.ok(helper.includes(gate),gate);
 assert.ok(runner.includes("createWindowsMutationCoexistenceFixture('managed_msi',true)"));
});
