/** Source-only synthetic route and capture contract; never starts a browser or listener. */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {windowsUpdateJobsOrigin} from './windows-update-jobs-browser.mjs';
import {createWindowsUpdateRetirementFixture,windowsUpdateRetirementRoute,windowsUpdateRetirementCaseName,windowsUpdateRetirementDisclosure,windowsUpdateRetirementScenes,windowsUpdateRetirementViewports,requireWindowsUpdateRetirementEvidence,requireWindowsUpdateRetirementDetails,validateWindowsUpdateRetirementReport} from './windows-update-retirement-browser.mjs';
function setup(){
 const fixture=createWindowsUpdateRetirementFixture(),state={blocked:[],external:[]},path='/api/devices/'+fixture.device.id+'/windows-update-jobs';
 const headers={origin:windowsUpdateJobsOrigin,'x-csrf-token':fixture.session.csrfToken,'content-type':'application/json'};
 const route=windowsUpdateRetirementRoute({base:windowsUpdateJobsOrigin,fixture,state,asset:async()=>{throw Error('Unexpected fixture asset')}});
 const invoke=async(suffix='',{method='GET',raw=null,sent=headers,origin=windowsUpdateJobsOrigin}={})=>{let result;await route({request:()=>({url:()=>origin+path+suffix,method:()=>method,postData:()=>raw,headers:()=>sent}),abort:async reason=>{result={abort:reason}},fulfill:async response=>{result={status:response.status,value:JSON.parse(response.body)}}});return result;};
 return {fixture,state,headers,invoke};
}
test('retirement fixture retains exact success/reboot through one canonical POST and saved GET-only reconciliation',async()=>{
 const f=setup(),initial=(await f.invoke()).value;
 assert.equal(initial.job.retirement.state,'available');assert.equal(initial.reusableJobs,true);assert.equal(initial.available,false);
 const saved=(await f.invoke('/retire',{method:'POST',raw:JSON.stringify(f.fixture.retirementBody)})).value;
 assert.equal(saved.job.retirement.state,'pending');assert.deepEqual(saved.job.result,initial.job.result);assert.equal(saved.job.resultDigest,initial.job.resultDigest);assert.equal(saved.job.result.rebootRequired,'yes');
 assert.deepEqual((await f.invoke('?jobId='+f.fixture.retirementID)).value,saved);assert.equal((await f.invoke('?history=1')).value.remainingCapacity,0);
 f.fixture.confirmRetired();const retired=(await f.invoke('?jobId='+f.fixture.retirementID)).value,h=(await f.invoke('?history=1')).value;
 assert.equal(retired.job.retirement.state,'retired');assert.deepEqual(retired.job.result,initial.job.result);assert.equal(retired.grantExpiresAt,initial.grantExpiresAt);assert.equal(retired.retiredFloor,'1');assert.equal(h.remainingCapacity,1);assert.equal(h.jobs[0].result.rebootRequired,'yes');assert.equal(Object.hasOwn(h.jobs[0],'resultDigest'),false);assert.equal(f.fixture.retirementCounts.postAttempts,1);assert.equal(f.fixture.retirementCounts.retire,1);assert.deepEqual(f.state,{blocked:[],external:[]});
 assert.deepEqual(await f.invoke('/retire',{method:'POST',raw:JSON.stringify(f.fixture.retirementBody)}),{abort:'blockedbyclient'});assert.equal(f.fixture.retirementCounts.retire,1);
});
test('retirement route rejects changed pins, unchecked consent, unsupported writes and untrusted request shapes',async()=>{
 const f=setup(),body=f.fixture.retirementBody;
 for(const patch of [{jobId:'update_'+'9'.repeat(32)},{occurrence:'2'},{envelopeDigest:'sha256:'+'9'.repeat(64)},{resultDigest:'sha256:'+'9'.repeat(64)},{acknowledged:false},{actorId:f.fixture.session.actorId}])assert.deepEqual(await f.invoke('/retire',{method:'POST',raw:JSON.stringify({...body,...patch})}),{abort:'blockedbyclient'});
 for(const suffix of ['/request','/approve','/retire?retry=1','?jobId=update_'+'9'.repeat(32),'?history=1&jobId='+body.jobId])assert.deepEqual(await f.invoke(suffix,{method:'POST',raw:JSON.stringify(body)}),{abort:'blockedbyclient'});
 for(const sent of [{}, {...f.headers,origin:'https://outside.invalid'},{...f.headers,'x-csrf-token':'wrong'}])assert.deepEqual(await f.invoke('/retire',{method:'POST',raw:JSON.stringify(body),sent}),{abort:'blockedbyclient'});
 assert.deepEqual(await f.invoke('',{origin:'https://outside.invalid'}),{abort:'blockedbyclient'});assert.equal(f.fixture.retirementCounts.retire,0);
});
test('one canonical four-capture scene and exact behavior contract feed the existing hosted runner',()=>{
 const sourceSha='a'.repeat(40),rows=windowsUpdateRetirementScenes.flatMap(scene=>['en','de'].flatMap(locale=>windowsUpdateRetirementViewports.map(viewport=>({file:`synthetic-windows-update-retirement-${scene}-${viewport.width}-${locale}.png`,sourceSha,test:windowsUpdateRetirementCaseName,locale,viewport,publicSafe:true,fullPage:false,fixtureDisclosure:windowsUpdateRetirementDisclosure}))));
 assert.deepEqual(requireWindowsUpdateRetirementEvidence(rows,sourceSha),{screens:4,nativeAcceptance:false});assert.throws(()=>requireWindowsUpdateRetirementEvidence(rows.slice(1),sourceSha));assert.throws(()=>requireWindowsUpdateRetirementEvidence([...rows,rows[0]],sourceSha));assert.throws(()=>requireWindowsUpdateRetirementEvidence(rows.map((row,i)=>i?row:{...row,fullPage:true}),sourceSha));
 const details={exactUncheckedReview:true,duplicateClickSuppressed:true,reloadGETOnly:true,retiredResultPreserved:true,rebootPreserved:true,noNextJobStarted:true,retireWrites:1,nativeAcceptance:false};assert.deepEqual(requireWindowsUpdateRetirementDetails(details),{retireWrites:1,nativeAcceptance:false});for(const key of Object.keys(details)){const missing={...details};delete missing[key];assert.throws(()=>requireWindowsUpdateRetirementDetails(missing));}
 const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8'),runner=read('./windows-service-actions-runner.mjs'),helper=read('./windows-update-retirement-browser.mjs');
 for(const marker of ['exerciseWindowsUpdateRetirement','requireWindowsUpdateRetirementEvidence(retirementScreenshots,sourceSha)','requireWindowsUpdateRetirementDetails(retirementDetails)','retirementVariants:passed?retirementVariants:[]','...retirementScreenshots'])assert.ok(runner.includes(marker),marker);
 assert.doesNotMatch(helper,/chromium\.launch|createServer|writeFile|execFile|spawn\(|fetch\(|page\.request|newContext\(|setViewportSize|addStyleTag|route\.continue|route\.fetch/);
});

test('PR and full Validate consume the same source-bound report and capture checker',()=>{
 const sourceSha='a'.repeat(40),details={exactUncheckedReview:true,duplicateClickSuppressed:true,reloadGETOnly:true,retiredResultPreserved:true,rebootPreserved:true,noNextJobStarted:true,retireWrites:1,nativeAcceptance:false};
 const retirementVariants=['en','de'].flatMap(locale=>windowsUpdateRetirementViewports.map(viewport=>({locale,width:viewport.width,...details}))),screenshots=retirementVariants.map(v=>({file:`synthetic-windows-update-retirement-review-${v.width}-${v.locale}.png`,sourceSha,test:windowsUpdateRetirementCaseName,locale:v.locale,viewport:windowsUpdateRetirementViewports.find(p=>p.width===v.width),publicSafe:true,fullPage:false,fixtureDisclosure:windowsUpdateRetirementDisclosure}));
 const report={sourceSha,status:'PASS',browserAcceptance:true,nativeAcceptance:false,requestsToRealAPI:0,runtimeErrorCount:0,retirementScope:windowsUpdateRetirementDisclosure,retirementStage:'complete',retirementVariants},manifest={sourceSha,screenshots};
 assert.deepEqual(validateWindowsUpdateRetirementReport(report,manifest,sourceSha),{screens:4,nativeAcceptance:false});
 for(const patch of [{retirementVariants:[]},{retirementVariants:[...retirementVariants.slice(1),retirementVariants[1]]},{retirementStage:'reload'},{requestsToRealAPI:1},{nativeAcceptance:true},{sourceSha:'b'.repeat(40)}])assert.throws(()=>validateWindowsUpdateRetirementReport({...report,...patch},manifest,sourceSha));
 const pr=fs.readFileSync(new URL('../security/pr_checks.py',import.meta.url),'utf8'),validate=fs.readFileSync(new URL('../../.github/workflows/validate.yml',import.meta.url),'utf8');assert.ok(pr.includes("'tests/e2e-review/windows-update-retirement-browser.mjs', '--check-evidence', plan['sha']"));assert.ok(validate.includes('node tests/e2e-review/windows-update-retirement-browser.mjs --check-evidence "$TRACEBOLT_SOURCE_SHA"'));
});
