/** Pure route and evidence-contract checks; no browser, listener or native provider. */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {windowsUpdateJobsOrigin} from './windows-update-jobs-browser.mjs';
import {createWindowsUpdateDownloadFixture,windowsUpdateDownloadRoute,windowsUpdateDownloadCaseName,windowsUpdateDownloadDisclosure,windowsUpdateDownloadScenes,windowsUpdateDownloadViewports,requireWindowsUpdateDownloadDetails,requireWindowsUpdateDownloadEvidence,validateWindowsUpdateDownloadReport} from './windows-update-download-browser.mjs';
function setup(coexistence=true){
 const fixture=createWindowsUpdateDownloadFixture({coexistence}),state={blocked:[],external:[]},path='/api/devices/'+fixture.device.id+'/windows-update-jobs';
 const headers={origin:windowsUpdateJobsOrigin,'x-csrf-token':fixture.session.csrfToken,'content-type':'application/json'};
 const route=windowsUpdateDownloadRoute({base:windowsUpdateJobsOrigin,fixture,state,asset:async()=>{throw Error('Unexpected fixture asset')}});
 const invoke=async(suffix='',{method='GET',raw=null,sent=headers,origin=windowsUpdateJobsOrigin}={})=>{let result;await route({request:()=>({url:()=>origin+path+suffix,method:()=>method,postData:()=>raw,headers:()=>sent}),abort:async reason=>{result={abort:reason}},fulfill:async response=>{result={status:response.status,value:JSON.parse(response.body)}}});return result;};
 return {fixture,state,headers,invoke};
}
test('download fixture requires one exact explicit download-only sequence and saves cached-only result',async()=>{
 const f=setup(false),initial=(await f.invoke()).value,id='update_'+'c'.repeat(32);
 assert.equal(initial.available,false);assert.equal(initial.downloadAvailable,true);assert.deepEqual(f.fixture.session.capabilities,['read','windows_update_download']);
 const requested=(await f.invoke('/request-download',{method:'POST',raw:JSON.stringify({requestId:id,...f.fixture.selection})})).value;assert.equal(requested.job.purpose,'download');assert.equal(requested.job.preview,null);
 const saved=(await f.invoke('?jobId='+id)).value;assert.equal(saved.job.state,'preview');
 const reviewed=(await f.invoke('/preview-download',{method:'POST',raw:JSON.stringify({requestId:id})})).value;assert.equal(reviewed.job.preview.readiness.downloaded,'no');
 const body={previewId:id,previewDigest:reviewed.job.preview.digest,acknowledged:true};assert.equal((await f.invoke('/approve-download',{method:'POST',raw:JSON.stringify(body)})).value.job.state,'approved');
 const result=(await f.invoke('?jobId='+id)).value;assert.equal(result.job.result.outcome,'succeeded');assert.equal(result.job.result.downloadedAfter,'yes');assert.equal(result.job.result.rebootRequired,'unknown');assert.equal(result.job.retirement.state,'available');assert.equal(result.downloadAvailable,false);assert.deepEqual((await f.invoke('?jobId='+id)).value,result);assert.deepEqual(f.fixture.downloadCounts,{request:1,preview:1,approve:1,status:4,postAttempts:3});assert.deepEqual(f.state,{blocked:[],external:[]});
 assert.deepEqual(await f.invoke('/approve-download',{method:'POST',raw:JSON.stringify(body)}),{abort:'blockedbyclient'});assert.equal(f.fixture.downloadCounts.approve,1);
});
test('download route refuses alternate purpose, unknown target, untrusted Origin/CSRF and oversized body',async()=>{
 for(const suffix of ['/request','/approve','/schedule','/retire','/request-download?retry=1','?jobId=update_'+'9'.repeat(32)]){const f=setup();assert.deepEqual(await f.invoke(suffix,{method:'POST',raw:'{}'}),{abort:'blockedbyclient'});assert.equal(f.fixture.downloadCounts.request,0)}
 for(const patch of [{method:'GET',raw:'{}'},{method:'POST',raw:' '.repeat(1025)},{method:'POST',raw:'{}',sent:{}},{method:'POST',raw:'{}',origin:'https://other.invalid'}]){const f=setup();assert.deepEqual(await f.invoke('/request-download',patch),{abort:'blockedbyclient'});assert.equal(f.fixture.downloadCounts.request,0)}
});
test('twelve source-bound EN/DE desktop/mobile scenes are executable in the existing runner and both CI paths',()=>{
 const sha='a'.repeat(40),details={manualDownloadWithInstallationScheduling:true,noDownloadSchedule:true,downloadOnly:true,exactUncheckedReview:true,duplicateClickSuppressed:true,reloadGETOnly:true,cachedNotInstalled:true,approvedWrites:1,noAutomaticInstall:true,nativeAcceptance:false};
 requireWindowsUpdateDownloadDetails(details);for(const key of Object.keys(details)){const value={...details};delete value[key];assert.throws(()=>requireWindowsUpdateDownloadDetails(value))}
 const rows=windowsUpdateDownloadScenes.flatMap(scene=>['en','de'].flatMap(locale=>windowsUpdateDownloadViewports.map(viewport=>({file:`synthetic-windows-update-download-${scene}-${viewport.width}-${locale}.png`,sourceSha:sha,test:windowsUpdateDownloadCaseName,locale,viewport,publicSafe:true,fullPage:false,fixtureDisclosure:windowsUpdateDownloadDisclosure}))));
 assert.deepEqual(requireWindowsUpdateDownloadEvidence(rows,sha),{screens:12,nativeAcceptance:false});for(const changed of [rows.slice(1),[...rows,rows[0]],rows.map((r,i)=>i?r:{...r,fullPage:true})])assert.throws(()=>requireWindowsUpdateDownloadEvidence(changed,sha));
 const report={sourceSha:sha,status:'PASS',browserAcceptance:true,nativeAcceptance:false,requestsToRealAPI:0,runtimeErrorCount:0,downloadScope:windowsUpdateDownloadDisclosure,downloadStage:'complete',downloadVariants:['en','de'].flatMap(locale=>windowsUpdateDownloadViewports.map(v=>({locale,width:v.width,...details})))},manifest={sourceSha:sha,screenshots:rows};assert.deepEqual(validateWindowsUpdateDownloadReport(report,manifest,sha),{screens:12,nativeAcceptance:false});assert.throws(()=>validateWindowsUpdateDownloadReport({...report,downloadStage:'review'},manifest,sha));
 const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8'),runner=read('./windows-service-actions-runner.mjs');for(const marker of ['exerciseWindowsUpdateDownload','requireWindowsUpdateDownloadEvidence(downloadScreenshots,sourceSha)','requireWindowsUpdateDownloadDetails(downloadDetails)','downloadVariants:passed?downloadVariants:[]','...downloadScreenshots'])assert.ok(runner.includes(marker),marker);
 assert.doesNotMatch(read('./windows-update-download-browser.mjs'),/chromium\.launch|createServer|writeFile|execFile|spawn\(|fetch\(|page\.request|newContext\(|setViewportSize|addStyleTag|route\.continue|route\.fetch/);
 assert.ok(read('../security/pr_checks.py').includes("'tests/e2e-review/windows-update-download-browser.mjs', '--check-evidence', plan['sha']"));assert.ok(read('../../.github/workflows/validate.yml').includes('node tests/e2e-review/windows-update-download-browser.mjs --check-evidence "$TRACEBOLT_SOURCE_SHA"'));
});

test('fresh coexistence is explicit and cannot give a download-only operator scheduling authority',async()=>{
 const legacy=setup(false),fresh=setup(),manual=(await legacy.invoke()).value,combined=(await fresh.invoke()).value;
 assert.equal(manual.backgroundScheduling,undefined);assert.equal(manual.schedulingAvailable,undefined);assert.equal(combined.backgroundScheduling,true);assert.equal(combined.schedulingAvailable,false);assert.equal(combined.available,false);assert.equal(combined.downloadAvailable,true);assert.deepEqual(fresh.fixture.session.capabilities,['read','windows_update_download']);
 const {backgroundScheduling:_,schedulingAvailable:__,...unchanged}=combined;assert.deepEqual(unchanged,manual);
 for(const op of ['schedule','schedule-download','approve','retire'])assert.deepEqual(await fresh.invoke('/'+op,{method:'POST',raw:'{}'}),{abort:'blockedbyclient'});
 assert.equal(fresh.fixture.downloadCounts.approve,0);assert.equal(fresh.fixture.downloadView().job,null);
});

test('the real runner classifier admits every exported download scene and rejects other capture names',()=>{
 // Evaluate only the inert classifier expression, never import or execute the runner.
 const runner=fs.readFileSync(new URL('./windows-service-actions-runner.mjs',import.meta.url),'utf8');
 assert.match(runner,/const \{[^}\n]*windowsUpdateDownloadScenes[^}\n]*\}=await bootstrap\('imports',\(\)=>import\('\.\/windows-update-download-browser\.mjs'\)\)/);
 const match=runner.match(/\n const isDownload=(.+);\n/);assert.ok(match);assert.match(match[1],/^windowsUpdateDownloadScenes\.some\(/);
 const accepts=name=>vm.runInNewContext('('+match[1]+')',{name,windowsUpdateDownloadScenes},{timeout:1000});
 for(const scene of windowsUpdateDownloadScenes)for(const locale of ['en','de'])for(const {width} of windowsUpdateDownloadViewports)assert.equal(accepts(`synthetic-windows-update-download-${scene}-${width}-${locale}`),true);
 for(const name of ['synthetic-windows-update-download-review-1440-en.png','synthetic-windows-update-download-coexistence-391-de','synthetic-windows-update-download-coexistence-390-fr','synthetic-windows-update-download-schedule-390-en','synthetic-windows-update-jobs-review-390-en','../synthetic-windows-update-download-coexistence-390-en'])assert.equal(accepts(name),false);
});
