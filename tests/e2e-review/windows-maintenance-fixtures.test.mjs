import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {windowsMaintenanceBrowserFixture,windowsMaintenanceBrowserChange,windowsMaintenanceTargetKey,windowsMaintenanceCaseName,windowsMaintenanceDisclosure,requireWindowsMaintenanceEvidence,guardWindowsMaintenanceRoute,windowsMaintenanceRouteState,windowsNotificationBrowserFixture,windowsNotificationBrowserEnable} from './windows-maintenance-browser.mjs';
const now='2026-10-12T12:00:00Z',expiry='2026-10-12T13:00:00Z',later='2026-10-12T12:00:01Z',endsAt='2026-10-12T12:30:00Z';
const read=file=>fs.readFileSync(new URL(file,import.meta.url),'utf8');
test('invented exact-target start and early end preserve original end and sibling scopes',()=>{
 const before=windowsMaintenanceBrowserFixture(now,expiry);assert.equal(before.view.targets.length,6);assert.equal(before.metadata.name,'Synthetic Windows Desk');
 const body={key:windowsMaintenanceTargetKey,revision:0,endsAt,intent:'planned-work'},started=windowsMaintenanceBrowserChange(null,'start',body,now),ended=windowsMaintenanceBrowserChange(started,'end',{key:windowsMaintenanceTargetKey,revision:1,windowId:1},later);
 const active=windowsMaintenanceBrowserFixture(later,expiry,started),after=windowsMaintenanceBrowserFixture(later,expiry,ended);
 assert.equal(active.view.targets[3].revision,1);assert.equal(active.view.targets[3].windows[0].endedAt,null);assert.equal(after.view.targets[3].revision,2);assert.equal(after.view.targets[3].windows[0].endedAt,later);assert.equal(after.view.targets[3].windows[0].endsAt,endsAt);
 for(const target of before.view.targets.filter(target=>target.domain!=='disk'))assert.deepEqual(after.view.targets.find(next=>next.key===target.key),target);
 assert.throws(()=>windowsMaintenanceBrowserChange(started,'start',body,later));assert.throws(()=>windowsMaintenanceBrowserChange(ended,'end',{key:windowsMaintenanceTargetKey,revision:1,windowId:1},later));
 for(const patch of [{key:'0'.repeat(64)},{revision:1},{endsAt:'2026-10-12T12:00:30Z'},{endsAt:'2026-10-13T12:00:01Z'},{endsAt:'2026-10-12T12:30:00.000Z'},{intent:'free text'},{command:'no'}])assert.throws(()=>windowsMaintenanceBrowserChange(null,'start',{...body,...patch},now));
});
test('twenty source-bound screenshots include unchecked recipient approval and suppression are required',()=>{
 const source='a'.repeat(40),rows=[],details={screens:20,cases:[],nativeAcceptance:false,liveStoreAcceptance:false};
 for(const locale of ['en','de'])for(const width of [1440,390]){
  for(const kind of ['review','active','ended','notification-review','notification-muted'])rows.push({file:`synthetic-windows-maintenance-${kind}-${width}-${locale}.png`,sourceSha:source,test:windowsMaintenanceCaseName,viewport:{width,height:width===390?844:1000},locale,fullPage:false,publicSafe:true,fixtureDisclosure:windowsMaintenanceDisclosure});
  details.cases.push({notificationCount:1,notificationReads:3,recipientReviewed:true,approvalInitiallyUnchecked:true,maintenanceSuppressed:true,noBacklog:true,locale,width,key:windowsMaintenanceTargetKey,startCount:1,endCount:1,startReadback:1,endReadback:1,reviewedEnd:endsAt,retainedEnd:endsAt,endedAt:later,revision:2,incidentUnchanged:true});
 }
 assert.deepEqual(requireWindowsMaintenanceEvidence(rows,source,details),{review:4,active:4,ended:4,notificationReviews:4,notificationMuted:4,explicitStarts:4,explicitEarlyEnds:4,explicitNotificationEnables:4});
 for(let index=0;index<rows.length;index++)for(const patch of [null,{sourceSha:'b'.repeat(40)},{publicSafe:false},{fullPage:true},{locale:'fr'},{viewport:{width:800,height:600}},{fixtureDisclosure:'native'}])assert.throws(()=>requireWindowsMaintenanceEvidence(patch?rows.map((row,i)=>i===index?{...row,...patch}:row):rows.filter((_,i)=>i!==index),source,details));
 for(const patch of [{key:'0'.repeat(64)},{startCount:0},{startCount:2},{endCount:0},{endCount:2},{startReadback:0},{endReadback:0},{retainedEnd:expiry},{endedAt:null},{endedAt:endsAt},{revision:1},{incidentUnchanged:false},{notificationCount:0},{notificationCount:2},{notificationReads:2},{recipientReviewed:false},{approvalInitiallyUnchecked:false},{maintenanceSuppressed:false},{noBacklog:false}])assert.throws(()=>requireWindowsMaintenanceEvidence(rows,source,{...details,cases:details.cases.map((row,i)=>i===0?{...row,...patch}:row)}));
 assert.throws(()=>requireWindowsMaintenanceEvidence([...rows,rows[0]],source,details));
});
test('route assertion failures are retained without raw diagnostics',async()=>{
 const before=windowsMaintenanceRouteState();await guardWindowsMaintenanceRoute({abort:async()=>{}},async()=>{throw new Error('inert failure');});assert.deepEqual(windowsMaintenanceRouteState(),{failures:before.failures+1,pending:0});
});
test('helper stays inert and requires exact routes, real shared login and two reviewed clicks',()=>{
 const helper=read('./windows-maintenance-browser.mjs'),runner=read('./windows-maintenance-runner.mjs');
 assert.doesNotMatch(helper,/chromium\.launch|newContext\(|spawn\(|execFile|writeFile|ignoreHTTPSErrors|localStorage|sessionStorage/);
 assert.match(helper,/assert\.equal\(session.loginMode,'shared'\)/);assert.match(helper,/assert\.equal\(req.headers\(\)\['x-csrf-token'\],session.csrfToken\)/);assert.match(helper,/assert\.equal\(body.endsAt,reviewedEnd\)/);assert.match(helper,/assert\.deepEqual\(body,\{key:windowsMaintenanceTargetKey,revision:1,windowId:1\}\)/);
 assert.match(helper,/expect\(startCount\)\.toBe\(0\)/);assert.match(helper,/expect\(endCount\)\.toBe\(0\)/);assert.match(helper,/await expect.poll\(\(\)=>startReadback\)\.toBe\(1\)/);assert.match(helper,/await expect.poll\(\(\)=>endReadback\)\.toBe\(1\)/);assert.match(helper,/expect\(await inbox.innerText\(\)\)\.toBe\(incidentText\)/);assert.match(helper,/expect\(record.windows\[0\].endsAt\)\.toBe\(reviewedEnd\)/);assert.match(helper,/unexpected.push\('unexpected-route'\);return route.abort\('blockedbyclient'\)/);
 assert.match(runner,/http:\/\/127\.0\.0\.1:19912/);assert.match(runner,/requireWindowsMaintenanceEvidence\(screenshots,sourceSha,details\)/);assert.match(runner,/300000/);assert.match(runner,/liveStoreAcceptance:false/);assert.match(runner,/process.exitCode=passed\?0:1/);assert.doesNotMatch(runner,/ignoreHTTPSErrors|executablePath|console\.log\(.*error/);
});
test('ordinary hosted workflow wires inert checks, bounded runner and source-bound artifacts',()=>{
 const workflow=read('../../.github/workflows/validate.yml'),manifest=JSON.parse(read('./inert-suites.json'));
 assert.ok(manifest.entries.includes('windows-maintenance-fixtures.test.mjs'));assert.match(workflow,/node --test tests\/e2e-review\/windows-maintenance-fixtures.test.mjs/);assert.match(workflow,/Bounded Windows maintenance and notification approval \(20 required screenshots\)[\s\S]*?timeout-minutes: 6[\s\S]*?TRACEBOLT_SOURCE_SHA: \$\{\{ github.sha \}\}[\s\S]*?run: node tests\/e2e-review\/windows-maintenance-runner.mjs/);
 for(const suffix of ['results','manifest'])assert.ok(workflow.includes(`artifacts/review/windows-maintenance-${suffix}.json`));assert.ok(workflow.includes('artifacts/review/synthetic-*.png'));
});

test('recipient-specific source approval starts off and separate synthetic suppression survives window end',()=>{
 const started=windowsMaintenanceBrowserChange(null,'start',{key:windowsMaintenanceTargetKey,revision:0,endsAt,intent:'planned-work'},now);
 const off=windowsNotificationBrowserFixture(now,expiry,started);assert.equal(off.targets[2].enabled,false);assert.equal(off.counts.suppressed,0);assert.equal(off.destinationHost,'receiver.example.test');
 const body={key:windowsMaintenanceTargetKey,revision:0,enabled:true,destinationBinding:off.destinationBinding,payloadAcknowledged:true};
 for(const patch of [{key:'0'.repeat(64)},{revision:1},{destinationBinding:'b'.repeat(64)},{payloadAcknowledged:false},{endpoint:'https://forbidden.invalid'}])assert.throws(()=>windowsNotificationBrowserEnable(null,{...body,...patch},now));
 const policy=windowsNotificationBrowserEnable(null,body,now),muted=windowsNotificationBrowserFixture(later,expiry,started,policy);assert.equal(muted.targets[2].effective,true);assert.equal(muted.targets[2].maintenanceUntil,endsAt);assert.equal(muted.counts.suppressed,1);assert.equal(muted.counts.queued,0);assert.throws(()=>windowsNotificationBrowserEnable(policy,body,now));
 const ended=windowsMaintenanceBrowserChange(started,'end',{key:windowsMaintenanceTargetKey,revision:1,windowId:1},later),after=windowsNotificationBrowserFixture(later,expiry,ended,policy);assert.equal(after.targets[2].maintenanceUntil,null);assert.equal(after.counts.queued,0);assert.equal(after.counts.suppressed,1);
});
