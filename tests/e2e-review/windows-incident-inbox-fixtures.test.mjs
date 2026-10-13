import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {windowsIncidentInboxBrowserFixture,windowsIncidentInboxTargetKey,windowsIncidentInboxQuery,windowsIncidentInboxCaseName,windowsIncidentInboxDisclosure,requireWindowsIncidentInboxEvidence,guardWindowsIncidentInboxRoute,windowsIncidentInboxRouteState,windowsIncidentInboxScenes,windowsServiceIncidentReviewDisclosure,windowsServiceIncidentReviewFixture,windowsServiceIncidentReviewRoute} from './windows-incident-inbox-browser.mjs';
const now='2026-10-12T12:00:00Z',expiry='2026-10-12T13:00:00Z',later='2026-10-12T12:00:01Z';
const read=file=>fs.readFileSync(new URL(file,import.meta.url),'utf8');
test('invented five-domain inbox preserves historical evidence across one explicit seen readback',()=>{
 const before=windowsIncidentInboxBrowserFixture(now,expiry),after=windowsIncidentInboxBrowserFixture(later,expiry,now,later);
 assert.equal(before.view.items.length,5);assert.equal(before.metadata.name,'Synthetic Windows Desk');assert.equal(windowsIncidentInboxQuery,'?scope=active&ack=all&offset=0&limit=25');
 for(const item of before.view.items){const next=after.view.items.find(row=>row.key===item.key);for(const field of ['openedAt','lastConfirmedAt','collectedAt','receivedAt','evaluatedAt','statusValidUntil','resolvedAt'])assert.equal(next[field],item[field]);}
 const target=after.view.items.find(row=>row.key===windowsIncidentInboxTargetKey);assert.equal(target.acknowledgedAt,later);assert.equal(target.resolvedAt,null);assert.equal(after.view.scope,'active');assert.equal(after.view.counts.active,before.view.counts.active);assert.equal(after.view.counts.acknowledged,before.view.counts.acknowledged+1);
 const expired=windowsIncidentInboxBrowserFixture('2026-10-12T12:03:00Z',expiry,now);assert.ok(expired.view.items.every(row=>row.status==='unknown'&&row.statusValidUntil===null));
});
test('twelve canonical screenshots preserve four seen readbacks and add two unapproved exact service previews',()=>{
 const source='a'.repeat(40),rows=[],details={screens:12,cases:[],serviceReviewCases:[],nativeAcceptance:false,liveStoreAcceptance:false};
 for(const locale of ['en','de'])for(const width of [1440,390]){
  for(const kind of ['list','seen'])rows.push({file:`synthetic-windows-incident-inbox-${kind}-${width}-${locale}.png`,sourceSha:source,test:windowsIncidentInboxCaseName,viewport:{width,height:width===390?844:1000},locale,fullPage:false,publicSafe:true,fixtureDisclosure:windowsIncidentInboxDisclosure});
  details.cases.push({locale,width,postKey:windowsIncidentInboxTargetKey,postCount:1,readbackKey:windowsIncidentInboxTargetKey,acknowledgedAt:later,readbackAcknowledgedAt:later,readbackResolvedAt:null,readbackScope:'active',readbackCount:1});
 }
 const fixture=windowsServiceIncidentReviewFixture(sharedSession());
 for(const [locale,width] of [['en',1440],['de',390]]){
  for(const kind of ['service-review','service-preview'])rows.push({file:`synthetic-windows-incident-inbox-${kind}-${width}-${locale}.png`,sourceSha:source,test:windowsIncidentInboxCaseName,viewport:{width,height:width===390?844:1000},locale,fullPage:false,publicSafe:true,fixtureDisclosure:windowsServiceIncidentReviewDisclosure});
  details.serviceReviewCases.push({locale,width,key:fixture.review.incident.key,target:fixture.review.incident.serviceName,bindingDigest:fixture.review.control.bindingDigest,counts:{inbox:1,review:1,status:1,preview:1,approve:0,acknowledge:0,collection:0},initialPreviewCount:0,operationInitiallyBlank:true,approvalChecked:false});
 }
 assert.deepEqual(rows.map(row=>row.file).sort(),windowsIncidentInboxScenes.map(scene=>scene.name+'.png').sort());
 assert.deepEqual(requireWindowsIncidentInboxEvidence(rows,source,details),{list:4,seen:4,explicitAcknowledgements:4,serviceReview:2,servicePreview:2,explicitPreviews:2,serviceApprovals:0});
 for(const patch of [{key:'0'.repeat(64)},{target:'ReplacementService'},{bindingDigest:'sha256:'+'0'.repeat(64)},{initialPreviewCount:1},{operationInitiallyBlank:false},{approvalChecked:true},...['review','status','preview','approve','acknowledge','collection'].map(key=>({counts:{...details.serviceReviewCases[0].counts,[key]:key==='review'||key==='status'||key==='preview'?0:1}}))])assert.throws(()=>requireWindowsIncidentInboxEvidence(rows,source,{...details,serviceReviewCases:details.serviceReviewCases.map((row,i)=>i===0?{...row,...patch}:row)}));
 assert.throws(()=>requireWindowsIncidentInboxEvidence(rows,source,{...details,serviceReviewCases:[]}));
 for(let index=0;index<rows.length;index++)for(const patch of [null,{sourceSha:'b'.repeat(40)},{publicSafe:false},{fullPage:true},{locale:'fr'},{viewport:{width:800,height:600}},{fixtureDisclosure:'native'}])assert.throws(()=>requireWindowsIncidentInboxEvidence(patch?rows.map((row,i)=>i===index?{...row,...patch}:row):rows.filter((_,i)=>i!==index),source,details));
 for(const patch of [{postCount:0},{postCount:2},{readbackCount:0},{readbackKey:'0'.repeat(64)},{readbackAcknowledgedAt:null},{readbackResolvedAt:later},{readbackScope:'resolved'}])assert.throws(()=>requireWindowsIncidentInboxEvidence(rows,source,{...details,cases:details.cases.map((row,i)=>i===0?{...row,...patch}:row)}));
 assert.throws(()=>requireWindowsIncidentInboxEvidence([...rows,rows[0]],source,details));
});
test('route assertion failures are retained without raw diagnostics',async()=>{
 const before=windowsIncidentInboxRouteState();await guardWindowsIncidentInboxRoute({abort:async()=>{}},async()=>{throw new Error('inert failure');});assert.deepEqual(windowsIncidentInboxRouteState(),{failures:before.failures+1,pending:0});
});
test('helper keeps exact allowlisted routes, real shared login and explicit button acknowledgement',()=>{
 const helper=read('./windows-incident-inbox-browser.mjs'),runner=read('./windows-incident-inbox-runner.mjs');
 assert.doesNotMatch(helper,/chromium\.launch|newContext\(|spawn\(|execFile|writeFile|ignoreHTTPSErrors|localStorage|sessionStorage/);
 assert.match(helper,/assert\.equal\(session.loginMode,'shared'\)/);assert.match(helper,/assert\.equal\(req.headers\(\)\['x-csrf-token'\],session.csrfToken\)/);assert.match(helper,/assert\.deepEqual\(body,\{key:windowsIncidentInboxTargetKey\}\)/);assert.match(helper,/assert\.equal\(url.search,windowsIncidentInboxQuery\)/);
 assert.match(helper,/expect\(postCount\)\.toBe\(0\)/);assert.match(helper,/await target.getByRole\('button'\)\.click\(\)/);assert.match(helper,/await expect.poll\(\(\)=>readbackCount\)\.toBe\(1\)/);assert.match(helper,/assert.equal\(readback.key,postKey\)/);assert.match(helper,/assert.equal\(readback.resolvedAt,null\)/);assert.match(helper,/unexpected.push\('unexpected-route'\);return route.abort\('blockedbyclient'\)/);
 assert.match(runner,/http:\/\/127\.0\.0\.1:19911/);assert.match(runner,/requireWindowsIncidentInboxEvidence\(screenshots,sourceSha,details\)/);assert.match(runner,/300000/);assert.match(runner,/liveStoreAcceptance:false/);assert.match(runner,/process.exitCode=passed\?0:1/);assert.doesNotMatch(runner,/ignoreHTTPSErrors|executablePath|console\.log\(.*error/);
});
test('ordinary hosted workflow wires this inert suite, bounded runner and source-bound artifacts',()=>{
 const workflow=read('../../.github/workflows/validate.yml'),manifest=JSON.parse(read('./inert-suites.json'));
 assert.ok(manifest.entries.includes('windows-incident-inbox-fixtures.test.mjs'));assert.match(workflow,/node --test tests\/e2e-review\/windows-incident-inbox-fixtures.test.mjs/);assert.match(workflow,/Windows incident inbox, seen readback and exact service review \(12 required screenshots\)[\s\S]*?timeout-minutes: 6[\s\S]*?TRACEBOLT_SOURCE_SHA: \$\{\{ github.sha \}\}[\s\S]*?run: node tests\/e2e-review\/windows-incident-inbox-runner.mjs/);
 for(const suffix of ['results','manifest'])assert.ok(workflow.includes(`artifacts/review/windows-incident-inbox-${suffix}.json`));assert.ok(workflow.includes('artifacts/review/synthetic-*.png'));
});

function sharedSession(){return {mode:'lan',transport:'http',insecureTestMode:true,transportWarning:'unencrypted_lan_test',authenticationRequired:true,authenticated:true,csrfToken:'SYNTHETIC_REVIEW_CSRF',serverNow:now,expiresAt:expiry,expiresInSeconds:3600,loginMode:'shared',actorId:null,capabilities:['read']};}
function inertRoute(url,{method='GET',body=null,headers={}}={}){
 const result={reply:null,continued:0,aborted:0};return {result,request:()=>({url:()=>url,method:()=>method,postData:()=>body,headers:()=>headers}),fulfill:async value=>{result.reply=JSON.parse(value.body);},continue:async()=>{result.continued++;},abort:async()=>{result.aborted++;}};
}
test('new capture fixture preserves the real Go review binding and original shifted evidence without action authority',()=>{
 const f=windowsServiceIncidentReviewFixture(sharedSession());assert.equal(f.session.loginMode,'named');assert.deepEqual(f.session.capabilities,['read','windows_service_control']);assert.equal(f.view.items.length,1);assert.deepEqual(f.view.items[0],f.review.incident);assert.equal(f.review.incident.domain,'service');assert.equal(f.preview.preview.binding,f.review.control.binding);assert.equal(f.preview.preview.operation,'restart');assert.equal(f.preview.preview.actorId,f.session.actorId);assert.equal(f.ready.preview,null);assert.equal(f.ready.job,null);assert.equal(Date.parse(f.review.authorityExpiresAt)-Date.parse(f.review.serverNow),60000);assert.equal(f.review.observation.collectedAt,new Date(now).toISOString());assert.deepEqual(f.counts,{inbox:0,review:0,status:0,preview:0,approve:0,acknowledge:0,collection:0});
});
test('new named scene API reads and manual preview are fully intercepted and exact-pin guarded',async()=>{
 const base='http://127.0.0.1:19911',fixture=windowsServiceIncidentReviewFixture(sharedSession()),external=[],unexpected=[],handle=windowsServiceIncidentReviewRoute({base,fixture,external,unexpected}),item=fixture.review.incident,action=`/api/devices/${item.deviceId}/windows-service-actions`,pin={'x-tracebolt-windows-service-review':fixture.review.control.bindingDigest};
 for(const path of ['/api/auth/session','/api/session','/api/overview','/api/fleet/identities','/api/fleet/groups','/api/fleet/windows-incidents'+windowsIncidentInboxQuery,`/api/fleet/windows-incidents/${item.key}/service-review`]){const route=inertRoute(base+path);await handle(route);assert.ok(route.result.reply);assert.equal(route.result.continued,0);}
 for(const value of [undefined,'sha256:'+'b'.repeat(64),fixture.review.control.bindingDigest+','+fixture.review.control.bindingDigest])await assert.rejects(()=>handle(inertRoute(base+action,{headers:{'x-tracebolt-windows-service-review':value}})));
 const status=inertRoute(base+action,{headers:pin});await handle(status);assert.deepEqual(status.result.reply,fixture.ready);assert.equal(fixture.counts.preview,0);
 for(const path of ['/api/fleet/windows-incidents'+windowsIncidentInboxQuery,`/api/fleet/windows-incidents/${item.key}/service-review`,action])await assert.rejects(()=>handle(inertRoute(base+path,{headers:pin})));
 const headers={...pin,origin:base,'x-csrf-token':fixture.session.csrfToken,'content-type':'application/json'},body=JSON.stringify({target:item.serviceName,operation:'restart'});
 for(const patch of [{method:'GET'},{headers:{...headers,'x-tracebolt-windows-service-review':'sha256:'+'b'.repeat(64)}},{headers:{...headers,origin:'https://external.invalid'}},{headers:{...headers,'x-csrf-token':'wrong'}},{body:JSON.stringify({target:'ReplacementService',operation:'restart'})},{body:JSON.stringify({target:item.serviceName,operation:'stop'})}])await assert.rejects(()=>handle(inertRoute(base+action+'/preview',{method:'POST',headers,body,...patch})));
 const preview=inertRoute(base+action+'/preview',{method:'POST',headers,body});await handle(preview);assert.deepEqual(preview.result.reply,fixture.preview);await assert.rejects(()=>handle(inertRoute(base+action+'/preview',{method:'POST',headers,body})));assert.deepEqual(fixture.counts,{inbox:1,review:1,status:1,preview:1,approve:0,acknowledge:0,collection:0});assert.deepEqual(external,[]);assert.deepEqual(unexpected,[]);
});
test('new scenes reject every approval, acknowledgement, collection and external fallback',async()=>{
 const base='http://127.0.0.1:19911',fixture=windowsServiceIncidentReviewFixture(sharedSession()),external=[],unexpected=[],handle=windowsServiceIncidentReviewRoute({base,fixture,external,unexpected}),action=`/api/devices/${fixture.review.incident.deviceId}/windows-service-actions`;
 for(const path of [action+'/approve','/api/fleet/windows-incidents/acknowledge','/api/devices/'+fixture.review.incident.deviceId+'/windows-event-content/request']){const route=inertRoute(base+path,{method:'POST',body:'{}'});await handle(route);assert.equal(route.result.aborted,1);assert.equal(route.result.continued,0);assert.equal(route.result.reply,null);}
 const outside=inertRoute('https://external.invalid/api/session');await handle(outside);assert.equal(outside.result.aborted,1);assert.deepEqual(external,['external']);assert.equal(unexpected.length,3);assert.deepEqual(fixture.counts,{inbox:0,review:0,status:0,preview:0,approve:1,acknowledge:1,collection:1});
 const wrong=inertRoute(base+'/api/fleet/windows-incidents/'+'0'.repeat(64)+'/service-review');await handle(wrong);assert.equal(wrong.result.aborted,1);assert.equal(wrong.result.continued,0);
});
test('four new scenes exercise real compiled App selectors with blank operation and unchecked approval',()=>{
 const helper=read('./windows-incident-inbox-browser.mjs'),runner=read('./windows-incident-inbox-runner.mjs');
 assert.equal(windowsIncidentInboxScenes.length,12);assert.equal(new Set(windowsIncidentInboxScenes.map(row=>row.name)).size,12);assert.deepEqual(windowsIncidentInboxScenes.filter(row=>row.fixtureDisclosure===windowsServiceIncidentReviewDisclosure).map(({locale,width})=>[locale,width]),[['en',1440],['en',1440],['de',390],['de',390]]);
 assert.match(helper,/serviceReviewCases.push\(await exerciseWindowsServiceIncidentReview/);assert.match(helper,/await page.goto\(base\+'\/#\/devices'\)/);assert.match(helper,/await expect\(choose\).toHaveValue\(''\)/);assert.match(helper,/await expect\(makePreview\).toBeDisabled\(\)/);assert.match(helper,/await choose.selectOption\('restart'\);await makePreview.click\(\)/);assert.match(helper,/await expect\(preview.getByRole\('checkbox'\)\).not.toBeChecked\(\)/);assert.match(helper,/approve:0,acknowledge:0,collection:0/);
 assert.match(runner,/windowsIncidentInboxScenes.find\(value=>value.name===name\)/);assert.match(runner,/screenshots.some\(value=>value.file===name\+'\.png'\)/);assert.match(runner,/path.join\(root,'web\/dist'\)/);assert.doesNotMatch(helper,/getByRole\('checkbox'\)\.check\(|getByRole\('button',\{name:de\?'Diese Aktion einmal freigeben':'Approve this action once',exact:true\}\)\.click\(/);
});
