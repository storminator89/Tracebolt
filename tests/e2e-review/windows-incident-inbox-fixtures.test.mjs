import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {windowsIncidentInboxBrowserFixture,windowsIncidentInboxTargetKey,windowsIncidentInboxQuery,windowsIncidentInboxCaseName,windowsIncidentInboxDisclosure,requireWindowsIncidentInboxEvidence,guardWindowsIncidentInboxRoute,windowsIncidentInboxRouteState} from './windows-incident-inbox-browser.mjs';
const now='2026-10-12T12:00:00Z',expiry='2026-10-12T13:00:00Z',later='2026-10-12T12:00:01Z';
const read=file=>fs.readFileSync(new URL(file,import.meta.url),'utf8');
test('invented five-domain inbox preserves historical evidence across one explicit seen readback',()=>{
 const before=windowsIncidentInboxBrowserFixture(now,expiry),after=windowsIncidentInboxBrowserFixture(later,expiry,now,later);
 assert.equal(before.view.items.length,5);assert.equal(before.metadata.name,'Synthetic Windows Desk');assert.equal(windowsIncidentInboxQuery,'?scope=active&ack=all&offset=0&limit=25');
 for(const item of before.view.items){const next=after.view.items.find(row=>row.key===item.key);for(const field of ['openedAt','lastConfirmedAt','collectedAt','receivedAt','evaluatedAt','statusValidUntil','resolvedAt'])assert.equal(next[field],item[field]);}
 const target=after.view.items.find(row=>row.key===windowsIncidentInboxTargetKey);assert.equal(target.acknowledgedAt,later);assert.equal(target.resolvedAt,null);assert.equal(after.view.scope,'active');assert.equal(after.view.counts.active,before.view.counts.active);assert.equal(after.view.counts.acknowledged,before.view.counts.acknowledged+1);
 const expired=windowsIncidentInboxBrowserFixture('2026-10-12T12:03:00Z',expiry,now);assert.ok(expired.view.items.every(row=>row.status==='unknown'&&row.statusValidUntil===null));
});
test('eight screenshots and four exact POST-to-active-seen readbacks are required',()=>{
 const source='a'.repeat(40),rows=[],details={screens:8,cases:[],nativeAcceptance:false,liveStoreAcceptance:false};
 for(const locale of ['en','de'])for(const width of [1440,390]){
  for(const kind of ['list','seen'])rows.push({file:`synthetic-windows-incident-inbox-${kind}-${width}-${locale}.png`,sourceSha:source,test:windowsIncidentInboxCaseName,viewport:{width,height:width===390?844:1000},locale,fullPage:false,publicSafe:true,fixtureDisclosure:windowsIncidentInboxDisclosure});
  details.cases.push({locale,width,postKey:windowsIncidentInboxTargetKey,postCount:1,readbackKey:windowsIncidentInboxTargetKey,acknowledgedAt:later,readbackAcknowledgedAt:later,readbackResolvedAt:null,readbackScope:'active',readbackCount:1});
 }
 assert.deepEqual(requireWindowsIncidentInboxEvidence(rows,source,details),{list:4,seen:4,explicitAcknowledgements:4});
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
 assert.ok(manifest.entries.includes('windows-incident-inbox-fixtures.test.mjs'));assert.match(workflow,/node --test tests\/e2e-review\/windows-incident-inbox-fixtures.test.mjs/);assert.match(workflow,/Windows incident inbox and seen readback \(8 required screenshots\)[\s\S]*?timeout-minutes: 6[\s\S]*?TRACEBOLT_SOURCE_SHA: \$\{\{ github.sha \}\}[\s\S]*?run: node tests\/e2e-review\/windows-incident-inbox-runner.mjs/);
 for(const suffix of ['results','manifest'])assert.ok(workflow.includes(`artifacts/review/windows-incident-inbox-${suffix}.json`));assert.ok(workflow.includes('artifacts/review/synthetic-*.png'));
});
