import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {fleetGroupsBrowserFixture,fleetGroupsPolicyFixture,fleetGroupIds,fleetGroupsCaseName,fleetGroupsDisclosure,requireFleetGroupsEvidence,guardFleetGroupsRoute,fleetGroupsRouteState} from './fleet-groups-browser.mjs';
const now='2026-10-11T12:00:10Z',expiry='2026-10-11T13:00:00Z';
test('invented group fixture projects only public names and exact admitted IDs',()=>{
 const fixture=fleetGroupsBrowserFixture(now,expiry);assert.equal(fixture.view.groups[0].unavailableMembers,1);assert.equal(fixture.view.devices.length,3);assert.deepEqual(Object.keys(fixture.view.groups[0]).sort(),['id','memberIds','name','revision','unavailableMembers']);assert.ok(fixture.metadata.every(d=>d.agentCertificate.checkedAt===now));
 for(const metric of ['disk','cpu','memory'])for(const enabled of [false,true]){const policy={enabled,thresholdPercent:90,revision:enabled?1:0},view=fleetGroupsPolicyFixture(now,expiry,fleetGroupIds.first,metric,policy);assert.deepEqual(view.policy,policy);assert.equal(view.status,enabled?'unknown':'disabled');assert.equal(view.observation,null);assert.equal(view.metric,metric==='disk'?undefined:metric);}
});
test('completion requires exactly twelve source-bound EN/DE desktop/mobile screenshots',()=>{
 const source='a'.repeat(40),rows=[];for(const kind of ['groups','review','results'])for(const locale of ['en','de'])for(const width of [1440,390])rows.push({file:`synthetic-fleet-groups-${kind}-${width}-${locale}.png`,sourceSha:source,test:fleetGroupsCaseName,viewport:{width,height:width===390?844:1000},locale,fullPage:false,publicSafe:true,fixtureDisclosure:fleetGroupsDisclosure});
 assert.deepEqual(requireFleetGroupsEvidence(rows,source),{groups:4,review:4,results:4});
 for(let index=0;index<rows.length;index++)for(const changed of [null,{sourceSha:'b'.repeat(40)},{fullPage:true},{publicSafe:false},{fixtureDisclosure:'native'},{test:'other'},{viewport:{width:800,height:600}}])assert.throws(()=>requireFleetGroupsEvidence(changed?rows.map((r,i)=>i===index?{...r,...changed}:r):rows.filter((_,i)=>i!==index),source));
 assert.throws(()=>requireFleetGroupsEvidence([...rows,rows[0]],source));
});
test('route assertion failures remain failures and cannot disappear in detached callbacks',async()=>{
 const before=fleetGroupsRouteState(),route={abort:async()=>{}};await guardFleetGroupsRoute(route,async()=>{throw new Error('inert failure');});assert.deepEqual(fleetGroupsRouteState(),{failures:before.failures+1,pending:0});
});
test('helper is inert and hosted runner keeps real loopback login with finite sanitized output',()=>{
 const helper=fs.readFileSync(new URL('./fleet-groups-browser.mjs',import.meta.url),'utf8'),runner=fs.readFileSync(new URL('./fleet-groups-runner.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(helper,/chromium\.launch|newContext\(|spawn\(|execFile|writeFile|ignoreHTTPSErrors|localStorage|sessionStorage/);
 assert.match(runner,/http:\/\/127\.0\.0\.1:19909/);assert.match(runner,/requireFleetGroupsEvidence\(screenshots,sourceSha\)/);assert.match(runner,/liveStoreAcceptance:false/);assert.match(runner,/fleet-groups-results.json/);assert.match(runner,/fleet-groups-manifest.json/);assert.match(runner,/300000/);assert.match(runner,/process.exitCode=passed\?0:1/);assert.doesNotMatch(runner,/ignoreHTTPSErrors|console\.log\(.*error/);
 assert.match(helper,/Current policy matches, but this does not prove our write succeeded/);assert.match(helper,/Stop remaining writes/);assert.match(helper,/removeUnavailableMembers,false/);assert.doesNotMatch(helper,/page\.getByRole\('table'\)/);assert.match(helper,/page\.getByRole\('dialog'\)\.getByRole\('table'\)/);assert.match(helper,/await page\.reload\(\)/);
});
