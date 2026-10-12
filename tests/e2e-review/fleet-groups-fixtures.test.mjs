import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {fleetGroupsBrowserFixture,fleetGroupsPolicyFixture,fleetGroupIds,fleetGroupsCaseName,fleetGroupsDisclosure,requireFleetGroupsEvidence,guardFleetGroupsRoute,fleetGroupsRouteState} from './fleet-groups-browser.mjs';
const now='2026-10-11T12:00:10Z',expiry='2026-10-11T13:00:00Z';
test('invented group fixture projects only public names and exact admitted IDs',()=>{
 const fixture=fleetGroupsBrowserFixture(now,expiry);assert.equal(fixture.view.groups[0].unavailableMembers,1);assert.equal(fixture.view.devices.length,3);assert.deepEqual(Object.keys(fixture.view.groups[0]).sort(),['id','memberIds','name','revision','unavailableMembers']);assert.ok(fixture.metadata.every(d=>d.agentCertificate.checkedAt===now));
 for(const metric of ['disk','cpu','memory'])for(const enabled of [false,true]){const policy={enabled,thresholdPercent:90,revision:enabled?1:0},view=fleetGroupsPolicyFixture(now,expiry,fleetGroupIds.first,metric,policy);assert.deepEqual(view.policy,policy);assert.equal(view.status,enabled?'unknown':'disabled');assert.equal(view.observation,null);assert.equal(view.metric,metric==='disk'?undefined:metric);}
});
test('completion requires exactly sixteen source-bound EN/DE desktop/mobile screenshots',()=>{
 const source='a'.repeat(40),rows=[];for(const kind of ['groups','draft','review','results'])for(const locale of ['en','de'])for(const width of [1440,390])rows.push({file:`synthetic-fleet-groups-${kind}-${width}-${locale}.png`,sourceSha:source,test:fleetGroupsCaseName,viewport:{width,height:width===390?844:1000},locale,fullPage:false,publicSafe:true,fixtureDisclosure:fleetGroupsDisclosure});
 assert.deepEqual(requireFleetGroupsEvidence(rows,source),{groups:4,draft:4,review:4,results:4});
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

test('uncertain readback checks the exact first-device outcome cell and bounded failure stages',()=>{
 const helper=fs.readFileSync(new URL('./fleet-groups-browser.mjs',import.meta.url),'utf8');
 const uncertain=helper.slice(helper.indexOf("stage='uncertain-review';mode='uncertain'"),helper.indexOf("stage='stop';mode='hold'"));
 assert.match(uncertain,/getByRole\('dialog'\)\.getByRole\('row'\)\.filter\(\{hasText:ids.first\}\)\.getByRole\('cell'\)\.last\(\)/);
 assert.match(uncertain,/expect\(uncertainOutcome\)\.toHaveText\('Physical RAM percentageUnconfirmed · write may have happenedCurrent policy matches, but this does not prove our write succeeded\.'\)/);
 assert.doesNotMatch(uncertain,/getByText\('Unconfirmed · write may have happened'/);
 assert.match(uncertain,/expect\(policyPosts\)\.toBe\(uncertainBefore\+1\)/);
 assert.match(uncertain,/getByText\('Not attempted',\{exact:true\}\)/);
 for(const stage of ['review','apply','result','remaining','count','close']){
  assert.ok(uncertain.includes(`stage='uncertain-${stage}'`));
  assert.ok(helper.slice(0,helper.indexOf('export function guardFleetGroupsRoute')).includes(`'uncertain-${stage}'`));
 }
});

test('fleet dialog retains desktop and compact mobile inner spacing',()=>{
 const css=fs.readFileSync(new URL('../../web/src/fleet-groups.css',import.meta.url),'utf8');
 assert.match(css.split('@media')[0],/\.fleet-group-dialog \.dialog\{[^}]*padding:28px[;}]/);
 assert.match(css,/\@media\(max-width:600px\)\{.*\.fleet-group-dialog \.dialog\{padding:22px\}/);
});

test('compact mobile rows keep all policy cells in the viewport without losing table semantics',()=>{
 const css=fs.readFileSync(new URL('../../web/src/fleet-groups.css',import.meta.url),'utf8'),ui=fs.readFileSync(new URL('../../web/src/fleet-groups.tsx',import.meta.url),'utf8'),helper=fs.readFileSync(new URL('./fleet-groups-browser.mjs',import.meta.url),'utf8');
 const mobile=css.slice(css.indexOf('/* Keep the table semantics'));
 assert.doesNotMatch(css,/min-width:450px/);
 assert.match(mobile,/\.fleet-group-table-wrap\{overflow-x:visible\}/);
 assert.match(mobile,/grid-template-columns:minmax\(0,1fr\)/);
 assert.match(mobile,/\.fleet-group-table td\{display:block;min-width:0;padding:0;border:0\}/);
 assert.match(mobile,/\.fleet-group-table thead\{[^}]*clip-path:inset\(50%\)/);
 assert.doesNotMatch(mobile,/display:none/);
 assert.match(mobile,/td\[data-label\]::before\{content:attr\(data-label\)/);
 for(const role of ['table','rowgroup','row','columnheader','cell'])assert.ok(ui.includes(`role="${role}"`));
 assert.match(ui,/data-label=\{c.before\}/);assert.match(ui,/data-label=\{c.outcome\}/);
 assert.match(helper,/expect\(layout.overflow\)\.toBeLessThanOrEqual\(1\)/);
 assert.match(helper,/expect\(cell.right\)\.toBeGreaterThanOrEqual\(-1\)/);
 assert.match(helper,/expect\(cell.overflow\)\.toBeLessThanOrEqual\(1\)/);
 for(const kind of ['review','results'])assert.ok(helper.includes('await verifyPolicyLayout();await shot(page,`synthetic-fleet-groups-'+kind+'-${width}-${locale}`'));
});
