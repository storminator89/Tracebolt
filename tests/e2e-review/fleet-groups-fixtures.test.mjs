import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {fleetGroupsBrowserFixture,fleetGroupsPolicyFixture,fleetGroupsMonitoringFixture,fleetGroupsMaintenanceFixture,fleetGroupsCaptureMatrix,fleetGroupsScenes,fleetGroupsCaptureName,fleetGroupIds,fleetGroupsCaseName,fleetGroupsDisclosure,requireFleetGroupsEvidence,guardFleetGroupsRoute,fleetGroupsRouteState} from './fleet-groups-browser.mjs';
const now='2026-10-11T12:00:10Z',expiry='2026-10-11T13:00:00Z';
test('invented group fixture projects only public names and exact admitted IDs',()=>{
 const fixture=fleetGroupsBrowserFixture(now,expiry);assert.equal(fixture.view.groups[0].unavailableMembers,1);assert.equal(fixture.view.devices.length,3);assert.deepEqual(Object.keys(fixture.view.groups[0]).sort(),['id','memberIds','name','revision','unavailableMembers']);assert.ok(fixture.metadata.every(d=>d.agentCertificate.checkedAt===now));
 for(const metric of ['disk','cpu','memory'])for(const enabled of [false,true]){const policy={enabled,thresholdPercent:90,revision:enabled?1:0},view=fleetGroupsPolicyFixture(now,expiry,fleetGroupIds.first,metric,policy);assert.deepEqual(view.policy,policy);assert.equal(view.status,enabled?'unknown':'disabled');assert.equal(view.observation,null);assert.equal(view.metric,metric==='disk'?undefined:metric);}
});
test('completion requires every canonical source-bound EN/DE desktop/mobile screenshot',()=>{
 const source='a'.repeat(40),rows=fleetGroupsCaptureMatrix.map(({file,width,height,locale})=>({file,sourceSha:source,test:fleetGroupsCaseName,viewport:{width,height},locale,fullPage:false,publicSafe:true,fixtureDisclosure:fleetGroupsDisclosure}));
 assert.deepEqual(requireFleetGroupsEvidence(rows,source),Object.fromEntries(fleetGroupsScenes.map(scene=>[scene,fleetGroupsCaptureMatrix.filter(row=>row.scene===scene).length])));
 for(let index=0;index<rows.length;index++)for(const changed of [null,{sourceSha:'b'.repeat(40)},{fullPage:true},{publicSafe:false},{fixtureDisclosure:'native'},{test:'other'},{viewport:{width:800,height:600}}])assert.throws(()=>requireFleetGroupsEvidence(changed?rows.map((r,i)=>i===index?{...r,...changed}:r):rows.filter((_,i)=>i!==index),source));
 assert.throws(()=>requireFleetGroupsEvidence([...rows,rows[0]],source));
});
test('hosted capture admission includes every required image and rejects noncontract names',()=>{
 const runner=fs.readFileSync(new URL('./fleet-groups-runner.mjs',import.meta.url),'utf8');
 assert.match(runner,/fleetGroupsCaptureMatrix.find\(row=>row.name===name\)/);
 for(const row of fleetGroupsCaptureMatrix)assert.equal(fleetGroupsCaptureName(row.scene,row.width,row.locale),row.name);
 for(const invalid of [['other',1440,'en'],['draft',800,'en'],['draft',1440,'fr']])assert.throws(()=>fleetGroupsCaptureName(...invalid));
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
 for(const kind of ['review','results'])assert.ok(helper.includes("await verifyPolicyLayout();await shot(page,fleetGroupsCaptureName('"+kind+"',width,locale)"));
});

test('inheritance fixture and capture contract stay exact, unchecked and source-bound',()=>{
 const fixture=fleetGroupsMonitoringFixture(now,expiry);assert.equal(fixture.targets.length,6);assert.equal(fixture.unavailableAssignments,1);assert.deepEqual(new Set(fixture.targets.map(t=>t.metric)),new Set(['disk','cpu','memory']));assert.equal(fixture.targets[4].status,'manual-override');assert.equal(fixture.targets[4].owned,false);
 const helper=fs.readFileSync(new URL('./fleet-groups-browser.mjs',import.meta.url),'utf8'),runner=fs.readFileSync(new URL('./fleet-groups-runner.mjs',import.meta.url),'utf8');
 for(const scene of fleetGroupsScenes.filter(scene=>scene.startsWith('inheritance-')))assert.ok(helper.includes(`fleetGroupsCaptureName('${scene}',width,locale)`));
 assert.match(helper,/expect\(consent\)\.not\.toBeChecked\(\)/);assert.match(helper,/expect\(monitoringPosts\)\.toBe\(inheritanceBefore\+2\)/);assert.match(helper,/policy\)\.toEqual\(previousPolicy\)/);
 assert.match(helper,/screens:fleetGroupsCaptureMatrix.length/);assert.match(runner,/requireFleetGroupsEvidence\(screenshots,sourceSha\)/);assert.match(helper,/getByRole\('combobox',\{name:de\?'Flottengruppen':'Fleet groups',exact:true\}\)/);
});


test('group maintenance adds exactly four canonical views and original-identity synthetic target keys',()=>{
 const fixture=fleetGroupsMaintenanceFixture(now);assert.equal(fixture.members.length,2);assert.equal(fixture.excludedLinuxMembers,1);assert.equal(fixture.unavailableMembers,1);assert.equal(new Set(fixture.members.flatMap(m=>m.targets.map(t=>t.key))).size,12);
 const scenes=fleetGroupsCaptureMatrix.filter(row=>row.scene.startsWith('maintenance-'));assert.equal(scenes.length,4);assert.deepEqual(new Set(scenes.map(row=>row.locale)),new Set(['en','de']));assert.deepEqual(new Set(scenes.map(row=>row.width)),new Set([1440,390]));
 const helper=fs.readFileSync(new URL('./fleet-groups-browser.mjs',import.meta.url),'utf8');assert.match(helper,/expect\(maintenanceConsent\)\.not\.toBeChecked\(\)/);assert.match(helper,/expect\(maintenancePosts\)\.toBe\(maintenanceBefore\+2\)/);assert.match(helper,/maintenanceBodies\[0\]\.endsAt\)\.toBe\(maintenanceBodies\[1\]\.endsAt\)/);assert.match(helper,/validGroupMaintenanceView/);
});
