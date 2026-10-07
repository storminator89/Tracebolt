import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {healthDashboardFixture,healthDashboardPhases,healthDisclosureFrameMs,openHealthDisclosure,healthDashboardLayout} from './health-dashboard-browser.mjs';
const id='agent_'+'d'.repeat(32);
test('Health dashboard browser fixtures cover honest current, issue, no-check, stale, awaiting and unavailable states',()=>{
 for(const phase of healthDashboardPhases){const {device,health}=healthDashboardFixture(phase,id);assert.equal(device.id,health.deviceId);assert.equal(device.source,'lan');assert.equal(device.synthetic,false);assert.equal(device.ip,null);assert.equal(health.deviceId,id);}
 const clear=healthDashboardFixture('clear',id);assert.equal(clear.health.monitoredServices.length,0);assert.equal(clear.health.status,'clear');assert.equal(clear.device.cpu.value,7.4);
 const selected=healthDashboardFixture('healthy-services',id);assert.equal(selected.health.monitoredServices.length,2);assert.equal(selected.health.checks.filter(x=>x.kind==='service'&&x.state==='ok').length,2);
 const issue=healthDashboardFixture('issue',id);assert.equal(issue.health.incidents.length,1);assert.equal(issue.health.incidents[0].resolvedAt,null);assert.equal(issue.health.checks.find(x=>x.kind==='service').state,'unknown');
 const stale=healthDashboardFixture('stale',id);assert.equal(stale.health.status,'unknown');assert.equal(stale.device.cpu.quality,'stale');assert.ok(stale.health.checks.every(x=>x.state==='unknown'&&x.value===null));
 assert.equal(healthDashboardFixture('awaiting',id).health.evaluatedAt,null);assert.throws(()=>healthDashboardFixture('healthy-everything',id));
});

test('paused-clock Health disclosures drain a bounded frame after click and before focus assertions',async()=>{
 const sequence=[];
 await openHealthDisclosure({click:async()=>{sequence.push('click');}},{clock:{runFor:async ms=>{sequence.push(['frame',ms]);}}});
 assert.equal(healthDisclosureFrameMs,32);assert.deepEqual(sequence,['click',['frame',32]]);
 const source=readFileSync(new URL('./health-dashboard-browser.mjs',import.meta.url),'utf8');
 for(const label of ['Show evidence','Choose services']){
  const start=source.indexOf(`await openHealthDisclosure(health.getByRole('button',{name:'${label}',exact:true}),page);`);
  assert.ok(start>=0,'disclosure must use the bounded frame helper');
  const focus=source.indexOf('.toBeFocused()',start),next=source.indexOf('await openHealthDisclosure(',start+1);
  assert.ok(focus>start&&(next<0||focus<next),'focus assertion must follow its drained frame');
 }

});

// Geometry values are invented booleans here. These checks validate diagnostic
// attribution and assertion preservation, not browser layout or the root cause.
test('Health layout failures retain finite viewport/card/issue/summary stages and never become success',async()=>{
 const groups=['viewport','cards','issues','summaries'];
 for(const failed of groups){
  const stages=[],expectedError=new Error('fixture geometry failure');
  const expect=value=>({toBe:expected=>{assert.equal(expected,true);if(!value)throw expectedError;}});
  const page={evaluate:async()=>failed!=='viewport'};
  const health={locator:selector=>({all:async()=>[{isVisible:async()=>true,evaluate:async()=>!(failed==='cards'&&selector==='.health-reading-card'||failed==='issues'&&selector==='.health-issue'||failed==='summaries'&&selector==='.health-disclosure > summary')} ]})};
  await assert.rejects(healthDashboardLayout(page,health,expect,stage=>stages.push(stage),'health-mobile-de-settings-layout'),error=>error===expectedError);
  assert.equal(stages.at(-1),`health-mobile-de-settings-layout-${failed}`);
 }
});
test('German settings and the following clear phase no longer inherit the previous successful screenshot stage',()=>{
 const source=readFileSync(new URL('./health-dashboard-browser.mjs',import.meta.url),'utf8');
 const stages=['health-mobile-de-settings-open','health-mobile-de-settings-visible','health-mobile-de-settings-scroll','synthetic-http-test-health-controls-mobile-de','health-mobile-de-clear-reload','health-mobile-de-clear-summary','health-mobile-de-clear-reading'];
 let previous=-1;for(const stage of stages){const index=source.indexOf(`mark('${stage}')`);assert.ok(index>previous,stage);previous=index;}
 assert.match(source,/try\{await layout\(page,health,expect,mark,'health-mobile-de-settings-layout'\);\}catch\(error\)/);
 assert.match(source,/page\.locator\('input\[type="password"\]'\)\)\.toHaveCount\(0\)/);
 assert.match(source,/await shot\(page,'synthetic-http-test-health-controls-layout-failure-mobile-de',fixtureDisclosure\);\s*\}finally\{throw error;\}/);
 assert.match(source,/el\.scrollWidth<=el\.clientWidth\+1/);
 assert.equal(healthDisclosureFrameMs,32);
});
