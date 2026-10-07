import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {healthDashboardFixture,healthDashboardPhases,healthDisclosureFrameMs,openHealthDisclosure} from './health-dashboard-browser.mjs';
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
