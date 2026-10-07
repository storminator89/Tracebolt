import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createApplicationCheckSettingsFixture,applicationCheckSettingsFixtureTargets,applicationCheckSettingsEditedTargets,applicationCheckSettingsFixtureDisclosure,applicationCheckSettingsCaseName} from './application-check-settings-browser.mjs';
import {validApplicationCheckSettings} from '../../web/src/application-check-settings-types.ts';
const path='/api/application-checks/settings';
const save=f=>({expectedRevision:f.settings().revision,operation:'save',intervalSeconds:75,targets:structuredClone(applicationCheckSettingsFixtureTargets)});
const enable=f=>({expectedRevision:f.settings().revision,operation:'enable',checksFromManagerAcknowledged:true,destinationsAcknowledged:true,plaintextAcknowledged:true});
const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8');

test('invented draft remains disabled until exact enable review; disable preserves targets and rotates revision',()=>{
 const f=createApplicationCheckSettingsFixture();assert.equal(validApplicationCheckSettings(f.settings()),true);assert.equal(f.settings().configured,false);
 const draft=f.handle('POST',path,save(f));assert.equal(validApplicationCheckSettings(draft),true);assert.equal(draft.enabled,false);assert.deepEqual(draft.targets,applicationCheckSettingsFixtureTargets);
 const enabled=f.handle('POST',path,enable(f));assert.equal(validApplicationCheckSettings(enabled),true);assert.equal(enabled.enabled,true);assert.notEqual(enabled.revision,draft.revision);
 const disabled=f.handle('POST',path,{expectedRevision:enabled.revision,operation:'disable'});assert.equal(validApplicationCheckSettings(disabled),true);assert.equal(disabled.enabled,false);assert.deepEqual(disabled.targets,draft.targets);assert.notEqual(disabled.revision,enabled.revision);
 assert.deepEqual(f.counts,{reads:0,saves:1,enables:1,disables:1});
});
test('editing a stored draft rotates its revision and stays off before new enable review',()=>{
 const f=createApplicationCheckSettingsFixture();f.handle('POST',path,save(f));const before=f.settings();
 const changed=f.handle('POST',path,{...save(f),targets:structuredClone(applicationCheckSettingsEditedTargets)});
 assert.equal(changed.enabled,false);assert.equal(changed.targets[1].port,8443);assert.notEqual(changed.revision,before.revision);assert.equal(f.counts.saves,2);
 assert.throws(()=>f.handle('POST',path,{...enable(f),expectedRevision:before.revision}));
});
test('fixture snapshot copies cannot mutate receiver targets',()=>{
 const f=createApplicationCheckSettingsFixture();f.handle('POST',path,save(f));const a=f.settings();a.targets[0].url='https://wrong.invalid';a.targets[0].allowedAddresses.push('10.9.9.9');assert.deepEqual(f.settings().targets,applicationCheckSettingsFixtureTargets);
});
test('fixture rejects other targets, implicit enablement and stale or extra fields',()=>{
 for(const change of [x=>x.targets[0].url='https://unreviewed.invalid',x=>x.enabled=true,x=>x.expectedRevision='f'.repeat(32),x=>delete x.intervalSeconds,x=>x.targets[0].allowPrivateLAN=false]){
  const f=createApplicationCheckSettingsFixture(),body=save(f);change(body);assert.throws(()=>f.handle('POST',path,body));assert.equal(f.counts.saves,0);assert.equal(f.settings().configured,false);
 }
});
test('enable requires saved targets and each distinct manager/destination/plaintext acknowledgement',()=>{
 const empty=createApplicationCheckSettingsFixture();assert.throws(()=>empty.handle('POST',path,enable(empty)));
 for(const change of [x=>x.checksFromManagerAcknowledged=false,x=>x.destinationsAcknowledged=false,x=>x.plaintextAcknowledged=false,x=>delete x.destinationsAcknowledged,x=>x.targets=applicationCheckSettingsFixtureTargets,x=>x.expectedRevision='a'.repeat(32)]){
  const f=createApplicationCheckSettingsFixture();f.handle('POST',path,save(f));const body=enable(f);change(body);assert.throws(()=>f.handle('POST',path,body));assert.equal(f.settings().enabled,false);assert.equal(f.counts.enables,0);
 }
});
test('unknown routes and check/probe methods never reach a real target',()=>{
 for(const [method,url,body] of [['POST','/api/application-checks/run',{}],['POST','/api/application-checks/test',{}],['PUT',path,{}],['GET',`${path}?target=x`,null],['GET',path,{}]])assert.throws(()=>createApplicationCheckSettingsFixture().handle(method,url,body));
});
test('hosted case adds exact intercepted setup without weakening the shared harness',()=>{
 const runner=read('./lan-browser.mjs'),source=read('./application-check-settings-browser.mjs');
 assert.equal((runner.match(/await check\(/g)||[]).length,20);assert.equal((runner.match(/await check\(applicationCheckSettingsCaseName/g)||[]).length,1);
 assert.match(runner,/applicationCheckSettingsBrowserCase\(\{pageAt,login,expect,base,shot\}\),'10m'/);
 assert.match(applicationCheckSettingsCaseName,/Synthetic application check setup/);assert.match(applicationCheckSettingsFixtureDisclosure,/no real configuration persistence, target probe, DNS request, TCP connection or permission grant/);
 assert.doesNotMatch(source,/chromium\.launch|newContext\(|setDefaultTimeout|waitForTimeout|ignoreHTTPSErrors|execFile|spawn\(/);
 assert.match(source,/url.origin!==base/);assert.match(source,/url.pathname!=='\/api\/application-checks\/settings'\|\|url.search/);assert.match(source,/route.abort\('blockedbyclient'\)/);
 assert.match(source,/method==='POST'&&url.pathname!=='\/api\/auth\/login'/);assert.match(source,/expect\(unexpected\)\.toEqual\(\[\]\)/);assert.match(source,/expect\(external\)\.toEqual\(\[\]\)/);
 assert.match(source,/name:'Cancel'/);assert.match(source,/toHaveCount\(3\)/);assert.match(source,/width:390,height:844/);assert.match(source,/application-setup-disabled-mobile-de/);assert.match(source,/localStorage/);assert.match(source,/name:'Edit targets'/);assert.match(source,/namedCapabilities=\['read'\]/);assert.match(source,/namedCapabilities=\['read','manage_application_checks'\]/);assert.match(source,/fixture.counts.reads\)\.toBe\(beforeReadOnly\)/);
});
