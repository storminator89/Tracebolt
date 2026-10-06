/** Pure in-memory DTO/runner tests. No browser, server, provider or API is started. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import {alarmSettingsCaseName,alarmSettingsFixtureDisclosure,alarmSettingsFixtureEndpoint,createAlarmSettingsFixture} from './alarm-settings-browser.mjs';
import {validAlarmSettings} from '../../web/src/alarm-settings-types.ts';
import {validAlarmStatus} from '../../web/src/alarm-status-types.ts';
const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8');
const replace=fixture=>({expectedRevision:fixture.settings().revision,operation:'replace',endpoint:alarmSettingsFixtureEndpoint,payloadSharingAcknowledged:true,plaintextAcknowledged:true});
const send=fixture=>({expectedRevision:fixture.settings().revision,requestId:'e'.repeat(32),testAcknowledged:true});

test('invented settings and status fixtures satisfy production validators without saved URL readback',()=>{
 const fixture=createAlarmSettingsFixture();const off=fixture.handle('GET','/api/alerts/settings',null);
 assert.equal(validAlarmSettings(off),true);assert.equal(off.configured,false);assert.equal(off.enabled,false);assert.equal(off.test,null);
 const saved=fixture.handle('POST','/api/alerts/settings',replace(fixture));assert.equal(validAlarmSettings(saved),true);assert.equal(saved.enabled,true);assert.equal(saved.configured,true);assert.equal(saved.destinationHost,'alarm-fixture.example.test');assert.notEqual(saved.revision,off.revision);assert.equal(saved.test,null);
 const encoded=JSON.stringify(saved);assert.equal(encoded.includes(alarmSettingsFixtureEndpoint),false);assert.equal(encoded.includes('NOT_A_REAL_SECRET'),false);assert.equal(Object.hasOwn(saved,'endpoint'),false);
 assert.equal(validAlarmStatus(fixture.handle('GET','/api/alerts/status',null)),true);assert.deepEqual(fixture.counts,{settingsReads:1,statusReads:1,settingsWrites:1,testWrites:0});
});

test('explicit separate test creates one queued event and fake state changes do not enqueue another',()=>{
 const fixture=createAlarmSettingsFixture();fixture.handle('POST','/api/alerts/settings',replace(fixture));const rev=fixture.settings().revision;
 const queued=fixture.handle('POST','/api/alerts/test',send(fixture));assert.equal(validAlarmSettings(queued),true);assert.equal(queued.revision,rev);assert.equal(queued.test.state,'queued');assert.equal(queued.test.eventId.length,64);assert.equal(fixture.status().queued,1);
 for(const [state,count] of [['provider_accepted','providerAccepted'],['uncertain','uncertain']]){const changed=fixture.setTestState(state);assert.equal(validAlarmSettings(changed),true);assert.equal(changed.test.state,state);assert.equal(fixture.status()[count],1);assert.equal(validAlarmStatus(fixture.status()),true);}
 assert.equal(fixture.counts.testWrites,1);assert.throws(()=>fixture.handle('POST','/api/alerts/test',send(fixture)));assert.equal(fixture.counts.testWrites,1);
 const disabled=fixture.handle('POST','/api/alerts/settings',{expectedRevision:rev,operation:'disable',endpoint:'',payloadSharingAcknowledged:false,plaintextAcknowledged:false});assert.equal(validAlarmSettings(disabled),true);assert.equal(disabled.enabled,false);assert.equal(disabled.destinationHost,'alarm-fixture.example.test');assert.notEqual(disabled.revision,rev);assert.equal(disabled.test.state,'uncertain');assert.equal(fixture.counts.settingsWrites,2);assert.equal(fixture.status().enabled,false);
});

test('fixture copies cannot mutate its receiver state',()=>{
 const fixture=createAlarmSettingsFixture();const copy=fixture.settings();copy.enabled=true;copy.destinationHost='not-fixture.example';assert.equal(fixture.settings().enabled,false);assert.equal(fixture.settings().destinationHost,'');
});

test('configuration mutations reject stale revisions, missing or extra fields, real targets, and missing HTTP consent',()=>{
 for(const mutate of [x=>{x.expectedRevision='f'.repeat(32);},x=>{delete x.endpoint;},x=>{x.token='synthetic';},x=>{x.endpoint='https://unexpected.example.test/hook';},x=>{x.payloadSharingAcknowledged=false;},x=>{x.plaintextAcknowledged=false;},x=>{x.operation='enable';}]){
  const fixture=createAlarmSettingsFixture(),data=replace(fixture);mutate(data);assert.throws(()=>fixture.handle('POST','/api/alerts/settings',data));assert.equal(fixture.counts.settingsWrites,0);assert.equal(fixture.settings().configured,false);
 }
});

test('the synthetic test requires configuration, exact acknowledgement and bounded random request ID',()=>{
 const unavailable=createAlarmSettingsFixture();assert.throws(()=>unavailable.handle('POST','/api/alerts/test',send(unavailable)));
 for(const mutate of [x=>{x.expectedRevision='f'.repeat(32);},x=>{x.testAcknowledged=false;},x=>{x.requestId='e'.repeat(31);},x=>{x.requestId='E'.repeat(32);},x=>{x.endpoint=alarmSettingsFixtureEndpoint;},x=>{delete x.testAcknowledged;}]){
  const fixture=createAlarmSettingsFixture();fixture.handle('POST','/api/alerts/settings',replace(fixture));const data=send(fixture);mutate(data);assert.throws(()=>fixture.handle('POST','/api/alerts/test',data));assert.equal(fixture.counts.testWrites,0);assert.equal(fixture.settings().test,null);
 }
});

test('unknown routes and noncontract methods are rejected, not passed to a real receiver',()=>{
 for(const [method,path,body] of [['DELETE','/api/alerts/settings',null],['PUT','/api/alerts/settings',{}],['POST','/api/alerts/status',{}],['GET','/api/alerts/test',null],['GET','/api/alerts/settings?extra=1',null],['GET','/api/alerts/settings',{extra:true}],['POST','/api/alerts/unknown',{}]])assert.throws(()=>createAlarmSettingsFixture().handle(method,path,body));
});

test('one hosted LAN case reuses the existing runner without launching another browser or weakening security',()=>{
 const runner=read('./lan-browser.mjs'),module=read('./alarm-settings-browser.mjs');
 assert.equal((runner.match(/await check\(/g)||[]).length,17);assert.equal((runner.match(/await check\(alarmSettingsCaseName/g)||[]).length,1);
 assert.match(runner,/alarmSettingsBrowserCase\(\{pageAt,login,expect,base,shot\}\),'10m'/);
 assert.match(alarmSettingsCaseName,/Synthetic alarm setup/);assert.match(alarmSettingsFixtureDisclosure,/Rendered production UI/);assert.match(alarmSettingsFixtureDisclosure,/invented/);assert.match(alarmSettingsFixtureDisclosure,/fake sender states/);assert.match(alarmSettingsFixtureDisclosure,/actual backend behavior is tested separately/);
 assert.doesNotMatch(module,/chromium\.launch|newContext\(|setDefaultTimeout|waitForTimeout|ignoreHTTPSErrors|execFile|spawn\(/);
 assert.match(module,/url.origin!==base/);assert.match(module,/route.abort\('blockedbyclient'\)/);assert.match(module,/!\['GET','POST'\]\.includes\(method\)/);assert.match(module,/!alarmPaths.has\(url.pathname\)\|\|url.search/);
 assert.match(module,/method==='POST'&&url.pathname!=='\/api\/auth\/login'/);assert.match(module,/expect\(unexpected\)\.toEqual\(\[\]\)/);assert.match(module,/expect\(external\)\.toEqual\(\[\]\)/);
 assert.match(module,/synthetic-http-test-alarm-setup-form-desktop-en/);assert.match(module,/synthetic-http-test-alarm-setup-test-uncertain-desktop-de/);assert.match(module,/width:390,height:844/);assert.match(module,/alarm-setup-form-mobile-\$\{locale\}/);
 assert.match(module,/name:'Cancel'/);assert.match(module,/press\('Escape'\)/);assert.match(module,/toBeFocused\(\)/);assert.match(module,/type','password'/);assert.match(module,/toHaveLength\(2\)/);assert.match(module,/toHaveLength\(1\)/);
});

test('the existing read-only alarm case allows only extra setup GETs and retains its no-mutation guard',()=>{
 const module=read('./alarm-status-browser.mjs');assert.match(module,/url.pathname==='\/api\/alerts\/status'/);assert.match(module,/setupRequests.every\(value=>value==='GET \/api\/alerts\/settings'\)/);
 assert.match(module,/expect\(mutations\)\.toEqual\(\[\]\)/);assert.match(module,/expect\(externalRequests\)\.toEqual\(\[\]\)/);assert.match(module,/expect\(alarmRequests.length\)\.toBe\(reads\)/);
});


test('captures reconcile the independent aggregate snapshot using only its explicit read control',()=>{
 const source=read('./alarm-settings-browser.mjs');
 assert.match(source,/const refreshAggregate=async/);assert.match(source,/const capture=async[^\n]*await refreshAggregate\(\)/);
 assert.match(source,/fixture.counts.statusReads/);assert.match(source,/const german=.*state=fixture.status\(\)/);
 assert.match(source,/aggregate.locator\('\.alarm-mode'\)/);assert.match(source,/aggregate.locator\('\.alarm-counts dd'\)/);
 assert.match(source,/enabled:current.enabled/);assert.match(source,/expect\(fixture.counts.testWrites\).toBe\(1\)/);
});
