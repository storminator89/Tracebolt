/** Pure synthetic receiver/source checks. This does not launch a browser. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import {createProactiveAIFixture,proactiveAIResultFixture,proactiveAICaseName,proactiveAIFixtureDisclosure,proactiveAIFixtureDevice,proactiveAIFixtureHostname,proactiveAIFixtureAddresses,proactiveAIIdentityFixture} from './proactive-ai-browser.mjs';
const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8');
const path='/api/ai/proactive';
const approval=f=>{const view=f.settings();return {expectedRevision:view.revision,configRevision:view.configRevision,enabled:true,deviceIds:[proactiveAIFixtureDevice],approvedBaseURL:view.baseURL,approvedModel:view.model,dataScope:'health-summary-v1',acknowledgeData:true};};
test('only exact scoped approval enables the synthetic receiver and rotates its revision',()=>{
 const fixture=createProactiveAIFixture();assert.equal(fixture.settings().enabled,false);const before=fixture.settings().revision;const enabled=fixture.handle('POST',path,approval(fixture));assert.equal(enabled.enabled,true);assert.notEqual(enabled.revision,before);assert.deepEqual(enabled.deviceIds,[proactiveAIFixtureDevice]);assert.equal(enabled.logsAllowed,false);assert.deepEqual(fixture.counts,{settingsReads:0,settingsWrites:1,resultReads:0,identityReads:0});
});
test('missing consent, stale provider and expanded scope never enable the receiver',()=>{
 for(const change of [v=>v.acknowledgeData=false,v=>v.expectedRevision='stale',v=>v.configRevision='stale',v=>v.approvedBaseURL='https://different.invalid',v=>v.approvedModel='different',v=>v.deviceIds=[],v=>v.deviceIds=['agent_'+('f'.repeat(32))],v=>v.dataScope='raw-logs',v=>v.logsAllowed=true]){const fixture=createProactiveAIFixture(),value=approval(fixture);change(value);assert.throws(()=>fixture.handle('POST',path,value));assert.equal(fixture.settings().enabled,false);assert.equal(fixture.counts.settingsWrites,0);}
});
test('snapshot copies do not modify approved scope, and reading durable results does not enable or run anything',()=>{
 const fixture=createProactiveAIFixture(),view=fixture.settings();view.availableDevices.length=0;assert.equal(fixture.settings().availableDevices.length,1);const result=fixture.handle('GET','/api/investigations?scope=open&offset=0',null);assert.equal(result.items[0].analysis.status,'completed');assert.equal(result.items[0].analysis.result.rootCauseConfirmed,false);assert.equal(result.items[0].analysis.result.packet.dataScope,'health-summary-v1');assert.equal(result.items[0].analysis.result.packet.case.id,result.items[0].incident.id);assert.deepEqual(result.items[0].analysis.result.packet.evidence.map(item=>item.id),['health-event','health-snapshot']);result.items[0].analysis.result.id='mutated';assert.notEqual(proactiveAIResultFixture().items[0].analysis.result.id,'mutated');assert.equal(fixture.counts.settingsWrites,0);assert.equal(fixture.settings().enabled,false);
});
test('unknown analysis, provider, log and malformed read routes are blocked',()=>{
 for(const [method,path,body] of [['POST','/api/cases/fixture/analyze',{}],['POST','/api/ai/config',{}],['POST','/api/ai/config/persistent',{}],['POST','/api/ai/proactive/test',{}],['POST','/api/devices/fixture/journal/create',{}],['GET','/api/ai/proactive?extra=1',null],['GET','/api/investigations?scope=open&offset=0',{raw:'ignored'}]])assert.throws(()=>createProactiveAIFixture().handle(method,path,body));
});
test('persisted provider/scope rendering is an invented read-only fixture, with no provider write path',()=>{
 const fixture=createProactiveAIFixture();assert.equal(fixture.provider().storage,'memory-only');assert.equal(fixture.provider().persistentKeyAllowed,false);fixture.loadPersistedReadFixture();
 const scope=fixture.handle('GET','/api/ai/proactive',null),provider=fixture.handle('GET','/api/ai/config',null);assert.equal(scope.resetsOnRestart,false);assert.equal(provider.storage,'protected-file');assert.equal(provider.resetsOnRestart,false);assert.equal(provider.persistenceAvailable,true);assert.equal(provider.keyConfigured,false);assert.equal(provider.persistentKeyAllowed,false);assert.equal(fixture.counts.settingsWrites,0);assert.throws(()=>fixture.handle('POST','/api/ai/config/persistent',{}));
});
test('one hosted case preserves real login and CSRF with intercepted synthetic data and explicit disclosure',()=>{
 const runner=read('./lan-browser.mjs'),source=read('./proactive-ai-browser.mjs');assert.equal((runner.match(/await check\(/g)||[]).length,21);assert.equal((runner.match(/await check\(proactiveAICaseName/g)||[]).length,1);assert.match(runner,/proactiveAIBrowserCase\(\{pageAt,login,expect,base,shot\}\),'10m'/);assert.match(runner,/name===proactiveAICaseName\?\{stage:proactiveAIFailureStage\(\)\}/);
 assert.match(proactiveAICaseName,/Synthetic proactive AI/);assert.match(proactiveAIFixtureDisclosure,/UI-only evidence/);assert.match(proactiveAIFixtureDisclosure,/No real provider call, log collection\/export/);assert.doesNotMatch(source,/chromium\.launch|newContext\(|setDefaultTimeout|waitForTimeout|ignoreHTTPSErrors|execFile|spawn\(/);assert.match(source,/url.origin!==base/);assert.match(source,/headers\['x-csrf-token'\]===csrf/);assert.match(source,/sessionSequence>consumedSession/);assert.match(source,/request.postData\(\)===null/);assert.match(source,/method==='POST'&&url.pathname==='\/api\/auth\/login'/);assert.match(source,/await page.goBack\(\)/);assert.match(source,/await page.goForward\(\)/);assert.match(source,/await page.reload\(\)/);assert.match(source,/button.click\(\);button.click\(\)/);assert.match(source,/name:'Close',exact:true/);assert.match(source,/may already have taken effect/);assert.match(source,/expect\(fixture.counts.settingsWrites\)\.toBe\(1\)/);assert.match(source,/expect\(unexpected\)\.toEqual\(\[\]\)/);assert.match(source,/expect\(external\)\.toEqual\(\[\]\)/);
 for(const suffix of ['collapsed-desktop-en','review-desktop-en','enabled-mobile-en','enabled-mobile-de','persisted-desktop-en','persisted-mobile-de','result-desktop-en','result-mobile-en'])assert.ok(source.includes('synthetic-http-test-proactive-ai-'+suffix));
});

test('reported hostname and scoped interface IPs remain read-only display metadata',()=>{
 const fixture=createProactiveAIFixture(),view=fixture.handle('GET','/api/fleet/endpoint-identities',null),item=view.items[0];
 assert.equal(item.deviceId,proactiveAIFixtureDevice);assert.equal(item.latest.reportedHostname.value,proactiveAIFixtureHostname);assert.equal(item.latest.interfaces.items[0].name,'eth0');
 assert.deepEqual(item.latest.interfaces.items[0].addresses.ipv4.items,[{family:'ipv4',address:proactiveAIFixtureAddresses[0],scope:'private'}]);
 assert.deepEqual(item.latest.interfaces.items[0].addresses.ipv6.items,[{family:'ipv6',address:proactiveAIFixtureAddresses[1],scope:'link-local'}]);
 assert.equal(fixture.counts.identityReads,1);assert.equal(fixture.counts.settingsWrites,0);assert.equal(fixture.settings().enabled,false);
 const body=approval(fixture),packet=proactiveAIResultFixture().items[0].analysis.result.packet;
 for(const value of [proactiveAIFixtureHostname,...proactiveAIFixtureAddresses]){assert.equal(JSON.stringify(body).includes(value),false);assert.equal(JSON.stringify(packet).includes(value),false);}
 assert.deepEqual(body.deviceIds,[proactiveAIFixtureDevice]);assert.throws(()=>fixture.handle('POST',path,{...body,hostname:proactiveAIFixtureHostname}));
 assert.throws(()=>fixture.handle('POST','/api/fleet/endpoint-identities',{}));assert.throws(()=>fixture.handle('GET','/api/fleet/endpoint-identities',{query:'collect'}));
 item.latest.reportedHostname.value='mutated';assert.equal(proactiveAIIdentityFixture().items[0].latest.reportedHostname.value,proactiveAIFixtureHostname);
});
test('stale and missing identity fixtures preserve original observation meaning',()=>{
 const stale=proactiveAIIdentityFixture('stale'),missing=proactiveAIIdentityFixture('not_collected');
 assert.equal(stale.items[0].status,'stale');assert.equal(Date.parse(stale.serverNow)-Date.parse(stale.items[0].latest.collectedAt),180000);
 assert.equal(missing.items[0].status,'not_collected');assert.equal(missing.items[0].latest,null);assert.equal(missing.items[0].sequence,null);assert.equal(missing.items[0].receivedAt,null);assert.equal(missing.items[0].expiresAt,null);
 assert.throws(()=>proactiveAIIdentityFixture('invented'));
});
