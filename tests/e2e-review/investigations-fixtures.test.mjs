import './health-dashboard-browser.test.mjs';
import './device-inventory-browser-contracts.test.mjs';
import './workspace-navigation-browser.test.mjs';
// Keep the display-only service-action privacy guards in the existing CI fixture entry point.
import './service-action-display-fixtures.test.mjs';
/** Pure DTO/source checks only; no browser, API, host or provider is started. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import {validHealthView} from '../../web/src/health-types.ts';
import {investigationsCaseName,investigationsFixtureDisclosure,investigationsFixtureDevice,investigationsFixture,investigationsDeviceFixture} from './investigations-browser.mjs';
const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8');
test('invented issue and stale views preserve one durable incident and original evidence times',()=>{
 const issue=investigationsFixture('issue'),stale=investigationsFixture('stale');
 for(const view of [issue,stale]){assert.equal(validHealthView(view.devices[0],investigationsFixtureDevice),true);assert.equal(validHealthView({...view.devices[0],incidents:view.items.map(item=>item.incident)},investigationsFixtureDevice),true);assert.equal(view.counts.open,1);assert.equal(view.items[0].incident.resolvedAt,null);}
 assert.deepEqual(stale.items,issue.items);assert.equal(stale.devices[0].checks[1].observedAt,issue.devices[0].checks[1].observedAt);assert.equal(issue.devices[0].checks[1].value,95);assert.equal(stale.devices[0].checks[1].value,null);assert.equal(stale.devices[0].checks[1].state,'unknown');assert.ok(Date.parse(stale.serverNow)-Date.parse(stale.devices[0].evaluatedAt)>120000);
});
test('empty retained history is an unknown current assessment, and a renewed fixture supplies a genuinely new observation',()=>{
 const unknown=investigationsFixture('unknown'),renewed=investigationsFixture('renewed');assert.equal(validHealthView(unknown.devices[0],investigationsFixtureDevice),true);assert.equal(unknown.total,0);assert.equal(unknown.items.length,0);assert.equal(unknown.devices[0].evaluatedAt,null);assert.equal(unknown.devices[0].status,'unknown');assert.ok(unknown.devices[0].checks.every(check=>check.state==='unknown'&&check.value===null&&check.observedAt===null));assert.equal(renewed.devices[0].checks[1].observedAt,renewed.serverNow);assert.equal(renewed.items[0].incident.openedAt,investigationsFixture().items[0].incident.openedAt);assert.equal(investigationsDeviceFixture().id,investigationsFixtureDevice);assert.throws(()=>investigationsFixture('unsupported'));
});
test('one hosted case preserves existing runner and exact read-only interception with screenshot disclosure',()=>{
 const runner=read('./lan-browser.mjs'),module=read('./investigations-browser.mjs');assert.equal((runner.match(/await check\(/g)||[]).length,25);assert.equal((runner.match(/await check\(investigationsCaseName/g)||[]).length,1);assert.match(runner,/investigationsBrowserCase\(\{pageAt,login,expect,base,shot\}\)/);assert.match(runner,/name===investigationsCaseName\?\{stage:investigationsFailureStage\(\)\}/);
 assert.match(investigationsCaseName,/Synthetic read-only Investigations/);assert.match(investigationsFixtureDisclosure,/UI-only evidence/);assert.match(investigationsFixtureDisclosure,/tested separately in Go/);assert.doesNotMatch(module,/chromium\.launch|newContext\(|setDefaultTimeout|waitForTimeout|ignoreHTTPSErrors|execFile|spawn\(/);assert.match(module,/url.origin!==base/);assert.match(module,/method!=='GET'&&/);assert.match(module,/url.search!=='\?scope=open&offset=0'/);assert.match(module,/request.postData\(\)!==null/);assert.match(module,/expect\(mutations\)\.toEqual\(\[\]\)/);assert.match(module,/expect\(unexpected\)\.toEqual\(\[\]\)/);assert.match(module,/expect\(external\)\.toEqual\(\[\]\)/);
 for(const name of ['issue-desktop-en','stale-desktop-en','unknown-mobile-en','issue-mobile-en','issue-mobile-de'])assert.ok(module.includes('synthetic-http-test-investigations-'+name));assert.match(module,/await page.goBack\(\)/);assert.match(module,/toHaveURL\(`/);assert.match(module,/width:390,height:844/);
});

test('new investigation paragraphs are isolated from the legacy mobile note grid and checked for text overlap',()=>{
 const module=read('./investigations-browser.mjs'),component=read('../../web/src/investigations.tsx'),css=read('../../web/src/investigations.css');
 assert.ok(component.includes('className="investigations-note"'));assert.doesNotMatch(component,/className="investigation-note(?:[" ])/);assert.doesNotMatch(css,/\.investigation-note(?:[ >{])/);assert.match(css,/\.investigations-note/);
 assert.match(module,/geometry\.display\)\.toBe\('block'\)/);assert.match(module,/geometry\.gridColumns\)\.toBe\('none'\)/);assert.match(module,/document\.createTreeWalker\(element,NodeFilter\.SHOW_TEXT\)/);assert.match(module,/range\.getClientRects\(\)/);assert.match(module,/geometry\.overlaps\)\.toBe\(0\)/);assert.match(module,/geometry\.availableWidth-1/);
});

test('capability browser amendment uses existing synthetic status fixtures and never hides a newer failure', async () => {
 const {capabilitySystemFixture,capabilityDeviceFixture,capabilityFixtureDisclosure}=await import('./capability-scenarios.mjs');
 const collected=capabilitySystemFixture(),denied=capabilitySystemFixture('denied'),failed=capabilitySystemFixture('failed'),stale=capabilitySystemFixture('stale');
 assert.equal(collected.latest.services.coverage,'complete');assert.equal(denied.latest.services.reason,'permission_denied');assert.equal(failed.latest.services.reason,'read_failed');
 assert.deepEqual(denied.lastComplete,collected.lastComplete);assert.deepEqual(failed.lastComplete,collected.lastComplete);assert.equal(stale.latest.services.observedAt,collected.latest.services.observedAt);assert.equal(stale.status,'stale');
 const renewed=capabilitySystemFixture('collected',1);assert.ok(Date.parse(renewed.serverNow)>Date.parse(stale.serverNow));assert.ok(Date.parse(renewed.latest.services.observedAt)>Date.parse(stale.latest.services.observedAt));assert.notEqual(renewed.latest.generationId,stale.latest.generationId);assert.throws(()=>capabilitySystemFixture('collected',2));
 assert.equal(Object.hasOwn(collected.latest,'socketOwnerProvenance'),false);assert.equal(capabilityDeviceFixture().id,collected.deviceId);assert.match(capabilityFixtureDisclosure,/intercepted synthetic/);assert.match(capabilityFixtureDisclosure,/no host, journal content, capture, grant or data write/);assert.throws(()=>capabilitySystemFixture('invented'));
});
test('capability hosted case is registered once with fixed diagnostic stages and read-only guards', () => {
 const runner=read('./lan-browser.mjs'),module=read('./capability-scenarios.mjs');
 assert.equal((runner.match(/await check\(capabilityCaseName/g)||[]).length,1);assert.match(runner,/capabilityBrowserCase\(\{pageAt,login,expect,base,shot\}\)/);assert.match(runner,/name===capabilityCaseName\?\{stage:capabilityFailureStage\(\)\}/);
 assert.match(module,/system-inventory-fixtures\.ts/);assert.doesNotMatch(module,/chromium\.launch|newContext\(|setDefaultTimeout|waitForTimeout|ignoreHTTPSErrors|execFile|spawn\(/);assert.match(module,/url.origin !== base/);assert.match(module,/request.method\(\) !== 'GET'/);assert.match(module,/request.postData\(\) !== null/);assert.match(module,/url.pathname.includes\('\/journal'\)/);assert.match(module,/url.pathname.endsWith\('\/query'\)/);
 for(const guard of ['writes','contentReads','external'])assert.ok(module.includes(`expect(${guard}).toEqual([])`));
 assert.match(module,/toHaveClass\(\/observed\/\)/);assert.match(module,/not.toHaveClass\(\/attention\/\)/);assert.match(module,/\['denied', 'failed', 'stale'\]/);assert.match(module,/width: 390, height: 844/);assert.match(module,/getByLabel\('Language'/);assert.match(module,/keyboard.press\('Enter'\)/);
});
