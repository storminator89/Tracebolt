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
 const runner=read('./lan-browser.mjs'),module=read('./investigations-browser.mjs');assert.equal((runner.match(/await check\(/g)||[]).length,17);assert.equal((runner.match(/await check\(investigationsCaseName/g)||[]).length,1);assert.match(runner,/investigationsBrowserCase\(\{pageAt,login,expect,base,shot\}\)/);assert.match(runner,/name===investigationsCaseName\?\{stage:investigationsFailureStage\(\)\}/);
 assert.match(investigationsCaseName,/Synthetic read-only Investigations/);assert.match(investigationsFixtureDisclosure,/UI-only evidence/);assert.match(investigationsFixtureDisclosure,/tested separately in Go/);assert.doesNotMatch(module,/chromium\.launch|newContext\(|setDefaultTimeout|waitForTimeout|ignoreHTTPSErrors|execFile|spawn\(/);assert.match(module,/url.origin!==base/);assert.match(module,/method!=='GET'&&/);assert.match(module,/url.search!=='\?scope=open&offset=0'/);assert.match(module,/request.postData\(\)!==null/);assert.match(module,/expect\(mutations\)\.toEqual\(\[\]\)/);assert.match(module,/expect\(unexpected\)\.toEqual\(\[\]\)/);assert.match(module,/expect\(external\)\.toEqual\(\[\]\)/);
 for(const name of ['issue-desktop-en','stale-desktop-en','unknown-mobile-en','issue-mobile-en','issue-mobile-de'])assert.ok(module.includes('synthetic-http-test-investigations-'+name));assert.match(module,/await page.goBack\(\)/);assert.match(module,/toHaveURL\(`/);assert.match(module,/width:390,height:844/);
});
