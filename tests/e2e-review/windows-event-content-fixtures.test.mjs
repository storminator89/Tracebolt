/** Pure invented DTO/source tests. Importing this suite never launches a browser. */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createWindowsEventContentFixture,exerciseWindowsEventContent,windowsEventContentDisclosure,windowsEventContentStages} from './windows-event-content-browser.mjs';
import {windowsBrowserFixture} from './windows-inventory-browser.mjs';
const at='2026-10-07T12:00:10Z',sessionExpiresAt='2026-10-08T12:00:00Z';
function setup(){const fixture=createWindowsEventContentFixture(),headers=windowsBrowserFixture(at,'event-content',at,at).events;return {fixture,args:{serverNow:at,sessionExpiresAt,headers,enabled:true}};}
const request=(args)=>({expectedFloor:'0',expectedHeaderGenerationId:args.headers.generationId,expectedHeaderSnapshotDigest:'sha256:'+'3'.repeat(64),selections:args.headers.channels.map(c=>({channel:c.channel,recordId:c.rows[0].recordId})),acknowledgeContent:true,acknowledgePlaintext:true});
test('selected-message source fixture uses explicit create, status and bounded query with real uint64 strings',()=>{
 const {fixture,args}=setup();const disabled=fixture.response({...args,enabled:false,action:'',body:null});assert.equal(disabled.localStatus,'disabled');assert.equal(disabled.headers,undefined);assert.equal(disabled.request,null);assert.deepEqual(fixture.counts(),{creates:0,queries:0,cancels:0});
 const pending=fixture.response({...args,action:'create',body:request(args)});assert.equal(pending.contentStatus,'pending');assert.equal(pending.request.description.query.events[0].recordId,'18446744073709551615');fixture.complete();const accepted=fixture.response({...args,action:'',body:null});const result=fixture.response({...args,action:'query',body:{identity:accepted.request.description.identity}});assert.equal(result.report.quality,'partial');assert.equal(result.report.events[1].reason,'windows_event_content_publisher_unavailable');assert.match(result.report.events[0].message,/<img/);assert.equal(result.expiresAt,pending.request.description.expiresAt);assert.equal(fixture.counts().creates,1);
 const canceled=fixture.response({...args,action:'cancel',body:{identity:accepted.request.description.identity}});assert.equal(canceled.request.state,'canceled');assert.throws(()=>fixture.response({...args,action:'query',body:{identity:accepted.request.description.identity}}));
});
test('fixture rejects hidden/arbitrary selections, narrowed record IDs and omitted consent',()=>{
 for(const mutate of [body=>body.selections[0].recordId=9007199254740993,body=>body.selections[0].channel='Security',body=>body.selections[0].recordId='1',body=>body.acknowledgeContent=false,body=>body.acknowledgePlaintext=false,body=>body.selections.push(body.selections[0]),body=>body.extra='secret']){const {fixture,args}=setup(),body=request(args);mutate(body);assert.throws(()=>fixture.response({...args,action:'create',body}));}
});
test('same synthetic header sample keeps its original capture across content polling',()=>{
 const before=windowsBrowserFixture(at,'event-content',at,at),after=windowsBrowserFixture('2026-10-07T12:00:13Z','event-content',at,at);assert.equal(before.events.collectedAt,after.events.collectedAt);assert.equal(before.events.generationId,after.events.generationId);
});
test('selected-message case is really called inside existing EN/DE desktop/mobile Windows loop',()=>{
 const runner=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8'),helper=fs.readFileSync(new URL('./windows-event-content-browser.mjs',import.meta.url),'utf8'),entry=fs.readFileSync(new URL('./windows-inventory-fixtures.test.mjs',import.meta.url),'utf8'),manifest=JSON.parse(fs.readFileSync(new URL('./inert-suites.json',import.meta.url),'utf8'));
 assert.equal(typeof exerciseWindowsEventContent,'function');assert.match(windowsEventContentDisclosure,/UI-only fixture/);assert.match(windowsEventContentDisclosure,/no native event read/);assert.equal(new Set(windowsEventContentStages).size,windowsEventContentStages.length);assert.ok(windowsEventContentStages.every(s=>/^content-[a-z-]+$/.test(s)));
 assert.match(runner,/await exerciseWindowsEventContent\(\{page,expect,locale,width,shot,fixture:eventContent/);assert.match(runner,/for\(const locale of \['en','de'\]\)for\(const width of \[1440,390\]\)/);assert.match(runner,/action&&phase!=='event-content'/);assert.match(runner,/missing-content-csrf/);
 assert.match(entry,/import '\.\/windows-event-content-fixtures\.test\.mjs'/);assert.ok(manifest.imported.includes('windows-event-content-fixtures.test.mjs'));assert.ok(!manifest.entries.includes('windows-event-content-fixtures.test.mjs'));
 for(const guard of ['unexpected','writes','external'])assert.ok(runner.includes(`expect(${guard}).toEqual([])`));assert.match(helper,/fixture\.counts\(\)/);assert.match(helper,/page\.keyboard\.press\('Enter'\)/);assert.match(helper,/await advance\(3000\)/);assert.match(helper,/synthetic-windows-selected-messages-\$\{width\}-\$\{locale\}/);assert.doesNotMatch(helper,/chromium\.launch|newContext\(|spawn\(|execFile|writeFile|ignoreHTTPSErrors|fetch\(|localStorage|sessionStorage|waitForTimeout|setDefaultTimeout/);
});
