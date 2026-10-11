import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import {windowsSessionContextBrowserFixture,requireWindowsSessionContextEvidence,windowsSessionContextDisclosure} from './windows-session-context-browser.mjs';
const serverNow='2026-10-07T12:00:10Z',capturedAt='2026-10-07T12:00:00Z';
test('session browser fixtures preserve original capture and independent join visibility',()=>{
 for(const phase of ['observed','denied','unavailable']){const view=windowsSessionContextBrowserFixture({serverNow,capturedAt,phase}),s=view.sessionContext;assert.equal(s.collectedAt,capturedAt);assert.equal(s.generationId,view.snapshot.generationId);assert.equal(s.join.name,'FIXTURE-WORKGROUP');if(phase!=='observed'){assert.equal(s.sessions.quality,phase);assert.equal(s.sessions.observedCount,null);assert.deepEqual(s.sessions.rows,[]);}}
 for(const phase of ['legacy','revoked','unavailable-view'])assert.equal(windowsSessionContextBrowserFixture({serverNow,capturedAt,phase}).sessionContext,undefined);
 const expired=windowsSessionContextBrowserFixture({serverNow:'2026-10-08T12:00:00Z',capturedAt});assert.equal(expired.sessionContext,undefined);assert.equal(expired.status,'unavailable');
});
test('session completion requires all eight exact-source screenshot records',()=>{
 const source='a'.repeat(40),name='synthetic',rows=[];for(const kind of ['summary','details'])for(const locale of ['en','de'])for(const width of [1440,390])rows.push({file:`synthetic-windows-sessions-${kind}-${width}-${locale}.png`,sourceSha:source,test:name,locale,viewport:{width,height:width===390?844:1000},publicSafe:true,fullPage:false,fixtureDisclosure:windowsSessionContextDisclosure});
 assert.deepEqual(requireWindowsSessionContextEvidence(rows,source,name),{sessionSummary:4,sessionDetails:4});
 for(const bad of [rows.slice(1),[...rows,rows[0]],rows.map((r,i)=>i?r:{...r,sourceSha:'b'.repeat(40)}),rows.map((r,i)=>i?r:{...r,publicSafe:false}),rows.map((r,i)=>i?r:{...r,viewport:{width:390,height:844}}),rows.map((r,i)=>i?r:{...r,fixtureDisclosure:'unverified'})])assert.throws(()=>requireWindowsSessionContextEvidence(bad,source,name));
});
test('shared hosted case navigates sessions and captures details without a new harness',()=>{
 const flow=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8'),runner=fs.readFileSync(new URL('./lan-browser.mjs',import.meta.url),'utf8'),helper=fs.readFileSync(new URL('./windows-session-context-browser.mjs',import.meta.url),'utf8');
 assert.match(flow,/mark\('sessions'\);phase='sessions'/);assert.match(flow,/exerciseWindowsSessionContext\(\{page,expect,locale,width,shot\}\)/);assert.match(runner,/requireWindowsSessionContextEvidence\(screenshots,sourceSha,name\)/);assert.match(helper,/details\.locator\('> summary'\)\.click\(\)/);
 assert.doesNotMatch(helper,/chromium\.launch|newContext\(|spawn\(|execFile|writeFile|ignoreHTTPSErrors|fetch\(|localStorage|sessionStorage|waitForTimeout|setDefaultTimeout|clock\.runFor/);
});
