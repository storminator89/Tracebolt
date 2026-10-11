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
test('retained session fixture preserves the latest failure and an independent original useful capture',()=>{
 const retainedCapturedAt='2026-10-07T11:00:00Z',fixture=at=>windowsSessionContextBrowserFixture({serverNow:at,capturedAt,phase:'retained',retainedCapturedAt});
 const view=fixture(serverNow),current=view.sessionContext,old=view.retainedContext.sessionContext;
 assert.equal(current.collectedAt,capturedAt);assert.equal(current.generationId,view.snapshot.generationId);assert.equal(view.sequence,2);
 assert.equal(old.collectedAt,retainedCapturedAt);assert.equal(old.generationId,`sample_${'b'.repeat(32)}`);assert.notEqual(old.generationId,current.generationId);assert.equal(old.grantId,current.grantId);
 assert.equal(Date.parse(current.collectedAt)-Date.parse(old.collectedAt),3600000);assert.equal(old.sessions.quality,'partial');assert.equal(old.sessions.rows[1].userName,'fixture-alex');assert.equal(old.join.name,'FIXTURE-WORKGROUP');
 assert.deepEqual(current.sessions,{quality:'unavailable',reason:'windows_session_context_budget_exhausted',observedCount:null,retainedCount:0,truncatedCount:null,rows:[]});
 assert.deepEqual(current.join,{quality:'unavailable',reason:'windows_session_context_budget_exhausted',status:'unknown',name:null});
 const repeated=fixture('2026-10-07T12:01:00Z');assert.deepEqual(repeated.retainedContext,view.retainedContext);assert.deepEqual(repeated.sessionContext,current);
 assert.ok(fixture('2026-10-08T10:59:59Z').retainedContext);const expired=fixture('2026-10-08T11:00:00Z');assert.equal(expired.retainedContext,undefined);assert.deepEqual(expired.sessionContext,current);assert.equal(expired.status,'stale');
 const baseExpired=fixture('2026-10-08T12:00:00Z');assert.equal(baseExpired.retainedContext,undefined);assert.equal(baseExpired.sessionContext,undefined);
 for(const invalid of [undefined,'not-a-date',capturedAt,'2026-10-07T12:00:01Z'])assert.throws(()=>windowsSessionContextBrowserFixture({serverNow,capturedAt,phase:'retained',retainedCapturedAt:invalid}),/Invalid synthetic/);
});
test('session completion requires all sixteen exact-source records with separate current and retained views',()=>{
 const source='a'.repeat(40),name='synthetic',rows=[];for(const kind of ['summary','details','current-failure','retained-details'])for(const locale of ['en','de'])for(const width of [1440,390])rows.push({file:`synthetic-windows-sessions-${kind}-${width}-${locale}.png`,sourceSha:source,test:name,locale,viewport:{width,height:width===390?844:1000},publicSafe:true,fullPage:false,fixtureDisclosure:windowsSessionContextDisclosure});
 const expected={sessionSummary:4,sessionDetails:4,sessionCurrentFailure:4,sessionRetainedDetails:4};assert.deepEqual(requireWindowsSessionContextEvidence(rows,source,name),expected);
 assert.throws(()=>requireWindowsSessionContextEvidence(rows.slice(0,8),source,name));
 assert.throws(()=>requireWindowsSessionContextEvidence(rows.filter(row=>!row.file.includes('current-failure')),source,name));
 for(let index=0;index<rows.length;index++){
  const missing=rows.filter((_,i)=>i!==index);assert.throws(()=>requireWindowsSessionContextEvidence(missing,source,name));
  assert.throws(()=>requireWindowsSessionContextEvidence([...rows,rows[index]],source,name));
  assert.throws(()=>requireWindowsSessionContextEvidence(rows.map((row,i)=>i===index?rows[(index+1)%rows.length]:row),source,name));
  for(const change of [{sourceSha:'b'.repeat(40)},{test:'another case'},{locale:'unsupported'},{viewport:{width:800,height:600}},{viewport:{...rows[index].viewport,height:900}},{publicSafe:false},{fullPage:true},{fixtureDisclosure:'unverified'}])assert.throws(()=>requireWindowsSessionContextEvidence(rows.map((row,i)=>i===index?{...row,...change}:row),source,name));
 }
 assert.deepEqual(requireWindowsSessionContextEvidence([...rows,{file:'synthetic-unrelated.png'}],source,name),expected);
});
test('shared hosted case navigates sessions and captures details without a new harness',()=>{
 const flow=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8'),runner=fs.readFileSync(new URL('./lan-browser.mjs',import.meta.url),'utf8'),helper=fs.readFileSync(new URL('./windows-session-context-browser.mjs',import.meta.url),'utf8');
 assert.match(flow,/mark\('sessions'\);phase='sessions'/);assert.match(flow,/exerciseWindowsSessionContext\(\{page,expect,locale,width,shot\}\)/);assert.match(runner,/requireWindowsSessionContextEvidence\(screenshots,sourceSha,name\)/);assert.match(helper,/details\.locator\('> summary'\)\.click\(\)/);
 assert.match(flow,/mark\('sessions-retained'\);phase='sessions-retained'/);assert.match(flow,/if\(phase==='sessions-retained'\)return reply\(windowsSessionContextBrowserFixture/);assert.match(flow,/exerciseWindowsSessionRetainedContext\(\{page,expect,locale,width,shot,capturedAt:updatesCapturedAt,retainedCapturedAt:sessionsRetainedCapturedAt\}\)/);
 assert.match(helper,/expect\(previous\)\.not\.toHaveAttribute\('open'\)/);assert.match(helper,/previous\.locator\('> summary'\)\.click\(\)/);assert.match(helper,/expect\(oldTime\)\.toHaveAttribute\('datetime',retainedCapturedAt\)/);
 const retained=helper.slice(helper.indexOf('export async function exerciseWindowsSessionRetainedContext'),helper.indexOf('/** Completion'));
 assert.match(retained,/synthetic-windows-sessions-current-failure-/);assert.match(retained,/synthetic-windows-sessions-retained-details-/);assert.match(retained,/latest\.scrollIntoViewIfNeeded\(\)/);assert.match(retained,/oldHeader\.scrollIntoViewIfNeeded\(\)/);assert.doesNotMatch(retained,/block:'start'|\[currentTime,failure,previous/);
 assert.doesNotMatch(helper,/chromium\.launch|newContext\(|spawn\(|execFile|writeFile|ignoreHTTPSErrors|fetch\(|localStorage|sessionStorage|waitForTimeout|setDefaultTimeout|clock\.runFor/);
});
