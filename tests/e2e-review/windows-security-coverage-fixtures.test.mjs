import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import {windowsSecurityCoverageBrowserFixture,requireWindowsSecurityCoverageEvidence,windowsSecurityCoverageDisclosure} from './windows-security-coverage-browser.mjs';
const serverNow='2026-10-07T12:00:10Z',capturedAt='2026-10-07T12:00:00Z';
test('security coverage fixtures keep source quality, original time and unknowns independent',()=>{
 assert.match(windowsSecurityCoverageDisclosure,/UI-only fixture evidence/);
 for(const phase of ['observed','empty','not-found','unsupported-antivirus','denied-tpm','partial','bounded','unknown-only']){
  const view=windowsSecurityCoverageBrowserFixture({serverNow,capturedAt,phase}),s=view.securityCoverage;
  assert.equal(s.collectedAt,capturedAt);assert.equal(s.generationId,view.snapshot.generationId);assert.equal(view.securityPosture.defender.mode,'normal');assert.notEqual(s.grantId,view.securityPosture.grantId);
  if(phase==='empty'){assert.equal(s.antivirus.reportedCount,0);assert.equal(s.antivirus.quality,'observed');}
  if(phase==='not-found'){assert.equal(s.tpm.presence,'not-found');assert.equal(s.tpm.version,'unknown');}
  if(phase==='unsupported-antivirus'){assert.equal(s.antivirus.reportedCount,null);assert.equal(s.antivirus.reason,'windows_security_coverage_unsupported_platform');assert.equal(s.tpm.presence,'present');}
  if(phase==='denied-tpm'){assert.equal(s.tpm.quality,'denied');assert.equal(s.tpm.presence,'unknown');assert.equal(s.antivirus.rows.length,2);}
  if(phase==='bounded'){assert.equal(s.antivirus.reportedCount,40);assert.equal(s.antivirus.truncated,true);assert.equal(s.antivirus.rows.length,2);}
  if(phase==='unknown-only'){assert.equal(s.antivirus.rows[0].name,null);assert.equal(s.antivirus.rows[0].state,'unknown');assert.equal(s.tpm.presence,'unknown');}
 }
 for(const phase of ['legacy','revoked','unavailable-view'])assert.equal(windowsSecurityCoverageBrowserFixture({serverNow,capturedAt,phase}).securityCoverage,undefined);
 const expired=windowsSecurityCoverageBrowserFixture({serverNow:'2026-10-08T12:00:00Z',capturedAt});assert.equal(expired.securityCoverage,undefined);assert.equal(expired.status,'unavailable');
 const stale=windowsSecurityCoverageBrowserFixture({serverNow:'2026-10-07T12:05:00Z',capturedAt});assert.equal(stale.securityCoverage.collectedAt,capturedAt);assert.equal(stale.status,'stale');
});
test('retained coverage does not erase current failure or renew source time',()=>{
 const retainedCapturedAt='2026-10-07T11:00:00Z',fixture=at=>windowsSecurityCoverageBrowserFixture({serverNow:at,capturedAt,phase:'retained',retainedCapturedAt}),view=fixture(serverNow),old=view.retainedContext.securityCoverage;
 assert.equal(view.securityCoverage.antivirus.quality,'unavailable');assert.equal(view.securityCoverage.tpm.quality,'unavailable');assert.equal(old.collectedAt,retainedCapturedAt);assert.equal(old.grantId,view.securityCoverage.grantId);assert.notEqual(old.generationId,view.securityCoverage.generationId);
 assert.deepEqual(fixture('2026-10-07T12:01:00Z').retainedContext,view.retainedContext);assert.ok(fixture('2026-10-08T10:59:59Z').retainedContext);assert.equal(fixture('2026-10-08T11:00:00Z').retainedContext,undefined);
 for(const value of [undefined,'invalid',capturedAt,'2026-10-07T12:00:01Z'])assert.throws(()=>windowsSecurityCoverageBrowserFixture({serverNow,capturedAt,phase:'retained',retainedCapturedAt:value}),/Invalid synthetic/);
});
test('coverage completion requires each source-bound EN/DE desktop/mobile screenshot',()=>{
 const source='a'.repeat(40),name='synthetic',rows=[];for(const kind of ['summary','details','current-failure','retained-details'])for(const locale of ['en','de'])for(const width of [1440,390])rows.push({file:`synthetic-windows-coverage-${kind}-${width}-${locale}.png`,sourceSha:source,test:name,locale,viewport:{width,height:width===390?844:1000},publicSafe:true,fullPage:false,fixtureDisclosure:windowsSecurityCoverageDisclosure});
 assert.deepEqual(requireWindowsSecurityCoverageEvidence(rows,source,name),{coverageSummary:4,coverageDetails:4,coverageCurrentFailure:4,coverageRetainedDetails:4});
 for(let index=0;index<rows.length;index++){
  assert.throws(()=>requireWindowsSecurityCoverageEvidence(rows.filter((_,i)=>i!==index),source,name));assert.throws(()=>requireWindowsSecurityCoverageEvidence([...rows,rows[index]],source,name));
  for(const change of [{sourceSha:'b'.repeat(40)},{test:'other'},{locale:'unsupported'},{viewport:{width:800,height:600}},{publicSafe:false},{fullPage:true},{fixtureDisclosure:'unverified'}])assert.throws(()=>requireWindowsSecurityCoverageEvidence(rows.map((row,i)=>i===index?{...row,...change}:row),source,name));
 }
});
test('shared case wires reviewed coverage assertions and gate without another browser or request',()=>{
 const flow=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8'),runner=fs.readFileSync(new URL('./lan-browser.mjs',import.meta.url),'utf8'),helper=fs.readFileSync(new URL('./windows-security-coverage-browser.mjs',import.meta.url),'utf8');
 assert.match(flow,/mark\('security-coverage'\);phase='security-coverage'/);assert.match(flow,/exerciseWindowsSecurityCoverage\(\{page,expect,locale,width,shot\}\)/);assert.match(flow,/exerciseWindowsSecurityCoverageState\(/);assert.match(flow,/exerciseWindowsSecurityCoverageRetained\(/);assert.match(runner,/requireWindowsSecurityCoverageEvidence\(screenshots,sourceSha,name\)/);
 assert.doesNotMatch(helper,/chromium\.launch|newContext\(|spawn\(|execFile|writeFile|ignoreHTTPSErrors|fetch\(|localStorage|sessionStorage|waitForTimeout|setDefaultTimeout|clock\.runFor/);
 const manifest=JSON.parse(fs.readFileSync(new URL('./inert-suites.json',import.meta.url),'utf8')),entry=fs.readFileSync(new URL('./windows-inventory-fixtures.test.mjs',import.meta.url),'utf8');assert.ok(manifest.imported.includes('windows-security-coverage-fixtures.test.mjs'));assert.match(entry,/import '\.\/windows-security-coverage-fixtures\.test\.mjs';/);
});
