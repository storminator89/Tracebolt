import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import {windowsSecurityPostureBrowserFixture,requireWindowsSecurityPostureEvidence,windowsSecurityPostureDisclosure} from './windows-security-posture-browser.mjs';
const serverNow='2026-10-07T12:00:10Z',capturedAt='2026-10-07T12:00:00Z';
test('security fixtures bind the original capture and preserve independent source quality',()=>{
 assert.match(windowsSecurityPostureDisclosure,/UI-only fixture evidence/);
 for(const phase of ['observed','passive','edr-block','unknown','partial','denied','unavailable']){
  const view=windowsSecurityPostureBrowserFixture({serverNow,capturedAt,phase}),s=view.securityPosture;
  assert.equal(s.collectedAt,capturedAt);assert.equal(s.generationId,view.snapshot.generationId);assert.equal(s.firewall.quality,'partial');assert.equal(s.firewall.profiles[1].enabled,'on');
  if(['passive','edr-block','unknown'].includes(phase))assert.equal(s.defender.mode,phase);
  if(['denied','unavailable'].includes(phase)){assert.equal(s.defender.mode,'unknown');assert.equal(s.defender.signatureAgeDays,null);}
 }
 for(const phase of ['legacy','revoked','unavailable-view'])assert.equal(windowsSecurityPostureBrowserFixture({serverNow,capturedAt,phase}).securityPosture,undefined);
 const expired=windowsSecurityPostureBrowserFixture({serverNow:'2026-10-08T12:00:00Z',capturedAt});assert.equal(expired.securityPosture,undefined);assert.equal(expired.status,'unavailable');
 const stale=windowsSecurityPostureBrowserFixture({serverNow:'2026-10-07T12:05:00Z',capturedAt});assert.equal(stale.securityPosture.collectedAt,capturedAt);assert.equal(stale.status,'stale');
});
test('completion requires source-bound actual screenshot records in EN/DE desktop/mobile',()=>{
 const source='a'.repeat(40),testName='synthetic',records=[];
 for(const kind of ['defender','firewall','details'])for(const locale of ['en','de'])for(const width of [1440,390])records.push({file:`synthetic-windows-security-${kind}-${width}-${locale}.png`,sourceSha:source,test:testName,locale,viewport:{width,height:width===390?844:1000},publicSafe:true,fullPage:false,fixtureDisclosure:windowsSecurityPostureDisclosure});
 assert.deepEqual(requireWindowsSecurityPostureEvidence(records,source,testName),{securityDefender:4,securityFirewall:4,securityDetails:4});
 assert.throws(()=>requireWindowsSecurityPostureEvidence(records.map(r=>({...r,sourceSha:null})),null,testName));
 for(const broken of [records.slice(1),[...records,records[0]],records.map((r,i)=>i?r:{...r,sourceSha:'b'.repeat(40)}),records.map((r,i)=>i?r:{...r,viewport:{width:390,height:844}}),records.map((r,i)=>i?r:{...r,publicSafe:false}),records.map((r,i)=>i?r:{...r,fixtureDisclosure:'unverified'})])assert.throws(()=>requireWindowsSecurityPostureEvidence(broken,source,testName));
});
test('shared hosted case wires security without a separate browser, request or clock mutation',()=>{
 const source=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8'),runner=fs.readFileSync(new URL('./lan-browser.mjs',import.meta.url),'utf8'),helper=fs.readFileSync(new URL('./windows-security-posture-browser.mjs',import.meta.url),'utf8');
 assert.match(source,/mark\('security'\);phase='security'/);assert.match(source,/exerciseWindowsSecurityPosture\(\{page,expect,locale,width,shot\}\)/);assert.match(source,/windowsSecurityPostureBrowserFixture\(\{serverNow:at,capturedAt:updatesCapturedAt\}\)/);assert.match(runner,/requireWindowsSecurityPostureEvidence\(screenshots,sourceSha,name\)/);
 assert.doesNotMatch(helper,/chromium\.launch|newContext\(|spawn\(|execFile|writeFile|ignoreHTTPSErrors|fetch\(|localStorage|sessionStorage|waitForTimeout|setDefaultTimeout|clock\.runFor/);
});

test('Docker web stage includes only exact synthetic cross-language snapshot inputs',()=>{
 const docker=fs.readFileSync(new URL('../../Dockerfile',import.meta.url),'utf8'),web=docker.split(' AS web\n')[1].split('FROM --platform=$BUILDPLATFORM golang:')[0];
 for(const path of ['internal/windowssecurity/testdata/snapshot.json','internal/windowspatchcontext/testdata/snapshot.json']){
  assert.ok(web.includes(`COPY ${path} /src/${path}`));assert.ok(web.indexOf(`COPY ${path}`)<web.indexOf('RUN npm run build'));
 }
 assert.doesNotMatch(web,/COPY internal\/ internal\//);
});
