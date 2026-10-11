import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import {windowsHardwareContextBrowserFixture,requireWindowsHardwareContextEvidence,windowsHardwareContextDisclosure} from './windows-hardware-context-browser.mjs';
const serverNow='2026-10-07T12:00:10Z',capturedAt='2026-10-07T12:00:00Z';
test('hardware fixtures preserve independent sources, absence and unknown battery truth',()=>{
 for(const phase of ['observed','absent-battery','unknown-battery','denied-bios','denied-chassis']){
  const view=windowsHardwareContextBrowserFixture({serverNow,capturedAt,phase}),h=view.hardwareContext;
  assert.equal(h.collectedAt,capturedAt);assert.equal(h.generationId,view.snapshot.generationId);assert.equal(h.system.model.value,'Example Laptop 14');
  if(phase==='absent-battery')assert.equal(h.power.batteryPresence,'absent');if(phase==='unknown-battery'){assert.equal(h.power.batteryPresence,'unknown');assert.equal(h.power.quality,'partial');}
  if(phase==='denied-bios'){assert.equal(h.firmware.quality,'denied');assert.equal(h.chassis.serialNumber.value,'FIXTURE-CHASSIS-0042');}
  if(phase==='denied-chassis'){assert.equal(h.chassis.quality,'denied');assert.equal(h.firmware.version.value,'F.42');}
 }
 for(const phase of ['legacy','revoked','unavailable-view'])assert.equal(windowsHardwareContextBrowserFixture({serverNow,capturedAt,phase}).hardwareContext,undefined);
 const expired=windowsHardwareContextBrowserFixture({serverNow:'2026-10-08T12:00:00Z',capturedAt});assert.equal(expired.hardwareContext,undefined);assert.equal(expired.status,'unavailable');
});
test('hardware retained fixture never refreshes a previous capture or erases current failure',()=>{
 const retainedCapturedAt='2026-10-07T11:00:00Z',fixture=at=>windowsHardwareContextBrowserFixture({serverNow:at,capturedAt,phase:'retained',retainedCapturedAt});
 const view=fixture(serverNow),h=view.hardwareContext,old=view.retainedContext.hardwareContext;
 for(const key of ['system','firmware','chassis','power'])assert.equal(h[key].quality,'unavailable');
 assert.equal(old.collectedAt,retainedCapturedAt);assert.equal(h.collectedAt,capturedAt);assert.equal(old.grantId,h.grantId);assert.notEqual(old.generationId,h.generationId);assert.equal(old.chassis.serialNumber.value,'FIXTURE-CHASSIS-0042');
 assert.deepEqual(fixture('2026-10-07T12:01:00Z').retainedContext,view.retainedContext);assert.ok(fixture('2026-10-08T10:59:59Z').retainedContext);assert.equal(fixture('2026-10-08T11:00:00Z').retainedContext,undefined);
 for(const invalid of [undefined,'invalid',capturedAt,'2026-10-07T12:00:01Z'])assert.throws(()=>windowsHardwareContextBrowserFixture({serverNow,capturedAt,phase:'retained',retainedCapturedAt:invalid}),/Invalid synthetic/);
});
test('hardware completion requires every exact-source EN/DE desktop/mobile screenshot',()=>{
 const source='a'.repeat(40),name='synthetic',rows=[];for(const kind of ['summary','details','current-failure','retained-details'])for(const locale of ['en','de'])for(const width of [1440,390])rows.push({file:`synthetic-windows-hardware-${kind}-${width}-${locale}.png`,sourceSha:source,test:name,locale,viewport:{width,height:width===390?844:1000},publicSafe:true,fullPage:false,fixtureDisclosure:windowsHardwareContextDisclosure});
 const expected={hardwareSummary:4,hardwareDetails:4,hardwareCurrentFailure:4,hardwareRetainedDetails:4};assert.deepEqual(requireWindowsHardwareContextEvidence(rows,source,name),expected);
 for(let index=0;index<rows.length;index++){
  assert.throws(()=>requireWindowsHardwareContextEvidence(rows.filter((_,i)=>i!==index),source,name));assert.throws(()=>requireWindowsHardwareContextEvidence([...rows,rows[index]],source,name));
  for(const change of [{sourceSha:'b'.repeat(40)},{test:'another'},{locale:'unsupported'},{viewport:{width:800,height:600}},{publicSafe:false},{fullPage:true},{fixtureDisclosure:'unverified'}])assert.throws(()=>requireWindowsHardwareContextEvidence(rows.map((row,i)=>i===index?{...row,...change}:row),source,name));
 }
});
test('shared runner invokes hardware UI assertions and enforces its completion gate',()=>{
 const flow=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8'),runner=fs.readFileSync(new URL('./lan-browser.mjs',import.meta.url),'utf8');
 assert.match(flow,/mark\('hardware'\);phase='hardware'/);assert.match(flow,/exerciseWindowsHardwareContext\(\{page,expect,locale,width,shot\}\)/);assert.match(flow,/exerciseWindowsHardwareRetainedContext\(/);assert.match(flow,/exerciseWindowsHardwareState\(/);assert.match(runner,/requireWindowsHardwareContextEvidence\(screenshots,sourceSha,name\)/);
});
