import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import {windowsStorageContextBrowserFixture,requireWindowsStorageContextEvidence,windowsStorageContextDisclosure} from './windows-storage-context-browser.mjs';
const serverNow='2026-10-07T12:00:10Z',capturedAt='2026-10-07T12:00:00Z';
test('storage fixtures preserve exact capacities, independent coverage and unknown provider values',()=>{
 for(const phase of ['observed','denied-drives','unsupported-disks','unknown','future-codes','virtual-raid','bounded','empty']){
  const view=windowsStorageContextBrowserFixture({serverNow,capturedAt,phase}),s=view.storageContext;
  assert.equal(s.collectedAt,capturedAt);assert.equal(s.generationId,view.snapshot.generationId);
  assert.deepEqual(view.volumes.rows[0].capacity,{totalBytes:'9007199254740993',freeBytes:'18446744073709551615',availableBytes:'42'});
  if(phase==='observed'){assert.equal(s.drives.rows[0].letter,'C:');assert.equal(s.drives.rows[0].volumeGuid,view.volumes.rows[0].volumeId);assert.equal(s.drives.complete,true);assert.equal(s.drives.quality,'partial');assert.equal(s.disks.rows[0].deviceId.value,'provider-local-04');assert.equal(s.disks.rows[1].healthStatus,null);assert.deepEqual(s.disks.rows[1].operationalStatus,[32768]);}
  if(phase==='denied-drives'){assert.equal(s.drives.quality,'denied');assert.equal(s.disks.rows[0].friendlyName.value,'Fixture NVMe');}
  if(phase==='unsupported-disks'){assert.equal(s.disks.reason,'windows_storage_context_unsupported_platform');assert.equal(s.drives.rows[0].letter,'C:');}
  if(phase==='unknown')assert.equal(s.disks.rows[0].healthStatus,null);
  if(phase==='future-codes')assert.equal(s.disks.rows[0].healthStatus,65535);
  if(phase==='virtual-raid')assert.deepEqual(s.disks.rows.map(row=>row.busType),[8,15]);
  if(phase==='bounded'){assert.equal(s.disks.observedCount,64);assert.equal(s.disks.countExact,false);assert.equal(s.disks.truncated,true);}
  if(phase==='empty'){assert.deepEqual(s.drives.rows,[]);assert.deepEqual(s.disks.rows,[]);assert.equal(s.disks.complete,true);}
  assert.equal(view.volumes.collectedAt,'2026-10-07T12:00:02.000Z');assert.notEqual(view.volumes.collectedAt,s.collectedAt);
 }
 for(const phase of ['legacy','revoked','unavailable-view'])assert.equal(windowsStorageContextBrowserFixture({serverNow,capturedAt,phase}).storageContext,undefined);
 const expired=windowsStorageContextBrowserFixture({serverNow:'2026-10-08T12:00:00Z',capturedAt});assert.equal(expired.storageContext,undefined);assert.equal(expired.status,'unavailable');
});
test('storage retained fixture keeps original age and never silently replaces current failure',()=>{
 const retainedCapturedAt='2026-10-07T11:00:00Z',fixture=at=>windowsStorageContextBrowserFixture({serverNow:at,capturedAt,phase:'retained',retainedCapturedAt});
 const view=fixture(serverNow),s=view.storageContext,old=view.retainedContext.storageContext;
 for(const key of ['drives','disks'])assert.equal(s[key].quality,'unavailable');
 assert.equal(old.collectedAt,retainedCapturedAt);assert.equal(s.collectedAt,capturedAt);assert.equal(old.grantId,s.grantId);assert.notEqual(old.generationId,s.generationId);assert.equal(old.drives.rows[0].letter,'C:');assert.notEqual(old.generationId,view.volumes.generationId);assert.notEqual(old.collectedAt,view.volumes.collectedAt);
 assert.deepEqual(fixture('2026-10-07T12:01:00Z').retainedContext,view.retainedContext);assert.ok(fixture('2026-10-08T10:59:59Z').retainedContext);assert.equal(fixture('2026-10-08T11:00:00Z').retainedContext,undefined);
 for(const invalid of [undefined,'invalid',capturedAt,'2026-10-07T12:00:01Z'])assert.throws(()=>windowsStorageContextBrowserFixture({serverNow,capturedAt,phase:'retained',retainedCapturedAt:invalid}),/Invalid synthetic/);
});
test('storage completion requires every exact-source EN/DE desktop/mobile screenshot',()=>{
 const source='a'.repeat(40),name='synthetic',rows=[];for(const kind of ['summary','details','current-failure','retained-details'])for(const locale of ['en','de'])for(const width of [1440,390])rows.push({file:`synthetic-windows-storage-context-${kind}-${width}-${locale}.png`,sourceSha:source,test:name,locale,viewport:{width,height:width===390?844:1000},publicSafe:true,fullPage:false,fixtureDisclosure:windowsStorageContextDisclosure});
 const expected={storageSummary:4,storageDetails:4,storageCurrentFailure:4,storageRetainedDetails:4};assert.deepEqual(requireWindowsStorageContextEvidence(rows,source,name),expected);
 for(let index=0;index<rows.length;index++){
  assert.throws(()=>requireWindowsStorageContextEvidence(rows.filter((_,i)=>i!==index),source,name));assert.throws(()=>requireWindowsStorageContextEvidence([...rows,rows[index]],source,name));
  for(const change of [{sourceSha:'b'.repeat(40)},{test:'another'},{locale:'unsupported'},{viewport:{width:800,height:600}},{publicSafe:false},{fullPage:true},{fixtureDisclosure:'unverified'}])assert.throws(()=>requireWindowsStorageContextEvidence(rows.map((row,i)=>i===index?{...row,...change}:row),source,name));
 }
});
test('shared runner invokes storage assertions and enforces its completion gate',()=>{
 const flow=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8'),runner=fs.readFileSync(new URL('./lan-browser.mjs',import.meta.url),'utf8');
 assert.match(flow,/mark\('storage-context'\);phase='storage-context'/);assert.match(flow,/exerciseWindowsStorageContext\(\{page,expect,locale,width,shot\}\)/);assert.match(flow,/exerciseWindowsStorageRetainedContext\(/);assert.match(flow,/exerciseWindowsStorageState\(/);assert.match(runner,/requireWindowsStorageContextEvidence\(screenshots,sourceSha,name\)/);
});
