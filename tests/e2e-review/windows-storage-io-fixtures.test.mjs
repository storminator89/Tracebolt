import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {windowsStorageIOBrowserFixture,windowsStorageIODisclosure,windowsStorageIOCaseName,requireWindowsStorageIOEvidence} from './windows-storage-io-browser.mjs';
const serverNow='2026-10-11T12:00:10Z',capturedAt='2026-10-11T12:00:00Z';
test('disk IO source fixture is the exact Go canonical encoder artifact',()=>{assert.deepEqual(fs.readFileSync(new URL('../../web/src/windows-storage-io-go-fixture.json',import.meta.url)),fs.readFileSync(new URL('../../internal/windowsstorageio/testdata/snapshot.json',import.meta.url)));});
test('disk IO invented fixtures keep times, unavailable reasons and idle truth',()=>{
 for(const phase of ['observed','idle','partial','denied','unsupported','timeout','future']){
  const v=windowsStorageIOBrowserFixture({serverNow,capturedAt,phase}),p=v.storageIO.perfDisk;assert.equal(v.storageIO.collectedAt,capturedAt);assert.notEqual(v.volumes.collectedAt,p.sampleEndedAt);
  if(phase==='idle'){assert.equal(p.readOperationsPerSecond.value,0);assert.equal(p.readLatencySeconds.value,null);assert.equal(p.readLatencySeconds.reason,'windows_storage_io_idle');assert.equal(p.writeLatencySeconds.value,0);}
  if(phase==='partial'){assert.equal(p.readBytesPerSecond.reason,'windows_storage_io_counter_missing');assert.equal(p.writeBytesPerSecond.reason,'windows_storage_io_counter_reset');assert.equal(p.averageQueueLength.reason,'windows_storage_io_invalid_timebase');}
  if(['denied','unsupported','timeout'].includes(phase)){assert.equal(p.sampleStartedAt,null);assert.equal(p.readBytesPerSecond.value,null);}
 }
 for(const phase of ['legacy','revoked'])assert.equal(windowsStorageIOBrowserFixture({serverNow,capturedAt,phase}).storageIO,undefined);
});
test('disk IO retention keeps original sample window without renewing expiry',()=>{
 const retainedCapturedAt='2026-10-11T11:00:00Z',fixture=now=>windowsStorageIOBrowserFixture({serverNow:now,capturedAt,phase:'retained',retainedCapturedAt}),v=fixture(serverNow);
 assert.equal(v.storageIO.perfDisk.readBytesPerSecond.value,null);assert.equal(v.storageIO.perfDisk.reason,'windows_storage_io_budget_exhausted');assert.equal(v.retainedContext.storageIO.collectedAt,retainedCapturedAt);assert.equal(v.retainedContext.storageIO.perfDisk.sampleEndedAt,'2026-10-11T11:00:01.250Z');
 assert.deepEqual(fixture('2026-10-11T12:01:00Z').retainedContext,v.retainedContext);assert.ok(fixture('2026-10-12T10:59:59Z').retainedContext);assert.equal(fixture('2026-10-12T11:00:00Z').retainedContext,undefined);
 for(const at of [undefined,'invalid',capturedAt,'2026-10-11T12:00:01Z'])assert.throws(()=>windowsStorageIOBrowserFixture({serverNow,capturedAt,phase:'retained',retainedCapturedAt:at}),/Invalid synthetic/);
});
test('disk IO completion requires exactly sixteen source-bound EN/DE mobile/desktop screenshots',()=>{
 const source='a'.repeat(40),rows=[];for(const kind of ['summary','details','failure','retained'])for(const locale of ['en','de'])for(const width of [1440,390])rows.push({file:`synthetic-windows-storage-io-${kind}-${width}-${locale}.png`,sourceSha:source,test:windowsStorageIOCaseName,viewport:{width,height:width===390?844:1000},locale,fullPage:false,publicSafe:true,fixtureDisclosure:windowsStorageIODisclosure});
 assert.deepEqual(requireWindowsStorageIOEvidence(rows,source),{summary:4,details:4,failure:4,retained:4});
 for(let index=0;index<rows.length;index++)for(const changed of [null,{sourceSha:'b'.repeat(40)},{fullPage:true},{publicSafe:false},{fixtureDisclosure:'native'},{test:'other'},{viewport:{width:800,height:600}}])assert.throws(()=>requireWindowsStorageIOEvidence(changed?rows.map((r,i)=>i===index?{...r,...changed}:r):rows.filter((_,i)=>i!==index),source));
 assert.throws(()=>requireWindowsStorageIOEvidence([...rows,rows[0]],source));
});
test('IO helper is inert and runner declares synthetic auth plus local-only serving',()=>{
 const helper=fs.readFileSync(new URL('./windows-storage-io-browser.mjs',import.meta.url),'utf8'),runner=fs.readFileSync(new URL('./windows-storage-io-runner.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(helper,/chromium\.launch|newContext\(|spawn\(|execFile|writeFile|ignoreHTTPSErrors|fetch\(|localStorage|sessionStorage/);
 assert.match(runner,/server\.listen\(0,'127\.0\.0\.1'/);assert.match(runner,/requireWindowsStorageIOEvidence\(screenshots,sourceSha\)/);assert.match(runner,/liveAuthenticationAcceptance:false/);assert.match(runner,/compiledBundleSha256/);assert.doesNotMatch(runner,/ignoreHTTPSErrors|go.+build|download/);
});
test('hosted browser job executes the bounded disk IO gate and retains its exact artifacts',()=>{
 const workflow=fs.readFileSync(new URL('../../.github/workflows/validate.yml',import.meta.url),'utf8');
 const browserJob=workflow.split('\n  browser:\n')[1]?.split(/\n  [a-z][a-z0-9-]*:\n/)[0];assert.ok(browserJob);
 const step=browserJob.split('      - name: Windows aggregate disk IO synthetic browser gate (16 required screenshots)\n')[1]?.split('\n      - name:')[0];assert.ok(step);
 assert.match(step,/if: \$\{\{ !cancelled\(\) \}\}/);assert.match(step,/timeout-minutes: 5/);assert.match(step,/TRACEBOLT_SOURCE_SHA: \$\{\{ github.sha \}\}/);
 assert.match(step,/run: node tests\/e2e-review\/windows-storage-io-runner\.mjs/);assert.doesNotMatch(step,/continue-on-error|\|\| true/);
 assert.equal((browserJob.match(/run: node tests\/e2e-review\/windows-storage-io-runner\.mjs/g)||[]).length,1);
 const artifacts=browserJob.split('      - name: Keep browser review evidence briefly\n')[1];assert.ok(artifacts);assert.match(artifacts,/if: always\(\)/);
 for(const file of ['windows-storage-io-results.json','windows-storage-io-manifest.json','synthetic-windows-storage-io-*.png'])assert.ok(artifacts.split('\n').some(line=>line.trim()==='artifacts/review/windows-storage-io/'+file));
 const runner=fs.readFileSync(new URL('./windows-storage-io-runner.mjs',import.meta.url),'utf8');assert.match(runner,/path\.join\(root,'artifacts\/review\/windows-storage-io'\)/);assert.match(runner,/process\.env\.TRACEBOLT_SOURCE_SHA!==sourceSha/);assert.match(runner,/process\.exitCode=passed\?0:1/);
});
