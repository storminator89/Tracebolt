/** Ordinary hosted-CI-only browser driver. Never run as a local browser fallback.
 * All routes are invented/intercepted. No listener or real manager is started. */
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {captureWindowsFleetMSIFixtures,windowsFleetMSIDisclosure,captureWindowsSavedMSIFixtures,windowsSavedMSIDisclosure,windowsSavedMSICaptureMatrix} from './capture-windows-fleet-msi-fixtures.mjs';
import {captureWindowsReusableMSIFixtures,reusableMSIDisclosure,reusableMSIScenes} from './capture-windows-reusable-msi-fixtures.mjs';
import {captureWindowsScheduledMSIFixtures,scheduledMSIDisclosure,scheduledMSIScenes} from './capture-windows-scheduled-msi-fixtures.mjs';
import {captureSoftwareCatalogueFixtures,softwareCatalogueDisclosure,softwareCatalogueScenes} from './capture-windows-software-catalogue-fixtures.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {chromium,expect}=require('@playwright/test');
const sourceSha=process.env.TRACEBOLT_SOURCE_SHA??'';
assert(process.env.GITHUB_ACTIONS==='true'&&process.env.RUNNER_ENVIRONMENT==='github-hosted','This driver requires ordinary hosted CI; use --check on the inert fixture locally.');
assert(/^[a-f0-9]{40}$/.test(sourceSha));
assert.equal(execFileSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).trim(),sourceSha);
const output=path.join(root,'artifacts/review'),temporary=await fs.mkdtemp(path.join(os.tmpdir(),'tracebolt-fleet-msi-browser-'));
await fs.mkdir(output,{recursive:true});
let browser,timer,passed=false;
try{
 await Promise.race([(async()=>{
  browser=await chromium.launch({headless:true,args:['--no-sandbox'],env:{...process.env,HOME:temporary,XDG_CONFIG_HOME:temporary,XDG_CACHE_HOME:temporary}});
  const manifest=await captureWindowsFleetMSIFixtures({browser,expect,output});
  assert.equal(manifest.browserExecuted,true);assert.equal(manifest.nativeAcceptance,false);assert.equal(manifest.captures.length,16);
  assert.equal(manifest.disclosure,windowsFleetMSIDisclosure);
  assert.equal(new Set(manifest.captures.map(c=>c.file)).size,16);
  for(const locale of ['en','de'])for(const width of [1440,390])for(const kind of ['uploaded-artifact','delivery-unchecked','saved-3010-shared-owner','saved-3010-owner-refreshed']){
   const file=`synthetic-windows-fleet-msi-${kind}-${width}-${locale}.png`,row=manifest.captures.find(c=>c.file===file);
   assert(row&&row.locale===locale&&row.width===width&&row.height===(width===390?844:1100)&&row.synthetic===true&&row.sourceDigest===manifest.sourceDigest&&row.disclosure===windowsFleetMSIDisclosure);
   assert.deepEqual(row.assertions,{targetCount:2,noAutomaticNextDevice:true,deliveryUnchecked:true,saved3010Registration:'unknown',sharedStatusPreservesResult:true});
   const bytes=await fs.readFile(path.join(output,file));assert(bytes.length>8&&bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])));
   row.sha256=createHash('sha256').update(bytes).digest('hex');row.sourceSha=sourceSha;row.publicSafe=true;row.fullPage=false;
  }
  const saved=await captureWindowsSavedMSIFixtures({browser,expect,output});
  assert.equal(saved.browserExecuted,true);assert.equal(saved.nativeAcceptance,false);assert.equal(saved.captures.length,windowsSavedMSICaptureMatrix.length);
  assert.equal(saved.sourceDigest,manifest.sourceDigest);assert.equal(saved.disclosure,windowsSavedMSIDisclosure);
  assert.equal(new Set(saved.captures.map(c=>c.file)).size,windowsSavedMSICaptureMatrix.length);
  for(const {scene,locale,width,height,file} of windowsSavedMSICaptureMatrix){
   const row=saved.captures.find(c=>c.file===file);
   assert(row&&row.scene===scene&&row.locale===locale&&row.width===width&&row.height===height&&row.synthetic===true&&row.sourceDigest===saved.sourceDigest&&row.disclosure===windowsSavedMSIDisclosure);
   const confirmation=scene.endsWith('-unchecked');
   assert.deepEqual(row.assertions,{targetCount:3,availableTargetCount:2,historicalOutcomeIsNotCurrent:true,confirmationUnchecked:confirmation,reopenedWithGETOnly:true,previewReads:confirmation?1:0,actualMutationRequests:0,retirementPreviewExact:scene==='retirement-unchecked',retiredOutcomesPreserved:scene==='retired-outcomes'});
   const bytes=await fs.readFile(path.join(output,file));assert(bytes.length>8&&bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])));
   row.sha256=createHash('sha256').update(bytes).digest('hex');row.sourceSha=sourceSha;row.publicSafe=true;row.fullPage=false;
  }
  saved.sourceSha=sourceSha;
  await fs.writeFile(path.join(output,'windows-saved-msi-manifest.json'),JSON.stringify(saved,null,2)+'\n');
  const reusable=await captureWindowsReusableMSIFixtures({browser,expect,output});
  assert.equal(reusable.browserExecuted,true);assert.equal(reusable.nativeAcceptance,false);assert.equal(reusable.captures.length,16);
  assert.equal(reusable.sourceDigest,manifest.sourceDigest);assert.equal(reusable.disclosure,reusableMSIDisclosure);
  assert.equal(new Set(reusable.captures.map(c=>c.file)).size,16);
  for(const locale of ['en','de'])for(const width of [1440,390])for(const scene of reusableMSIScenes){
   const file=`synthetic-windows-reusable-msi-${scene}-${width}-${locale}.png`,row=reusable.captures.find(c=>c.file===file);
   assert(row&&row.locale===locale&&row.width===width&&row.height===(width===390?844:1100)&&row.synthetic===true&&row.sourceDigest===reusable.sourceDigest&&row.disclosure===reusableMSIDisclosure);
   const bytes=await fs.readFile(path.join(output,file));assert(bytes.length>8&&bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])));
   row.sha256=createHash('sha256').update(bytes).digest('hex');row.sourceSha=sourceSha;row.publicSafe=true;row.fullPage=false;
  }
  const scheduled=await captureWindowsScheduledMSIFixtures({browser,expect,output});
  assert.equal(scheduled.browserExecuted,true);assert.equal(scheduled.nativeAcceptance,false);assert.equal(scheduled.captures.length,scheduledMSIScenes.length*4);
  assert.equal(scheduled.sourceDigest,manifest.sourceDigest);assert.equal(scheduled.disclosure,scheduledMSIDisclosure);for(const file of ['web/scripts/capture-windows-scheduled-msi-fixtures.mjs','web/scripts/run-windows-fleet-msi-ci.mjs'])assert(scheduled.sourceInputs.some(input=>input.file===file));assert.equal(new Set(scheduled.captures.map(c=>c.file)).size,scheduledMSIScenes.length*4);
  for(const locale of ['en','de'])for(const width of [1440,390])for(const scene of scheduledMSIScenes){
   const file=`synthetic-windows-scheduled-msi-${scene}-${width}-${locale}.png`,row=scheduled.captures.find(c=>c.file===file);
   assert(row&&row.locale===locale&&row.width===width&&row.height===(width===390?844:1100)&&row.synthetic===true&&row.sourceDigest===scheduled.sourceDigest&&row.disclosure===scheduledMSIDisclosure);
   assert.deepEqual(row.assertions,{fleet:scene.startsWith('fleet-'),confirmationUnchecked:scene==='fleet-shared-window-unchecked'||scene==='approval-unchecked',sharedWindowExact:scene==='fleet-shared-window-unchecked',mixedSavedOutcome:scene==='fleet-mixed-scheduled-unsent',previewReads:scene==='fleet-shared-window-unchecked'?1:0,actualMutationRequests:0});
   const bytes=await fs.readFile(path.join(output,file));assert(bytes.length>8&&bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])));
   row.sha256=createHash('sha256').update(bytes).digest('hex');row.sourceSha=sourceSha;row.publicSafe=true;row.fullPage=false;
  }
  scheduled.sourceSha=sourceSha;
  await fs.writeFile(path.join(output,'windows-scheduled-msi-manifest.json'),JSON.stringify(scheduled,null,2)+'\n');
  const catalogue=await captureSoftwareCatalogueFixtures({browser,expect,output});
  assert.equal(catalogue.browserExecuted,true);assert.equal(catalogue.nativeAcceptance,false);assert.equal(catalogue.captures.length,8);assert.equal(catalogue.sourceDigest,manifest.sourceDigest);assert.equal(catalogue.disclosure,softwareCatalogueDisclosure);assert.equal(new Set(catalogue.captures.map(c=>c.file)).size,8);
  for(const locale of ['en','de'])for(const width of [1440,390])for(const scene of softwareCatalogueScenes){
   const file=`synthetic-windows-software-catalogue-${scene}-${width}-${locale}.png`,row=catalogue.captures.find(c=>c.file===file);
   assert(row&&row.locale===locale&&row.width===width&&row.height===(width===390?844:1100)&&row.synthetic===true&&row.sourceDigest===catalogue.sourceDigest&&row.disclosure===softwareCatalogueDisclosure);
   const bytes=await fs.readFile(path.join(output,file));assert(bytes.length>8&&bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])));
   row.sha256=createHash('sha256').update(bytes).digest('hex');row.sourceSha=sourceSha;row.publicSafe=true;row.fullPage=false;
  }
  catalogue.sourceSha=sourceSha;
  await fs.writeFile(path.join(output,'windows-software-catalogue-manifest.json'),JSON.stringify(catalogue,null,2)+'\n');
  reusable.sourceSha=sourceSha;
  await fs.writeFile(path.join(output,'windows-reusable-msi-manifest.json'),JSON.stringify(reusable,null,2)+'\n');
  manifest.sourceSha=sourceSha;
  await fs.writeFile(path.join(output,'windows-fleet-msi-manifest.json'),JSON.stringify(manifest,null,2)+'\n');
 })(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('Synthetic fleet MSI browser gate timed out')),240000)})]);
 passed=true;
}catch{console.log('FAIL: synthetic fleet MSI browser gate; raw diagnostics withheld.');}
finally{
 clearTimeout(timer);try{if(browser)await browser.close();}catch{passed=false}
 await fs.writeFile(path.join(output,'windows-scheduled-msi-results.json'),JSON.stringify({sourceSha,status:passed?'PASS':'FAIL',browserAcceptance:passed,variants:passed?4:0,screenshots:passed?scheduledMSIScenes.length*4:0,syntheticPreviewReads:passed?4:0,actualMutationRequests:0,requestsToRealAPI:0,nativeAcceptance:false,disclosure:scheduledMSIDisclosure},null,2)+'\n');
 await fs.writeFile(path.join(output,'windows-fleet-msi-results.json'),JSON.stringify({sourceSha,status:passed?'PASS':'FAIL',browserAcceptance:passed,variants:passed?4:0,screenshots:passed?16:0,requestsToRealAPI:0,nativeAcceptance:false,disclosure:windowsFleetMSIDisclosure},null,2)+'\n');
 await fs.writeFile(path.join(output,'windows-saved-msi-results.json'),JSON.stringify({sourceSha,status:passed?'PASS':'FAIL',browserAcceptance:passed,variants:passed?4:0,screenshots:passed?windowsSavedMSICaptureMatrix.length:0,syntheticPreviewReads:passed?windowsSavedMSICaptureMatrix.filter(row=>row.scene.endsWith('-unchecked')).length:0,requestsToRealAPI:0,actualMutationRequests:0,nativeAcceptance:false,disclosure:windowsSavedMSIDisclosure},null,2)+'\n');
 await fs.writeFile(path.join(output,'windows-reusable-msi-results.json'),JSON.stringify({sourceSha,status:passed?'PASS':'FAIL',browserAcceptance:passed,variants:passed?4:0,screenshots:passed?16:0,requestsToRealAPI:0,nativeAcceptance:false,disclosure:reusableMSIDisclosure},null,2)+'\n');
 await fs.writeFile(path.join(output,'windows-software-catalogue-results.json'),JSON.stringify({sourceSha,status:passed?'PASS':'FAIL',browserAcceptance:passed,variants:passed?4:0,screenshots:passed?8:0,requestsToRealAPI:0,nativeAcceptance:false,disclosure:softwareCatalogueDisclosure},null,2)+'\n');
 await fs.rm(temporary,{recursive:true,force:true});process.exitCode=passed?0:1;
 if(passed)console.log(`PASS: 16 exact-source fleet MSI, ${windowsSavedMSICaptureMatrix.length} saved-worklist, 16 reusable MSI, ${scheduledMSIScenes.length*4} scheduled-MSI and 8 recent-package screenshots across EN/DE desktop/mobile; independent unchecked batch confirmations, exact endpoint cleanup review, retained failed/restart-required outcomes and manual next-package selection.`);
}
