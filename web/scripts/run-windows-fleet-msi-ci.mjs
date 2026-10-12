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
import {captureWindowsFleetMSIFixtures,windowsFleetMSIDisclosure} from './capture-windows-fleet-msi-fixtures.mjs';
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
  manifest.sourceSha=sourceSha;
  await fs.writeFile(path.join(output,'windows-fleet-msi-manifest.json'),JSON.stringify(manifest,null,2)+'\n');
 })(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('Synthetic fleet MSI browser gate timed out')),120000)})]);
 passed=true;
}catch{console.log('FAIL: synthetic fleet MSI browser gate; raw diagnostics withheld.');}
finally{
 clearTimeout(timer);try{if(browser)await browser.close();}catch{passed=false}
 await fs.writeFile(path.join(output,'windows-fleet-msi-results.json'),JSON.stringify({sourceSha,status:passed?'PASS':'FAIL',browserAcceptance:passed,variants:passed?4:0,screenshots:passed?16:0,requestsToRealAPI:0,nativeAcceptance:false,disclosure:windowsFleetMSIDisclosure},null,2)+'\n');
 await fs.rm(temporary,{recursive:true,force:true});process.exitCode=passed?0:1;
 if(passed)console.log('PASS: 16 exact-source fleet MSI screenshots across EN/DE desktop/mobile; independent targets and original saved-result truth.');
}
