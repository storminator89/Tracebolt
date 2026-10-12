/** Ordinary hosted-CI-only driver for three changed catalogue flows.
 * Every browser route is invented/intercepted. No real manager or listener runs. */
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {captureWindowsMSICatalogueFixtures,msiCatalogueDisclosure,msiCatalogueCaptureMatrix} from './capture-windows-msi-catalogue-fixtures.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const sourceSha=process.env.TRACEBOLT_SOURCE_SHA??'';
assert(process.env.GITHUB_ACTIONS==='true'&&process.env.RUNNER_ENVIRONMENT==='github-hosted','Ordinary hosted CI only; use the inert fixture --check locally.');
assert(/^[a-f0-9]{40}$/.test(sourceSha));
assert.equal(execFileSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).trim(),sourceSha);
assert(msiCatalogueCaptureMatrix.length>0&&msiCatalogueCaptureMatrix.length<=12);
assert.equal(new Set(msiCatalogueCaptureMatrix.map(row=>row.scene)).size,3);
const {chromium,expect}=require('@playwright/test');
const output=path.join(root,'artifacts/review'),temporary=await fs.mkdtemp(path.join(os.tmpdir(),'tracebolt-msi-catalogue-browser-'));
await fs.mkdir(output,{recursive:true});
let browser,timer,passed=false;
try{
 await Promise.race([(async()=>{
  browser=await chromium.launch({headless:true,args:['--no-sandbox'],env:{...process.env,HOME:temporary,XDG_CONFIG_HOME:temporary,XDG_CACHE_HOME:temporary}});
  const manifest=await captureWindowsMSICatalogueFixtures({browser,expect,output});
  assert.equal(manifest.browserExecuted,true);assert.equal(manifest.nativeAcceptance,false);assert.equal(manifest.disclosure,msiCatalogueDisclosure);
  assert(/^[a-f0-9]{64}$/.test(manifest.sourceDigest));assert.equal(manifest.captures.length,msiCatalogueCaptureMatrix.length);assert.equal(new Set(manifest.captures.map(row=>row.file)).size,msiCatalogueCaptureMatrix.length);
  for(const expected of msiCatalogueCaptureMatrix){
   const row=manifest.captures.find(value=>value.file===expected.file);
   assert(row&&row.scene===expected.scene&&row.locale===expected.locale&&row.width===expected.width&&row.height===expected.height&&row.synthetic===true&&row.sourceDigest===manifest.sourceDigest&&row.disclosure===msiCatalogueDisclosure);
   assert(/^synthetic-windows-msi-catalogue-[a-z0-9-]+\.png$/.test(row.file));
   const bytes=await fs.readFile(path.join(output,row.file));assert(bytes.length>8&&bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])));
   row.sha256=createHash('sha256').update(bytes).digest('hex');row.sourceSha=sourceSha;row.publicSafe=true;row.fullPage=false;
  }
  manifest.sourceSha=sourceSha;
  await fs.writeFile(path.join(output,'windows-msi-catalogue-manifest.json'),JSON.stringify(manifest,null,2)+'\n');
 })(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('Synthetic MSI catalogue browser gate timed out')),120000)})]);
 passed=true;
}catch{console.log('FAIL: synthetic MSI catalogue browser gate; raw diagnostics withheld.');}
finally{
 clearTimeout(timer);try{if(browser)await browser.close();}catch{passed=false}
 await fs.writeFile(path.join(output,'windows-msi-catalogue-results.json'),JSON.stringify({sourceSha,status:passed?'PASS':'FAIL',browserAcceptance:passed,scenes:passed?3:0,screenshots:passed?msiCatalogueCaptureMatrix.length:0,requestsToRealAPI:0,actualMutationRequests:0,nativeAcceptance:false,disclosure:msiCatalogueDisclosure},null,2)+'\n');
 await fs.rm(temporary,{recursive:true,force:true});process.exitCode=passed?0:1;
 if(passed)console.log(`PASS: ${msiCatalogueCaptureMatrix.length} exact-source MSI catalogue captures for package/storage choice, selected-device worklists and retained outcomes; no real requests or mutation.`);
}
