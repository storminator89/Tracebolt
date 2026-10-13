/** Approved ordinary hosted CI only; never a denied-local-browser workaround. */
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createRequire} from 'node:module';
import {mkdir,writeFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {capture,captureMatrix,contract,disclosure} from './capture-macos-enrollment.mjs';
import {validateEvidence} from './check-macos-enrollment-evidence.mjs';
const root=fileURLToPath(new URL('../../',import.meta.url)),require=createRequire(new URL('../package.json',import.meta.url));
assert(process.env.GITHUB_ACTIONS==='true'&&process.env.RUNNER_ENVIRONMENT==='github-hosted','Hosted CI only; use --check locally.');
const sourceSha=process.env.TRACEBOLT_SOURCE_SHA;
assert(/^[a-f0-9]{40}$/.test(sourceSha));assert.equal(execFileSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).trim(),sourceSha);
const {chromium,expect}=require('@playwright/test'),output=path.join(root,'artifacts/review');await mkdir(output,{recursive:true});
let browser,timer,passed=false,stage='launch';
try{
 await Promise.race([(async()=>{browser=await chromium.launch({headless:true});stage='capture';const manifest=await capture({browser,expect,output});stage='manifest';await writeFile(path.join(output,'macos-enrollment-manifest.json'),JSON.stringify({...manifest,sourceSha},null,2)+'\n');})(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('capture deadline')),120000);})]);
 passed=true;
}catch{console.log(`FAIL: synthetic macOS UI gate at ${stage}; diagnostics withheld.`);}
finally{
 clearTimeout(timer);try{await browser?.close();}catch{passed=false;stage='close';}
 const report={sourceSha,status:passed?'PASS':'FAIL',browserAcceptance:passed,scenes:passed?contract.scenes.length:0,screenshots:passed?captureMatrix.length:0,requestsToRealAPI:0,actualMutationRequests:0,nativeAcceptance:false,disclosure,...(!passed?{failure:{stage}}:{})};
 const reportFile=path.join(output,'macos-enrollment-results.json');await writeFile(reportFile,JSON.stringify(report,null,2)+'\n');
 if(passed){try{await validateEvidence(output,sourceSha);}catch{passed=false;Object.assign(report,{status:'FAIL',browserAcceptance:false,scenes:0,screenshots:0,failure:{stage:'evidence'}});await writeFile(reportFile,JSON.stringify(report,null,2)+'\n');}}
 process.exitCode=passed?0:1;if(passed)console.log('PASS: 16 exact-source synthetic macOS UI captures; no real actions or native acceptance.');
}
