/** Hosted-only additive managed-MSI gate, against compiled web/dist.
 * Every request is intercepted; no listener, real API or native action. */
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {createWindowsManagedMSIFixture,windowsManagedMSIRoute,exerciseWindowsManagedMSI,windowsManagedMSIOrigin,windowsManagedMSICaseName,windowsManagedMSIDisclosure,windowsManagedMSIFailureStage,requireWindowsManagedMSIEvidence,requireWindowsManagedMSIDetails} from './windows-managed-msi-browser.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..'),require=createRequire(path.join(root,'web/package.json'));
const {chromium,expect}=require('@playwright/test');
const out=path.join(root,'artifacts/review'),dist=path.join(root,'web/dist'),temporary=await fs.mkdtemp(path.join(os.tmpdir(),'tracebolt-managed-msi-browser-'));
const sourceSha=process.env.TRACEBOLT_SOURCE_SHA??null,screenshots=[],variants=[];let browser,context,timer,errors=0,passed=false;
const failure=()=>new Error('Synthetic managed MSI browser gate failed; raw state withheld.');
await fs.mkdir(out,{recursive:true});
async function shot(page,name,fixtureDisclosure){
 if(!/^synthetic-windows-managed-msi-(uploaded|imported|ready|outcome)-(1440|390)-(en|de)$/.test(name)||fixtureDisclosure!==windowsManagedMSIDisclosure)throw failure();
 await page.screenshot({path:path.join(out,name+'.png'),fullPage:false,animations:'disabled'});
 screenshots.push({file:name+'.png',sourceSha,publicSafe:true,fullPage:false,viewport:page.viewportSize(),locale:await page.locator('html').getAttribute('lang'),fixtureDisclosure,test:windowsManagedMSICaseName});
}
async function run(){
 if(!/^[a-f0-9]{40}$/.test(sourceSha??''))throw failure();
 const realDist=await fs.realpath(dist);await fs.access(path.join(realDist,'index.html'));
 // Unchanged ordinary hosted Chromium convention; never invoked locally.
 browser=await chromium.launch({headless:true,args:['--no-sandbox'],env:{...process.env,HOME:temporary,XDG_CONFIG_HOME:temporary,XDG_CACHE_HOME:temporary}});
 for(const locale of ['en','de'])for(const width of [1440,390]){
  const fixture=createWindowsManagedMSIFixture(),state={blocked:[],external:[]};
  context=await browser.newContext({viewport:{width,height:width===390?844:1000},locale:'en-GB',serviceWorkers:'block'});
  const page=await context.newPage();page.on('pageerror',()=>errors++);
  await page.clock.install({time:new Date(fixture.now)});await page.clock.pauseAt(new Date(Date.parse(fixture.now)+100));
  await page.route('**/*',windowsManagedMSIRoute({base:windowsManagedMSIOrigin,fixture,state,asset:async(route,pathname)=>{
   const file=await fs.realpath(path.join(realDist,pathname==='/'?'index.html':decodeURIComponent(pathname)));
   const types={'.html':'text/html','.js':'text/javascript','.css':'text/css','.woff':'font/woff','.woff2':'font/woff2','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon'};
   if(!file.startsWith(realDist+path.sep)||!types[path.extname(file)])throw failure();
   await route.fulfill({status:200,contentType:types[path.extname(file)],body:await fs.readFile(file)});
  }}));
  const details=await exerciseWindowsManagedMSI({page,expect,base:windowsManagedMSIOrigin,fixture,locale,width,shot});requireWindowsManagedMSIDetails(details);
  expect(state.blocked).toEqual([]);expect(state.external).toEqual([]);expect(await context.cookies()).toEqual([]);
  const stored=await page.evaluate(()=>JSON.stringify({local:{...localStorage},session:{...sessionStorage}}));
  for(const value of [fixture.managedSaved().transferId,fixture.managedSelection.sha256,fixture.managedNativeDigest,fixture.managedReadinessDigest,fixture.session.csrfToken])expect(stored.includes(value)).toBe(false);
  variants.push({locale,width,...details});await context.close();context=null;
 }
 requireWindowsManagedMSIEvidence(screenshots,sourceSha);if(errors||variants.length!==4)throw failure();
}
try{await Promise.race([run(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(failure()),120000);})]);passed=true;}
catch{console.log('FAIL: synthetic managed MSI browser gate; raw diagnostics withheld.');}
finally{
 clearTimeout(timer);try{if(context)await context.close();}catch{passed=false;}try{if(browser)await browser.close();}catch{passed=false;}
 const report={sourceSha,createdAt:new Date().toISOString(),name:windowsManagedMSICaseName,status:passed?'PASS':'FAIL',stage:windowsManagedMSIFailureStage(),scope:windowsManagedMSIDisclosure,variants:passed?variants:[],runtimeErrorCount:errors,requestsToRealAPI:0,browserAcceptance:passed,durableStoreAcceptance:false,nativeAcceptance:false,secretsExported:false,realTelemetryExported:false};
 await fs.writeFile(path.join(out,'windows-managed-msi-results.json'),JSON.stringify(report,null,2));await fs.writeFile(path.join(out,'windows-managed-msi-manifest.json'),JSON.stringify({sourceSha,screenshots},null,2));await fs.rm(temporary,{recursive:true,force:true});process.exitCode=passed?0:1;
}
