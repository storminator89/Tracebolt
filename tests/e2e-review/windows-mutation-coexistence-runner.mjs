/** Hosted-only additive read-only coexistence gate against compiled web/dist.
 * All requests are intercepted. This runner is never launched locally. */
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {createWindowsMutationCoexistenceFixture,windowsMutationCoexistenceRoute,exerciseWindowsMutationCoexistence,windowsMutationCoexistenceOrigin,windowsMutationCoexistenceCaseName,windowsMutationCoexistenceDisclosure,windowsMutationCoexistenceFailureStage,requireWindowsMutationCoexistenceDetails,requireWindowsMutationCoexistenceReport} from './windows-mutation-coexistence-browser.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..'),require=createRequire(path.join(root,'web/package.json'));
const {chromium,expect}=require('@playwright/test');
const out=path.join(root,'artifacts/review'),dist=path.join(root,'web/dist'),temporary=await fs.mkdtemp(path.join(os.tmpdir(),'tracebolt-mutation-coexistence-browser-'));
const sourceSha=process.env.TRACEBOLT_SOURCE_SHA??null,screenshots=[],variants=[];let browser,context,timer,errors=0,passed=false;
const failure=()=>new Error('Synthetic read-only coexistence browser gate failed; raw state withheld.');
await fs.mkdir(out,{recursive:true});
async function shot(page,name,fixtureDisclosure){
 if(!/^synthetic-windows-mutation-coexistence-(software|updates)-(blocked|released)-(1440|390)-(en|de)$/.test(name)||fixtureDisclosure!==windowsMutationCoexistenceDisclosure)throw failure();
 const file=name+'.png';await page.screenshot({path:path.join(out,file),fullPage:false,animations:'disabled'});
 screenshots.push({file,sourceSha,publicSafe:true,fullPage:false,viewport:page.viewportSize(),locale:await page.locator('html').getAttribute('lang'),fixtureDisclosure,test:windowsMutationCoexistenceCaseName,sha256:createHash('sha256').update(await fs.readFile(path.join(out,file))).digest('hex')});
}
const makeReport=success=>({sourceSha,createdAt:new Date().toISOString(),name:windowsMutationCoexistenceCaseName,status:success?'PASS':'FAIL',stage:windowsMutationCoexistenceFailureStage(),scope:windowsMutationCoexistenceDisclosure,variants:success?variants:[],runtimeErrorCount:errors,requestsToRealAPI:0,browserAcceptance:success,durableStoreAcceptance:false,nativeAcceptance:false,secretsExported:false,realTelemetryExported:false});
async function run(){
 if(!/^[a-f0-9]{40}$/.test(sourceSha??''))throw failure();const realDist=await fs.realpath(dist);await fs.access(path.join(realDist,'index.html'));
 browser=await chromium.launch({headless:true,args:['--no-sandbox'],env:{...process.env,HOME:temporary,XDG_CONFIG_HOME:temporary,XDG_CACHE_HOME:temporary}});
 for(const locale of ['en','de'])for(const width of [1440,390]){
  const fixture=createWindowsMutationCoexistenceFixture('managed_msi',true),state={blocked:[],external:[]};
  context=await browser.newContext({viewport:{width,height:width===390?844:1000},locale:'en-GB',serviceWorkers:'block'});
  const page=await context.newPage();page.on('pageerror',()=>errors++);await page.clock.install({time:new Date(fixture.now)});await page.clock.pauseAt(new Date(Date.parse(fixture.now)+100));
  await page.route('**/*',windowsMutationCoexistenceRoute({base:windowsMutationCoexistenceOrigin,fixture,state,asset:async(route,pathname)=>{
   const file=await fs.realpath(path.join(realDist,pathname==='/'?'index.html':decodeURIComponent(pathname))),types={'.html':'text/html','.js':'text/javascript','.css':'text/css','.woff':'font/woff','.woff2':'font/woff2','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon'};
   if(!file.startsWith(realDist+path.sep)||!types[path.extname(file)])throw failure();await route.fulfill({status:200,contentType:types[path.extname(file)],body:await fs.readFile(file)});
  }}));
  const details=await exerciseWindowsMutationCoexistence({page,expect,base:windowsMutationCoexistenceOrigin,fixture,locale,width,shot});requireWindowsMutationCoexistenceDetails(details);
  expect(state.blocked).toEqual([]);expect(state.external).toEqual([]);expect(await context.cookies()).toEqual([]);
  const stored=await page.evaluate(()=>JSON.stringify({local:{...localStorage},session:{...sessionStorage}}));
  for(const value of [fixture.coexistenceJob,fixture.managedSelection.sha256,fixture.managedNativeDigest,fixture.session.csrfToken])expect(stored.includes(value)).toBe(false);
  variants.push({locale,width,...details});await context.close();context=null;
 }
 requireWindowsMutationCoexistenceReport(makeReport(true),{sourceSha,screenshots},sourceSha);
}
try{await Promise.race([run(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(failure()),120000);})]);passed=true;}
catch{console.log('FAIL: synthetic read-only coexistence browser gate; raw diagnostics withheld.');}
finally{
 clearTimeout(timer);try{if(context)await context.close();}catch{passed=false;}try{if(browser)await browser.close();}catch{passed=false;}
 await fs.writeFile(path.join(out,'windows-mutation-coexistence-results.json'),JSON.stringify(makeReport(passed),null,2));await fs.writeFile(path.join(out,'windows-mutation-coexistence-manifest.json'),JSON.stringify({sourceSha,screenshots},null,2));await fs.rm(temporary,{recursive:true,force:true});process.exitCode=passed?0:1;
}
