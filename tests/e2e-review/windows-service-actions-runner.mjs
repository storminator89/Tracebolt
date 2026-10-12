/** Hosted-only synthetic browser gate. Uses the ordinary locked Chromium
 * installation and built web/dist. No Go process, SCM adapter or real API. */
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {createServer} from 'node:http';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {createWindowsServiceActionsFixture,exerciseWindowsServiceActions,windowsServiceActionsRoute,windowsServiceActionsCaseName,windowsServiceActionsDisclosure,windowsServiceActionsFailureStage,requireWindowsServiceActionsEvidence} from './windows-service-actions-browser.mjs';
import {createWindowsUpdateJobsFixture,windowsUpdateJobsRoute,exerciseWindowsUpdateJobs,windowsUpdateJobsCaseName,windowsUpdateJobsDisclosure,windowsUpdateJobsFailureStage,requireWindowsUpdateJobsEvidence,windowsUpdateJobsOrigin} from './windows-update-jobs-browser.mjs';
import {createWindowsServiceActionHistoryFixture,windowsServiceActionHistoryRoute,exerciseWindowsServiceActionHistory,windowsServiceActionHistoryCaseName,requireWindowsServiceActionHistoryEvidence} from './windows-service-action-history-browser.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..'),require=createRequire(path.join(root,'web/package.json'));
const {chromium,expect}=require('@playwright/test');
const out=path.join(root,'artifacts/review'),dist=path.join(root,'web/dist'),temporary=await fs.mkdtemp(path.join(os.tmpdir(),'tracebolt-windows-actions-browser-'));
const sourceSha=process.env.TRACEBOLT_SOURCE_SHA??null,screenshots=[],historyScreenshots=[],updateScreenshots=[],variants=[],historyVariants=[],updateVariants=[];let browser,context,server,timer,errors=0,apiRequests=0,passed=false;
await fs.mkdir(out,{recursive:true});
const failure=()=>new Error('Synthetic Windows action browser gate failed; raw state withheld.');
async function shot(page,name,fixtureDisclosure){
 const isUpdate=/^synthetic-windows-update-jobs-(review|result)-(1440|390)-(en|de)$/.test(name);
 if(isUpdate?fixtureDisclosure!==windowsUpdateJobsDisclosure:!/^synthetic-windows-service-(actions|action-history)-(1440|390)-(en|de)$/.test(name)||fixtureDisclosure!==windowsServiceActionsDisclosure)throw failure();
 await page.screenshot({path:path.join(out,name+'.png'),fullPage:false,animations:'disabled'});
 const isHistory=name.startsWith('synthetic-windows-service-action-history-');
 (isUpdate?updateScreenshots:isHistory?historyScreenshots:screenshots).push({file:name+'.png',sourceSha,publicSafe:true,fullPage:false,viewport:page.viewportSize(),locale:await page.locator('html').getAttribute('lang'),fixtureDisclosure,test:isUpdate?windowsUpdateJobsCaseName:isHistory?windowsServiceActionHistoryCaseName:windowsServiceActionsCaseName});
}
async function run(){
 if(!/^[a-f0-9]{40}$/.test(sourceSha??''))throw failure();
 const realDist=await fs.realpath(dist);await fs.access(path.join(realDist,'index.html'));
 server=createServer(async(request,response)=>{
  try{
   const url=new URL(request.url,'http://127.0.0.1');
   if(url.pathname.startsWith('/api/')){apiRequests++;response.writeHead(503);response.end();return;}
   if(request.method!=='GET'||url.search){response.writeHead(404);response.end();return;}
   const file=await fs.realpath(path.join(realDist,url.pathname==='/'?'index.html':decodeURIComponent(url.pathname)));
   const contentTypes={'.html':'text/html','.js':'text/javascript','.css':'text/css','.woff':'font/woff','.woff2':'font/woff2','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon'};
   if(!file.startsWith(realDist+path.sep)||!contentTypes[path.extname(file)])throw failure();
   response.writeHead(200,{'Content-Type':contentTypes[path.extname(file)],'Cache-Control':'no-store'});response.end(await fs.readFile(file));
  }catch{response.writeHead(404);response.end();}
 });
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
 const base='http://127.0.0.1:'+server.address().port;
 // Uses the existing hosted runner convention, including its --no-sandbox flag.
 // No alternate executable, download route, installation or local bypass.
 browser=await chromium.launch({headless:true,args:['--no-sandbox'],env:{...process.env,HOME:temporary,XDG_CONFIG_HOME:temporary,XDG_CACHE_HOME:temporary}});
 for(const locale of ['en','de'])for(const width of [1440,390]){
  const fixture=createWindowsServiceActionsFixture(),state={blocked:[],external:[]};
  context=await browser.newContext({viewport:{width,height:width===390?844:1000},locale:'en-GB'});const page=await context.newPage();page.on('pageerror',()=>errors++);
  await page.clock.install({time:new Date(fixture.now)});await page.clock.pauseAt(new Date(Date.parse(fixture.now)+100));
  await page.route('**/*',windowsServiceActionsRoute({base,fixture,state}));
  const details=await exerciseWindowsServiceActions({page,expect,base,fixture,locale,width,shot});
  expect(state.blocked).toEqual([]);expect(state.external).toEqual([]);expect(await context.cookies()).toEqual([]);
  const stored=await page.evaluate(()=>JSON.stringify({local:{...localStorage},session:{...sessionStorage}}));for(const value of [fixture.preview.preview.id,fixture.preview.preview.digest,fixture.session.csrfToken])expect(stored.includes(value)).toBe(false);
  variants.push({locale,width,...details});await context.close();context=null;
  const historyFixture=createWindowsServiceActionHistoryFixture(),historyState={blocked:[],external:[]};
  context=await browser.newContext({viewport:{width,height:width===390?844:1000},locale:'en-GB'});const historyPage=await context.newPage();historyPage.on('pageerror',()=>errors++);
  await historyPage.clock.install({time:new Date(historyFixture.now)});await historyPage.clock.pauseAt(new Date(Date.parse(historyFixture.now)+100));
  await historyPage.route('**/*',windowsServiceActionHistoryRoute({base,fixture:historyFixture,state:historyState}));
  const historyDetails=await exerciseWindowsServiceActionHistory({page:historyPage,expect,base,fixture:historyFixture,locale,width,shot});
  expect(historyState.blocked).toEqual([]);expect(historyState.external).toEqual([]);expect(await context.cookies()).toEqual([]);
  const historyStorage=await historyPage.evaluate(()=>JSON.stringify({local:{...localStorage},session:{...sessionStorage}}));for(const detail of historyFixture.details)expect(historyStorage.includes(detail.job.identity.jobId)).toBe(false);
  historyVariants.push({locale,width,...historyDetails});await context.close();context=null;
  const updateFixture=createWindowsUpdateJobsFixture(),updateState={blocked:[],external:[]};
  context=await browser.newContext({viewport:{width,height:width===390?844:1000},locale:'en-GB'});const updatePage=await context.newPage();updatePage.on('pageerror',()=>errors++);
  await updatePage.clock.install({time:new Date(updateFixture.now)});await updatePage.clock.pauseAt(new Date(Date.parse(updateFixture.now)+100));
  // Virtual HTTPS document: every request is fulfilled or aborted before any
  // DNS/TLS/network activity. No certificate exception or browser bypass.
  await updatePage.route('**/*',windowsUpdateJobsRoute({base:windowsUpdateJobsOrigin,fixture:updateFixture,state:updateState,asset:async(route,pathname)=>{
   const file=await fs.realpath(path.join(realDist,pathname==='/'?'index.html':decodeURIComponent(pathname)));
   const contentTypes={'.html':'text/html','.js':'text/javascript','.css':'text/css','.woff':'font/woff','.woff2':'font/woff2','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon'};
   if(!file.startsWith(realDist+path.sep)||!contentTypes[path.extname(file)])throw failure();
   await route.fulfill({status:200,contentType:contentTypes[path.extname(file)],body:await fs.readFile(file)});
  }}));
  const updateDetails=await exerciseWindowsUpdateJobs({page:updatePage,expect,base:windowsUpdateJobsOrigin,fixture:updateFixture,locale,width,shot});
  expect(updateState.blocked).toEqual([]);expect(updateState.external).toEqual([]);expect(await context.cookies()).toEqual([]);
  const updateStorage=await updatePage.evaluate(()=>JSON.stringify({local:{...localStorage},session:{...sessionStorage}}));for(const value of [updateFixture.savedID(),updateFixture.digest,updateFixture.session.csrfToken])expect(updateStorage.includes(value)).toBe(false);
  updateVariants.push({locale,width,...updateDetails});await context.close();context=null;
 }
 requireWindowsServiceActionsEvidence(screenshots,sourceSha);requireWindowsServiceActionHistoryEvidence(historyScreenshots,sourceSha);if(errors||apiRequests||variants.length!==4)throw failure();if(historyVariants.length!==4)throw failure();requireWindowsUpdateJobsEvidence(updateScreenshots,sourceSha);if(updateVariants.length!==4)throw failure();
}
try{await Promise.race([run(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(failure()),120000);})]);passed=true;}
catch{console.log('FAIL: synthetic Windows action browser gate; raw diagnostics withheld.');}
finally{
 clearTimeout(timer);try{if(context)await context.close();}catch{passed=false;}try{if(browser)await browser.close();}catch{passed=false;}
 if(server){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
 const report={sourceSha,createdAt:new Date().toISOString(),name:windowsServiceActionsCaseName,status:passed?'PASS':'FAIL',stage:windowsServiceActionsFailureStage(),scope:windowsServiceActionsDisclosure,variants:passed?variants:[],historyVariants:passed?historyVariants:[],updateVariants:passed?updateVariants:[],updateScope:windowsUpdateJobsDisclosure,updateStage:windowsUpdateJobsFailureStage(),runtimeErrorCount:errors,requestsToRealAPI:apiRequests,browserAcceptance:passed,durableStoreAcceptance:false,nativeAcceptance:false,secretsExported:false,realTelemetryExported:false};
 await fs.writeFile(path.join(out,'windows-service-actions-results.json'),JSON.stringify(report,null,2));await fs.writeFile(path.join(out,'windows-service-actions-manifest.json'),JSON.stringify({sourceSha,screenshots:[...screenshots,...historyScreenshots,...updateScreenshots]},null,2));await fs.rm(temporary,{recursive:true,force:true});process.exitCode=passed?0:1;
}
