/** Hosted-only synthetic browser gate. Uses the ordinary locked Chromium
 * installation and built web/dist. No Go process, SCM adapter or real API. */
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {createServer} from 'node:http';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {createWindowsServiceActionsFixture,exerciseWindowsServiceActions,windowsServiceActionsRoute,windowsServiceActionsCaseName,windowsServiceActionsDisclosure,windowsServiceActionsFailureStage,requireWindowsServiceActionsEvidence} from './windows-service-actions-browser.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..'),require=createRequire(path.join(root,'web/package.json'));
const {chromium,expect}=require('@playwright/test');
const out=path.join(root,'artifacts/review'),dist=path.join(root,'web/dist'),temporary=await fs.mkdtemp(path.join(os.tmpdir(),'tracebolt-windows-actions-browser-'));
const sourceSha=process.env.TRACEBOLT_SOURCE_SHA??null,screenshots=[],variants=[];let browser,context,server,timer,errors=0,apiRequests=0,passed=false;
await fs.mkdir(out,{recursive:true});
const failure=()=>new Error('Synthetic Windows action browser gate failed; raw state withheld.');
async function shot(page,name,fixtureDisclosure){
 if(!/^synthetic-windows-service-actions-(1440|390)-(en|de)$/.test(name)||fixtureDisclosure!==windowsServiceActionsDisclosure)throw failure();
 await page.screenshot({path:path.join(out,name+'.png'),fullPage:false,animations:'disabled'});
 screenshots.push({file:name+'.png',sourceSha,publicSafe:true,fullPage:false,viewport:page.viewportSize(),locale:await page.locator('html').getAttribute('lang'),fixtureDisclosure,test:windowsServiceActionsCaseName});
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
 }
 requireWindowsServiceActionsEvidence(screenshots,sourceSha);if(errors||apiRequests||variants.length!==4)throw failure();
}
try{await Promise.race([run(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(failure()),120000);})]);passed=true;}
catch{console.log('FAIL: synthetic Windows action browser gate; raw diagnostics withheld.');}
finally{
 clearTimeout(timer);try{if(context)await context.close();}catch{passed=false;}try{if(browser)await browser.close();}catch{passed=false;}
 if(server){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
 const report={sourceSha,createdAt:new Date().toISOString(),name:windowsServiceActionsCaseName,status:passed?'PASS':'FAIL',stage:windowsServiceActionsFailureStage(),scope:windowsServiceActionsDisclosure,variants:passed?variants:[],runtimeErrorCount:errors,requestsToRealAPI:apiRequests,browserAcceptance:passed,durableStoreAcceptance:false,nativeAcceptance:false,secretsExported:false,realTelemetryExported:false};
 await fs.writeFile(path.join(out,'windows-service-actions-results.json'),JSON.stringify(report,null,2));await fs.writeFile(path.join(out,'windows-service-actions-manifest.json'),JSON.stringify({sourceSha,screenshots},null,2));await fs.rm(temporary,{recursive:true,force:true});process.exitCode=passed?0:1;
}
