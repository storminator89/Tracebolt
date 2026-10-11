/** Bounded synthetic gate in the existing hosted browser job. The compiled production UI is served only on
 * loopback. All API/session data is invented and intercepted; no Go/provider
 * process or native Windows source is started. */
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {windowsStorageIOBrowserCase,windowsStorageIOCaseName,windowsStorageIODisclosure,windowsStorageIOFailureStage,requireWindowsStorageIOEvidence} from './windows-storage-io-browser.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..'),require=createRequire(path.join(root,'web/package.json'));
const {chromium,expect}=require('@playwright/test'),dist=path.join(root,'web/dist');
const out=path.resolve(process.env.TRACEBOLT_IO_EVIDENCE_DIR||path.join(root,'artifacts/review/windows-storage-io')),temporary=await fs.mkdtemp(path.join(os.tmpdir(),'tracebolt-storage-io-browser-'));
const sourceSha=execFileSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).trim();
const screenshots=[];let browser,context,server,timer,passed=false,result=null,errorCount=0,browserVersion=null,base;
await fs.mkdir(out,{recursive:true});
const mime={'.html':'text/html','.js':'application/javascript','.css':'text/css','.woff2':'font/woff2','.svg':'image/svg+xml','.png':'image/png'};
async function filesUnder(dir){const rows=[];for(const item of await fs.readdir(dir,{withFileTypes:true})){const f=path.join(dir,item.name);if(item.isDirectory())rows.push(...await filesUnder(f));else if(item.isFile())rows.push(f);}return rows.sort();}
const bundleHash=createHash('sha256');for(const file of await filesUnder(dist)){bundleHash.update(path.relative(dist,file));bundleHash.update(await fs.readFile(file));}const compiledBundleSha256=bundleHash.digest('hex');
const sourceFiles=['web/src/windows-inventory-types.ts','web/src/windows-inventory-resource.ts','web/src/windows-inventory.tsx','web/src/windows-retained-context.tsx',...(await fs.readdir(path.join(root,'web/src'))).filter(file=>file.startsWith('windows-storage-io')).map(file=>'web/src/'+file),'tests/e2e-review/windows-storage-io-browser.mjs','tests/e2e-review/windows-storage-io-runner.mjs'];
const sourceHash=createHash('sha256');for(const file of sourceFiles.sort()){sourceHash.update(file);sourceHash.update(await fs.readFile(path.join(root,file)));}const uiSourceSha256=sourceHash.digest('hex');
async function shot(page,name,fixtureDisclosure){
 if(!/^synthetic-windows-storage-io-(summary|details|failure|retained)-(1440|390)-(en|de)$/.test(name)||fixtureDisclosure!==windowsStorageIODisclosure)throw new Error('Unexpected screenshot');
 const file=name+'.png';await page.screenshot({path:path.join(out,file),fullPage:false,animations:'disabled'});
 screenshots.push({file,sourceSha,uiSourceSha256,compiledBundleSha256,test:windowsStorageIOCaseName,viewport:page.viewportSize(),locale:await page.locator('html').getAttribute('lang'),fullPage:false,publicSafe:true,fixtureDisclosure});
}
try{
 if(process.env.TRACEBOLT_SOURCE_SHA&&process.env.TRACEBOLT_SOURCE_SHA!==sourceSha)throw new Error('Source revision mismatch');
 await fs.access(path.join(dist,'index.html'));
 server=http.createServer(async(req,res)=>{
  try{const url=new URL(req.url,'http://127.0.0.1');if(req.method!=='GET'||url.pathname.startsWith('/api/')){res.writeHead(404);return res.end();}
   const file=path.resolve(dist,'.'+decodeURIComponent(url.pathname==='/'?'/index.html':url.pathname));if(!file.startsWith(dist+path.sep)){res.writeHead(403);return res.end();}
   const body=await fs.readFile(file);res.writeHead(200,{'Content-Type':mime[path.extname(file)]||'application/octet-stream','Cache-Control':'no-store'});res.end(body);
  }catch{res.writeHead(404);res.end();}
 });await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});base='http://127.0.0.1:'+server.address().port;
 browser=await chromium.launch({headless:true,...(process.env.TRACEBOLT_CHROMIUM_EXECUTABLE?{executablePath:process.env.TRACEBOLT_CHROMIUM_EXECUTABLE}:{}),args:['--no-sandbox'],env:{...process.env,HOME:temporary,XDG_CONFIG_HOME:temporary,XDG_CACHE_HOME:temporary}});browserVersion=browser.version();
 context=await browser.newContext({viewport:{width:1440,height:1000},locale:'en-GB',serviceWorkers:'block'});const page=await context.newPage();page.on('pageerror',()=>errorCount++);
 result=await Promise.race([windowsStorageIOBrowserCase({page,expect,base,shot}),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('Bounded UI fixture deadline')),180000);})]);
 requireWindowsStorageIOEvidence(screenshots,sourceSha);if(errorCount)throw new Error('Browser runtime error');passed=true;
}catch(error){console.log(`FAIL: Windows disk IO UI fixture at ${windowsStorageIOFailureStage()}: ${error instanceof Error?error.message.split('\n')[0]:'unknown'}`);}
finally{
 clearTimeout(timer);try{if(context)await context.close();}catch{passed=false;}try{if(browser)await browser.close();}catch{passed=false;}if(server){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
 const report={name:windowsStorageIOCaseName,status:passed?'PASS':'FAIL',stage:windowsStorageIOFailureStage(),sourceSha,sourceState:'sourceSha identifies checkout HEAD; source and compiled bundle hashes identify the tested bytes',uiSourceSha256,compiledBundleSha256,browserVersion,customPreinstalledBrowser:Boolean(process.env.TRACEBOLT_CHROMIUM_EXECUTABLE),createdAt:new Date().toISOString(),fixtureDisclosure:windowsStorageIODisclosure,details:passed?result:null,runtimeErrorCount:errorCount,browserAcceptance:passed,liveAuthenticationAcceptance:false,liveStoreAcceptance:false,nativeAcceptance:false};
 await fs.writeFile(path.join(out,'windows-storage-io-results.json'),JSON.stringify(report,null,2)+'\n');await fs.writeFile(path.join(out,'windows-storage-io-manifest.json'),JSON.stringify({sourceSha,uiSourceSha256,compiledBundleSha256,screenshots},null,2)+'\n');await fs.rm(temporary,{recursive:true,force:true});if(passed)console.log('PASS: Windows disk IO UI fixture, 16 screenshots; invented session and transport only.');process.exitCode=passed?0:1;
}
