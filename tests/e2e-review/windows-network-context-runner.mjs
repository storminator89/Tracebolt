/** Independent opt-in hosted gate. Run only on the ordinary browser CI runner
 * after its locked Playwright Chromium installation. Never a native-host gate. */
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {spawn,execFileSync} from 'node:child_process';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {windowsNetworkContextBrowserCase,windowsNetworkContextCaseName,windowsNetworkContextDisclosure,windowsNetworkContextFailureStage} from './windows-network-context-browser.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..'),require=createRequire(path.join(root,'web/package.json'));
const {chromium,expect}=require('@playwright/test');
const out=path.join(root,'artifacts/review'),temporary=await fs.mkdtemp(path.join(os.tmpdir(),'tracebolt-network-context-browser-'));
const sourceSha=process.env.TRACEBOLT_SOURCE_SHA||null,base='http://127.0.0.1:19890',password='TRACEBOLT_BROWSER_FIXTURE_NOT_A_REAL_PASSWORD';
const screenshots=[];let browser,context,server,timer,errors=0,passed=false,details=null,serverFailed=false;
await fs.mkdir(out,{recursive:true});
const safeFailure=()=>new Error('Route-counter browser gate failed; raw state intentionally withheld.');
async function stop(){if(server&&!serverFailed&&server.exitCode===null){const end=new Promise(resolve=>server.once('exit',resolve));server.kill('SIGTERM');const deadline=setTimeout(()=>server.kill('SIGKILL'),5000);await end;clearTimeout(deadline);}server=null;}
async function shot(page,name,fixtureDisclosure){
 const match=/^synthetic-windows-network-context-(routes|counters)-(1440|390)-(en|de)$/.exec(name);
 if(!match||page.viewportSize()?.width!==Number(match[2])||await page.locator('html').getAttribute('lang')!==match[3]||fixtureDisclosure!==windowsNetworkContextDisclosure)throw safeFailure();
 await page.screenshot({path:path.join(out,name+'.png'),fullPage:false,animations:'disabled'});
 screenshots.push({file:name+'.png',sourceSha,publicSafe:true,fullPage:false,viewport:page.viewportSize(),locale:await page.locator('html').getAttribute('lang'),fixtureDisclosure,test:windowsNetworkContextCaseName});
}
async function login(page){await page.getByLabel('Operator password',{exact:true}).fill(password);await page.getByRole('button',{name:'Sign in',exact:true}).click();await expect(page.locator('.app-shell')).toBeVisible();}
try{
 if(!/^[a-f0-9]{40}$/.test(sourceSha??''))throw safeFailure();
 execFileSync(process.env.GO_BIN||'go',['build','-buildvcs=false','-o',path.join(temporary,'lanfixture'),'./tests/e2e-review/lanfixture'],{cwd:root,stdio:'ignore',timeout:120000});
 server=spawn(path.join(temporary,'lanfixture'),['--listen',new URL(base).host,'--db',path.join(temporary,'app.db'),'--web',path.join(root,'web/dist'),'--fixture',path.join(root,'docs/lan-api-examples.json'),'--ttl','10m'],{cwd:root,stdio:'ignore'});server.on('error',()=>{serverFailed=true;});
 let ready=false;
 for(let i=0;i<80;i++){if(serverFailed||server.exitCode!==null)throw safeFailure();try{if((await fetch(base+'/api/auth/session',{signal:AbortSignal.timeout(1000),redirect:'error'})).ok){ready=true;break;}}catch{}await new Promise(resolve=>setTimeout(resolve,100));}
 if(!ready)throw safeFailure();
 // No custom executable or alternate browser-download route is accepted.
 browser=await chromium.launch({headless:true,args:['--no-sandbox'],env:{...process.env,HOME:temporary,XDG_CONFIG_HOME:temporary,XDG_CACHE_HOME:temporary}});
 context=await browser.newContext({viewport:{width:1440,height:1000},locale:'en-GB'});const page=await context.newPage();page.on('pageerror',()=>errors++);await page.goto(base+'/#/devices');
 details=await Promise.race([windowsNetworkContextBrowserCase({page,expect,base,login,shot}),new Promise((_,reject)=>{timer=setTimeout(()=>reject(safeFailure()),300000);})]);
 const expected=new Set(['en','de'].flatMap(locale=>[1440,390].flatMap(width=>[`synthetic-windows-network-context-routes-${width}-${locale}.png`,`synthetic-windows-network-context-counters-${width}-${locale}.png`])));
 if(errors||screenshots.length!==expected.size||screenshots.some(item=>!expected.delete(item.file)||item.sourceSha!==sourceSha)||expected.size)throw safeFailure();passed=true;
}catch{console.log('FAIL: Windows routes and raw counters hosted browser gate; raw diagnostics withheld.');}
finally{
 clearTimeout(timer);try{if(context)await context.close();}catch{passed=false;}try{if(browser)await browser.close();}catch{passed=false;}try{await stop();}catch{passed=false;}
 const report={sourceSha,createdAt:new Date().toISOString(),name:windowsNetworkContextCaseName,status:passed?'PASS':'FAIL',stage:windowsNetworkContextFailureStage(),scope:windowsNetworkContextDisclosure,details:passed?details:null,runtimeErrorCount:errors,browserAcceptance:passed,liveStoreAcceptance:false,transport:'intercepted invented pages',unexecutedNativeGate:true,secretsExported:false,privateKeysExported:false,realTelemetryExported:false};
 await fs.writeFile(path.join(out,'windows-network-context-results.json'),JSON.stringify(report,null,2));await fs.writeFile(path.join(out,'windows-network-context-manifest.json'),JSON.stringify({sourceSha,screenshots},null,2));await fs.rm(temporary,{recursive:true,force:true});process.exitCode=passed?0:1;
}
