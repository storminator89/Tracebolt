/** Real operator complete-overview UI with invented typed generations only.
 * No host inventory reader, collector, installer or permission change. */
import {createRequire} from 'node:module';
import {spawn,execFileSync} from 'node:child_process';
import {createInterface} from 'node:readline';
import {createHash} from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {chromium,expect}=require('@playwright/test');
const out=path.join(root,'artifacts/review');
await fs.mkdir(out,{recursive:true});
const temporary=await fs.mkdtemp(path.join(os.tmpdir(),'tracebolt-overview-browser-'));
const sourceSha=process.env.TRACEBOLT_SOURCE_SHA||null;
const base=`http://127.0.0.1:${Number(process.env.OVERVIEW_REVIEW_PORT||19898)}`;
const password='TRACEBOLT_OVERVIEW_BROWSER_FIXTURE_NOT_A_REAL_PASSWORD';
const apiSmoke=process.argv.includes('--api-smoke');
const results=[],screenshots=[];
let browser,server,context,pipe,waiting,devices,currentTest='',stage='setup',runtimeErrorCount=0,fatal=false;
const mark=value=>{stage=value;};
// Fixed projection only: no request URLs, identifiers, headers, response text or rows.
let readOutcomes=[],readTasks=[],queryEvents=[],failurePage=null,queryStep='not started',queryField=null;
async function exactStorageBusy(response){
 if(response.status()!==429||response.headers()['retry-after']!=='2')return false;
 try{const raw=await response.body();return raw.length<=2048&&JSON.parse(raw.toString('utf8'))?.error?.code==='storage_busy';}catch{return false;}
}
function observeReads(page){
 failurePage=page;
 const queries=new WeakMap();let count=0;
 const record=(request,phase,status=0)=>{const id=queries.get(request);if(id&&queryEvents.length<32)queryEvents.push({id,phase,status:Number.isInteger(status)&&status>=0&&status<=599?status:0});};
 page.on('request',request=>{if(count<8&&request.method()==='POST'&&request.url()===base+endpoint('alpha','query')){queries.set(request,++count);record(request,'request');}});
 page.on('requestfinished',request=>record(request,'finished'));
 page.on('requestfailed',request=>record(request,request.failure()?.errorText==='net::ERR_ABORTED'?'aborted':'failed'));
 page.on('response',response=>{
  record(response.request(),'response',response.status());
  if(response.request().method()!=='GET'||!response.url().startsWith(base+'/api/devices/'))return;
  const resource=['endpoint-identity','packages','overview'].find(name=>response.url().endsWith('/inventory/'+name));
  if(!resource||readTasks.length>=24)return;
  const status=response.status();const value={resource,status:Number.isInteger(status)&&status>=100&&status<=599?status:0,storageBusy:false};readOutcomes.push(value);
  readTasks.push(exactStorageBusy(response).then(busy=>{value.storageBusy=busy;}).catch(()=>{}));
 });
}
async function readEvidence(){const outcomes=readOutcomes.slice(),tasks=readTasks.slice();await Promise.allSettled(tasks);return JSON.stringify(outcomes);}
async function failureEvidence(caught){
 const kind=['Error','TimeoutError','AssertionError','TypeError','SyntaxError','AbortError'].includes(caught?.name)?caught.name:'other';
 const detail={kind,queryStep,queryField,queryEvents:queryEvents.slice()};
 if(!failurePage)return JSON.stringify(detail);
 let timer;
 try{
  const view=await Promise.race([failurePage.evaluate(()=>{
   const panel=document.querySelector('.complete-overview'),search=panel?.querySelector('input[type=search]'),button=panel?.querySelector('.complete-package-search button');
   return{present:Boolean(panel),busy:panel?.getAttribute('aria-busy')==='true',alertPresent:Boolean(panel?.querySelector('[role=alert]')),rows:Math.min(100,panel?.querySelectorAll('tbody tr:not(.overview-group)').length??0),searchPresent:Boolean(search),searchButtonDisabled:button?.matches(':disabled')??false,progressPresent:Boolean(panel?.querySelector('.overview-progress')),documentVisible:document.visibilityState==='visible',privateInert:Boolean(document.querySelector('.auth-private-view[inert]'))};
  }),new Promise(resolve=>{timer=setTimeout(()=>resolve({unavailable:true}),1000);})]);
  return JSON.stringify({...detail,view});
 }catch{return JSON.stringify({...detail,view:{unavailable:true}});}finally{clearTimeout(timer);}
}

const endpoint=(label='alpha',action='')=>`/api/devices/${devices[label]}/inventory/overview${action?'/'+action:''}`;
const rows=page=>page.locator('.complete-overview tbody tr:not(.overview-group)');
const panel=page=>page.locator('.complete-overview');

async function stop(){
 if(server?.pid&&server.exitCode===null){
  const end=new Promise(r=>server.once('exit',r));
  const wait=async()=>{let timer;try{await Promise.race([end,new Promise(r=>timer=setTimeout(r,1500))]);}finally{clearTimeout(timer);}};
  server.stdin.end();await wait();
  for(const signal of ['SIGTERM','SIGKILL'])if(server.exitCode===null){server.kill(signal);await wait();}
  if(server.exitCode===null)fatal=true;
 }
 pipe?.close();server=null;waiting=null;
}
async function control(action,extra={}){
 if(waiting)throw new Error('CONTROL_CONCURRENCY');
 let entry;const pending=new Promise((resolve,reject)=>{entry={resolve,reject};waiting=entry;});
 const timeout=setTimeout(()=>{if(waiting===entry){waiting=null;entry.reject(new Error('CONTROL_TIMEOUT'));}},15000);
 try{server.stdin.write(JSON.stringify({action,...extra})+'\n');const answer=await pending;expect(answer.ok).toBe(true);return answer;}
 finally{clearTimeout(timeout);if(waiting===entry)waiting=null;}
}
async function start(){
 const dir=await fs.mkdtemp(path.join(temporary,'state-'));
 server=spawn(path.join(temporary,'overviewfixture'),['--listen',new URL(base).host,'--state',dir,'--web',path.join(root,'web/dist')],{cwd:root,stdio:['pipe','pipe','ignore']});
 pipe=createInterface({input:server.stdout});
 pipe.on('line',line=>{const cb=waiting;waiting=null;if(cb){try{cb.resolve(JSON.parse(line));}catch{cb.reject(new Error('CONTROL_RESPONSE'));}}});
 server.on('error',()=>{waiting?.reject(new Error('FIXTURE_START_FAILED'));waiting=null;});
 server.stdin.on('error',()=>{waiting?.reject(new Error('FIXTURE_PIPE_FAILED'));waiting=null;});
 server.on('exit',()=>{waiting?.reject(new Error('FIXTURE_EXITED'));waiting=null;});
 devices=(await control('info')).devices;
}
async function pageAt({mobile=false}={}){
 context=await browser.newContext({viewport:mobile?{width:390,height:844}:{width:1440,height:1000},locale:'en-GB'});
 const page=await context.newPage();observeReads(page);page.on('pageerror',()=>runtimeErrorCount++);
 mark('open signed-out overview fixture');await page.goto(base+'/#/devices');
 mark('sign in to overview fixture');await page.getByLabel('Operator password',{exact:true}).fill(password);
 await page.getByRole('button',{name:'Sign in',exact:true}).click();
 await expect(page.locator('.app-shell')).toBeVisible();return page;
}

async function get(route){const response=await context.request.get(base+route);expect(response.status()).toBe(200);return response.json();}
async function post(route,data){const auth=await get('/api/auth/session');return context.request.post(base+route,{headers:{Origin:base,'X-CSRF-Token':auth.csrfToken},data});}
async function settled(page,selector='.complete-overview'){await expect(page.locator(selector)).toHaveAttribute('aria-busy','false');await expect(page.locator(selector).getByRole('alert')).toHaveCount(0);}
async function device(page,label='alpha'){
 mark('open invented overview device');await page.goto(`${base}/#/devices/${devices[label]}`);
 await expect(page.getByRole('region',{name:`Device QA synthetic overview ${label}`,exact:true})).toBeVisible();
 await expect(page.locator('.device-essentials')).toBeVisible();
}
async function open(page,label='alpha'){
 await device(page,label);mark('open primary complete Processes source');await page.getByRole('tab',{name:'Inventory',exact:true}).click();await page.getByRole('tablist',{name:'Inventory source',exact:true}).getByRole('tab',{name:'Processes',exact:true}).click();
 await expect(page.getByRole('tablist',{name:'Inventory source',exact:true}).getByRole('tab',{name:'Processes',exact:true})).toHaveAttribute('aria-selected','true');await settled(page);
}
async function source(page,name){mark('switch complete inventory section');await page.getByRole('tablist',{name:'Inventory source',exact:true}).getByRole('tab',{name,exact:true}).click();await settled(page);}
async function refresh(page){mark('refresh original section metadata');await page.getByRole('button',{name:'Refresh section and restart',exact:true}).click();await settled(page);}
const fact=(page,selector,label)=>page.locator(selector+' > div').filter({has:page.locator('dt').filter({hasText:new RegExp('^'+label+'$')})}).locator('dd');
const processRow=(page,pid)=>rows(page).filter({has:page.getByRole('rowheader',{name:String(pid),exact:true})});
async function clean(page){expect(await page.evaluate(values=>{const storage=JSON.stringify({...localStorage,...sessionStorage});return values.some(v=>storage.includes(v));},[password,'Needle[.*]','/synthetic/alpha/'])).toBe(false);expect(new URL(page.url()).search).toBe('');}
async function bounds(page){expect(await page.evaluate(()=>scrollX===0&&scrollY===0&&document.documentElement.scrollWidth<=innerWidth+1&&document.body.scrollWidth<=innerWidth+1&&document.documentElement.scrollHeight<=innerHeight+1)).toBe(true);}
async function shot(page,name){
 await expect(page.locator('.enrollment-secret,.enrollment-fingerprint,.enrollment-comparison')).toHaveCount(0);
 expect(await page.evaluate(value=>document.body.innerText.includes(value)||[...document.querySelectorAll('input')].some(e=>e.value.includes(value)),password)).toBe(false);
 await clean(page);await bounds(page);const file=name+'.png';await page.screenshot({path:path.join(out,file),fullPage:false,animations:'disabled'});
 screenshots.push({file,sourceSha,sha256:createHash('sha256').update(await fs.readFile(path.join(out,file))).digest('hex'),viewport:page.viewportSize(),locale:await page.locator('html').getAttribute('lang'),fullPage:false,publicSafe:true,fixtureDisclosure:'Invented process and mount rows, directly admitted through typed generation begin/append/finalize and the real operator HTTP-test handler. No host inventory read or native ingress.',test:currentTest});
}
async function held(page,url,run,{releaseBusy=false}={}){
 let release,arrived=0,completed=0;const statuses=[];const gate=new Promise(r=>release=r);
 const handler=async route=>{try{const response=await route.fetch();if(releaseBusy&&route.request().method()==='GET'&&await exactStorageBusy(response)){await route.fulfill({response});return;}statuses.push(response.status());arrived++;await gate;await route.fulfill({response});}catch{}finally{completed++;}};
 await page.route(url,handler);try{await run({arrived:()=>arrived,completed:()=>completed,statuses:()=>statuses,release});}finally{release();await page.unroute(url,handler);}
}
async function pageAction(page,action,expected={}){
 queryField=null;queryStep='perform action';
 const reply=page.waitForResponse(r=>r.url()===base+endpoint('alpha','query')&&r.request().method()==='POST');
 await action();queryStep='await response headers';const response=await reply;queryStep='require HTTP200';expect(response.status()).toBe(200);queryStep='read response JSON';const value=await response.json();
 queryStep='assert response fields';for(const [key,want]of Object.entries(expected)){queryField=['section','totalRows','exhausted','binding','collectedAt','retainedUntil','cursorExpiresAt'].includes(key)?key:'other';expect(value[key]).toEqual(want);}
 queryField=null;queryStep='wait for rendered row count';await expect(rows(page)).toHaveCount(value.items.length);queryStep='wait for settled view';await settled(page);queryStep='page action complete';return value;
}
async function search(page,text){queryField=null;queryStep='fill search input';await page.getByRole('searchbox',{name:'Search this complete section',exact:true}).fill(text);queryStep='wait for prior rows to clear';await expect(rows(page)).toHaveCount(0);return pageAction(page,()=>page.getByRole('button',{name:'Search from first page',exact:true}).click());}
// Real browser timers deliberately remain real. Each paused window exceeds one
// 15-second polling interval without changing request, assertion or session budgets.
async function liveFirstPage(page){
 const text='Synthetic alpha process';let statusReads=0,pageReads=0,unrelatedActions=0;
 page.on('request',request=>{const pathname=new URL(request.url()).pathname;if(pathname===endpoint()&&request.method()==='GET')statusReads++;if(pathname===endpoint('alpha','query')&&request.method()==='POST')pageReads++;if(/\/(journal|service-actions)(?:\/|$)/.test(pathname))unrelatedActions++;});
 mark('submit a first-page search before live generation replacement');await search(page,text);await expect(rows(page)).toHaveCount(100);
 const old=await get(endpoint()),oldId=old.processes.complete.binding.generationId;
 const originalPanel=await panel(page).elementHandle(),originalTable=await panel(page).locator('table').elementHandle(),originalInput=await page.getByRole('searchbox',{name:'Search this complete section',exact:true}).elementHandle(),originalScroll=await panel(page).locator('.package-table-scroll').elementHandle();
 const scroll=await page.evaluate(()=>{const main=document.querySelector('main'),table=document.querySelector('.complete-overview .package-table-scroll');main.scrollTop=120;table.scrollTop=80;table.scrollLeft=40;return{main:main.scrollTop,top:table.scrollTop,left:table.scrollLeft};});
 const beforeStatus=statusReads,beforePages=pageReads;
 await held(page,'**'+endpoint('alpha','query'),async gate=>{
  const replacementRequest=page.waitForRequest(request=>request.url()===base+endpoint('alpha','query')&&request.method()==='POST'&&request.postDataJSON().generationId!==oldId);
  mark('admit a newer real typed process generation while its first page is live');await control('sample',{device:'alpha',section:'processes',mode:'replace'});const fresh=await get(endpoint());expect(fresh.processes.complete.binding.generationId).not.toBe(oldId);
  const request=await replacementRequest;expect(request.postDataJSON()).toEqual({section:'processes',generationId:fresh.processes.complete.binding.generationId,cursor:'',search:text,limit:100});
  await expect.poll(gate.arrived).toBe(1);expect(gate.statuses()).toEqual([200]);
  mark('held automatic page keeps old rows and metadata together without a loading remount');await expect(rows(page)).toHaveCount(100);await expect(processRow(page,1)).not.toContainText(' new');await expect(panel(page)).toContainText(oldId);await expect(panel(page)).not.toContainText(fresh.processes.complete.binding.generationId);await expect(panel(page)).toHaveAttribute('aria-busy','false');await expect(page.getByRole('button',{name:'Search from first page',exact:true})).toBeEnabled();
  gate.release();await expect(processRow(page,1)).toContainText(' new');await expect(panel(page)).toContainText(fresh.processes.complete.binding.generationId);await expect(panel(page)).toContainText(fresh.processes.complete.manifest.collectedAt);await settled(page);
  mark('automatic generation swap retains selected source, search, DOM and scroll');await expect(page.getByRole('tablist',{name:'Inventory source',exact:true}).getByRole('tab',{name:'Processes',exact:true})).toHaveAttribute('aria-selected','true');await expect(page.getByRole('searchbox',{name:'Search this complete section',exact:true})).toHaveValue(text);
  expect(await originalPanel.evaluate(el=>el===document.querySelector('.complete-overview'))).toBe(true);expect(await originalTable.evaluate(el=>el===document.querySelector('.complete-overview table'))).toBe(true);expect(await originalInput.evaluate(el=>el===document.querySelector('.complete-overview input[type=search]'))).toBe(true);expect(await originalScroll.evaluate(el=>el===document.querySelector('.complete-overview .package-table-scroll'))).toBe(true);
  expect(await page.evaluate(()=>{const main=document.querySelector('main'),table=document.querySelector('.complete-overview .package-table-scroll');return{main:main.scrollTop,top:table.scrollTop,left:table.scrollLeft};})).toEqual(scroll);
  expect(pageReads).toBe(beforePages+1);expect(statusReads-beforeStatus).toBeGreaterThanOrEqual(1);expect(statusReads-beforeStatus).toBeLessThanOrEqual(2); // One status GET plus its existing single storage_busy retry.
 });
 mark('later-page browsing visibly pauses automatic replacement');await pageAction(page,()=>page.getByRole('button',{name:'Continue search',exact:true}).click());await expect(page.getByLabel('Inventory auto-refresh',{exact:true})).toContainText('Paused');
 const laterStatus=statusReads,laterPages=pageReads,laterFirst=await rows(page).first().textContent();await control('sample',{device:'alpha',section:'processes',mode:'replace'});await page.waitForTimeout(16000);expect(statusReads).toBe(laterStatus);expect(pageReads).toBe(laterPages);expect(await rows(page).first().textContent()).toBe(laterFirst);
 mark('unsubmitted search stays draft without a poll or implicit query');await page.getByRole('searchbox',{name:'Search this complete section',exact:true}).fill('Unsubmitted fixture search');await expect(rows(page)).toHaveCount(0);await expect(page.getByLabel('Inventory auto-refresh',{exact:true})).toContainText('Paused');const draftStatus=statusReads,draftPages=pageReads;await page.waitForTimeout(16000);expect(statusReads).toBe(draftStatus);expect(pageReads).toBe(draftPages);await expect(page.getByRole('searchbox',{name:'Search this complete section',exact:true})).toHaveValue('Unsubmitted fixture search');expect(unrelatedActions).toBe(0);await clean(page);
}
async function check(name,run){currentTest=name;readOutcomes=[];readTasks=[];queryEvents=[];failurePage=null;queryStep='not started';queryField=null;mark('fixture setup');const began=Date.now();try{await start();await run();console.log('READ_OUTCOMES '+await readEvidence());results.push({name,status:'PASS',durationMs:Date.now()-began});console.log(`PASS ${name}`);}catch(caught){results.push({name,status:'FAIL',stage,durationMs:Date.now()-began,error:'Bounded assertion failure. Fixed read outcomes: '+await readEvidence()+'. Fixed query evidence: '+await failureEvidence(caught)});console.log(`FAIL ${name} (${stage})`);}finally{if(context)await context.close();context=null;await stop();}}

try{
 mark('compile complete overview fixture');execFileSync(process.env.GO_BIN||'go',['build','-buildvcs=false','-o',path.join(temporary,'overviewfixture'),'./tests/e2e-review/overviewfixture'],{cwd:root,stdio:'ignore'});
 if(apiSmoke){
  const decoderFile=path.join(temporary,'overview-decoder.mjs');require('esbuild').buildSync({entryPoints:[path.join(root,'web/src/complete-overview-types.ts')],bundle:true,platform:'node',format:'esm',outfile:decoderFile,logLevel:'silent'});const {validOverviewView,validOverviewPage}=await import(pathToFileURL(decoderFile).href);
  await start();let cookie='',csrf='';
  const call=async(route,data,status=200)=>{const response=await fetch(base+route,{method:data?'POST':'GET',headers:{...(cookie?{Cookie:cookie}:{}),...(data?{Origin:base,'Content-Type':'application/json',...(csrf?{'X-CSRF-Token':csrf}:{})}:{})},body:data?JSON.stringify(data):undefined});if(response.headers.get('set-cookie'))cookie=response.headers.get('set-cookie').split(';')[0];expect(response.status).toBe(status);return response.json();};
  mark('real operator auth and independent overview metadata');expect((await fetch(base+endpoint())).status).toBe(401);await call('/api/auth/login',{password});csrf=(await call('/api/auth/session')).csrfToken;
  const initial=await call(endpoint());expect(validOverviewView(initial,devices.alpha)).toBe(true);expect(initial.processes.complete.manifest.observedCount).toBe(205);expect(initial.volumes.complete.manifest.observedCount).toBe(125);
  const q={section:'processes',generationId:initial.processes.complete.binding.generationId,cursor:'',search:'',limit:100};
  mark('real generation page and frontend decoder');const first=await call(endpoint('alpha','query'),q);expect(validOverviewPage(first,devices.alpha,'processes',initial.processes.complete,'','')).toBe(true);expect(first.items).toHaveLength(100);const second=await call(endpoint('alpha','query'),{...q,cursor:first.nextCursor});expect(second.items).toHaveLength(100);const third=await call(endpoint('alpha','query'),{...q,cursor:second.nextCursor});expect(third.items).toHaveLength(5);expect(third.exhausted).toBe(true);expect(third.retainedUntil).toBe(first.retainedUntil);
  const found=await call(endpoint('alpha','query'),{...q,search:'nEeDlE[.*]'});expect(validOverviewPage(found,devices.alpha,'processes',initial.processes.complete,'nEeDlE[.*]','')).toBe(true);expect(found.items).toHaveLength(3);expect(found.exhausted).toBe(true);expect(found.binding).toEqual(first.binding);expect(found.collectedAt).toBe(first.collectedAt);expect(found.retainedUntil).toBe(first.retainedUntil);
  const missing=await call(endpoint('alpha','query'),{...q,search:'^does-not-match$'});expect(validOverviewPage(missing,devices.alpha,'processes',initial.processes.complete,'^does-not-match$','')).toBe(true);expect(missing.items).toHaveLength(0);expect(missing.exhausted).toBe(true);expect(missing.binding).toEqual(first.binding);expect(missing.collectedAt).toBe(first.collectedAt);expect(missing.retainedUntil).toBe(first.retainedUntil);
  const mounts=await call(endpoint('alpha','query'),{...q,section:'volumes',generationId:initial.volumes.complete.binding.generationId});expect(validOverviewPage(mounts,devices.alpha,'volumes',initial.volumes.complete,'','')).toBe(true);expect(mounts.items).toHaveLength(100);
  mark('real independent failed and current siblings');await control('advance',{seconds:121});await control('fail',{device:'alpha',section:'processes',reason:'timeout'});await control('sample',{device:'alpha',section:'volumes',mode:'replace'});const mixed=await call(endpoint());expect(mixed.processes.complete).toEqual(initial.processes.complete);expect(mixed.processes.failure.reason).toBe('timeout');expect(mixed.volumes.complete.binding.generationId).not.toBe(initial.volumes.complete.binding.generationId);
  mark('successful zero and missing generations');const zero=await call(endpoint('beta'));expect(zero.processes.complete.manifest.observedCount).toBe(0);expect((await call(endpoint('awaiting'))).processes.complete).toBeNull();
  const pkg=await call(`/api/devices/${devices.alpha}/inventory/packages`);expect(pkg.complete.manifest.observedCount).toBe(205);expect(pkg.complete.manifest.installedCount).toBe(200);
  mark('original section retention expires independently');await control('advance',{seconds:86280});const expired=await call(endpoint());expect(expired.processes.status).toBe('expired');expect(expired.volumes.status).toBe('available');expect(expired.processes.complete.retainedUntil).toBe(initial.processes.complete.retainedUntil);await call(endpoint('alpha','query'),q,409);
  const priorCookie=cookie;await call('/api/auth/logout',{});expect((await fetch(base+endpoint(),{headers:{Cookie:priorCookie}})).status).toBe(401);results.push({name:'Real complete overview paging, decoder, search, independent retention, counts and auth',status:'PASS'});console.log('PASS complete overview real-handler API smoke');
 }else{
  const launch={headless:true,args:['--no-sandbox'],env:{...process.env,HOME:temporary,XDG_CONFIG_HOME:temporary,XDG_CACHE_HOME:temporary}};if(process.env.CHROMIUM_PATH)launch.executablePath=process.env.CHROMIUM_PATH;mark('hosted Chromium launch');browser=await chromium.launch(launch);
  await check('Primary complete Processes preserves every page, literal search, field outcomes and original generation',async()=>{
   const page=await pageAt();await open(page);mark('complete process totals and unknown field outcomes');await expect(rows(page)).toHaveCount(100);await expect(fact(page,'.overview-totals','Complete enumeration rows')).toHaveText('205');await expect(processRow(page,1).locator('td').nth(3)).toHaveText('0 B');await expect(processRow(page,1).locator('td').nth(4)).toHaveText('0');await expect(processRow(page,2)).toContainText('Permission denied');await expect(processRow(page,3)).toContainText('Exited during capture');await expect(processRow(page,4)).toContainText('Unavailable');await expect(panel(page)).toContainText('CPU time is cumulative, not current utilization');
   const initial=await get(endpoint());await page.locator('.complete-overview .package-table-scroll').scrollIntoViewIfNeeded();await shot(page,'synthetic-complete-overview-processes-en');
   mark('second and third complete process pages');const second=await pageAction(page,()=>page.getByRole('button',{name:'Next page',exact:true}).click(),{totalRows:205,binding:initial.processes.complete.binding,retainedUntil:initial.processes.complete.retainedUntil});expect(second.items).toHaveLength(100);const third=await pageAction(page,()=>page.getByRole('button',{name:'Next page',exact:true}).click(),{totalRows:205,exhausted:true,binding:second.binding,collectedAt:second.collectedAt,retainedUntil:second.retainedUntil,cursorExpiresAt:second.cursorExpiresAt});expect(third.items).toHaveLength(5);await expect(fact(page,'.overview-progress','Rows scanned so far')).toHaveText('205 / 205');await expect(page.getByRole('button',{name:'Next page',exact:true})).toHaveCount(0);
   mark('literal match search traverses exact pinned generation');const found=await search(page,'nEeDlE[.*]');mark('literal match search returns three rows');expect(found.items).toHaveLength(3);mark('literal match search preserves metacharacters');expect(found.items.every(row=>row.process.name.toLowerCase().includes('needle[.*]'))).toBe(true);mark('literal match search preserves generation binding');expect(found.binding).toEqual(second.binding);mark('literal match search displays three matches');await expect(fact(page,'.overview-progress','Matches found so far')).toHaveText('3');mark('literal no-match search traverses exact pinned generation');const missing=await search(page,'^does-not-match$');mark('literal no-match search returns zero rows');expect(missing.items).toHaveLength(0);mark('literal no-match search exhausts generation');expect(missing.exhausted).toBe(true);mark('literal no-match search displays explicit empty result');await expect(panel(page)).toContainText('No matches in the complete generation.');await clean(page);await liveFirstPage(page);
  });
  await check('Complete Mounts paginates truthful capacity groups and remains usable in German mobile',async()=>{
   const page=await pageAt();await open(page);await source(page,'Mounts');mark('mount counts and observed zero capacity');await expect(rows(page)).toHaveCount(100);await expect(fact(page,'.overview-totals','Complete enumeration rows')).toHaveText('125');await expect(panel(page)).toContainText('N/A · zero capacity');await expect(panel(page)).toContainText('do not sum capacities');await expect(page.locator('.overview-group')).toContainText('Measured local filesystems');
   const next=await pageAction(page,()=>page.getByRole('button',{name:'Next page',exact:true}).click(),{section:'volumes',totalRows:125,exhausted:true});expect(next.items).toHaveLength(25);await expect(panel(page)).toContainText('Denied');await expect(panel(page)).toContainText('Remote filesystem not measured');await expect(panel(page)).toContainText('Not applicable');await expect(page.locator('.overview-group')).toContainText(['Measured local filesystems','Local filesystems · capacity unavailable','Memory-backed filesystems','Remote filesystems','Virtual and pseudo filesystems']);
   mark('German mobile table keyboard scroll');await page.setViewportSize({width:390,height:844});await page.getByLabel('Language').selectOption('de');const region=page.locator('.complete-overview .package-table-scroll');await expect(region).toHaveAttribute('aria-label','Mounts · vollständige sichtbare Aufzählung');await region.scrollIntoViewIfNeeded();await region.focus();await page.keyboard.press('ArrowRight');await expect.poll(()=>region.evaluate(el=>el.scrollLeft)).toBeGreaterThan(0);await region.evaluate(el=>el.scrollLeft=0);await bounds(page);await page.getByRole('button',{name:'Dunkles Design aktivieren',exact:true}).click();await shot(page,'synthetic-complete-overview-mounts-de');await clean(page);
  });
  await check('Failed and current process or mount siblings retain independent original times and row generations',async()=>{
   const page=await pageAt();await open(page);const original=await get(endpoint());await control('advance',{seconds:121});await control('fail',{device:'alpha',section:'processes',reason:'timeout'});await control('sample',{device:'alpha',section:'volumes',mode:'replace'});mark('failed processes retain original generation beside new mounts');await refresh(page);await expect(rows(page)).toHaveCount(100);await expect(panel(page)).toContainText('Latest collection attempt failed');await expect(panel(page)).toContainText('Collection timed out');await expect(panel(page)).toContainText('does not refresh it');await expect(page.locator('.overview-independent')).toContainText('Mixed captures');const mixed=await get(endpoint());expect(mixed.processes.complete).toEqual(original.processes.complete);expect(mixed.volumes.complete.binding.generationId).not.toBe(original.volumes.complete.binding.generationId);
   await source(page,'Mounts');await expect(rows(page)).toHaveCount(100);await expect(panel(page)).not.toContainText('Latest collection attempt failed');await control('advance',{seconds:121});await control('fail',{device:'alpha',section:'volumes',reason:'permission_denied'});await control('sample',{device:'alpha',section:'processes',mode:'replace'});mark('failed mounts retain original generation beside new processes');await refresh(page);await expect(panel(page)).toContainText('Permission denied');await expect(rows(page)).toHaveCount(100);const reversed=await get(endpoint());expect(reversed.volumes.complete).toEqual(mixed.volumes.complete);expect(reversed.processes.complete.binding.generationId).not.toBe(mixed.processes.complete.binding.generationId);await source(page,'Processes');await expect(rows(page)).toHaveCount(100);await expect(panel(page)).not.toContainText('Latest collection attempt failed');await clean(page);
  });
  await check('Successful zero, missing data, cursor expiry and original section retention remain distinct',async()=>{
   const page=await pageAt();await open(page,'beta');mark('successful empty enumeration versus no generation');await expect(panel(page)).toContainText('Successful complete enumeration contained zero rows');await expect(fact(page,'.overview-totals','Complete enumeration rows')).toHaveText('0');await open(page,'awaiting');await expect(panel(page)).toContainText('Missing or failed collection is not a successful zero-row capture');await expect(rows(page)).toHaveCount(0);
   await open(page);await expect(rows(page)).toHaveCount(100);const original=await get(endpoint());mark('pin later page before server-only expiry advance');await pageAction(page,()=>page.getByRole('button',{name:'Next page',exact:true}).click(),{binding:original.processes.complete.binding});await expect(page.getByLabel('Inventory auto-refresh',{exact:true})).toContainText('Paused');await control('advance',{seconds:901});mark('expired cursor clears old page until explicit restart');const denied=page.waitForResponse(r=>r.url()===base+endpoint('alpha','query')&&r.status()===409);await page.getByRole('button',{name:'Next page',exact:true}).click();await denied;await expect(rows(page)).toHaveCount(0);await expect(panel(page).getByRole('alert')).toContainText('generation or cursor changed or expired');await refresh(page);await expect(rows(page)).toHaveCount(100);expect((await get(endpoint())).processes.complete.retainedUntil).toBe(original.processes.complete.retainedUntil);
   await control('sample',{device:'alpha',section:'processes',mode:'replace'});await control('advance',{seconds:85500});mark('old mount expires while later process generation stays available');await source(page,'Mounts');await expect(rows(page)).toHaveCount(0);await expect(panel(page)).toContainText('Original observations have expired');const current=await get(endpoint());expect(current.volumes.status).toBe('expired');expect(current.volumes.complete.retainedUntil).toBe(original.volumes.complete.retainedUntil);expect(current.processes.status).toBe('available');await source(page,'Processes');await expect(rows(page)).toHaveCount(100);await clean(page);
  });
  await check('Visibility and device changes clear held overview rows and real Sign out removes private state',async()=>{
   const page=await pageAt();await open(page);await expect(rows(page)).toHaveCount(100);mark('hidden visibility clears private overview');await page.evaluate(()=>{Object.defineProperty(document,'visibilityState',{configurable:true,value:'hidden'});document.dispatchEvent(new Event('visibilitychange'));});await expect(rows(page)).toHaveCount(0);
   await held(page,'**'+endpoint(),async gate=>{mark('visible restore waits for fresh overview metadata');await page.evaluate(()=>{Object.defineProperty(document,'visibilityState',{configurable:true,value:'visible'});document.dispatchEvent(new Event('visibilitychange'));});await expect.poll(gate.arrived).toBeGreaterThan(0);expect(gate.statuses().every(value=>value===200)).toBe(true);await expect(rows(page)).toHaveCount(0);gate.release();await expect(rows(page)).toHaveCount(100);await settled(page);},{releaseBusy:true});
   await held(page,'**'+endpoint('alpha','query'),async gate=>{mark('device navigation discards old held process page');await page.getByRole('button',{name:'Next page',exact:true}).click();await expect.poll(gate.arrived).toBe(1);expect(gate.statuses()).toEqual([200]);await expect(rows(page)).toHaveCount(0);await page.evaluate(id=>{location.hash='/devices/'+id;},devices.beta);await expect(page.getByRole('region',{name:'Device QA synthetic overview beta',exact:true})).toBeVisible();await page.getByRole('tab',{name:'Inventory',exact:true}).click();await page.getByRole('tablist',{name:'Inventory source',exact:true}).getByRole('tab',{name:'Processes',exact:true}).click();await settled(page);gate.release();await expect.poll(gate.completed).toBe(1);await expect(rows(page)).toHaveCount(0);await expect(panel(page)).toContainText('Successful complete enumeration contained zero rows');});
   await open(page);await expect(rows(page)).toHaveCount(100);const cookie=(await context.cookies()).map(c=>`${c.name}=${c.value}`).join('; ');await held(page,'**/api/auth/logout',async gate=>{mark('actual logout clears content before server response');await page.getByRole('button',{name:'Sign out',exact:true}).click();await expect.poll(gate.arrived).toBe(1);expect(gate.statuses()).toEqual([200]);await expect(page.locator('.app-shell,.complete-overview')).toHaveCount(0);gate.release();await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();});expect((await context.request.get(base+endpoint(),{headers:{Cookie:cookie}})).status()).toBe(401);await clean(page);await page.reload();await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();
  });
  await check('Software overview uses complete dpkg metadata counts and opens Packages without promoting bounded samples',async()=>{
   const page=await pageAt();let pages=0;page.on('request',r=>{if(r.url().endsWith('/inventory/packages/query'))pages++;});await device(page);await page.getByRole('tab',{name:'Details',exact:true}).click();mark('software total comes from complete metadata without page query');await settled(page,'.software-overview');await expect(fact(page,'.software-total','Complete dpkg rows')).toHaveText('205');await expect(fact(page,'.software-total','Installed rows')).toHaveText('200');await expect(fact(page,'.software-total','Incomplete rows')).toHaveText('5');expect(pages).toBe(0);await expect(page.locator('.software-overview')).toContainText('Snap, Flatpak and other software sources are not included');
   const actual=await get(`/api/devices/${devices.alpha}/inventory/packages`);expect(actual.complete.manifest.observedCount).toBe(205);expect(actual.complete.manifest.installedCount).toBe(200);await page.getByRole('button',{name:'Open Packages',exact:true}).click();await expect(page.getByRole('tablist',{name:'Inventory source',exact:true}).getByRole('tab',{name:'Packages',exact:true})).toHaveAttribute('aria-selected','true');await settled(page,'.complete-packages');await expect(page.locator('.complete-packages tbody tr')).toHaveCount(100);expect(pages).toBe(1);
   mark('bounded preview is secondary with explicit complete software count');await page.locator('.inventory-legacy-source summary').click();await page.getByRole('button',{name:'Open bounded preview',exact:true}).click();await settled(page,'.operational-panel');await expect(page.locator('.inventory-preview-intro')).toContainText('Legacy bounded sample. These row counts are not complete inventory totals.');await expect(page.getByRole('tab',{name:'Legacy bounded preview',exact:true})).toHaveAttribute('aria-selected','true');await expect(page.locator('.software-overview,.complete-packages,.complete-overview')).toHaveCount(0);await page.getByRole('tab',{name:'Details',exact:true}).click();await settled(page,'.software-overview');await expect(fact(page,'.software-total','Complete dpkg rows')).toHaveText('205');await clean(page);
  });
 }
}catch{fatal=true;console.log(`Complete overview setup failed (${stage}); raw diagnostics withheld.`);}
finally{
 if(context)await context.close();await stop();if(browser)await browser.close();
 const safe={secretsExported:false,realTelemetryExported:false,hostInventoryRead:false,collectorExecuted:false,permissionChanges:false,installerExecuted:false,userVmAccessed:false};
 const report={sourceSha,createdAt:new Date().toISOString(),scope:apiSmoke?'Real-handler complete overview API smoke; no browser executed':'Built React and real authenticated loopback HTTP-test overview with typed synthetic generation admission',fixture:'Disposable generated activated v3 identities and invented process/mount/dpkg rows. Begin/append/finalize admission does not prove native ingress, collection, local consent or host inventory.',faultInjection:'Held real responses, injected visibility state and forward-only service clock. First-page live replacement and paused paging/draft windows use real browser timers; auth clock and existing expiry budgets remain real.',existingGate:'Inherited104 required cases, three enrollment skips and five review cycles retained; two runners adapt only inventory navigation.',runtimeErrorCount,...safe,results,summary:{passed:results.filter(r=>r.status==='PASS').length,failed:results.filter(r=>r.status==='FAIL').length,setupFailure:fatal}};
 await fs.writeFile(path.join(out,apiSmoke?'complete-overview-api-smoke.json':'complete-overview-browser-results.json'),JSON.stringify(report,null,2));if(!apiSmoke)await fs.writeFile(path.join(out,'complete-overview-browser-manifest.json'),JSON.stringify({sourceSha,...safe,screenshots},null,2));await fs.rm(temporary,{recursive:true,force:true});process.exitCode=fatal||runtimeErrorCount||results.some(r=>r.status==='FAIL')?1:0;
}
