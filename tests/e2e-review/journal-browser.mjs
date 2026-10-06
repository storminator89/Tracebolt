/** Hosted Chromium + real operator journal handler with wholly invented content.
 * No journal reader, helper, local permission, agent transport or installer runs.
 */
import {createRequire} from 'node:module';
import {spawn,execFileSync} from 'node:child_process';
import {createInterface} from 'node:readline';
import {createHash} from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {installJournalPrimaryBody} from './journal-primary-body.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {chromium,expect}=require('@playwright/test');
const out=path.join(root,'artifacts/review');
await fs.mkdir(out,{recursive:true});
const temporary=await fs.mkdtemp(path.join(os.tmpdir(),'tracebolt-journal-browser-'));
const sourceSha=process.env.TRACEBOLT_SOURCE_SHA||null;
const base=`http://127.0.0.1:${Number(process.env.JOURNAL_REVIEW_PORT||19896)}`;
const password='TRACEBOLT_JOURNAL_BROWSER_FIXTURE_NOT_A_REAL_PASSWORD';
const apiSmoke=process.argv.includes('--api-smoke');
const results=[],screenshots=[];
let browser,server,context,pipe,waiting,devices,currentTest='',stage='setup',runtimeErrorCount=0,fatal=false;
const mark=value=>{stage=value;};
let failureSnapshot=null,failureEvents=null,queryStep='not started',queryField=null,queryNumber=0;
async function boundedFailure(caught){
 const kind=['TimeoutError','AssertionError','Error','TypeError','SyntaxError','AbortError'].includes(caught?.name)?caught.name:'other',query={number:queryNumber,step:queryStep,field:queryField};
 if(!failureSnapshot)return JSON.stringify({kind,query});
 const events=failureEvents?failureEvents():[];
 let timer;try{const detail=await Promise.race([failureSnapshot(),new Promise(resolve=>{timer=setTimeout(()=>resolve({unavailable:true}),1000);})]);return JSON.stringify({kind,query,events,...detail});}catch{return JSON.stringify({kind,query,events,unavailable:true});}finally{clearTimeout(timer);}
}
// Fixed route categories/statuses and DOM booleans only; no URLs, IDs, bodies,
// input values, exception messages or response text enter the failure report.
function observeFailure(page,kind){
 const events=[];
 const resource=url=>{const pathname=new URL(url).pathname;if(pathname==='/api/auth/session')return'auth';if(pathname==='/api/session')return'csrf';const prefix=`/api/devices/${devices.alpha}`;if(kind==='journal'&&pathname===prefix+'/journal')return'journal-status';if(kind==='journal'&&pathname===prefix+'/journal/create')return'journal-create';if(kind==='journal'&&pathname===prefix+'/journal/cancel')return'journal-cancel';if(kind==='journal'&&pathname===prefix+'/journal/query')return'journal-query';if(kind==='journal'&&pathname===prefix+'/inventory/system')return'inventory-system';if(kind==='journal'&&pathname===prefix+'/inventory/system/query')return'inventory-system-query';if(kind==='packages'&&pathname===prefix+'/inventory/packages')return'package-status';if(kind==='packages'&&pathname===prefix+'/inventory/packages/query')return'package-query';return null;};
 const record=(request,phase,status=0)=>{const route=resource(request.url());if(route&&['GET','POST'].includes(request.method())&&Number.isInteger(status)&&status>=0&&status<=599){if(events.length===32)events.shift();events.push({resource:route,method:request.method(),phase,status});}};
 page.on('request',request=>record(request,'request'));page.on('response',response=>record(response.request(),'response',response.status()));page.on('requestfinished',request=>record(request,'finished'));page.on('requestfailed',request=>record(request,request.failure()?.errorText==='net::ERR_ABORTED'?'aborted':'failed'));
 failureEvents=()=>events.slice();
 failureSnapshot=async()=>({view:await page.evaluate(kind=>{
  const section=document.querySelector(kind==='journal'?'.journal-panel':'.complete-packages');
  const buttons=section?.querySelectorAll(kind==='journal'?'.journal-preset-hint button':'.complete-package-pagination button')??[];
  const button=buttons[0],rect=button?.getBoundingClientRect();
  return{present:Boolean(section),busy:section?.getAttribute('aria-busy')==='true',alertPresent:Boolean(section?.querySelector('[role=alert]')),rows:Math.min(500,section?.querySelectorAll('tbody tr').length??0),actionCount:Math.min(10,buttons.length),actionDisabled:button?.matches(':disabled')??false,actionVisible:Boolean(rect&&rect.width>0&&rect.height>0&&getComputedStyle(button).visibility==='visible'),privateInert:Boolean(document.querySelector('.auth-private-view[inert]')),documentVisible:document.visibilityState==='visible'};
 },kind)});
}

const endpoint=(label='alpha',action='')=>`/api/devices/${devices[label]}/journal${action?'/'+action:''}`;
const rows=page=>page.locator('.journal-table tbody tr');
const panel=page=>page.locator('.journal-panel');
const state=page=>page.locator('.journal-state strong');

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
 server=spawn(path.join(temporary,'journalfixture'),['--listen',new URL(base).host,'--state',dir,'--web',path.join(root,'web/dist')],{cwd:root,stdio:['pipe','pipe','ignore']});
 pipe=createInterface({input:server.stdout});
 pipe.on('line',line=>{const cb=waiting;waiting=null;if(cb){try{cb.resolve(JSON.parse(line));}catch{cb.reject(new Error('CONTROL_RESPONSE'));}}});
 server.on('error',()=>{waiting?.reject(new Error('FIXTURE_START_FAILED'));waiting=null;});
 server.stdin.on('error',()=>{waiting?.reject(new Error('FIXTURE_PIPE_FAILED'));waiting=null;});
 server.on('exit',()=>{waiting?.reject(new Error('FIXTURE_EXITED'));waiting=null;});
 devices=(await control('info')).devices;
}
async function pageAt({mobile=false}={}){
 context=await browser.newContext({viewport:mobile?{width:390,height:844}:{width:1440,height:1000},locale:'en-GB'});
 const page=await context.newPage();observeFailure(page,'journal');page.on('pageerror',()=>runtimeErrorCount++);
 await page.addInitScript(installJournalPrimaryBody,{url:base+endpoint('alpha','query')});
 mark('open signed-out journal fixture');await page.goto(base+'/#/devices');
 mark('sign in to journal fixture');await page.getByLabel('Operator password',{exact:true}).fill(password);
 await page.getByRole('button',{name:'Sign in',exact:true}).click();
 await expect(page.locator('.app-shell')).toBeVisible();return page;
}
async function get(route){const response=await context.request.get(base+route);expect(response.status()).toBe(200);return response.json();}
async function post(route,data){const auth=await get('/api/auth/session');return context.request.post(base+route,{headers:{Origin:base,'X-CSRF-Token':auth.csrfToken},data});}
async function settled(page){await expect(panel(page)).toHaveAttribute('aria-busy','false');await expect(panel(page).getByRole('alert')).toHaveCount(0);}
async function open(page,label='alpha'){
 mark('open journal device page');await page.goto(`${base}/#/devices/${devices[label]}`);
 await expect(page.getByRole('region',{name:`Device QA synthetic journal ${label}`,exact:true})).toBeVisible();
 mark('open lazy Logs tab');await page.getByRole('tab',{name:'Logs',exact:true}).click();
 mark('read initial journal status');await expect(state(page)).toBeVisible();await settled(page);
}
async function refresh(page){await page.getByRole('button',{name:'Refresh status',exact:true}).click();await expect(state(page)).toBeVisible();await settled(page);}
async function openAdvanced(page){const details=page.locator('.journal-advanced');if(await details.getAttribute('open')===null)await details.locator('summary').click();}
async function review(page){await page.getByRole('button',{name:'Fetch logs',exact:true}).click();await expect(page.getByRole('dialog',{name:'Review log request',exact:true})).toBeVisible();}
async function capture(page){
 await openAdvanced(page);
 mark('choose exact journal service');await page.getByLabel('Exact service unit',{exact:true}).fill('invented.service');
 mark('choose journal severity');const severity=page.getByRole('combobox',{name:'Include severity through',exact:true});await severity.selectOption('7');await expect(severity).toHaveValue('7');
 mark('review exact journal request');await review(page);
 mark('acknowledge journal content');await page.getByRole('checkbox',{name:/^I understand that log messages/}).check();
 mark('acknowledge plaintext journal transport');await page.getByRole('checkbox',{name:/^I also accept that this HTTP test/}).check();
 mark('create explicit journal capture');await page.getByRole('button',{name:'Capture logs',exact:true}).click();
 mark('await committed pending journal request');await expect(state(page)).toHaveText('Pending');await settled(page);
}
async function deliver(page,label='alpha',mode='complete'){
 mark('admit invented journal snapshot');const proof=await control('deliver',{device:label,mode});
 mark('read accepted journal status');await refresh(page);mark('read first captured journal page');await expect(rows(page)).toHaveCount(100);await settled(page);return proof;
}
async function clean(page){
 expect(await page.evaluate(values=>{const saved=JSON.stringify({...localStorage,...sessionStorage});return values.some(value=>saved.includes(value));},[password,'Needle[.*]','SYNTHETIC journal','invented.service'])).toBe(false);
 expect(new URL(page.url()).search).toBe('');
}
async function bounds(page){
 expect(await page.evaluate(()=>scrollX===0&&scrollY===0&&document.documentElement.scrollWidth<=innerWidth+1&&document.body.scrollWidth<=innerWidth+1&&document.documentElement.scrollHeight<=innerHeight+1)).toBe(true);
 const box=await page.locator('main.device-main').boundingBox();expect(box).not.toBeNull();
 expect(box.x>=0&&box.y>=0&&box.x+box.width<=page.viewportSize().width+1&&box.y+box.height<=page.viewportSize().height+1).toBe(true);
}
async function shot(page,name){
 await expect(page.locator('.enrollment-secret,.enrollment-fingerprint,.enrollment-comparison')).toHaveCount(0);
 expect(await page.evaluate(value=>document.body.innerText.includes(value)||[...document.querySelectorAll('input')].some(e=>e.value.includes(value)),password)).toBe(false);
 await clean(page);await bounds(page);
 const file=name+'.png';await page.screenshot({path:path.join(out,file),fullPage:false,animations:'disabled'});
 screenshots.push({file,sourceSha,sha256:createHash('sha256').update(await fs.readFile(path.join(out,file))).digest('hex'),viewport:page.viewportSize(),locale:await page.locator('html').getAttribute('lang'),fullPage:false,publicSafe:true,fixtureDisclosure:'Entirely invented journal messages admitted through typed cache/store calls and the real operator HTTP-test handler. No host log read, helper, local grant or native journal transport.',test:currentTest});
}
async function held(page,url,run){
 let release,arrived=0,completed=0;const statuses=[];const gate=new Promise(r=>release=r);
 const handler=async route=>{try{const response=await route.fetch();statuses.push(response.status());arrived++;await gate;await route.fulfill({response});}catch{}finally{completed++;}};
 await page.route(url,handler);
 try{await run({arrived:()=>arrived,completed:()=>completed,statuses:()=>statuses,release});}
 finally{release();await page.unroute(url,handler);}
}
function counts(page){
 const tally={create:0,cancel:0,query:0,status:0};
 page.on('request',request=>{const url=new URL(request.url());if(url.pathname.includes('/journal')){
  const last=url.pathname.split('/').at(-1);if(last==='journal')tally.status++;else if(Object.hasOwn(tally,last))tally[last]++;
 }});return tally;
}
async function queryAction(page,action,expected){
 queryNumber=Math.min(100,queryNumber+1);queryField=null;queryStep='perform action';
 const capture=await page.evaluate(()=>window.__traceboltJournalBody.arm());
 const reply=page.waitForResponse(r=>r.url()===base+endpoint('alpha','query')&&r.request().method()==='POST');
 await action();queryStep='await response headers';const response=await reply;queryStep='require HTTP200';expect(response.status()).toBe(200);
 // Observe only bytes consumed by the application's original bounded reader.
 // CDP may lose a body after fetch has consumed it; never fetch or clone it again.
 queryStep='await primary response consumption';await expect.poll(()=>page.evaluate(id=>window.__traceboltJournalBody.state(id),capture)).not.toMatch(/^(armed|waiting|reading)$/);
 queryStep='require complete primary response';expect(await page.evaluate(id=>window.__traceboltJournalBody.state(id),capture)).toBe('complete');const consumed=await page.evaluate(id=>window.__traceboltJournalBody.take(id),capture);expect(consumed).not.toBeNull();expect(consumed.status).toBe(200);const body=consumed.body;
 queryStep='assert response fields';for(const [key,value]of Object.entries(expected)){queryField=['offset','nextOffset','totalCapturedRows','matchedRows','snapshotDigest','identity','expiresAt','observedAt','search','searchScope'].includes(key)?key:'other';expect(body[key]).toEqual(value);}
 queryField=null;queryStep='wait for rendered row count';await expect(rows(page)).toHaveCount(body.rows.length);queryStep='wait for settled view';await settled(page);queryStep='query action complete';return body;
}
async function check(name,run){
 failureSnapshot=null;failureEvents=null;queryStep='not started';queryField=null;queryNumber=0;currentTest=name;mark('fixture setup');const began=Date.now();
 try{await start();await run();results.push({name,status:'PASS',durationMs:Date.now()-began});console.log(`PASS ${name}`);}
 catch(caught){results.push({name,status:'FAIL',stage,durationMs:Date.now()-began,error:'Bounded assertion failure; fixed diagnostics: '+await boundedFailure(caught)});console.log(`FAIL ${name} (${stage})`);}
 finally{if(context)await context.close();context=null;await stop();}
}

try{
 mark('compile journal fixture');execFileSync(process.env.GO_BIN||'go',['build','-buildvcs=false','-o',path.join(temporary,'journalfixture'),'./tests/e2e-review/journalfixture'],{cwd:root,stdio:'ignore'});
 if(apiSmoke){
  const decoderFile=path.join(temporary,'journal-decoder.mjs');
  require('esbuild').buildSync({entryPoints:[path.join(root,'web/src/journal-types.ts')],bundle:true,platform:'node',format:'esm',outfile:decoderFile,logLevel:'silent'});
  const {validJournalView,validJournalPage}=await import(pathToFileURL(decoderFile).href);
  const systemDecoder=path.join(temporary,'system-decoder.mjs');require('esbuild').buildSync({entryPoints:[path.join(root,'web/src/system-inventory-types.ts')],bundle:true,platform:'node',format:'esm',outfile:systemDecoder,logLevel:'silent'});const {validSystemView,validSystemPage}=await import(pathToFileURL(systemDecoder).href);
  await start();let cookie='',csrf='';
  const call=async(route,data,status=200)=>{const response=await fetch(base+route,{method:data?'POST':'GET',headers:{...(cookie?{Cookie:cookie}:{}),...(data?{Origin:base,'Content-Type':'application/json',...(csrf?{'X-CSRF-Token':csrf}:{})}:{})},body:data?JSON.stringify(data):undefined});if(response.headers.get('set-cookie'))cookie=response.headers.get('set-cookie').split(';')[0];expect(response.status).toBe(status);return response.json();};
  mark('real operator authentication and journal acknowledgements');expect((await fetch(base+endpoint())).status).toBe(401);
  await call('/api/auth/login',{password});csrf=(await call('/api/auth/session')).csrfToken;
  const initial=await call(endpoint());expect(validJournalView(initial,devices.alpha)).toBe(true);expect(initial.request).toBeNull();expect(initial.configured).toBe(true);
  mark('private invented metadata change preserves stable identity and observation time');const metadataPath=`/api/devices/${devices.alpha}`,oldMetadata=await call(metadataPath);expect(oldMetadata.name).toBe('QA synthetic journal alpha');await control('metadata',{device:'alpha'});const refreshedMetadata=await call(metadataPath);expect(refreshedMetadata.name).toBe('QA synthetic journal alpha refreshed');expect(refreshedMetadata.id).toBe(oldMetadata.id);expect(refreshedMetadata.lastSeen).toBe(oldMetadata.lastSeen);

  mark('real protected observed service inventory and frontend decoder');const systemPath=`/api/devices/${devices.alpha}/inventory/system`;expect((await fetch(base+systemPath)).status).toBe(401);const observed=await call(systemPath);expect(validSystemView(observed,devices.alpha)).toBe(true);expect(observed.lastComplete.services.meta.observedCount).toBe(3);expect(observed.latest.sockets.coverage).toBe('failed');const observedPage=await call(systemPath+'/query',{section:'services',generationId:observed.lastComplete.services.meta.generationId,cursor:'',search:'',filter:'all',limit:100});expect(validSystemPage(observedPage,devices.alpha,'services',observed.lastComplete.services,'','','all')).toBe(true);expect(observedPage.services.map(row=>row.name)).toEqual(['invented-backup.service','invented.service','invented:unsupported.service']);
  const query={unit:'invented.service',start:new Date(Date.parse(initial.serverNow)-60000).toISOString(),end:new Date(initial.serverNow).toISOString(),maxPriority:7};
  const input={expectedFloor:'0',query,acknowledgeLogContent:false,acknowledgePlaintext:false};
  expect((await call(endpoint('alpha','create'),input,400)).error.code).toBe('journal_acknowledgement_required');
  expect((await call(endpoint('alpha','create'),{...input,acknowledgeLogContent:true},400)).error.code).toBe('journal_plaintext_acknowledgement_required');
  const pending=await call(endpoint('alpha','create'),{...input,acknowledgeLogContent:true,acknowledgePlaintext:true});expect(pending.request.state).toBe('pending');
  mark('typed cache result and immutable literal query pages');const proof=await control('deliver',{device:'alpha',mode:'complete'});
  const accepted=await call(endpoint());expect(validJournalView(accepted,devices.alpha)).toBe(true);expect(accepted.request.state).toBe('accepted');
  const pageInput={identity:accepted.request.description.identity,snapshotDigest:accepted.request.receipt.resultDigest,search:'',offset:0,limit:100};
  const page=await call(endpoint('alpha','query'),pageInput);expect(validJournalPage(page,accepted,'',0)).toBe(true);expect(page.rows).toHaveLength(100);expect(page.totalCapturedRows).toBe(205);expect(page.nextOffset).toBe(100);expect(page.snapshotDigest).toBe(proof.snapshotDigest);
  for(const [offset,length,next]of [[100,100,200],[200,5,null],[100,100,200]]){const paged=await call(endpoint('alpha','query'),{...pageInput,offset});expect(validJournalPage(paged,accepted,'',offset)).toBe(true);expect(paged.rows).toHaveLength(length);expect(paged.nextOffset).toBe(next);expect(paged.identity).toEqual(page.identity);expect(paged.snapshotDigest).toBe(page.snapshotDigest);expect(paged.observedAt).toBe(page.observedAt);expect(paged.expiresAt).toBe(page.expiresAt);}
  const found=await call(endpoint('alpha','query'),{...pageInput,search:'nEeDlE[.*]'});expect(found.rows).toHaveLength(3);expect(found.searchScope).toBe('captured_snapshot_only');expect(found.observedAt).toBe(page.observedAt);
  const missing=await call(endpoint('alpha','query'),{...pageInput,search:'^does-not-match$'});expect(validJournalPage(missing,accepted,'^does-not-match$',0)).toBe(true);expect(missing.rows).toHaveLength(0);expect(missing.totalCapturedRows).toBe(205);expect(missing.identity).toEqual(page.identity);expect(missing.snapshotDigest).toBe(page.snapshotDigest);expect(missing.observedAt).toBe(page.observedAt);expect(missing.expiresAt).toBe(page.expiresAt);
  mark('cancel clears cache and preserves consumed floor');await call(endpoint('alpha','cancel'),{identity:pageInput.identity});expect((await call(endpoint())).request.state).toBe('canceled');await call(endpoint('alpha','query'),pageInput,409);
  const beta=await call(endpoint('beta'));const betaQuery={...query,end:new Date(beta.serverNow).toISOString(),start:new Date(Date.parse(beta.serverNow)-60000).toISOString()};
  const second=await call(endpoint('beta','create'),{...input,query:betaQuery,acknowledgeLogContent:true,acknowledgePlaintext:true});await control('advance',{seconds:120});await control('deliver',{device:'beta',mode:'partial'});
  const betaAccepted=await call(endpoint('beta'));const betaInput={identity:betaAccepted.request.description.identity,snapshotDigest:betaAccepted.request.receipt.resultDigest,search:'',offset:0,limit:100};
  const partial=await call(endpoint('beta','query'),betaInput);expect(validJournalView(betaAccepted,devices.beta)).toBe(true);expect(validJournalPage(partial,betaAccepted,'',0)).toBe(true);expect(partial.coverage).toBe('partial');expect(partial.countExact).toBe(false);expect(partial.expiresAt).toBe(second.request.description.expiresAt);
  mark('original fifteen-minute expiry and real session revocation');await control('advance',{seconds:781});const expired=await call(endpoint('beta'));expect(expired.request.state).toBe('expired');expect(expired.request.description.expiresAt).toBe(partial.expiresAt);await call(endpoint('beta','query'),betaInput,409);
  const priorCookie=cookie;await call('/api/auth/logout',{});expect((await fetch(base+endpoint(),{headers:{Cookie:priorCookie}})).status).toBe(401);
  results.push({name:'Real journal auth, acknowledgement, typed result, literal paging, cancel and original expiry',status:'PASS'});console.log('PASS journal real-handler API smoke');
 }else{
  const launch={headless:true,args:['--no-sandbox'],env:{...process.env,HOME:temporary,XDG_CONFIG_HOME:temporary,XDG_CACHE_HOME:temporary}};
  if(process.env.CHROMIUM_PATH)launch.executablePath=process.env.CHROMIUM_PATH;
  mark('hosted Chromium launch');browser=await chromium.launch(launch);

  await check('Explicit content and HTTP acknowledgements gate one lazy journal request and honest pending state',async()=>{
   const page=await pageAt();const tally=counts(page);let inventoryReads=0,authReads=0;
   const systemEndpoint=`${base}/api/devices/${devices.alpha}/inventory/system`;
   page.on('request',request=>{if([systemEndpoint,systemEndpoint+'/query'].includes(request.url()))inventoryReads++;if(request.url()===base+'/api/auth/session'&&request.method()==='GET')authReads++;});
   await page.goto(`${base}/#/devices/${devices.alpha}`);await expect(page.getByRole('region',{name:'Device QA synthetic journal alpha',exact:true})).toBeVisible();
   mark('journal stays lazy before selecting Logs');expect(tally.status).toBe(0);expect(tally.create).toBe(0);
   await page.getByRole('tab',{name:'Logs',exact:true}).click();await expect(state(page)).toHaveText('Awaiting a request');await settled(page);
   mark('observed service inventory stays lazy until picker opens');expect(inventoryReads).toBe(0);
   mark('compact query workspace excludes manual fields and preemptive consent');await expect(page.locator('.journal-advanced')).not.toHaveAttribute('open');await expect(page.getByLabel('Exact service unit',{exact:true})).not.toBeVisible();await expect(page.getByRole('checkbox')).toHaveCount(0);await page.locator('.journal-query-bar').scrollIntoViewIfNeeded();await shot(page,'synthetic-journal-workspace-desktop-en');
   const chooser=page.getByRole('button',{name:'Choose observed service',exact:true}),picker=page.getByRole('region',{name:'Observed services',exact:true}),unit=page.getByLabel('Exact service unit',{exact:true});
   const statusReply=page.waitForResponse(response=>response.url()===systemEndpoint&&response.request().method()==='GET'),serviceReply=page.waitForResponse(response=>response.url()===systemEndpoint+'/query'&&response.request().method()==='POST');
   mark('open observed service picker');await chooser.click();
   mark('await observed service inventory response headers');const statusResponse=await statusReply;
   mark('observed service inventory returns HTTP200');expect(statusResponse.status()).toBe(200);
   mark('read observed service inventory response JSON');const system=await statusResponse.json();
   mark('observed service inventory matches selected device');expect(system.deviceId).toBe(devices.alpha);
   mark('observed service inventory retains three services');expect(system.lastComplete.services.meta.observedCount).toBe(3);
   mark('await observed service query response headers');const serviceResponse=await serviceReply;
   mark('observed service query returns HTTP200');expect(serviceResponse.status()).toBe(200);
   mark('read observed service query response JSON');const services=await serviceResponse.json();
   mark('observed service query returns exact invented rows');expect(services.services.map(row=>row.name)).toEqual(['invented-backup.service','invented.service','invented:unsupported.service']);
   mark('observed service query matches services section');expect(services.section).toBe('services');
   mark('observed service picker is visible');await expect(picker).toBeVisible();
   mark('open observed service permission disclosure');await picker.getByText('Selection & permission',{exact:true}).click();
   mark('observed service picker does not imply local permission');await expect(picker).toContainText('Observed inventory does not confirm local journal allowlist membership or grant access.');
   mark('observed service picker discloses selection does not capture');await expect(picker).toContainText('Selecting a service only fills the exact-unit field; it does not capture logs.');
   mark('observed service picker rejects unsupported unit');await expect(picker.getByRole('button',{name:'Use invented:unsupported.service',exact:true})).toBeDisabled();
   mark('observed service picker performs exactly two inventory reads');expect(inventoryReads).toBe(2);
   mark('observed service picker creates no journal request');expect(tally.create).toBe(0);
   mark('observed service picker cancels no journal request');expect(tally.cancel).toBe(0);
   mark('picker Escape closes locally and restores its trigger focus');await picker.getByRole('button',{name:'Close service picker',exact:true}).focus();await page.keyboard.press('Escape');await expect(picker).toHaveCount(0);await expect(chooser).toBeFocused();await expect(page).toHaveURL(base+'/#/devices/'+devices.alpha);await expect(unit).toHaveValue('');
   mark('observed service selection fills only the manual field');await chooser.click();await picker.getByRole('button',{name:'Use invented.service',exact:true}).click();await expect(picker).toHaveCount(0);await expect(unit).toHaveValue('invented.service');await expect(chooser).toBeFocused();await expect(chooser).toHaveAttribute('aria-expanded','false');await expect(page.getByRole('checkbox',{name:/^I understand that log messages/})).toHaveCount(0);await expect(page.getByRole('checkbox',{name:/^I also accept that this HTTP test/})).toHaveCount(0);expect(tally.create).toBe(0);expect(tally.cancel).toBe(0);
   mark('presets use the displayed checked reference without any journal request');await openAdvanced(page);const group=page.getByRole('group',{name:'Windows ending at the displayed reference time',exact:true}),from=page.getByLabel('From (UTC)',{exact:true}),to=page.getByLabel('To (UTC)',{exact:true}),severity=page.getByRole('combobox',{name:'Include severity through',exact:true});await severity.selectOption('4');const reference=await group.locator('time').getAttribute('datetime');expect(Number.isFinite(Date.parse(reference))).toBe(true);const beforePresets={...tally};
   const windowMatches=async(ref,minutes)=>{const start=Date.parse((await from.inputValue())+'Z'),end=Date.parse((await to.inputValue())+'Z');expect(end).toBe(Math.floor(Date.parse(ref)/1000)*1000);expect(end-start).toBe(minutes*60000);};
   for(const [minutes,label]of [[5,'5 minutes ending at reference time'],[15,'15 minutes ending at reference time'],[30,'30 minutes ending at reference time'],[60,'1 hour ending at reference time']]){const button=group.getByRole('button',{name:label,exact:true});await button.click();await expect(button).toHaveAttribute('aria-pressed','true');await expect(button).toHaveAccessibleDescription('Reference time (UTC, last checked manager time): '+reference);await windowMatches(reference,minutes);expect(tally).toEqual(beforePresets);}
   await expect(panel(page)).toContainText('The reference stays fixed between reads and may be old.');await expect(unit).toHaveValue('invented.service');await expect(severity).toHaveValue('4');await expect(page.getByRole('button',{name:'Capture logs',exact:true})).toHaveCount(0);await expect(page.getByRole('button',{name:'Fetch logs',exact:true})).toBeEnabled();
   mark('ordinary idle keeps the selected draft and reference time');await page.evaluate(()=>new Promise(resolve=>window.setTimeout(resolve,1100)));await windowMatches(reference,60);await expect(group.locator('time')).toHaveAttribute('datetime',reference);await expect(unit).toHaveValue('invented.service');await expect(severity).toHaveValue('4');expect(tally).toEqual(beforePresets);
   mark('advance fixture reference clock');const advanced=await control('advance',{seconds:60}),priorAuthReads=authReads,priorStatusReads=tally.status;const refreshed=page.waitForResponse(response=>response.url()===base+endpoint()&&response.request().method()==='GET');
   mark('click exact journal reference refresh');await group.getByRole('button',{name:'Refresh status and reference time',exact:true}).click();
   mark('journal reference refresh returns HTTP200 headers');const refreshedResponse=await refreshed;expect(refreshedResponse.status()).toBe(200);
   mark('journal reference refresh settles without alert');await settled(page);
   mark('journal reference refresh rechecked authorization once');expect(authReads).toBe(priorAuthReads+1);expect(tally.status).toBe(priorStatusReads+1);
   // The UI's reference is installed only after the real bounded body is fully
   // decoded and accepted. Assert that result directly: a second CDP body read
   // can fail after Chromium has already delivered the response to fetch.
   mark('journal reference time advances from prior read');await expect.poll(async()=>Date.parse(await group.locator('time').getAttribute('datetime')??'')).toBeGreaterThan(Date.parse(reference));const checkedReference=await group.locator('time').getAttribute('datetime');expect(Date.parse(checkedReference)).toBeGreaterThanOrEqual(Date.parse(advanced.serverNow));
   mark('journal reference refresh preserves the old draft window');await windowMatches(reference,60);await expect(group.locator('button[aria-pressed=true]')).toHaveCount(0);
   mark('journal reference refresh preserves service and severity');await expect(unit).toHaveValue('invented.service');await expect(severity).toHaveValue('4');
   mark('journal reference refresh performs no capture cancel or query');expect(tally.create).toBe(0);expect(tally.cancel).toBe(0);expect(tally.query).toBe(0);
   mark('choose fifteen-minute window at refreshed reference');await group.getByRole('button',{name:'15 minutes ending at reference time',exact:true}).click();await windowMatches(checkedReference,15);const chosenStart=new Date(Date.parse((await from.inputValue())+'Z')).toISOString(),chosenEnd=new Date(Date.parse((await to.inputValue())+'Z')).toISOString();await expect(page.getByRole('checkbox',{name:/^I understand that log messages/})).toHaveCount(0);await expect(page.getByRole('checkbox',{name:/^I also accept that this HTTP test/})).toHaveCount(0);
   mark('both journal acknowledgements still gate capture');await page.getByLabel('Exact service unit',{exact:true}).fill('invented.service');await review(page);expect(tally.create).toBe(0);expect(tally.cancel).toBe(0);await expect(page.getByRole('checkbox',{name:/^I understand that log messages/})).not.toBeChecked();await expect(page.getByRole('checkbox',{name:/^I also accept that this HTTP test/})).not.toBeChecked();const submit=page.getByRole('button',{name:'Capture logs',exact:true});await expect(submit).toBeDisabled();
   mark('review dismissals discard consent without changing the draft or existing request');
   const reviewDialog=page.getByRole('dialog',{name:'Review log request',exact:true});
   await shot(page,'synthetic-journal-review-desktop-en');
   await expect(reviewDialog).toContainText('invented.service');await expect(reviewDialog).toContainText('4 · Warning');expect(Date.parse(await reviewDialog.locator('time').nth(0).getAttribute('datetime'))).toBe(Date.parse(chosenStart));expect(Date.parse(await reviewDialog.locator('time').nth(1).getAttribute('datetime'))).toBe(Date.parse(chosenEnd));
   for(const action of ['Back','Close','Escape']){
    await page.getByRole('checkbox',{name:/^I understand that log messages/}).check();await page.getByRole('checkbox',{name:/^I also accept that this HTTP test/}).check();await expect(submit).toBeEnabled();
    if(action==='Escape')await page.keyboard.press('Escape');else await reviewDialog.getByRole('button',{name:action,exact:true}).click();
    await expect(reviewDialog).toHaveCount(0);await expect(page.getByRole('button',{name:'Fetch logs',exact:true})).toBeFocused();await expect(unit).toHaveValue('invented.service');await windowMatches(checkedReference,15);expect(tally.create).toBe(0);expect(tally.cancel).toBe(0);
    await review(page);await expect(page.getByRole('checkbox',{name:/^I understand that log messages/})).not.toBeChecked();await expect(page.getByRole('checkbox',{name:/^I also accept that this HTTP test/})).not.toBeChecked();await expect(submit).toBeDisabled();
   }
   await page.getByRole('checkbox',{name:/^I understand that log messages/}).check();await expect(submit).toBeDisabled();expect(tally.create).toBe(0);
   await page.getByRole('checkbox',{name:/^I also accept that this HTTP test/}).check();await expect(submit).toBeEnabled();
   await held(page,'**'+endpoint('alpha','create'),async gate=>{mark('single consented creation waits for exact committed response');await submit.click();await expect.poll(gate.arrived).toBe(1);expect(gate.statuses()).toEqual([200]);await expect(submit).toHaveCount(0);await expect(page.getByRole('button',{name:'Fetch logs',exact:true})).toBeDisabled();expect(tally.create).toBe(1);await expect(rows(page)).toHaveCount(0);gate.release();await expect(state(page)).toHaveText('Pending');await settled(page);});
   await expect(submit).toHaveCount(0);await expect(page.getByRole('button',{name:'Fetch logs',exact:true})).toBeDisabled();await expect(panel(page)).toContainText('No content is available yet');await expect(panel(page)).not.toContainText('Complete coverage');
   const current=await get(endpoint());expect(current.request.state).toBe('pending');expect(current.expectedFloor).toBe('1');expect(current.contentStatus).toBe('unavailable');expect(tally.create).toBe(1);expect(current.request.description.query).toEqual({unit:'invented.service',start:chosenStart.replace('.000Z','Z'),end:chosenEnd.replace('.000Z','Z'),maxPriority:4});expect(tally.cancel).toBe(0);await clean(page);
   mark('service table opens Logs without creating or canceling a capture');
   await page.getByRole('tab',{name:'Inventory',exact:true}).click();
   await page.getByRole('tablist',{name:'Inventory source'}).getByRole('tab',{name:'Services',exact:true}).click();
   await expect(page.locator('.system-inventory tbody tr')).toHaveCount(3);
   await expect(page.getByRole('button',{name:'Open logs: invented:unsupported.service',exact:true})).toHaveCount(0);
   await page.getByRole('button',{name:'Open logs: invented-backup.service',exact:true}).click();
   await expect(page.getByRole('tab',{name:'Logs',exact:true})).toBeFocused();await settled(page);
   await expect(unit).toHaveValue('invented-backup.service');await expect(state(page)).toHaveText('Pending');
   await expect(page.getByRole('checkbox',{name:/^I understand that log messages/})).toHaveCount(0);
   await expect(page.getByRole('checkbox',{name:/^I also accept that this HTTP test/})).toHaveCount(0);
   expect(tally.create).toBe(1);expect(tally.cancel).toBe(0);expect(tally.query).toBe(0);
   mark('repeated Logs selection and metadata refresh preserve the service draft');
   await openAdvanced(page);await unit.fill('draft.service');const actions=()=>({create:tally.create,cancel:tally.cancel,query:tally.query}),beforeRepeated=actions();
   await page.getByRole('tab',{name:'Logs',exact:true}).click();await page.getByRole('tab',{name:'Logs',exact:true}).click();
   await expect(unit).toHaveValue('draft.service');expect(actions()).toEqual(beforeRepeated);
   await unit.evaluate(el=>{el.dataset.diagnosisProbe='same';});
   const metadata=page.waitForResponse(response=>response.url()===`${base}/api/devices/${devices.alpha}`&&response.request().method()==='GET');
   await page.getByRole('button',{name:'Refresh device metadata',exact:true}).click();expect((await metadata).status()).toBe(200);
   await expect(page.getByRole('button',{name:'Refresh device metadata',exact:true})).toBeEnabled();
   await expect(unit).toHaveValue('draft.service');await expect(unit).toHaveAttribute('data-diagnosis-probe','same');expect(actions()).toEqual(beforeRepeated);
   mark('Back and browser history discard the service handoff');
   await page.getByRole('button',{name:'Back to devices',exact:true}).click();await expect(page).toHaveURL(base+'/#/devices');await expect(panel(page)).toHaveCount(0);
   await page.goBack();await expect(page.getByRole('tab',{name:'Overview',exact:true})).toHaveAttribute('aria-selected','true');
   await page.getByRole('tab',{name:'Logs',exact:true}).click();await settled(page);await expect(unit).toHaveValue('');
   expect(tally.create).toBe(1);expect(tally.cancel).toBe(0);await clean(page);

  });

  await check('Source guidance and recognizable search shortcuts never expand local journal permission',async()=>{
   const page=await pageAt();const tally=counts(page);await open(page);
   await page.getByText('Permissions & sources',{exact:true}).click();const sources=page.getByRole('region',{name:'Log sources',exact:true});
   await expect(sources).toBeVisible();await sources.getByText('Other Linux log sources',{exact:true}).click();
   await expect(sources.getByText('Not supported by this collector',{exact:true})).toHaveCount(3);
   for(const label of ['Kernel & hardware','Whole system journal','System-wide authentication'])await expect(sources.getByText(label,{exact:true})).toBeVisible();
   await expect(sources.getByRole('button')).toHaveCount(0);expect(tally.create).toBe(0);expect(tally.cancel).toBe(0);
   await page.getByRole('button',{name:'Choose observed service',exact:true}).click();
   const picker=page.getByRole('region',{name:'Observed services',exact:true});await expect(picker.getByRole('button',{name:'Use invented.service',exact:true})).toBeVisible();
   await picker.getByRole('button',{name:'SSH logins',exact:true}).click();
   await expect(picker.getByLabel('Search observed services',{exact:true})).toHaveValue('ssh');
   await expect(picker.getByText('No matches in the complete service inventory.',{exact:true})).toBeVisible();
   await expect(picker.getByRole('button',{name:'Use ssh.service',exact:true})).toHaveCount(0);
   await picker.getByRole('button',{name:'All services',exact:true}).click();
   await expect(picker.getByRole('button',{name:'Use invented.service',exact:true})).toBeVisible();
   await expect(picker.getByText('Permission unknown',{exact:true})).toHaveCount(3);
   await picker.scrollIntoViewIfNeeded();await shot(page,'synthetic-journal-source-picker-desktop-en');
   await picker.getByRole('button',{name:'Use invented.service',exact:true}).click();
   await expect(page.locator('.journal-source-selection')).toContainText('Permission not verified.');
   await expect(page.getByRole('checkbox')).toHaveCount(0);await review(page);for(const box of await page.getByRole('checkbox').all())await expect(box).not.toBeChecked();await page.getByRole('button',{name:'Back',exact:true}).click();
   expect(tally.create).toBe(0);expect(tally.cancel).toBe(0);expect(tally.query).toBe(0);
   await page.setViewportSize({width:390,height:844});await page.getByLabel('Language').selectOption('de');
   await page.getByRole('region',{name:'Log-Quellen',exact:true}).scrollIntoViewIfNeeded();
   await expect(page.getByText('Kernel & Hardware',{exact:true})).toBeVisible();await shot(page,'synthetic-journal-source-options-mobile-de');
   mark('compact German mobile query and unchecked request-time consent');await page.getByText('Freigabe & Quellen',{exact:true}).click();await expect(page.locator('.journal-context-details')).not.toHaveAttribute('open');await page.locator('.journal-query-bar').scrollIntoViewIfNeeded();await shot(page,'synthetic-journal-workspace-mobile-de');await page.getByRole('button',{name:'Logs abrufen',exact:true}).click();const mobileReview=page.getByRole('dialog',{name:'Log-Anfrage prüfen',exact:true});await expect(mobileReview).toBeVisible();for(const box of await mobileReview.getByRole('checkbox').all())await expect(box).not.toBeChecked();await expect(mobileReview.getByRole('button',{name:'Logs erfassen',exact:true})).toBeDisabled();await shot(page,'synthetic-journal-review-mobile-de');await mobileReview.getByRole('button',{name:'Zurück',exact:true}).click();expect(tally.create).toBe(0);expect(tally.cancel).toBe(0);expect(tally.query).toBe(0);
   await clean(page);
  });

  await check('Complete and partial invented messages render inertly with honest English and German mobile coverage',async()=>{
   const page=await pageAt();await open(page);await capture(page);await deliver(page);
   mark('complete capture renders text without HTML or navigation');await expect(state(page)).toHaveText('Captured snapshot available');await expect(page.locator('.journal-count')).toContainText('205 matches · 205 captured');await expect(page.locator('.journal-count')).toContainText('Complete coverage for the requested window visible to the agent');
   await expect(page.locator('.journal-message').nth(1)).toContainText('<img');await expect(page.locator('.journal-results img,.journal-results script,.journal-results a')).toHaveCount(0);expect(await page.evaluate(()=>window.__journalFixtureHTMLExecuted??false)).toBe(false);
   await page.locator('.journal-count').scrollIntoViewIfNeeded();await shot(page,'synthetic-journal-desktop-en');
   await open(page,'beta');await capture(page);await deliver(page,'beta','partial');mark('partial source remains partial in German mobile');
   await page.setViewportSize({width:390,height:844});await page.getByLabel('Language').selectOption('de');await expect(page.getByRole('heading',{name:'Logs',exact:true})).toBeVisible();
   await expect(page.locator('.journal-count')).toContainText('Teilweise Abdeckung');await expect(page.locator('.journal-count')).toContainText('Quellensichtbarkeit eingeschränkt');
   await page.getByRole('button',{name:'Dunkles Design aktivieren',exact:true}).click();await page.locator('.journal-count').scrollIntoViewIfNeeded();await shot(page,'synthetic-journal-mobile-de');
   await expect(rows(page)).toHaveCount(100);await clean(page);
  });

  await check('Literal case-insensitive captured-snapshot search and hundred-row pages preserve digest and original times',async()=>{
   const page=await pageAt();const tally=counts(page);await open(page);await capture(page);const proof=await deliver(page);
   const status=await get(endpoint());const identity=status.request.description.identity,digest=status.request.receipt.resultDigest;
   mark('second page binds one original snapshot');const second=await queryAction(page,()=>page.getByRole('button',{name:'Next page',exact:true}).click(),{offset:100,nextOffset:200,totalCapturedRows:205,matchedRows:205,snapshotDigest:digest,identity,expiresAt:proof.expiresAt});
   mark('third page binds original snapshot and times');const third=await queryAction(page,()=>page.getByRole('button',{name:'Next page',exact:true}).click(),{offset:200,nextOffset:null,totalCapturedRows:205,matchedRows:205,snapshotDigest:digest,identity,observedAt:second.observedAt,expiresAt:second.expiresAt});mark('third page contains final five rows');expect(third.rows).toHaveLength(5);mark('final page disables Next page');await expect(page.getByRole('button',{name:'Next page',exact:true})).toBeDisabled();
   mark('previous page preserves snapshot and times');await queryAction(page,()=>page.getByRole('button',{name:'Previous page',exact:true}).click(),{offset:100,snapshotDigest:digest,observedAt:second.observedAt,expiresAt:second.expiresAt});
   mark('literal metacharacters across the captured snapshot');await page.getByLabel('Literal text in captured messages',{exact:true}).fill('nEeDlE[.*]');
   const found=await queryAction(page,()=>page.getByRole('button',{name:'Search capture',exact:true}).click(),{search:'nEeDlE[.*]',searchScope:'captured_snapshot_only',offset:0,matchedRows:3,totalCapturedRows:205,snapshotDigest:digest,identity,observedAt:second.observedAt,expiresAt:second.expiresAt});expect(found.rows.every(row=>row.message.toLowerCase().includes('needle[.*]'))).toBe(true);await expect(page.locator('.journal-message mark')).toHaveCount(3);await expect(page.getByRole('button',{name:'Previous page',exact:true})).toBeDisabled();
   mark('literal no-match search preserves captured total');await page.getByLabel('Literal text in captured messages',{exact:true}).fill('^does-not-match$');await queryAction(page,()=>page.getByRole('button',{name:'Search capture',exact:true}).click(),{matchedRows:0,totalCapturedRows:205});await expect(panel(page)).toContainText('No literal matches in this captured snapshot.');expect(tally.create).toBe(1);await clean(page);
  });

  await check('Cancel clears rows immediately and a lost committed response reconciles without mutation replay',async()=>{
   const page=await pageAt();const tally=counts(page);await open(page);await capture(page);await deliver(page);
   let release,arrived=0;const statuses=[];const gate=new Promise(r=>release=r);const handler=async route=>{try{const response=await route.fetch();statuses.push(response.status());arrived++;await gate;await route.abort('failed');}catch{}};
   await page.route('**'+endpoint('alpha','cancel'),handler);
   try{mark('cancel clears content before lost committed response');await page.getByRole('button',{name:'Cancel request / discard content',exact:true}).click();await expect.poll(()=>arrived).toBe(1);expect(statuses).toEqual([200]);await expect(rows(page)).toHaveCount(0);expect(tally.cancel).toBe(1);release();await expect(state(page)).toHaveText('Canceled');await settled(page);}
   finally{release();await page.unroute('**'+endpoint('alpha','cancel'),handler);}
   mark('fresh reload preserves cancellation and no automatic new request');const current=await get(endpoint());expect(current.request.state).toBe('canceled');expect(current.contentStatus).toBe('unavailable');expect(current.expectedFloor).toBe('1');await page.reload();await page.getByRole('tab',{name:'Logs',exact:true}).click();await expect(state(page)).toHaveText('Canceled');await expect(rows(page)).toHaveCount(0);expect(tally.cancel).toBe(1);expect(tally.create).toBe(1);await clean(page);
  });

  await check('Visibility restoration revalidates cleared content and expiry remains fifteen minutes from creation',async()=>{
   const page=await pageAt();const tally=counts(page);await open(page);await capture(page);const created=await get(endpoint());
   await control('advance',{seconds:120});const proof=await deliver(page);expect(proof.expiresAt).toBe(created.request.description.expiresAt);expect(Date.parse(proof.expiresAt)-Date.parse(created.request.description.createdAt)).toBe(900000);
   mark('idle journal timers retain the selected draft controls');
   const draft={unit:'invented-followup.service',start:new Date(Date.parse(created.serverNow)-300000).toISOString().slice(0,16)+':17',end:new Date(Date.parse(created.serverNow)-60000).toISOString().slice(0,16)+':17',priority:'5'};
   const unit=page.getByLabel('Exact service unit',{exact:true}),from=page.getByLabel('From (UTC)',{exact:true}),to=page.getByLabel('To (UTC)',{exact:true}),severity=page.getByRole('combobox',{name:'Include severity through',exact:true});
   const contentAck=page.getByRole('checkbox',{name:/^I understand that log messages/}),httpAck=page.getByRole('checkbox',{name:/^I also accept that this HTTP test/});
   const selected=async()=>{await expect(unit).toHaveValue(draft.unit);await expect(from).toHaveValue(draft.start);await expect(to).toHaveValue(draft.end);await expect(severity).toHaveValue(draft.priority);};
   await openAdvanced(page);await unit.fill(draft.unit);await from.fill(draft.start);await to.fill(draft.end);await severity.selectOption(draft.priority);const searchDraft=page.getByLabel('Literal text in captured messages',{exact:true});await searchDraft.fill('Needle[.*]');await review(page);await contentAck.check();await httpAck.check();
   // Cross multiple real 250 ms idle checks without changing browser clocks.
   await page.evaluate(()=>new Promise(resolve=>window.setTimeout(resolve,1100)));await selected();await expect(contentAck).toBeChecked();await expect(httpAck).toBeChecked();await expect(searchDraft).toHaveValue('Needle[.*]');await expect(rows(page)).toHaveCount(100);
   await page.getByRole('button',{name:'Back',exact:true}).click();
   mark('explicit device metadata refresh preserves the selected live Logs subtree');
   const metadataURL=`${base}/api/devices/${devices.alpha}`,oldMetadata=await get(`/api/devices/${devices.alpha}`),journalBefore={...tally};let metadataReads=0;
   const countMetadata=request=>{if(request.url()===metadataURL&&request.method()==='GET')metadataReads++;};page.on('request',countMetadata);
   await expect(page.locator('.device-page h1')).toHaveText('QA synthetic journal alpha');await control('metadata',{device:'alpha'});
   await held(page,metadataURL,async gate=>{
    const update=page.getByRole('button',{name:'Refresh device metadata',exact:true});await update.click();await expect.poll(gate.arrived).toBe(1);expect(gate.statuses()).toEqual([200]);
    await review(page);await contentAck.check();await httpAck.check();await expect(update).toBeDisabled();await expect(page.locator('#device-metadata-status')).toContainText('Checking device metadata');await expect(page.locator('.device-page h1')).toHaveText(oldMetadata.name);
    await expect(page.getByRole('tab',{name:'Logs',exact:true})).toHaveAttribute('aria-selected','true');await selected();for(const field of [unit,from,to,severity])await expect(field).toBeEnabled();await expect(contentAck).toBeChecked();await expect(httpAck).toBeChecked();await expect(searchDraft).toHaveValue('Needle[.*]');await expect(rows(page)).toHaveCount(100);expect(tally).toEqual(journalBefore);
    gate.release();await expect.poll(gate.completed).toBe(1);await expect(page.locator('.device-page h1')).toHaveText('QA synthetic journal alpha refreshed');await expect(update).toBeEnabled();await expect(page.locator('#device-metadata-status')).toContainText('Last successful check:');
   });page.off('request',countMetadata);
   expect(metadataReads).toBe(1);await expect(page.getByRole('tab',{name:'Logs',exact:true})).toHaveAttribute('aria-selected','true');await selected();await expect(contentAck).toBeChecked();await expect(httpAck).toBeChecked();await expect(searchDraft).toHaveValue('Needle[.*]');await expect(rows(page)).toHaveCount(100);expect(tally).toEqual(journalBefore);expect(tally.create).toBe(1);expect(tally.cancel).toBe(0);
   const refreshedMetadata=await get(`/api/devices/${devices.alpha}`);expect(refreshedMetadata.id).toBe(oldMetadata.id);expect(refreshedMetadata.name).toBe('QA synthetic journal alpha refreshed');expect(refreshedMetadata.lastSeen).toBe(oldMetadata.lastSeen);
   mark('visible blur exposes paused status with retained disabled controls');expect(await page.evaluate(()=>document.visibilityState)).toBe('visible');await page.evaluate(()=>window.dispatchEvent(new Event('blur')));
   await expect(panel(page).getByRole('status')).toContainText('Log content is paused while this page is inactive.');await expect(panel(page)).toContainText('No new capture is started.');await expect(rows(page)).toHaveCount(0);await expect(page.locator('.journal-results,.journal-search')).toHaveCount(0);await expect(page.locator('.journal-capture')).toBeVisible();await selected();
   for(const field of [unit,from,to,severity])await expect(field).toBeDisabled();await expect(contentAck).toHaveCount(0);await expect(httpAck).toHaveCount(0);await expect(page.getByRole('button',{name:'Refresh status',exact:true})).toBeEnabled();expect(tally.create).toBe(1);expect(tally.cancel).toBe(0);
   await page.evaluate(()=>new Promise(resolve=>window.setTimeout(resolve,1100)));await selected();await expect(panel(page).getByRole('status')).toContainText('Log content is paused');await expect(rows(page)).toHaveCount(0);
   let authReads=0;const countAuth=request=>{if(request.url()===base+'/api/auth/session'&&request.method()==='GET')authReads++;};page.on('request',countAuth);
   await held(page,'**'+endpoint(),async gate=>{
    mark('explicit paused refresh rechecks access before held original status');await page.getByRole('button',{name:'Refresh status',exact:true}).click();await expect.poll(gate.arrived).toBe(1);expect(gate.statuses()).toEqual([200]);expect(authReads).toBeGreaterThan(0);await expect(panel(page).getByRole('status')).toContainText('Reading journal status or captured content');await expect(rows(page)).toHaveCount(0);await selected();for(const field of [unit,from,to,severity])await expect(field).toBeDisabled();
    mark('explicit refresh restores the same accepted snapshot without replay');await queryAction(page,async()=>gate.release(),{identity:created.request.description.identity,snapshotDigest:proof.snapshotDigest,observedAt:proof.observedAt,expiresAt:proof.expiresAt,search:'',offset:0,totalCapturedRows:205});
   });page.off('request',countAuth);
   await selected();for(const field of [unit,from,to,severity])await expect(field).toBeEnabled();await expect(contentAck).toHaveCount(0);await expect(httpAck).toHaveCount(0);await expect(page.getByLabel('Literal text in captured messages',{exact:true})).toHaveValue('');expect(tally.create).toBe(1);expect(tally.cancel).toBe(0);
   await review(page);await expect(contentAck).not.toBeChecked();await expect(httpAck).not.toBeChecked();await page.getByRole('button',{name:'Back',exact:true}).click();
   const resumed=await get(endpoint());expect(resumed.request.description).toEqual(created.request.description);expect(resumed.request.receipt.resultDigest).toBe(proof.snapshotDigest);expect(resumed.contentStatus).toBe('available');
   await control('advance',{seconds:700});mark('injected hidden visibility clears captured rows');await page.evaluate(()=>{Object.defineProperty(document,'visibilityState',{configurable:true,value:'hidden'});document.dispatchEvent(new Event('visibilitychange'));});await expect(rows(page)).toHaveCount(0);await expect(page.locator('.journal-search')).toHaveCount(0);
   await held(page,'**'+endpoint(),async gate=>{mark('visible restore waits for a fresh real status');await page.evaluate(()=>{Object.defineProperty(document,'visibilityState',{configurable:true,value:'visible'});document.dispatchEvent(new Event('visibilitychange'));});await expect.poll(gate.arrived).toBeGreaterThan(0);expect(gate.statuses().every(value=>value===200)).toBe(true);await expect(rows(page)).toHaveCount(0);gate.release();await expect(rows(page)).toHaveCount(100);await settled(page);});
   const retained=await get(endpoint());expect(retained.request.description.expiresAt).toBe(proof.expiresAt);expect(retained.request.receipt.resultDigest).toBe(proof.snapshotDigest);
   mark('original request expiry hides content before a later collection-based deadline');await control('advance',{seconds:81});await refresh(page);await expect(state(page)).toHaveText('Expired');await expect(rows(page)).toHaveCount(0);await expect(page.locator('.journal-search')).toHaveCount(0);
   const expired=await get(endpoint());expect(expired.request.state).toBe('expired');expect(expired.request.description.expiresAt).toBe(proof.expiresAt);expect(Date.parse(expired.serverNow)).toBeLessThan(Date.parse(proof.observedAt)+900000);expect(tally.create).toBe(1);expect(tally.cancel).toBe(0);await clean(page);
  });

  await check('Device navigation discards held journal pages and real operator logout removes private content',async()=>{
   const page=await pageAt();await open(page);await capture(page);await deliver(page);
   await held(page,'**'+endpoint('alpha','query'),async gate=>{mark('device change while previous content page is held');await page.getByLabel('Literal text in captured messages',{exact:true}).fill('Needle[.*]');await page.getByRole('button',{name:'Search capture',exact:true}).click();await expect.poll(gate.arrived).toBe(1);expect(gate.statuses()).toEqual([200]);await expect(rows(page)).toHaveCount(0);
    await page.evaluate(id=>{location.hash='/devices/'+id;},devices.beta);await expect(page.getByRole('region',{name:'Device QA synthetic journal beta',exact:true})).toBeVisible();await page.getByRole('tab',{name:'Logs',exact:true}).click();await expect(state(page)).toHaveText('Awaiting a request');gate.release();await expect.poll(gate.completed).toBe(1);await expect(rows(page)).toHaveCount(0);await expect(panel(page)).not.toContainText('Needle[.*]');});
   await open(page);await expect(rows(page)).toHaveCount(100);const priorCookie=(await context.cookies()).map(cookie=>`${cookie.name}=${cookie.value}`).join('; ');
   await held(page,'**/api/auth/logout',async gate=>{mark('actual Sign out clears content before real CSRF logout response');await page.getByRole('button',{name:'Sign out',exact:true}).click();await expect.poll(gate.arrived).toBe(1);expect(gate.statuses()).toEqual([200]);await expect(page.locator('.app-shell,.journal-panel')).toHaveCount(0);gate.release();await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();});
   expect((await context.request.get(base+endpoint(),{headers:{Cookie:priorCookie}})).status()).toBe(401);await clean(page);await page.reload();await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();await expect(rows(page)).toHaveCount(0);
  });
 }
}catch{fatal=true;console.log(`Journal setup failed (${stage}); raw diagnostics withheld.`);}
finally{
 if(context)await context.close();await stop();if(browser)await browser.close();
 const safe={secretsExported:false,realTelemetryExported:false,hostJournalRead:false,helperExecuted:false,permissionChanges:false,collectorExecuted:false,installerExecuted:false,userVmAccessed:false};
 const report={sourceSha,createdAt:new Date().toISOString(),scope:apiSmoke?'Real-handler journal API smoke; no browser executed':'Built React and real authenticated loopback HTTP-test journal handler with typed synthetic cache/store admission',fixture:'Disposable generated activated v3 identities and invented journal rows. Direct cache/store admission does not prove native ingress, helper isolation, local consent or host journal access.',faultInjection:'Held or lost real responses, injected visibility state and service-only forward clock. Auth clock remains real.',existingGate:'Inherited98 required cases, three enrollment skips and five review cycles unchanged.',runtimeErrorCount,...safe,results,summary:{passed:results.filter(r=>r.status==='PASS').length,failed:results.filter(r=>r.status==='FAIL').length,setupFailure:fatal}};
 await fs.writeFile(path.join(out,apiSmoke?'journal-api-smoke.json':'journal-browser-results.json'),JSON.stringify(report,null,2));
 if(!apiSmoke)await fs.writeFile(path.join(out,'journal-browser-manifest.json'),JSON.stringify({sourceSha,...safe,screenshots},null,2));
 await fs.rm(temporary,{recursive:true,force:true});process.exitCode=fatal||runtimeErrorCount||results.some(r=>r.status==='FAIL')?1:0;
}
