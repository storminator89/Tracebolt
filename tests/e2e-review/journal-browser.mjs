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
 const page=await context.newPage();page.on('pageerror',()=>runtimeErrorCount++);
 await page.goto(base+'/#/devices');
 await page.getByLabel('Operator password',{exact:true}).fill(password);
 await page.getByRole('button',{name:'Sign in',exact:true}).click();
 await expect(page.locator('.app-shell')).toBeVisible();return page;
}
async function get(route){const response=await context.request.get(base+route);expect(response.status()).toBe(200);return response.json();}
async function post(route,data){const auth=await get('/api/auth/session');return context.request.post(base+route,{headers:{Origin:base,'X-CSRF-Token':auth.csrfToken},data});}
async function settled(page){await expect(panel(page)).toHaveAttribute('aria-busy','false');await expect(panel(page).getByRole('alert')).toHaveCount(0);}
async function open(page,label='alpha'){
 await page.goto(`${base}/#/devices/${devices[label]}`);
 await expect(page.getByRole('region',{name:`Device QA synthetic journal ${label}`,exact:true})).toBeVisible();
 await page.getByRole('tab',{name:'Logs',exact:true}).click();
 await expect(state(page)).toBeVisible();await settled(page);
}
async function refresh(page){await page.getByRole('button',{name:'Refresh status',exact:true}).click();await expect(state(page)).toBeVisible();await settled(page);}
async function capture(page){
 await page.getByLabel('Exact service unit',{exact:true}).fill('invented.service');
 await page.getByLabel('Include severity through',{exact:true}).selectOption('7');
 await page.getByRole('checkbox',{name:/^I understand that log messages/}).check();
 await page.getByRole('checkbox',{name:/^I also accept that this HTTP test/}).check();
 await page.getByRole('button',{name:'Capture logs',exact:true}).click();
 await expect(state(page)).toHaveText('Pending');await settled(page);
}
async function deliver(page,label='alpha',mode='complete'){
 const proof=await control('deliver',{device:label,mode});
 await refresh(page);await expect(rows(page)).toHaveCount(100);await settled(page);return proof;
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
 const reply=page.waitForResponse(r=>r.url()===base+endpoint('alpha','query')&&r.request().method()==='POST');
 await action();const response=await reply;expect(response.status()).toBe(200);const body=await response.json();
 for(const [key,value]of Object.entries(expected))expect(body[key]).toEqual(value);
 await expect(rows(page)).toHaveCount(body.rows.length);await settled(page);return body;
}
async function check(name,run){
 currentTest=name;mark('fixture setup');const began=Date.now();
 try{await start();await run();results.push({name,status:'PASS',durationMs:Date.now()-began});console.log(`PASS ${name}`);}
 catch{results.push({name,status:'FAIL',stage,durationMs:Date.now()-began,error:'Bounded assertion failure; raw content, responses, credentials and state withheld.'});console.log(`FAIL ${name} (${stage})`);}
 finally{if(context)await context.close();context=null;await stop();}
}

try{
 mark('compile journal fixture');execFileSync(process.env.GO_BIN||'go',['build','-buildvcs=false','-o',path.join(temporary,'journalfixture'),'./tests/e2e-review/journalfixture'],{cwd:root,stdio:'ignore'});
 if(apiSmoke){
  const decoderFile=path.join(temporary,'journal-decoder.mjs');
  require('esbuild').buildSync({entryPoints:[path.join(root,'web/src/journal-types.ts')],bundle:true,platform:'node',format:'esm',outfile:decoderFile,logLevel:'silent'});
  const {validJournalView,validJournalPage}=await import(pathToFileURL(decoderFile).href);
  await start();let cookie='',csrf='';
  const call=async(route,data,status=200)=>{const response=await fetch(base+route,{method:data?'POST':'GET',headers:{...(cookie?{Cookie:cookie}:{}),...(data?{Origin:base,'Content-Type':'application/json',...(csrf?{'X-CSRF-Token':csrf}:{})}:{})},body:data?JSON.stringify(data):undefined});if(response.headers.get('set-cookie'))cookie=response.headers.get('set-cookie').split(';')[0];expect(response.status).toBe(status);return response.json();};
  mark('real operator authentication and journal acknowledgements');expect((await fetch(base+endpoint())).status).toBe(401);
  await call('/api/auth/login',{password});csrf=(await call('/api/auth/session')).csrfToken;
  const initial=await call(endpoint());expect(validJournalView(initial,devices.alpha)).toBe(true);expect(initial.request).toBeNull();expect(initial.configured).toBe(true);
  const query={unit:'invented.service',start:new Date(Date.parse(initial.serverNow)-60000).toISOString(),end:new Date(initial.serverNow).toISOString(),maxPriority:7};
  const input={expectedFloor:'0',query,acknowledgeLogContent:false,acknowledgePlaintext:false};
  expect((await call(endpoint('alpha','create'),input,400)).error.code).toBe('journal_acknowledgement_required');
  expect((await call(endpoint('alpha','create'),{...input,acknowledgeLogContent:true},400)).error.code).toBe('journal_plaintext_acknowledgement_required');
  const pending=await call(endpoint('alpha','create'),{...input,acknowledgeLogContent:true,acknowledgePlaintext:true});expect(pending.request.state).toBe('pending');
  mark('typed cache result and immutable literal query pages');const proof=await control('deliver',{device:'alpha',mode:'complete'});
  const accepted=await call(endpoint());expect(validJournalView(accepted,devices.alpha)).toBe(true);expect(accepted.request.state).toBe('accepted');
  const pageInput={identity:accepted.request.description.identity,snapshotDigest:accepted.request.receipt.resultDigest,search:'',offset:0,limit:100};
  const page=await call(endpoint('alpha','query'),pageInput);expect(validJournalPage(page,accepted,'',0)).toBe(true);expect(page.rows).toHaveLength(100);expect(page.totalCapturedRows).toBe(205);expect(page.nextOffset).toBe(100);expect(page.snapshotDigest).toBe(proof.snapshotDigest);
  const found=await call(endpoint('alpha','query'),{...pageInput,search:'nEeDlE[.*]'});expect(found.rows).toHaveLength(3);expect(found.searchScope).toBe('captured_snapshot_only');expect(found.observedAt).toBe(page.observedAt);
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
   const page=await pageAt();const tally=counts(page);
   await page.goto(`${base}/#/devices/${devices.alpha}`);await expect(page.getByRole('region',{name:'Device QA synthetic journal alpha',exact:true})).toBeVisible();
   mark('journal stays lazy before selecting Logs');expect(tally.status).toBe(0);expect(tally.create).toBe(0);
   await page.getByRole('tab',{name:'Logs',exact:true}).click();await expect(state(page)).toHaveText('Awaiting a request');await settled(page);
   await page.getByLabel('Exact service unit',{exact:true}).fill('invented.service');const submit=page.getByRole('button',{name:'Capture logs',exact:true});await expect(submit).toBeDisabled();
   await page.getByRole('checkbox',{name:/^I understand that log messages/}).check();await expect(submit).toBeDisabled();expect(tally.create).toBe(0);
   await page.getByRole('checkbox',{name:/^I also accept that this HTTP test/}).check();await expect(submit).toBeEnabled();
   await held(page,'**'+endpoint('alpha','create'),async gate=>{mark('single consented creation waits for exact committed response');await submit.click();await expect.poll(gate.arrived).toBe(1);expect(gate.statuses()).toEqual([200]);await expect(submit).toBeDisabled();expect(tally.create).toBe(1);await expect(rows(page)).toHaveCount(0);gate.release();await expect(state(page)).toHaveText('Pending');await settled(page);});
   await expect(submit).toBeDisabled();await expect(panel(page)).toContainText('No content is available yet');await expect(panel(page)).not.toContainText('Complete coverage');
   const current=await get(endpoint());expect(current.request.state).toBe('pending');expect(current.expectedFloor).toBe('1');expect(current.contentStatus).toBe('unavailable');expect(tally.create).toBe(1);await clean(page);
  });

  await check('Complete and partial invented messages render inertly with honest English and German mobile coverage',async()=>{
   const page=await pageAt();await open(page);await capture(page);await deliver(page);
   mark('complete capture renders text without HTML or navigation');await expect(state(page)).toHaveText('Captured snapshot available');await expect(page.locator('.journal-count')).toContainText('205 matches · 205 captured');await expect(page.locator('.journal-count')).toContainText('Complete coverage for the requested window visible to the agent');
   await expect(page.locator('.journal-message').nth(1)).toContainText('<img');await expect(page.locator('.journal-results img,.journal-results script,.journal-results a')).toHaveCount(0);expect(await page.evaluate(()=>window.__journalFixtureHTMLExecuted??false)).toBe(false);
   await page.locator('.journal-count').scrollIntoViewIfNeeded();await shot(page,'synthetic-journal-desktop-en');
   await open(page,'beta');await capture(page);await deliver(page,'beta','partial');mark('partial source remains partial in German mobile');
   await page.setViewportSize({width:390,height:844});await page.getByLabel('Language').selectOption('de');await expect(page.getByRole('heading',{name:'Service-Logs',exact:true})).toBeVisible();
   await expect(page.locator('.journal-count')).toContainText('Teilweise Abdeckung');await expect(page.locator('.journal-count')).toContainText('Quellensichtbarkeit eingeschränkt');
   await page.getByRole('button',{name:'Dunkles Design aktivieren',exact:true}).click();await page.locator('.journal-count').scrollIntoViewIfNeeded();await shot(page,'synthetic-journal-mobile-de');
   await expect(rows(page)).toHaveCount(100);await clean(page);
  });

  await check('Literal case-insensitive captured-snapshot search and hundred-row pages preserve digest and original times',async()=>{
   const page=await pageAt();const tally=counts(page);await open(page);await capture(page);const proof=await deliver(page);
   const status=await get(endpoint());const identity=status.request.description.identity,digest=status.request.receipt.resultDigest;
   mark('pagination binds one original snapshot');const second=await queryAction(page,()=>page.getByRole('button',{name:'Next page',exact:true}).click(),{offset:100,nextOffset:200,totalCapturedRows:205,matchedRows:205,snapshotDigest:digest,identity,expiresAt:proof.expiresAt});
   const third=await queryAction(page,()=>page.getByRole('button',{name:'Next page',exact:true}).click(),{offset:200,nextOffset:null,totalCapturedRows:205,matchedRows:205,snapshotDigest:digest,identity,observedAt:second.observedAt,expiresAt:second.expiresAt});expect(third.rows).toHaveLength(5);await expect(page.getByRole('button',{name:'Next page',exact:true})).toBeDisabled();
   await queryAction(page,()=>page.getByRole('button',{name:'Previous page',exact:true}).click(),{offset:100,snapshotDigest:digest,observedAt:second.observedAt,expiresAt:second.expiresAt});
   mark('literal metacharacters across the captured snapshot');await page.getByLabel('Literal text in captured messages',{exact:true}).fill('nEeDlE[.*]');
   const found=await queryAction(page,()=>page.getByRole('button',{name:'Search capture',exact:true}).click(),{search:'nEeDlE[.*]',searchScope:'captured_snapshot_only',offset:0,matchedRows:3,totalCapturedRows:205,snapshotDigest:digest,identity,observedAt:second.observedAt,expiresAt:second.expiresAt});expect(found.rows.every(row=>row.message.toLowerCase().includes('needle[.*]'))).toBe(true);await expect(page.locator('.journal-message mark')).toHaveCount(3);await expect(page.getByRole('button',{name:'Previous page',exact:true})).toBeDisabled();
   await page.getByLabel('Literal text in captured messages',{exact:true}).fill('^does-not-match$');await queryAction(page,()=>page.getByRole('button',{name:'Search capture',exact:true}).click(),{matchedRows:0,totalCapturedRows:205});await expect(panel(page)).toContainText('No literal matches in this captured snapshot.');expect(tally.create).toBe(1);await clean(page);
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
   await control('advance',{seconds:700});mark('injected hidden visibility clears captured rows');await page.evaluate(()=>{Object.defineProperty(document,'visibilityState',{configurable:true,value:'hidden'});document.dispatchEvent(new Event('visibilitychange'));});await expect(rows(page)).toHaveCount(0);await expect(page.locator('.journal-search')).toHaveCount(0);
   await held(page,'**'+endpoint(),async gate=>{mark('visible restore waits for a fresh real status');await page.evaluate(()=>{Object.defineProperty(document,'visibilityState',{configurable:true,value:'visible'});document.dispatchEvent(new Event('visibilitychange'));});await expect.poll(gate.arrived).toBeGreaterThan(0);expect(gate.statuses().every(value=>value===200)).toBe(true);await expect(rows(page)).toHaveCount(0);gate.release();await expect(rows(page)).toHaveCount(100);await settled(page);});
   const retained=await get(endpoint());expect(retained.request.description.expiresAt).toBe(proof.expiresAt);expect(retained.request.receipt.resultDigest).toBe(proof.snapshotDigest);
   mark('original request expiry hides content before a later collection-based deadline');await control('advance',{seconds:81});await refresh(page);await expect(state(page)).toHaveText('Expired');await expect(rows(page)).toHaveCount(0);await expect(page.locator('.journal-search')).toHaveCount(0);
   const expired=await get(endpoint());expect(expired.request.state).toBe('expired');expect(expired.request.description.expiresAt).toBe(proof.expiresAt);expect(Date.parse(expired.serverNow)).toBeLessThan(Date.parse(proof.observedAt)+900000);expect(tally.create).toBe(1);await clean(page);
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
