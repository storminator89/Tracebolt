/** Real operator/store/React endpoint-identity acceptance with wholly invented data.
 * No VM, installer execution, native collection, real credentials or TLS bypass.
 */
import {createRequire} from 'node:module';
import {spawn,execFileSync} from 'node:child_process';
import {createInterface} from 'node:readline';
import {createHash} from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {chromium,expect}=require('@playwright/test');
const out=path.join(root,'artifacts/review');await fs.mkdir(out,{recursive:true});
const temporary=await fs.mkdtemp(path.join(os.tmpdir(),'tracebolt-endpoint-browser-'));
const sourceSha=process.env.TRACEBOLT_SOURCE_SHA||null;
const base=`http://127.0.0.1:${Number(process.env.FLEET_IDENTITY_REVIEW_PORT||19907)}`;
const password='TRACEBOLT_ENDPOINT_BROWSER_FIXTURE_NOT_A_REAL_PASSWORD';
const results=[],screenshots=[];let browser,server,context,pipe,waiting,devices,currentTest='',stage='setup',runtimeErrorCount=0,fatal=false;
const mark=value=>{stage=value;};
// Fixed projection only: no request URLs, identifiers, headers, response text or rows.
let readOutcomes=[],readTasks=[];
async function exactStorageBusy(response){
 if(response.status()!==429||response.headers()['retry-after']!=='2')return false;
 try{const raw=await response.body();return raw.length<=2048&&JSON.parse(raw.toString('utf8'))?.error?.code==='storage_busy';}catch{return false;}
}
function observeReads(page){
 page.on('response',response=>{
  if(response.request().method()!=='GET'||response.url()!==base+'/api/fleet/endpoint-identities')return;
  const resource='fleet-endpoint-identities';
  if(!resource||readTasks.length>=24)return;
  const status=response.status();const value={resource,status:Number.isInteger(status)&&status>=100&&status<=599?status:0,storageBusy:false};readOutcomes.push(value);
  readTasks.push(exactStorageBusy(response).then(busy=>{value.storageBusy=busy;}).catch(()=>{}));
 });
}
async function readEvidence(){const outcomes=readOutcomes.slice(),tasks=readTasks.slice();await Promise.allSettled(tasks);return JSON.stringify(outcomes);}

async function stop(){if(server?.pid&&server.exitCode===null){const end=new Promise(r=>server.once('exit',r));const wait=async()=>{let timer;try{await Promise.race([end,new Promise(r=>timer=setTimeout(r,1500))]);}finally{clearTimeout(timer);}};server.stdin.end();await wait();if(server.exitCode===null){server.kill('SIGTERM');await wait();}if(server.exitCode===null){server.kill('SIGKILL');await wait();}if(server.exitCode===null)fatal=true;}pipe?.close();server=null;waiting=null;}
async function control(action,extra={}){if(waiting)throw new Error('CONTROL_CONCURRENCY');let entry;const pending=new Promise((resolve,reject)=>{entry={resolve,reject};waiting=entry;});const timeout=setTimeout(()=>{if(waiting===entry){waiting=null;entry.reject(new Error('CONTROL_TIMEOUT'));}},15000);try{server.stdin.write(JSON.stringify({action,...extra})+'\n');const answer=await pending;expect(answer.ok).toBe(true);return answer;}finally{clearTimeout(timeout);if(waiting===entry)waiting=null;}}
async function start(){const dir=await fs.mkdtemp(path.join(temporary,'state-'));server=spawn(path.join(temporary,'endpointfixture'),['--listen',new URL(base).host,'--state',dir,'--web',path.join(root,'web/dist')],{cwd:root,stdio:['pipe','pipe','ignore']});pipe=createInterface({input:server.stdout});pipe.on('line',line=>{const cb=waiting;waiting=null;if(cb){try{cb.resolve(JSON.parse(line));}catch{cb.reject(new Error('CONTROL_RESPONSE'));}}});server.on('error',()=>{waiting?.reject(new Error('FIXTURE_START_FAILED'));waiting=null;});server.stdin.on('error',()=>{waiting?.reject(new Error('FIXTURE_PIPE_FAILED'));waiting=null;});server.on('exit',()=>{waiting?.reject(new Error('FIXTURE_EXITED'));waiting=null;});devices=(await control('info')).devices;}
async function pageAt(route='/devices',{mobile=false}={}){context=await browser.newContext({viewport:mobile?{width:390,height:844}:{width:1440,height:1000},locale:'en-GB'});const page=await context.newPage();observeReads(page);page.on('pageerror',()=>runtimeErrorCount++);await page.goto(`${base}/#${route}`);await page.getByLabel('Operator password',{exact:true}).fill(password);await page.getByRole('button',{name:'Sign in',exact:true}).click();await expect(page.locator('.app-shell')).toBeVisible();return page;}
async function get(route){const response=await context.request.get(base+route);expect(response.status()).toBe(200);return response.json();}
const hostname=label=>`qa-host-<lab>&${label}`;
async function clean(page){expect(await page.evaluate(values=>{const storage=JSON.stringify({...localStorage,...sessionStorage});return values.some(value=>storage.includes(value));},[password,hostname('alpha'),'192.0.2.19','2001:db8::19'])).toBe(false);}
async function shot(page,name){mark('invented identity viewport capture');await expect(page.locator('.enrollment-secret,.enrollment-fingerprint,.enrollment-comparison')).toHaveCount(0);await expect(page.getByLabel('Operator password',{exact:true})).toHaveCount(0);expect(await page.evaluate(value=>document.body.innerText.includes(value)||[...document.querySelectorAll('input')].some(e=>e.value.includes(value)),password)).toBe(false);await bounds(page);const file=name+'.png';await page.screenshot({path:path.join(out,file),fullPage:false,animations:'disabled'});screenshots.push({file,sourceSha,sha256:createHash('sha256').update(await fs.readFile(path.join(out,file))).digest('hex'),viewport:page.viewportSize(),locale:await page.locator('html').getAttribute('lang'),fullPage:false,publicSafe:true,fixtureDisclosure:'Entirely invented hostname and documentation-range addresses, directly admitted through typed v2 frames to the real store on loopback HTTP-test. No host collector, local consent file, installer, real telemetry or user endpoint.',test:currentTest});}
async function check(name,run){currentTest=name;readOutcomes=[];readTasks=[];mark('fixture setup');const began=Date.now();try{await start();await run();console.log('READ_OUTCOMES '+await readEvidence());results.push({name,status:'PASS',durationMs:Date.now()-began});console.log(`PASS ${name}`);}catch(error){console.log(String(error).slice(0,900));results.push({name,status:'FAIL',stage,durationMs:Date.now()-began,error:'Bounded assertion failure. Fixed read outcomes: '+await readEvidence()});console.log(`FAIL ${name} (${stage})`);}finally{if(context)await context.close();context=null;await stop();}}

async function bounds(page){expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1&&document.body.scrollWidth<=innerWidth+1)).toBe(true);}
const fleetPath='/api/fleet/endpoint-identities';
async function fleetReady(page){await expect(page.locator('.fleet-identity-notice [role=alert]')).toHaveCount(0);await expect(page.getByRole('button',{name:'Refresh hostnames and IP addresses',exact:true})).toBeEnabled();}
const fleetRow=(page,label='alpha')=>page.locator('.device-table tbody tr').filter({has:page.locator('.fleet-identity-id',{hasText:devices[label]})});
async function fleetRefresh(page){await page.getByRole('button',{name:'Refresh hostnames and IP addresses',exact:true}).click();await fleetReady(page);}
try{
 execFileSync(process.env.GO_BIN||'go',['build','-buildvcs=false','-o',path.join(temporary,'endpointfixture'),'./tests/e2e-review/endpointfixture'],{cwd:root,stdio:'ignore'});
 browser=await chromium.launch({headless:true,args:['--no-sandbox'],executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',env:{...process.env,HOME:temporary,XDG_CONFIG_HOME:temporary,XDG_CACHE_HOME:temporary}});
 await check('One bounded fleet read displays escaped hostname and scoped multiple IPs, searches locally and preserves stable routing',async()=>{
  const page=await pageAt();await fleetReady(page);const row=fleetRow(page);await expect(row.locator('strong')).toHaveText(hostname('alpha'));await expect(row).toContainText('192.0.2.19');await expect(row).toContainText('qa-eth0');await expect(row).toContainText('+2 more in device details');await expect(row.locator('img,a')).toHaveCount(0);
  const collection=await get(fleetPath);expect(collection.items.length).toBeLessThanOrEqual(25);expect(collection.items.find(item=>item.deviceId===devices.alpha).latest.reportedHostname.value).toBe(hostname('alpha'));
  let reads=0;page.on('request',r=>{if(r.url().endsWith(fleetPath))reads++;});await page.getByRole('textbox',{name:'Search devices'}).fill('198.51.100.24');await expect(fleetRow(page)).toBeVisible();await page.getByRole('textbox',{name:'Search devices'}).fill('qa-host-<lab>&alpha');await expect(page.locator('.device-table tbody tr')).toHaveCount(1);expect(reads).toBe(0);await page.getByRole('textbox',{name:'Search devices'}).fill('');
  await page.getByLabel('Sort devices').selectOption('name');const overview=await get('/api/overview');const reported=new Map(collection.items.map(item=>[item.deviceId,item.latest?.reportedHostname.value]));const expected=overview.devices.slice().sort((a,b)=>(reported.get(a.id)||a.name).localeCompare(reported.get(b.id)||b.name,'en')).map(item=>'ID: '+item.id);expect(await page.locator('.device-table .fleet-identity-id').allTextContents()).toEqual(expected);
  await shot(page,'synthetic-fleet-identity-desktop-en');await page.getByRole('button',{name:'Open details: '+hostname('alpha'),exact:true}).click();await expect(page).toHaveURL(base+'/#/devices/'+devices.alpha);await expect(page.locator('main.device-main')).toBeVisible();await page.getByRole('button',{name:'Back to devices',exact:true}).click();await fleetReady(page);await expect(fleetRow(page).locator('strong')).toHaveText(hostname('alpha'));await clean(page);
 });
 await check('German mobile table preserves hostname, IPs, scope, filters and unavailable identity distinctions',async()=>{
  await control('sample',{device:'beta',mode:'partial'});const page=await pageAt('/devices',{mobile:true});await fleetReady(page);await page.getByLabel('Language').selectOption('de');await expect(fleetRow(page,'beta')).toContainText('Hostname nicht verfügbar');await expect(fleetRow(page,'beta')).toContainText('Zugriff verweigert');await expect(fleetRow(page,'beta')).toContainText('Teilweise erfasst');await expect(fleetRow(page)).toContainText('192.0.2.19');mark('mobile metadata rows viewport');await fleetRow(page).or(fleetRow(page,'beta')).last().scrollIntoViewIfNeeded();await expect(fleetRow(page)).toBeInViewport({ratio:1});await expect(fleetRow(page,'beta')).toBeInViewport({ratio:1});await bounds(page);await shot(page,'synthetic-fleet-identity-mobile-de');
  mark('mobile reported-hostname search');await page.getByRole('textbox',{name:'Geräte durchsuchen'}).fill('qa-host-<lab>&alpha');await expect(page.locator('.device-table tbody tr')).toHaveCount(1);await expect(fleetRow(page)).toBeVisible();await page.getByRole('textbox',{name:'Geräte durchsuchen'}).fill('');
  // This fixture admits endpoint/system snapshots, not a metrics telemetry
  // bundle. Enrollment's Linux platform must not become observed Device.platform.
  mark('mobile OS fixture contract');const alpha=await get('/api/devices/'+devices.alpha);expect(alpha).toMatchObject({platform:'unknown',os:'Awaiting agent'});
  mark('mobile Linux filter excludes unknown platform');await page.getByLabel('Nach Betriebssystem filtern').selectOption('linux');await expect(fleetRow(page)).toHaveCount(0);
  mark('mobile unknown-platform filter restores alpha');await page.getByLabel('Nach Betriebssystem filtern').selectOption('unknown');await expect(fleetRow(page)).toBeVisible();
  mark('mobile all-platform filter preserves alpha');await page.getByLabel('Nach Betriebssystem filtern').selectOption('all');await expect(fleetRow(page)).toBeVisible();await clean(page);
 });
 await check('Original age survives ordinary reports and fleet refresh; revoked and expired values disappear',async()=>{
  const page=await pageAt();
  // The first metadata effect can start after the initial enabled button renders.
  // Finish that read before advancing its clock or issuing a nonblocking fixture write.
  mark('initial fleet snapshot before age controls');await expect(fleetRow(page).locator('strong')).toHaveText(hostname('alpha'));await expect(fleetRow(page)).toContainText('192.0.2.19');await fleetReady(page);
  mark('capture original identity receipt');const original=(await get(fleetPath)).items.find(item=>item.deviceId===devices.alpha);
  mark('advance original identity age');await control('advance',{seconds:121});
  mark('save ordinary system fixture report');await control('sample',{device:'alpha',mode:'ordinary'});
  mark('verify original stale identity receipt');await fleetRefresh(page);await expect(fleetRow(page)).toContainText('Stale');const retained=(await get(fleetPath)).items.find(item=>item.deviceId===devices.alpha);expect(retained.latest.collectedAt).toBe(original.latest.collectedAt);expect(retained.sequence).toBe(original.sequence);
  mark('revoke fixture identity');await control('revoke',{device:'alpha'});await fleetRefresh(page);await expect(fleetRow(page)).toContainText('Revoked');await expect(fleetRow(page)).not.toContainText(hostname('alpha'));await expect(fleetRow(page)).not.toContainText('192.0.2.19');
  mark('advance original retention expiry');await control('advance',{seconds:86400});await fleetRefresh(page);await expect(fleetRow(page,'beta')).toContainText('Expired');await expect(fleetRow(page,'beta')).not.toContainText('192.0.2.19');
 });
 await check('Failed refresh and suspended visibility clear values; recovery performs a new batch',async()=>{
  const page=await pageAt();await fleetReady(page);await page.route('**'+fleetPath,route=>route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({error:{code:'inventory_unavailable',message:'Synthetic read failure'}})}));await page.getByRole('button',{name:'Refresh hostnames and IP addresses'}).click();await expect(page.locator('.fleet-identity-notice [role=alert]')).toBeVisible();await expect(page.locator('.device-table')).not.toContainText(hostname('alpha'));await page.unroute('**'+fleetPath);await fleetRefresh(page);await expect(fleetRow(page)).toContainText(hostname('alpha'));
  await page.evaluate(()=>window.dispatchEvent(new Event('blur')));await expect(page.locator('.device-table')).not.toContainText(hostname('alpha'));await page.evaluate(()=>window.dispatchEvent(new Event('focus')));await fleetReady(page);await expect(fleetRow(page)).toContainText(hostname('alpha'));await clean(page);
 });
 await check('Operator logout rejects the batch and clears all fleet observations',async()=>{
  const page=await pageAt();
  // The initial button can be enabled before the first metadata effect starts.
  // Require a validated snapshot to be visible before revoking its access.
  mark('initial fleet identity rendered before logout');await expect(fleetRow(page).locator('strong')).toHaveText(hostname('alpha'));await expect(fleetRow(page)).toContainText('192.0.2.19');await fleetReady(page);
  mark('backend logout and explicit fleet refresh');const auth=await get('/api/auth/session');const logout=await context.request.post(base+'/api/auth/logout',{headers:{Origin:base,'X-CSRF-Token':auth.csrfToken},data:{}});expect(logout.ok()).toBe(true);expect((await context.request.get(base+fleetPath)).status()).toBe(401);await page.getByRole('button',{name:'Refresh hostnames and IP addresses'}).click();await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();await expect(page.locator('.fleet-identity-name')).toHaveCount(0);await clean(page);
 });
}catch(error){fatal=true;console.log('Fleet fixture setup failed:',String(error).slice(0,400));}
finally{if(context)await context.close();await stop();if(browser)await browser.close();const report={sourceSha,createdAt:new Date().toISOString(),scope:'Compiled React and authenticated real operator/store loopback fixture; invented metadata only',runtimeErrorCount,secretsExported:false,realTelemetryExported:false,collectorExecuted:false,consentFilesWritten:false,installerExecuted:false,userVmAccessed:false,results,summary:{passed:results.filter(r=>r.status==='PASS').length,failed:results.filter(r=>r.status==='FAIL').length,setupFailure:fatal}};await fs.writeFile(path.join(out,'fleet-identity-browser-results.json'),JSON.stringify(report,null,2));await fs.writeFile(path.join(out,'fleet-identity-browser-manifest.json'),JSON.stringify({sourceSha,screenshots},null,2));await fs.rm(temporary,{recursive:true,force:true});process.exitCode=fatal||runtimeErrorCount||results.some(r=>r.status==='FAIL')?1:0;}
