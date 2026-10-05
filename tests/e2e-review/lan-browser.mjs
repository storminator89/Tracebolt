/** Browser acceptance of the real operator handler's explicit HTTP-test profile.
 * Loopback only. The awaiting-device contract and password are synthetic. No
 * persistent credential, external provider, TLS bypass or real telemetry.
 */
import {createRequire} from 'node:module';
import {spawn,execFileSync} from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {chromium,expect}=require('@playwright/test');
const out=path.join(root,'artifacts/review');await fs.mkdir(out,{recursive:true});
const temporary=await fs.mkdtemp(path.join(os.tmpdir(),'tracebolt-lan-browser-'));
const sourceSha=process.env.TRACEBOLT_SOURCE_SHA||null;
const base=`http://127.0.0.1:${Number(process.env.LAN_REVIEW_PORT||19886)}`;
const password='TRACEBOLT_BROWSER_FIXTURE_NOT_A_REAL_PASSWORD';
const fakeKey='TRACEBOLT_BROWSER_FIXTURE_NOT_A_REAL_API_KEY';
const results=[],screenshots=[];let browser,server,context,currentTest='',runtimeErrorCount=0,fatal=false;
async function stop(){if(server&&server.exitCode===null){const end=new Promise(r=>server.once('exit',r));server.kill('SIGTERM');await end;}server=null;}
async function start(ttl='60s'){
 const dir=await fs.mkdtemp(path.join(temporary,'state-'));
 server=spawn(path.join(temporary,'lanfixture'),['--listen',new URL(base).host,'--db',path.join(dir,'app.db'),'--web',path.join(root,'web/dist'),'--fixture',path.join(root,'docs/lan-api-examples.json'),'--ttl',ttl],{cwd:root,stdio:'ignore'});
 for(let n=0;n<80;n++){if(server.exitCode!==null)throw new Error('FIXTURE_EXITED');try{if((await fetch(`${base}/api/auth/session`)).ok)return;}catch{}await new Promise(r=>setTimeout(r,100));}throw new Error('FIXTURE_NOT_READY');
}
async function pageAt(route='/overview',viewport={width:1440,height:1000}){context=await browser.newContext({viewport,locale:'en-GB'});const page=await context.newPage();page.on('pageerror',()=>runtimeErrorCount++);await page.goto(`${base}/#${route}`);return page;}
async function login(page){await page.getByLabel('Operator password',{exact:true}).fill(password);await page.getByRole('button',{name:'Sign in',exact:true}).click();await expect(page.locator('.app-shell')).toBeVisible();}
async function check(name,run,ttl='60s'){
 currentTest=name;const begin=Date.now();try{await start(ttl);await run();results.push({name,status:'PASS',durationMs:Date.now()-begin});console.log(`PASS ${name}`);}catch{results.push({name,status:'FAIL',durationMs:Date.now()-begin,error:'Assertion failed; raw state and credential-bearing diagnostics intentionally withheld.'});console.log(`FAIL ${name}`);}finally{if(context)await context.close();context=null;await stop();}
}
async function shot(page,name){await page.screenshot({path:path.join(out,`${name}.png`),fullPage:false,animations:'disabled'});screenshots.push({file:`${name}.png`,sourceSha,publicSafe:true,fullPage:false,viewport:page.viewportSize(),locale:await page.locator('html').getAttribute('lang'),fixtureDisclosure:'Loopback HTTP-test UI; synthetic awaiting-agent contract; no deployed endpoint or trusted TLS browser validation',test:currentTest});}
async function cleanStorage(page){const value=await page.evaluate(()=>JSON.stringify({local:{...localStorage},session:{...sessionStorage}}));expect(value.includes(password)||value.includes(fakeKey)).toBe(false);const cookies=await context.cookies();for(const cookie of cookies)expect(value.includes(cookie.value)).toBe(false);}
try {
 execFileSync(process.env.GO_BIN||'go',['build','-buildvcs=false','-o',path.join(temporary,'lanfixture'),'./tests/e2e-review/lanfixture'],{cwd:root,stdio:'inherit'});
 const options={headless:true,args:['--no-sandbox'],env:{...process.env,HOME:temporary,XDG_CONFIG_HOME:temporary,XDG_CACHE_HOME:temporary}};if(process.env.CHROMIUM_PATH)options.executablePath=process.env.CHROMIUM_PATH;browser=await chromium.launch(options);
 await check('Real HTTP-test login defaults to English, blocks protected data and retains a localized transport warning',async()=>{
  context=await browser.newContext({viewport:{width:1440,height:1000}});const page=await context.newPage();page.on('pageerror',()=>runtimeErrorCount++);let protectedReads=0;page.on('request',r=>{if(/\/api\/(overview|devices|cases|capabilities|ai\/)/.test(r.url()))protectedReads++;});await page.goto(`${base}/#/overview`);
  await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();await expect(page.locator('html')).toHaveAttribute('lang','en');await expect(page.getByRole('note')).toContainText('Unencrypted LAN test');await expect(page.getByRole('note')).toContainText('Passwords and data');expect(protectedReads).toBe(0);await expect(page.locator('.app-shell')).toHaveCount(0);await shot(page,'synthetic-http-test-login-desktop-en');
  await page.getByLabel('Language').selectOption('de');await expect(page.getByRole('heading',{name:'Anmelden',exact:true})).toBeVisible();await expect(page.getByRole('note')).toContainText('Unverschlüsselter LAN-Test');expect(protectedReads).toBe(0);
 });
 await check('Malformed or unavailable bootstrap fails closed and explicit retry recovers without fake access',async()=>{
  context=await browser.newContext();const page=await context.newPage();page.on('pageerror',()=>runtimeErrorCount++);let reads=0;page.on('request',r=>{if(r.url().endsWith('/api/overview'))reads++;});await page.route('**/api/auth/session',route=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({mode:'development',authenticationRequired:false,authenticated:false})}));await page.goto(base);await expect(page.getByRole('heading',{name:'Access unavailable'})).toBeVisible();expect(reads).toBe(0);await expect(page.locator('.app-shell')).toHaveCount(0);await page.unroute('**/api/auth/session');await page.getByRole('button',{name:'Check status again'}).click();await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();expect(reads).toBe(0);
 });
 await check('Actual password rejection and repeated login clear the draft, use one request and keep session cookies out of script storage',async()=>{
  const page=await pageAt();await page.getByLabel('Operator password').fill('WRONG_SYNTHETIC_PASSWORD');await page.getByRole('button',{name:'Sign in',exact:true}).click();await expect(page.getByRole('alert')).toContainText('Check your password');await expect(page.getByLabel('Operator password')).toHaveValue('');
  let release;const gate=new Promise(r=>release=r);let reached;const intercepted=new Promise(r=>reached=r);let posts=0;await page.route('**/api/auth/login',async route=>{posts++;reached();await gate;await route.continue();});await page.getByLabel('Operator password').fill(password);await page.getByRole('button',{name:'Sign in',exact:true}).dblclick();await intercepted;await expect(page.getByLabel('Operator password')).toHaveValue('');await expect(page.getByRole('button',{name:'Sign in',exact:true})).toBeDisabled();expect(posts).toBe(1);release();await expect(page.locator('.app-shell')).toBeVisible();await page.unroute('**/api/auth/login');
  const cookies=await context.cookies();const session=cookies.find(c=>c.name==='tracebolt-http-test-session');expect(Boolean(session)).toBe(true);expect(session.httpOnly).toBe(true);expect(session.sameSite).toBe('Strict');expect(session.secure).toBe(false);expect((await page.evaluate(()=>document.cookie)).includes(session.name)).toBe(false);await cleanStorage(page);await expect(page.getByRole('note')).toContainText('Unencrypted LAN test');
 });
 await check('Authenticated LAN contract shows unknown awaiting-agent data with no demo fleet or healthy empty-state claim',async()=>{
  const page=await pageAt('/devices');await login(page);await expect(page.locator('.device-table tbody tr')).toHaveCount(1);await expect(page.locator('.inventory-tabs')).toContainText('LAN agents');await expect(page.locator('.inventory-tabs')).not.toContainText('Demo devices');await expect(page.locator('.demo-banner')).toContainText('LAN');await expect(page.locator('.demo-banner')).not.toContainText('DEMO');await expect(page.locator('.device-table').getByRole('columnheader',{name:'Overall health',exact:true})).toBeVisible();await expect(page.locator('.device-table .status')).toHaveText('Not assessed');await expect(page.locator('.device-table .status')).toHaveAttribute('title','Overall health has not been assessed. The last observation time is shown separately.');
  await page.getByRole('button',{name:'Open details: Fixture workstation'}).click();await expect(page.getByRole('region',{name:'Device Fixture workstation',exact:true})).toContainText('Time unknown');await page.getByRole('tab',{name:'Details',exact:true}).click();await expect(page.getByRole('region',{name:'Device Fixture workstation',exact:true})).toContainText('Approved LAN agent');await expect(page.locator('.device-metric-card .unavailable')).toHaveCount(3);await expect(page.getByRole('region',{name:'Device Fixture workstation',exact:true})).not.toContainText('01.01.1');await page.getByRole('button',{name:'Back to devices',exact:true}).click();await page.goto(`${base}/#/overview`);await expect(page.locator('.attention-panel')).toContainText('No automated device assessment yet');await shot(page,'synthetic-http-test-awaiting-desktop-en');
 });
 await check('Real CSRF-protected logout removes private content and rejects later protected API reads',async()=>{
  const page=await pageAt('/settings');await login(page);let logoutRequest;page.on('request',r=>{if(r.url().endsWith('/api/auth/logout'))logoutRequest=r;});await page.getByRole('button',{name:'Sign out',exact:true}).click();await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();expect(logoutRequest.method()).toBe('POST');expect(Boolean((await logoutRequest.allHeaders())['x-csrf-token'])).toBe(true);await expect(page.locator('.app-shell')).toHaveCount(0);expect((await context.request.get(`${base}/api/overview`)).status()).toBe(401);await page.reload();await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();await cleanStorage(page);
 });
 await check('Actual short session expiry locks the browser and backend using server-relative TTL',async()=>{
  const page=await pageAt();await login(page);await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible({timeout:8000});await expect(page.getByRole('status')).toContainText('Session expired');await expect(page.locator('.app-shell')).toHaveCount(0);expect((await context.request.get(`${base}/api/overview`)).status()).toBe(401);
 },'3s');
 await check('Protected 401 unmounts provider drafts and a fresh login never replays the interrupted write',async()=>{
  const page=await pageAt('/settings');await login(page);await page.getByLabel('AI base URL').fill('http://127.0.0.1:19999/v1');await page.getByLabel('AI model').fill('fixture-model');await page.getByLabel('AI API key').fill(fakeKey);let writes=0;await page.route('**/api/ai/config',route=>{if(route.request().method()==='POST'){writes++;return route.fulfill({status:401,contentType:'application/json',body:JSON.stringify({error:{code:'authentication_required',message:'controlled expiry'}})});}return route.continue();});await page.getByRole('button',{name:'Save configuration',exact:true}).click();await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();await expect(page.locator('.app-shell')).toHaveCount(0);expect(writes).toBe(1);await login(page);await expect(page.getByLabel('AI API key')).toHaveValue('');expect(writes).toBe(1);await cleanStorage(page);
 });
 await check('Unconfirmed logout stays locked across reload and explicit retry performs real logout',async()=>{
  const page=await pageAt();await login(page);await page.route('**/api/auth/logout',route=>route.abort('failed'));await page.getByRole('button',{name:'Sign out',exact:true}).click();await expect(page.getByRole('button',{name:'Sign out again'})).toBeVisible();await expect(page.locator('.app-shell')).toHaveCount(0);await page.reload();await expect(page.getByRole('button',{name:'Sign out again'})).toBeVisible();await expect(page.locator('.app-shell')).toHaveCount(0);await page.unroute('**/api/auth/logout');await page.getByRole('button',{name:'Sign out again'}).click();await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();expect((await context.request.get(`${base}/api/overview`)).status()).toBe(401);await cleanStorage(page);
 });
 await check('Logout from another tab clears its private view and prevents authenticated restoration',async()=>{
  const page=await pageAt();await login(page);const other=await context.newPage();other.on('pageerror',()=>runtimeErrorCount++);await other.goto(`${base}/#/devices`);await expect(other.locator('.app-shell')).toBeVisible();await other.getByRole('button',{name:'Sign out',exact:true}).click();await expect(other.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();await expect(page.locator('.app-shell')).toHaveCount(0);await page.bringToFront();await page.reload();await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();
 });
 await check('Mobile HTTP-test login and shell keep the warning visible with no horizontal overflow',async()=>{
  const page=await pageAt('/devices',{width:390,height:844});await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();await shot(page,'synthetic-http-test-login-mobile-en');await login(page);await expect(page.getByRole('note')).toBeInViewport();await expect(page.getByRole('note')).toContainText('Passwords and data');expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth&&document.body.scrollWidth<=innerWidth)).toBe(true);await page.getByRole('button',{name:'Open navigation'}).click();await expect(page.getByRole('button',{name:'Sign out',exact:true})).toBeVisible();await page.getByRole('button',{name:'Sign out',exact:true}).click();await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();
 });
} catch {fatal=true;console.log('LAN browser setup failed; raw diagnostics intentionally withheld.');}
finally {
 if(context)await context.close();await stop();if(browser)await browser.close();
 const report={sourceSha,createdAt:new Date().toISOString(),scope:'Real LAN operator HTTP-test handler on loopback with synthetic contract data; not the production CLI, real enrollment or trusted TLS browser acceptance',faultInjection:'Explicit malformed bootstrap, protected 401, and interrupted logout',credentialMaterial:'Disposable known fixture only; never persisted or exported',screenshots:'Viewport-only synthetic contract/login screens',runtimeErrorCount,results,summary:{passed:results.filter(r=>r.status==='PASS').length,failed:results.filter(r=>r.status==='FAIL').length,setupFailure:fatal}};
 await fs.writeFile(path.join(out,'lan-browser-results.json'),JSON.stringify(report,null,2));await fs.writeFile(path.join(out,'lan-browser-manifest.json'),JSON.stringify({sourceSha,screenshots},null,2));await fs.rm(temporary,{recursive:true,force:true});process.exitCode=fatal||runtimeErrorCount||results.some(r=>r.status==='FAIL')?1:0;
}
