/** Independent local-only acceptance checks.
 * Run from repository root: node tests/e2e-review/run.mjs
 * Uses the built web/dist, compiles a disposable manager, and creates a unique
 * temporary SQLite database. No production state or external origin is used.
 */
import { createRequire } from 'node:module';
import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runAIReview } from './ai-scenarios.mjs';
import { runShellReview } from './shell-scenarios.mjs';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const require = createRequire(path.join(root, 'web/package.json'));
const { chromium, expect } = require('@playwright/test');
const out = path.join(root, 'artifacts/review');
await fs.mkdir(out, { recursive: true });
for (const file of await fs.readdir(out)) if (file.endsWith('.png') || ['results.json','screenshot-manifest.json'].includes(file)) await fs.rm(path.join(out,file),{force:true});
const sourceSha = process.env.TRACEBOLT_SOURCE_SHA || null;
const screenshots = [];
const sanitize = value => String(value).replaceAll(root, '<repository>').replaceAll(os.homedir(), '<home>').replace(/\/tmp\/(tracebolt-ui-review|playwright_[^ /]+)[^ /]*/g,'<temporary-directory>');
const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'tracebolt-ui-review-'));
const managerPath = path.join(temp, 'manager');
execFileSync(process.env.GO_BIN || 'go', ['build', '-buildvcs=false', '-o', managerPath, './cmd/manager'], { cwd: root, stdio: 'inherit' });
const port = Number(process.env.REVIEW_PORT || 19879);
const base = `http://127.0.0.1:${port}`;
const log = await fs.open(path.join(out, 'manager.log'), 'w');
let manager;
function start() { manager = spawn(managerPath, ['--port', String(port), '--db', path.join(temp, 'review.db'), '--web', path.join(root, 'web/dist')], { cwd: root, stdio: ['ignore', log.fd, log.fd] }); }
async function ready() { for (let i=0;i<60;i++) { if (manager.exitCode !== null) throw new Error(`manager exited ${manager.exitCode}`); try { if ((await fetch(`${base}/api/health`)).ok) return; } catch {} await new Promise(r=>setTimeout(r,100)); } throw new Error('Manager not ready'); }
async function stop() { if (!manager || manager.exitCode !== null) return; const done = new Promise(r=>manager.once('exit',r)); manager.kill('SIGTERM'); await done; }
start(); await ready();
let browser;
try {
 const launchOptions = { headless: true, args: ['--no-sandbox'], env: { ...process.env, HOME: temp, XDG_CONFIG_HOME: temp, XDG_CACHE_HOME: temp } };
 if (process.env.CHROMIUM_PATH) launchOptions.executablePath = process.env.CHROMIUM_PATH;
 browser = await chromium.launch(launchOptions);
} catch (error) {
 await fs.writeFile(path.join(out,'results.json'),JSON.stringify({createdAt:new Date().toISOString(),status:'BLOCKED',stage:'browser-launch',sourceSha,error:sanitize(error.message.split('\n')[0]),results:[],summary:{passed:0,failed:0,notRun:'all browser scenarios'}},null,2));
 await stop(); await log.close(); await fs.rm(temp,{recursive:true,force:true}); throw error;
}
const results = [];
let data = await (await fetch(`${base}/api/overview`)).json();
const device = data.devices.find(d=>d.id==='demo-win-01');
const caseItem = data.cases.find(c=>c.deviceId===device.id);
const nextCase = data.cases.find(c=>c.id!==caseItem.id);
const noteText = '<img src=x onerror="window.__reviewXss=1"> Review: literal evidence, never markup.';
const allPages = new Set();
const runtimeErrors = [];
async function pageAt(hash='/overview', viewport={width:1440,height:1000}, extra={}) {
 const {reviewLocale='de',...contextOptions}=extra;
 const context = await browser.newContext({ viewport, locale:'de-DE', ...contextOptions });
 if(reviewLocale) await context.addInitScript(value=>localStorage.setItem('tracebolt.locale',value),reviewLocale);
 const page = await context.newPage(); allPages.add(context);
 page.on('pageerror', error=>runtimeErrors.push({test:currentTest, message:error.message}));
 await page.goto(`${base}/#${hash}`); return page;
}
let currentTest='';
async function test(name, run) { currentTest=name; const begun=Date.now(); try { await run(); results.push({name, status:'PASS', durationMs:Date.now()-begun}); console.log(`PASS ${name}`); } catch(error) { results.push({name,status:'FAIL',error:sanitize(name.startsWith('AI ') ? error.message.split('\n')[0] : error.message),durationMs:Date.now()-begun}); console.log(`FAIL ${name}: ${error.message.split('\n')[0]}`); } finally { for(const context of allPages) await context.close(); allPages.clear(); } }
async function loaded(page) { await expect(page.locator('.page-footer')).toBeVisible(); }
async function shot(page,name,section=null) {
 const fullPage=false,dialog=await page.getByRole('dialog').count()>0;
 if(!dialog) {
  await page.locator('.main-content').evaluate(el=>el.scrollTo({top:0,left:0,behavior:'instant'})).catch(()=>{});
  const target=section || (name.includes('ai-fixture-case')?'.ai-analysis-panel':null);
  if(target) await page.locator(target).evaluate(el=>el.scrollIntoView({block:'start',behavior:'instant'}));
 }
 await page.screenshot({path:path.join(out,`${name}.png`),fullPage,animations:'disabled'});
 screenshots.push({fullPage,file:`${name}.png`,sourceSha,publicSafe:name.startsWith('synthetic-'),fixtureDisclosure:name.includes('ai-fixture')?'Testanbieter / keine reale Modellanalyse':null,viewport:page.viewportSize(),section:section || (name.includes('ai-fixture-case')?'AI analysis':dialog?'dialog':'top'),contentScrollTop:await page.locator('.main-content').evaluate(el=>el.scrollTop).catch(()=>null),theme:await page.locator('html').getAttribute('data-theme'),locale:await page.locator('html').getAttribute('lang'),test:currentTest});
}
async function noOverflow(page) { const size=await page.evaluate(()=>({view:innerWidth,body:document.body.scrollWidth,html:document.documentElement.scrollWidth})); expect(size.body).toBeLessThanOrEqual(size.view+1); expect(size.html).toBeLessThanOrEqual(size.view+1); }
async function rows(page) { return page.locator('.device-table tbody tr'); }
try {
 await test('Desktop light overview: real API, provenance, no layout overflow', async()=>{
  const page=await pageAt(); await loaded(page);
  await expect(page.getByRole('heading',{name:'Übersicht',exact:true,level:1})).toBeVisible();
  await expect(page.locator('.demo-banner')).toContainText('DEMO + LOKAL');
  await expect(page.locator('.summary-strip button').first()).toContainText(String(data.devices.length));
  await noOverflow(page); await shot(page,'desktop-overview-light');
 });
 await test('Dark theme persists through reload', async()=>{
  const page=await pageAt(); await loaded(page);
  await page.getByRole('button',{name:'Dunkles Design aktivieren'}).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme','dark'); await page.reload(); await loaded(page);
  await expect(page.locator('html')).toHaveAttribute('data-theme','dark'); await shot(page,'desktop-overview-dark');
 });
 await test('Inventory search, OS/status filters, empty reset and sorting', async()=>{
  const page=await pageAt('/devices'); await loaded(page); await expect(await rows(page)).toHaveCount(data.devices.length);
  const search=page.getByRole('textbox',{name:'Geräte durchsuchen'});
  await search.fill('BER-DC-01'); await expect(await rows(page)).toHaveCount(1); await expect((await rows(page)).first()).toContainText('BER-DC-01');
  await page.getByRole('button',{name:'Suche leeren'}).click();
  for(const platform of ['windows','macos','linux']) { await page.getByLabel('Nach Betriebssystem filtern').selectOption(platform); await expect(await rows(page)).toHaveCount(data.devices.filter(d=>d.platform===platform).length); }
  await page.getByLabel('Nach Betriebssystem filtern').selectOption('all');
  await page.getByLabel('Nach Status filtern').selectOption('stale'); await expect(await rows(page)).toHaveCount(1); await expect((await rows(page)).first()).toContainText('Veraltet'); await expect((await rows(page)).first().locator('.unavailable')).toHaveCount(3);
  await page.getByLabel('Nach Status filtern').selectOption('all');
  await page.getByLabel('Geräte sortieren').selectOption('name');
  expect(await page.locator('.device-name-button strong').allTextContents()).toEqual([...data.devices].sort((a,b)=>a.name.localeCompare(b.name)).map(d=>d.name));
  await page.getByLabel('Geräte sortieren').selectOption('seen');
  expect(await page.locator('.device-name-button strong').allTextContents()).toEqual([...data.devices].sort((a,b)=>Date.parse(b.lastSeen)-Date.parse(a.lastSeen)).map(d=>d.name));
  await search.fill('not-a-real-device-9ae9'); await expect(page.getByRole('heading',{name:'Keine passenden Geräte'})).toBeVisible(); await expect(page.getByRole('button',{name:'CSV exportieren'})).toBeDisabled(); await shot(page,'desktop-inventory-empty');
  await page.getByRole('button',{name:'Filter zurücksetzen'}).click(); await expect(await rows(page)).toHaveCount(data.devices.length); await shot(page,'desktop-inventory-light');
 });
 await test('Attention summary count agrees with clicked inventory', async()=>{
  const page=await pageAt(); await loaded(page); await page.locator('.summary-strip button').filter({hasText:'Aufmerksamkeit'}).click();
  await expect(await rows(page)).toHaveCount(data.stats.attentionDevices);
 });
 await test('Saved filtered inventory can be restored after reload', async()=>{
  const page=await pageAt('/devices'); await loaded(page); await page.getByLabel('Nach Betriebssystem filtern').selectOption('macos'); await page.getByRole('button',{name:'Ansicht speichern'}).click();
  await page.reload(); await loaded(page); await page.getByRole('button',{name:'Gespeicherte Ansicht'}).click(); await expect(page.getByLabel('Nach Betriebssystem filtern')).toHaveValue('macos'); await expect(await rows(page)).toHaveCount(2);
 });
 await test('Source filter and unknown data never become healthy', async()=>{
  const page=await pageAt('/devices'); await loaded(page); await page.locator('.inventory-tabs button').filter({hasText:'Lokale Quellen'}).click(); await expect(await rows(page)).toHaveCount(1); await expect((await rows(page)).first()).toContainText('Lokal');
  const sandbox=data.devices.find(d=>!d.synthetic); expect(sandbox.status).toBe('unknown'); await expect((await rows(page)).first()).toContainText('Unbekannt');
  await page.locator('.device-name-button').click(); await page.getByRole('tab',{name:'Details',exact:true}).click(); await expect(page.locator('.device-page')).toContainText('Lokale Linux-Umgebung. Messwerte werden nur angezeigt, wenn ein Collector sie geliefert hat.'); await shot(page,'sandbox-provenance');
 });
 await test('Device details → evidence → case, history Back/Forward', async()=>{
  const page=await pageAt('/devices'); await loaded(page);
  await page.getByRole('button',{name:`${device.name}: Details öffnen`}).click(); await expect(page.getByRole('region',{name:`Gerät ${device.name}`,exact:true})).toBeVisible();
  await page.getByRole('tab',{name:'Details',exact:true}).click(); await expect(page.locator('.device-page')).toContainText('Synthetisches Beispielgerät');
  await page.getByRole('tab',{name:/Belege/}).click(); await page.locator('.device-page .evidence-card summary').first().click(); await expect(page.locator('.device-page .evidence-content').first()).toBeVisible(); await shot(page,'desktop-device-evidence');
  await page.getByRole('tab',{name:'Übersicht',exact:true}).click(); await page.locator('.linked-case').first().click(); await expect(page.locator('.case-detail-header h1')).toHaveText(caseItem.title);
  await page.locator('.evidence-card summary').first().click(); await expect(page.locator('.evidence-content').first()).toBeVisible(); await shot(page,'desktop-case-evidence');
  await page.goBack(); await expect(page.getByRole('region',{name:`Gerät ${device.name}`,exact:true})).toBeVisible(); await page.goForward(); await expect(page.locator('.case-detail-header h1')).toHaveText(caseItem.title);
 });
 await test('Device page keyboard navigation, Escape and Back return focus to inventory', async()=>{
  const page=await pageAt('/devices'); await loaded(page); const opener=page.getByRole('button',{name:`${device.name}: Details öffnen`}); await opener.click();
  const detail=page.getByRole('region',{name:`Gerät ${device.name}`,exact:true}); await expect(detail).toBeFocused();
  await expect(page.getByRole('dialog')).toHaveCount(0); await expect(page.locator('.inventory-panel,.enrollment-panel')).toHaveCount(0);
  await page.getByRole('tab',{name:'Details',exact:true}).click();await expect(page.locator('.device-technical')).not.toHaveAttribute('open','');const technical=page.locator('.device-technical summary');await technical.focus();await page.keyboard.press('Enter');await expect(page.locator('.device-technical')).toHaveAttribute('open','');await expect(page.locator('.device-technical .metadata-grid')).toBeVisible();await page.keyboard.press('Enter');await expect(page.locator('.device-technical')).not.toHaveAttribute('open','');await detail.focus();
  await page.keyboard.press('Shift+Tab'); expect(await page.evaluate(()=>document.activeElement?.closest('.device-page')===null)).toBe(true);
  await detail.focus(); await page.keyboard.press('Tab'); await expect(page.getByRole('button',{name:'Zurück zu Geräten',exact:true})).toBeFocused();
  await page.keyboard.press('Escape'); await expect(detail).toHaveCount(0); await expect(page).toHaveURL(base+'/#/devices'); await expect(page.locator('main')).toBeFocused(); await expect(opener).toBeVisible();
  await opener.click(); await page.getByRole('button',{name:'Zurück zu Geräten',exact:true}).click(); await expect(detail).toHaveCount(0); await expect(page.locator('main')).toBeFocused();
  await page.goBack(); await expect(detail).toBeFocused(); await page.goForward(); await expect(detail).toHaveCount(0); await expect(page.locator('main')).toBeFocused();
  await page.keyboard.press('Control+k'); await expect(page.getByRole('textbox',{name:'Geräte durchsuchen'})).toBeFocused();
 });
 await test('Help modal owns focus, shortcuts and dismissal without losing the device page', async()=>{
  const page=await pageAt('/devices'); await loaded(page); await page.getByRole('button',{name:`${device.name}: Details öffnen`}).click();
  const detail=page.getByRole('region',{name:`Gerät ${device.name}`,exact:true}); await expect(detail).toBeFocused();
  await page.keyboard.press('?'); const help=page.getByRole('dialog',{name:'Tastenkürzel',exact:true}); await expect(help).toBeVisible(); await expect(page.getByRole('dialog')).toHaveCount(1);
  await page.keyboard.press('Shift+Tab'); expect(await page.evaluate(()=>document.activeElement?.closest('[role=dialog]')!==null)).toBe(true);
  for(let i=0;i<16;i++) await page.keyboard.press('Tab'); expect(await page.evaluate(()=>document.activeElement?.closest('[role=dialog]')!==null)).toBe(true);
  await page.keyboard.press('?'); await page.keyboard.press('Control+k'); await expect(help).toBeVisible(); await expect(page.getByRole('dialog')).toHaveCount(1); await expect(page).toHaveURL(base+'/#/devices/'+device.id);
  await page.keyboard.press('Escape'); await expect(help).toHaveCount(0); await expect(detail).toBeVisible(); await expect(page).toHaveURL(base+'/#/devices/'+device.id);
  await page.keyboard.press('?'); await expect(help).toBeVisible(); await page.locator('.dialog-backdrop').click({position:{x:10,y:10}}); await expect(help).toHaveCount(0); await expect(detail).toBeVisible();
  await page.keyboard.press('Escape'); await expect(detail).toHaveCount(0); await expect(page.locator('main')).toBeFocused();
 });
 for(const [label,viewport,mobile] of [['desktop',{width:1440,height:1000},false],['mobile',{width:390,height:844},true]]) for(const theme of ['light','dark']) await test(`Synthetic-only gallery ${label} ${theme}`, async()=>{
  const page=await pageAt('/devices',viewport,{isMobile:mobile,hasTouch:mobile,reviewLocale:null}); await loaded(page);
  if(theme==='dark') await page.getByRole('button',{name:'Switch to dark theme'}).click();
  await page.getByLabel('Filter by operating system').selectOption('windows'); await expect(await rows(page)).toHaveCount(3);
  // All displayed inventory rows are Windows demo fixtures. Never publish the
  // overview or sandbox screenshots, which can contain the real local sample.
  await shot(page,`synthetic-inventory-${label}-${theme}`);
  await page.getByRole('button',{name:`Open details: ${device.name}`}).click(); await expect(page.getByRole('region',{name:`Device ${device.name}`,exact:true})).toBeVisible();
  await page.getByRole('tab',{name:/Evidence/}).click(); await page.locator('.device-page .evidence-card summary').first().click(); await shot(page,`synthetic-device-${label}-${theme}`);
  await page.getByRole('tab',{name:'Overview',exact:true}).click(); await page.locator('.linked-case').first().click(); await expect(page.locator('.case-detail-header h1')).toHaveText(caseItem.title);
  await page.locator('.evidence-card summary').first().click(); await shot(page,`synthetic-case-${label}-${theme}`);
 });
 await test('Notes: real API, literal XSS payload, single write on repeated click, reload persistence', async()=>{
  const page=await pageAt(`/cases/${caseItem.id}`); await expect(page.locator('.case-detail-header h1')).toHaveText(caseItem.title);
  let posts=0; page.on('request',r=>{if(r.method()==='POST' && r.url().endsWith('/notes')) posts++;});
  await page.getByRole('textbox',{name:'Notiz zur Untersuchung'}).fill(noteText); await page.getByRole('button',{name:'Notiz speichern'}).dblclick(); await expect(page.locator('.success-banner')).toContainText('Notiz lokal gespeichert'); expect(posts).toBe(1);
  await expect(page.locator('.notes-list')).toContainText(noteText); expect(await page.evaluate(()=>window.__reviewXss)).toBeUndefined(); expect(await page.locator('.notes-list img').count()).toBe(0);
  await page.reload(); await expect(page.locator('.notes-list')).toContainText(noteText); const current=await (await fetch(`${base}/api/cases/${caseItem.id}`)).json(); expect(current.notes.filter(n=>n.text===noteText)).toHaveLength(1); await shot(page,'desktop-case-note-persisted');
 });
 await test('Status transitions persist through reload and manager restart', async()=>{
  const page=await pageAt(`/cases/${caseItem.id}`); await expect(page.getByRole('button',{name:'Untersuchung beginnen'})).toBeVisible(); await page.getByRole('button',{name:'Untersuchung beginnen'}).dblclick(); await expect(page.locator('.case-detail-header .case-status')).toHaveText('In Untersuchung');
  await page.getByRole('button',{name:'Fall abschließen'}).click(); await expect(page.locator('.case-detail-header .case-status')).toHaveText('Abgeschlossen'); await page.reload(); await expect(page.locator('.case-detail-header .case-status')).toHaveText('Abgeschlossen');
  await stop(); start(); await ready(); await page.reload(); await expect(page.locator('.case-detail-header .case-status')).toHaveText('Abgeschlossen'); await expect(page.locator('.notes-list')).toContainText(noteText);
  await page.getByRole('button',{name:'Wieder öffnen'}).click(); await expect(page.locator('.case-detail-header .case-status')).toHaveText('Offen');
 });
 await test('Failed note mutation preserves typed text and exposes retryable error', async()=>{
  const page=await pageAt(`/cases/${caseItem.id}`); await expect(page.getByRole('textbox',{name:'Notiz zur Untersuchung'})).toBeVisible();
  await page.route('**/api/cases/*/notes',route=>route.fulfill({status:500,contentType:'application/json',body:JSON.stringify({error:{message:'Controlled review failure'}})}));
  await page.getByRole('textbox',{name:'Notiz zur Untersuchung'}).fill('Unsaved review note'); await page.getByRole('button',{name:'Notiz speichern'}).click(); await expect(page.getByRole('alert')).toContainText('Controlled review failure'); await expect(page.getByRole('textbox',{name:'Notiz zur Untersuchung'})).toHaveValue('Unsaved review note'); await expect(page.getByRole('button',{name:'Notiz speichern'})).toBeEnabled();
 });
 await test('Changing case during delayed note save cannot replace new case content', async()=>{
  const page=await pageAt(`/cases/${caseItem.id}`); await expect(page.getByRole('textbox',{name:'Notiz zur Untersuchung'})).toBeVisible();
  let release; const gate=new Promise(r=>release=r); let intercepted; const reached=new Promise(r=>intercepted=r);
  await page.route('**/api/cases/*/notes',async route=>{ const response=await route.fetch(); intercepted(); await gate; await route.fulfill({response}); });
  await page.getByRole('textbox',{name:'Notiz zur Untersuchung'}).fill('Delayed save review note'); await page.getByRole('button',{name:'Notiz speichern'}).click(); await reached;
  await page.evaluate(id=>location.hash=`/cases/${id}`,nextCase.id); await expect(page.locator('.case-detail-header h1')).toHaveText(nextCase.title); release(); await page.waitForTimeout(350);
  await expect(page.locator('.case-detail-header h1')).toHaveText(nextCase.title); await expect(page).toHaveURL(new RegExp(nextCase.id));
 });
 await test('First-load API failure shows explicit error without fake data; retry recovers', async()=>{
  const context=await browser.newContext({viewport:{width:1440,height:1000}}); allPages.add(context); await context.addInitScript(()=>localStorage.setItem('tracebolt.locale','de')); const page=await context.newPage(); page.on('pageerror',error=>runtimeErrors.push({test:currentTest,message:error.message})); await page.route('**/api/overview',route=>route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({error:{message:'Controlled manager unavailable'}})}));
  await page.goto(`${base}/#/overview`); await expect(page.getByRole('alert')).toContainText('Keine Verbindung'); await expect(page.getByRole('alert')).toContainText('keine Ersatz-Demodaten'); await expect(page.locator('.device-table')).toHaveCount(0); await shot(page,'desktop-api-error');
  await page.unroute('**/api/overview'); await page.getByRole('button',{name:'Erneut versuchen'}).click(); await loaded(page);
 });
 await test('Loading state is visible and refreshing error keeps stale data labeled', async()=>{
  const context=await browser.newContext({viewport:{width:1440,height:1000}}); allPages.add(context); await context.addInitScript(()=>localStorage.setItem('tracebolt.locale','de')); const page=await context.newPage(); page.on('pageerror',error=>runtimeErrors.push({test:currentTest,message:error.message}));
  let release; const gate=new Promise(r=>release=r); await page.route('**/api/overview',async route=>{await gate; await route.continue();}); await page.goto(`${base}/#/overview`); await expect(page.locator('.initial-loading')).toBeVisible(); await expect(page.locator('.initial-loading').getByRole('status')).toContainText('geladen'); await shot(page,'desktop-loading'); release(); await loaded(page); await page.unroute('**/api/overview');
  await page.route('**/api/overview',route=>route.abort('failed')); await page.getByRole('button',{name:'Aktualisieren',exact:true}).click(); await expect(page.getByRole('alert')).toContainText('letzten erfolgreichen Abruf'); await expect(page.locator('.device-table')).toBeVisible(); await expect(page.locator('.page-footer')).toContainText('Letzter erfolgreicher Abruf');
 });
 await test('Unknown device and case links show safe recoverable error', async()=>{
  const page=await pageAt('/devices/does-not-exist'); await expect(page.getByRole('alert')).toContainText('Gerät nicht verfügbar'); await page.getByRole('button',{name:'Zurück zu Geräten',exact:true}).click(); await expect(page.locator('.device-page')).toHaveCount(0); await expect(page.locator('main')).toBeFocused();
  await page.goto(`${base}/#/cases/does-not-exist`); await expect(page.getByRole('alert')).toContainText('Untersuchung nicht verfügbar'); await page.getByRole('button',{name:'Alle Untersuchungen'}).click(); await expect(page.getByRole('heading',{name:'Untersuchungen',exact:true,level:1})).toBeVisible();
 });
 await test('Malformed percent-encoded route cannot blank the application', async()=>{
  const page=await pageAt('/devices/%E0%A4%A'); await expect(page.locator('.app-shell')).toBeVisible(); await expect(page.getByRole('heading',{name:'Geräte',exact:true,level:1})).toBeVisible();
 });
 await test('Skip link focuses main without changing the active view', async()=>{
  const page=await pageAt('/devices'); await loaded(page); await page.keyboard.press('Tab'); await expect(page.getByRole('link',{name:'Zum Inhalt'})).toBeFocused(); await page.keyboard.press('Enter');
  await expect(page.getByRole('heading',{name:'Geräte',exact:true,level:1})).toBeVisible(); expect(await page.evaluate(()=>document.activeElement?.id)).toBe('main-content');
 });
 for(const theme of ['light','dark']) await test(`Mobile 390px ${theme}: inventory, navigation, case, device page, no overflow`, async()=>{
  const page=await pageAt('/overview',{width:390,height:844},{isMobile:true,hasTouch:true}); await loaded(page); if(theme==='dark') await page.getByRole('button',{name:'Dunkles Design aktivieren'}).click();
  await noOverflow(page); await shot(page,`mobile-overview-${theme}`); await page.getByRole('button',{name:'Menü öffnen'}).click(); await expect(page.locator('.sidebar')).toHaveClass(/is-open/); await shot(page,`mobile-navigation-${theme}`); await page.locator('nav .nav-item').filter({hasText:'Geräte'}).click(); await expect(page.locator('.sidebar')).not.toHaveClass(/is-open/); await expect(page.getByRole('textbox',{name:'Geräte durchsuchen'})).toBeVisible(); await noOverflow(page); await shot(page,`mobile-inventory-${theme}`);
  await page.getByRole('button',{name:`${device.name}: Details öffnen`}).click(); await expect(page.getByRole('region',{name:`Gerät ${device.name}`,exact:true})).toBeVisible(); await noOverflow(page); await shot(page,`mobile-device-${theme}`); await page.locator('.linked-case').first().click(); await expect(page.locator('.case-detail-header h1')).toHaveText(caseItem.title); await noOverflow(page); await shot(page,`mobile-case-${theme}`);
 });
 await test('Mobile primary interaction targets are at least 40×40 CSS px', async()=>{
  const page=await pageAt('/devices',{width:390,height:844},{isMobile:true,hasTouch:true}); await loaded(page);
  const sizes=await page.locator('.mobile-menu,.topbar .icon-button,.device-name-button,.row-open,.filter-toolbar select,.filter-toolbar .button').evaluateAll(elements=>elements.filter(e=>{const r=e.getBoundingClientRect();return r.width && r.height;}).map(e=>({text:e.getAttribute('aria-label')||e.textContent?.trim(),width:e.getBoundingClientRect().width,height:e.getBoundingClientRect().height})));
  const small=sizes.filter(s=>s.width<40||s.height<40); expect(small,JSON.stringify(small)).toEqual([]);
 });
 await test('Settings states capability boundary without claiming native OS support', async()=>{
  const page=await pageAt('/settings'); await loaded(page); await expect(page.getByRole('heading',{name:'Einstellungen',exact:true,level:1})).toBeVisible(); await expect(page.locator('.setting-row').filter({has:page.getByText('Manager',{exact:true})})).toContainText(`127.0.0.1:${port}`); await expect(page.locator('.main-content')).toContainText('Windows'); await expect(page.locator('.main-content')).toContainText('macOS'); await shot(page,'desktop-settings');
 });
 await runShellReview({test,pageAt,loaded,shot,expect,caseItem,cleanCase:data.cases.find(c=>c.deviceId==='demo-linux-01')});
 if(process.env.TRACEBOLT_REVIEW_AI==='1') await runAIReview({test,pageAt,loaded,shot,base,data,expect,restartManager:async()=>{await stop();start();await ready();}});
} finally {
 await browser.close(); await stop(); await log.close();
 const report={createdAt:new Date().toISOString(),sourceSha,base,aiFixtureReview:process.env.TRACEBOLT_REVIEW_AI==='1',viewportDesktop:'1440×1000',viewportMobile:'390×844',browser:process.env.CHROMIUM_PATH ? `Chromium at ${process.env.CHROMIUM_PATH}` : 'Playwright Chromium headless shell',database:'disposable unique temporary database (never production)',results,runtimeErrors,summary:{passed:results.filter(r=>r.status==='PASS').length,failed:results.filter(r=>r.status==='FAIL').length,runtimeErrorCount:runtimeErrors.length}};
 await fs.writeFile(path.join(out,'results.json'),JSON.stringify(report,null,2)); await fs.writeFile(path.join(out,'screenshot-manifest.json'),JSON.stringify({sourceSha,createdAt:report.createdAt,screenshots},null,2)); console.log(JSON.stringify(report.summary)); await fs.rm(temp,{recursive:true,force:true});
}
process.exitCode=results.some(r=>r.status==='FAIL') || runtimeErrors.length ? 1 : 0;
