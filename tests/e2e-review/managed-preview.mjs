/** Actual two-process Linux development transport browser acceptance.
 * No external provider, fake telemetry, screenshot, raw metric, database or
 * receipt upload. Output is bounded pass/fail metadata only. Not production
 * enrollment, sender authentication, or native Windows/macOS validation.
 */
import { createRequire } from 'node:module';
import { spawn, spawnSync, execFileSync } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {chromium,expect}=require('@playwright/test');
const temporary=await fs.mkdtemp(path.join(os.tmpdir(),'tracebolt-managed-ui-'));
const output=path.join(root,'artifacts/review/managed-preview-result.json');
await fs.mkdir(path.dirname(output),{recursive:true});
const checks=[];let manager,browser,managerLog,pageErrors=0;let fatal=false;
let receipt,device,initial,initialSample;
const port=Number(process.env.MANAGED_REVIEW_PORT||19883),base=`http://127.0.0.1:${port}`;
async function read(route){const response=await fetch(`${base}/api${route}`);if(!response.ok)throw new Error('READ_FAILED');return response.json();}
async function check(name,fn){try{await fn();checks.push({name,status:'PASS'});console.log(`PASS ${name}`);}catch{checks.push({name,status:'FAIL'});console.log(`FAIL ${name} (details withheld to avoid telemetry disclosure)`);}}
try {
 for(const command of ['manager','dev-agent'])execFileSync(process.env.GO_BIN||'go',['build','-buildvcs=false','-o',path.join(temporary,command),`./cmd/${command}`],{cwd:root,stdio:'inherit'});
 managerLog=await fs.open(path.join(temporary,'manager.log'),'w');
 manager=spawn(path.join(temporary,'manager'),['--managed-preview','--port',String(port),'--db',path.join(temporary,'state.db'),'--web',path.join(root,'web/dist')],{cwd:root,stdio:['ignore',managerLog.fd,managerLog.fd]});
 let ready=false;for(let attempt=0;attempt<60;attempt++){if(manager.exitCode!==null)throw new Error('MANAGER_EXITED');try{if((await read('/health')).status==='ok'){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,100));}if(!ready)throw new Error('MANAGER_NOT_READY');
 const launch={headless:true,args:['--no-sandbox'],env:{...process.env,HOME:temporary,XDG_CONFIG_HOME:temporary,XDG_CACHE_HOME:temporary}};if(process.env.CHROMIUM_PATH)launch.executablePath=process.env.CHROMIUM_PATH;browser=await chromium.launch(launch);
 const page=await browser.newPage({viewport:{width:1440,height:1000},locale:'de-DE'});page.on('pageerror',()=>pageErrors++);await page.addInitScript(()=>localStorage.setItem('tracebolt.locale','de'));
 await check('Awaiting state has no manager-generated sample and seven distinct synthetic devices',async()=>{
  initial=await read('/dev/telemetry/status');initialSample=await read('/devices/sandbox-local');const overview=await read('/overview');expect(initial.mode).toBe('managed-preview');expect(initial.state).toBe('awaiting');expect(initial.acceptedSamples).toBe(0);expect(initial.collectedAt).toBeNull();expect(initial.receivedAt).toBeNull();expect(initialSample.status).toBe('unknown');expect(initialSample.evidence).toEqual([]);expect(overview.devices.filter(d=>d.synthetic)).toHaveLength(7);expect(overview.devices).toHaveLength(8);for(const key of ['cpu','memory','disk'])expect(initialSample[key].value).toBeNull();
 });
 await check('Awaiting UI exposes unavailable values and unknown collection time rather than year one',async()=>{
  await page.goto(`${base}/#/devices/sandbox-local`);await expect(page.getByRole('region',{name:'Gerät Local sandbox',exact:true})).toBeVisible();await expect(page.locator('.device-metric-card .unavailable')).toHaveCount(3);await page.getByRole('tab',{name:'Details',exact:true}).click();await page.locator('.device-technical summary').click();await expect(page.getByRole('region',{name:'Gerät Local sandbox',exact:true})).toContainText('Unbekannt');await expect(page.getByRole('region',{name:'Gerät Local sandbox',exact:true})).toContainText('Zeitpunkt unbekannt');expect(await page.getByRole('region',{name:'Gerät Local sandbox',exact:true}).innerText()).not.toMatch(/01\.01\.0?1\b|vor [0-9]{5,} Tagen/);
 });
 await check('Separate one-shot Linux sender exits after one accepted observation with fixed role and source',async()=>{
  const sender=spawnSync(path.join(temporary,'dev-agent'),['--manager',base],{cwd:root,encoding:'utf8',timeout:12000,maxBuffer:65536});expect(sender.status).toBe(0);expect(sender.pid).not.toBe(manager.pid);receipt=JSON.parse(sender.stdout);device=await read('/devices/sandbox-local');const status=await read('/dev/telemetry/status');expect(status.state).toBe('fresh');expect(status.acceptedSamples).toBe(1);expect(receipt.sequence).toBe(1);expect(device.id).toBe('sandbox-local');expect(device.platform).toBe('linux');expect(device.source).toBe('sandbox');expect(device.synthetic).toBe(false);expect(device.ip).toBeNull();expect(device.status).toBe('unknown');expect(device.lastSeen).toBe(receipt.collectedAt);expect(status.receivedAt).toBe(receipt.receivedAt);expect(device.evidence.some(e=>e.id==='local-agent-transport')).toBe(true);
 });
 await check('Accepted UI metric values match the actual manager sample and provenance preserves collection and receipt',async()=>{
  if(!receipt||!device)throw new Error('NO_RECEIPT');await page.reload();await expect(page.getByRole('region',{name:'Gerät Local sandbox',exact:true})).toContainText('Local sandbox');const cards=page.locator('.device-metric-card');for(const [index,key] of ['cpu','memory','disk'].entries()){const value=device[key].value;if(value===null)await expect(cards.nth(index).locator('.unavailable')).toBeVisible();else await expect(cards.nth(index).locator('.metric-value')).toContainText(String(Math.round(value)));}
  await page.getByRole('tab',{name:/Belege/}).click();const transport=page.locator('.evidence-card').filter({has:page.locator('summary').filter({hasText:'Local agent transport'})});await transport.locator('summary').click();await expect(transport).toContainText(receipt.receivedAt);await expect(transport).toContainText('does not authenticate');await expect(transport).toContainText('not proof of continuous availability');const evidence=device.evidence.find(e=>e.id==='local-agent-transport');expect(evidence.collectedAt).toBe(receipt.collectedAt);const collectedLabel=await page.evaluate(at=>new Intl.DateTimeFormat('de-DE',{dateStyle:'medium',timeStyle:'medium'}).format(new Date(at)),receipt.collectedAt);await expect(transport.locator('.evidence-foot')).toContainText(collectedLabel);await expect(page.locator('.detail-badges .status')).toHaveText('Unbekannt');
 });
 await check('Real expiry after sender exit leaves timestamps unchanged and never falls back to manager collection',async()=>{
  if(!receipt)throw new Error('NO_RECEIPT');const state=await read('/dev/telemetry/status');const expires=Date.parse(receipt.receivedAt)+state.maxAgeSeconds*1000+1200;
  while(Date.now()<expires){await new Promise(r=>setTimeout(r,Math.min(5000,expires-Date.now())));const current=await read('/dev/telemetry/status');expect(current.acceptedSamples).toBe(1);expect(current.receivedAt).toBe(receipt.receivedAt);expect(current.collectedAt).toBe(receipt.collectedAt);}
  const current=await read('/dev/telemetry/status');const aged=await read('/devices/sandbox-local');expect(current.state).toBe('stale');expect(aged.lastSeen).toBe(receipt.collectedAt);expect(aged.status).toBe('unknown');for(const key of ['cpu','memory','disk'])expect(aged[key].quality).not.toBe('healthy');expect(aged.evidence.find(e=>e.id==='local-agent-transport').quality).toBe('stale');
 });
 await check('Stale UI displays stale evidence and unknown whole-device health after actual two-minute expiry',async()=>{
  if(!receipt)throw new Error('NO_RECEIPT');await page.reload();await expect(page.locator('.detail-badges .status')).toHaveText('Unbekannt');await page.getByRole('tab',{name:/Belege/}).click();const transport=page.locator('.evidence-card').filter({has:page.locator('summary').filter({hasText:'Local agent transport'})});await expect(transport.locator('.quality-pill')).toHaveText('Veraltet');await transport.locator('summary').click();await expect(transport).toContainText(receipt.receivedAt);await page.getByRole('button',{name:'Zurück zu Geräten',exact:true}).click();await expect(page.locator('.device-table tbody tr')).toHaveCount(8);await page.locator('.inventory-tabs button').filter({hasText:'Demo-Geräte'}).click();await expect(page.locator('.device-table tbody tr')).toHaveCount(7);
 });
 if(pageErrors)throw new Error('BROWSER_RUNTIME_ERRORS');
} catch {fatal=true;console.log('Managed-preview browser setup or execution failed; raw details are not exported.');}
finally {
 if(browser)await browser.close();if(manager&&manager.exitCode===null){const ended=new Promise(r=>manager.once('exit',r));manager.kill('SIGTERM');await ended;}if(managerLog)await managerLog.close();
 const report={sourceSha:process.env.TRACEBOLT_SOURCE_SHA||null,createdAt:new Date().toISOString(),status:!fatal&&!checks.some(c=>c.status==='FAIL')?'PASS':'FAIL',scope:'Actual separate Linux manager and one-shot dev-agent, loopback development preview',checks,runtimeErrorCount:pageErrors,telemetryExported:false,screenshotsCaptured:false,nativeWindowsMacOSValidated:false,productionManagedFleet:false,summary:{passed:checks.filter(c=>c.status==='PASS').length,failed:checks.filter(c=>c.status==='FAIL').length,setupOrRuntimeFailure:fatal}};
 await fs.writeFile(output,JSON.stringify(report,null,2));await fs.rm(temporary,{recursive:true,force:true});process.exitCode=report.status==='PASS'?0:1;
}
