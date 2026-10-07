/** Invented Windows inventory in the existing real loopback login and compiled UI.
 * Durable enrollment/sender/storage authority has separate Go fixtures. This case
 * never collects an endpoint, creates an invitation or installs a service. */
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {build}=require('esbuild');
const fixtureModule=await build({stdin:{contents:"export * from './windows-inventory-fixture'; export * from './windows-volumes-fixture'; export * from './resource-history-fixture'; export {validWindowsInventoryView} from './windows-inventory-types';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {windowsVolumes,windowsDevice,windowsDeviceId,windowsNow,windowsSection,windowsView,historyFixture,validWindowsInventoryView}=await import('data:text/javascript;base64,'+Buffer.from(fixtureModule.outputFiles[0].text).toString('base64'));
export const windowsInventoryCaseName='Synthetic Windows inventory shares device charts and explicit enrollment consent without Linux reads';
export const windowsInventoryFixtureDisclosure='Real loopback HTTP-test fixture login with intercepted invented Windows inventory and resource history in the production UI. UI-only evidence; no native endpoint acceptance, collection, invitation, service installation or external request.';
let stage='setup';
const stages=new Set(['setup','login','overview','inventory','storage','events','legacy','partial','denied','enrollment','access-loss']);
export const windowsInventoryFailureStage=()=>stages.has(stage)?stage:'setup';
const mark=value=>{stage=value;};
export function windowsBrowserFixture(now,phase='fresh'){
 const view=windowsView(),time=Date.parse(now);view.serverNow=now;view.receivedAt=new Date(time-1000).toISOString();view.snapshot.collectedAt=new Date(time-(phase==='stale'?300000:2000)).toISOString();
 view.events={schemaVersion:'tracebolt.windows-event-metadata.v1',scope:'windows-application-system-event-headers-v1',grantId:'e'.repeat(32),generationId:view.snapshot.generationId,collectedAt:view.snapshot.collectedAt,channels:[{channel:'Application',quality:'observed',reason:'',complete:true,truncated:false,observedCount:1,rows:[{recordId:'18446744073709551615',eventId:42,level:2,provider:'Invented Event Provider',timestamp:new Date(time-60000).toISOString()}]},{channel:'System',quality:'denied',reason:'windows_events_access_denied',complete:false,truncated:false,observedCount:0,rows:[]}]};
 if(phase==='legacy')delete view.events;
 else {view.volumes=windowsVolumes();view.volumes.collectedAt=new Date(time-(phase==='stale'?300000:1500)).toISOString();}
 if(phase==='stale'){
  view.status='stale';view.snapshot.processes={...view.snapshot.processes,quality:'partial',countExact:false,complete:false,truncated:true,observedCount:200};
  view.snapshot.services={...windowsSection([]),quality:'denied',complete:false,countExact:false};
 }
 if(!validWindowsInventoryView(view,windowsDeviceId))throw new Error('Invalid invented Windows fixture');return view;
}
function shifted(value,now){
 if(Array.isArray(value))return value.map(item=>shifted(item,now));
 if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([key,item])=>[key,shifted(item,now)]));
 if(typeof value==='string'&&/^2026-\d\d-\d\dT/.test(value))return new Date(Date.parse(value)+Date.parse(now)-Date.parse(windowsNow)).toISOString();
 return value;
}
export async function windowsInventoryBrowserCase({pageAt,login,expect,base,shot}){
 const page=await pageAt('/devices/'+windowsDeviceId),prefix='/api/devices/'+windowsDeviceId,unexpected=[],writes=[],external=[];let phase='fresh';
 const now=()=>new Date().toISOString();
 await page.route('**/*',async route=>{
  const request=route.request(),url=new URL(request.url());
  if(url.origin!==base){external.push('external');return route.abort('blockedbyclient');}
  if(request.method()!=='GET'&&!(request.method()==='POST'&&url.pathname==='/api/auth/login')){writes.push('write');return route.abort('blockedbyclient');}
  const reply=data=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(data)}),at=now(),device=shifted(windowsDevice(),at);
  if(url.pathname===prefix+'/windows-inventory'){
   if(url.search||request.postData()!==null)throw new Error('Unexpected Windows query');
   if(phase==='session')return route.fulfill({status:401,contentType:'application/json',body:JSON.stringify({error:{code:'authentication_required'}})});
   return reply(windowsBrowserFixture(at,phase));
  }
  if(url.pathname===prefix)return reply(device);
  if(url.pathname===prefix+'/resource-history')return reply({...shifted(historyFixture(),at),deviceId:windowsDeviceId});
  if(url.pathname==='/api/overview')return reply({generatedAt:at,devices:[device],cases:[],activity:[],stats:{totalDevices:1,healthyDevices:0,attentionDevices:0,unknownDevices:1,openCases:0,criticalCases:0}});
  if(url.pathname==='/api/windows/enrollment')return reply({schemaVersion:'tracebolt.enrollment-operator.v2',serverNow:at,enabled:true,platforms:['windows'],recordLimit:25,collectionProfile:'windows-inventory-v1',collectionPrivacy:'windows_inventory_metadata_may_be_sensitive',items:[]});
  if(url.pathname.startsWith(prefix+'/')){unexpected.push('unexpected-device-read');return route.fulfill({status:404,contentType:'application/json',body:JSON.stringify({error:{code:'fixture_unexpected_route'}})});}
  return route.continue();
 });
 mark('login');await login(page);
 for(const locale of ['en','de'])for(const width of [1440,390]){
  await page.setViewportSize({width,height:width===390?844:1000});
  const language=page.locator('select[aria-label="Language"],select[aria-label="Sprache"]');await language.selectOption(locale);
  phase='fresh';await page.goto(`${base}/#/devices/${windowsDeviceId}`);await expect(page.locator('html')).toHaveAttribute('lang',locale);
  mark('overview');await expect(page.getByRole('heading',{name:'fixture-windows',exact:true})).toBeVisible();await expect(page.getByRole('img',{name:/^(System volume|Systemvolume)/})).toBeVisible();
  await shot(page,`synthetic-windows-overview-${width}-${locale}`,windowsInventoryFixtureDisclosure);
  mark('inventory');await page.getByRole('tab',{name:locale==='de'?'Inventar':'Inventory',exact:true}).click();
  for(const label of [locale==='de'?'Prozesse':'Processes',locale==='de'?'Dienste':'Services','Software','Hostname',locale==='de'?'Schnittstellen':'Interfaces']){
   await page.getByRole('tab',{name:label,exact:true}).click();await expect(page.locator('.windows-inventory-table')).toBeVisible();
   expect(await page.locator('.windows-inventory').evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
  }
  await expect(page.getByText('192.0.2.40',{exact:true})).toBeVisible();
  if(width===390)await page.locator('.windows-inventory-table tbody tr').first().scrollIntoViewIfNeeded();
  await shot(page,`synthetic-windows-inventory-${width}-${locale}`,windowsInventoryFixtureDisclosure);
  mark('storage');await page.getByRole('tab',{name:locale==='de'?'Speicher':'Storage',exact:true}).click();
  await expect(page.getByLabel('9007199254740993 '+(locale==='de'?'Bytes':'bytes'),{exact:true})).toBeVisible();
  await expect(page.getByText(locale==='de'?'Zugriff verweigert':'Access denied',{exact:true})).toBeVisible();
  expect(await page.locator('.windows-inventory').evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
  await shot(page,`synthetic-windows-storage-${width}-${locale}`,windowsInventoryFixtureDisclosure);
  mark('events');await page.getByRole('tab',{name:locale==='de'?'Health & Verlauf':'Health & history',exact:true}).click();
  await expect(page.getByText(locale==='de'?'Zugriff verweigert':'Access denied',{exact:true})).toBeVisible();
  await page.getByText(locale==='de'?'Ereignisse ansehen':'View events',{exact:true}).click();await expect(page.getByText('Invented Event Provider',{exact:true})).toBeVisible();
  expect(await page.locator('.windows-inventory').evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
  await shot(page,`synthetic-windows-events-${width}-${locale}`,windowsInventoryFixtureDisclosure);
  await page.getByRole('tab',{name:locale==='de'?'Inventar':'Inventory',exact:true}).click();
  mark('legacy');phase='legacy';await page.getByRole('button',{name:locale==='de'?'Windows-Inventar aktualisieren':'Refresh Windows inventory',exact:true}).click();
  await page.getByRole('tab',{name:locale==='de'?'Speicher':'Storage',exact:true}).click();
  await expect(page.getByText(locale==='de'?/Eine separate lokale Zustimmung ist erforderlich/:/Separate local consent is required/)).toBeVisible();
  await expect(page.locator('.windows-inventory-table')).toHaveCount(0);
  mark('partial');phase='stale';await page.getByRole('button',{name:locale==='de'?'Windows-Inventar aktualisieren':'Refresh Windows inventory',exact:true}).click();await page.getByRole('tab',{name:locale==='de'?'Prozesse':'Processes',exact:true}).click();await expect(page.locator('.windows-inventory-count')).toContainText(locale==='de'?'mindestens 200':'at least 200');
  mark('denied');await page.getByRole('tab',{name:locale==='de'?'Dienste':'Services',exact:true}).click();await expect(page.locator('.windows-inventory-table')).toHaveCount(0);await expect(page.locator('.windows-inventory')).toContainText(locale==='de'?'Berechtigung verweigert':'Permission denied');
  if(width===390)await page.locator('.windows-inventory-empty').scrollIntoViewIfNeeded();
  await shot(page,`synthetic-windows-denied-${width}-${locale}`,windowsInventoryFixtureDisclosure);
  mark('enrollment');await page.goto(`${base}/#/devices`);await page.getByRole('combobox',{name:locale==='de'?'Betriebssystem':'Operating system',exact:true}).selectOption('windows');await page.getByRole('button',{name:locale==='de'?'Gerät hinzufügen':'Add device',exact:true}).click();
  const dialog=page.getByRole('dialog'),create=dialog.getByRole('button',{name:locale==='de'?'Einladung erstellen':'Create invitation',exact:true});await expect(dialog.getByRole('checkbox')).toHaveCount(2);await expect(create).toBeDisabled();await shot(page,`synthetic-windows-consent-${width}-${locale}`,windowsInventoryFixtureDisclosure);
  if(width===390){
   // Retain the scope-first capture and also show the separate HTTP approval
   // and final controls before either acknowledgement is changed.
   await create.scrollIntoViewIfNeeded();
   await create.evaluate(el=>el.scrollIntoView({block:'center',inline:'nearest',behavior:'instant'}));
   await expect(dialog.locator('.enrollment-windows-http')).toBeInViewport({ratio:1});await expect(create).toBeInViewport({ratio:1});
   await expect(dialog.getByRole('checkbox').nth(0)).not.toBeChecked();await expect(dialog.getByRole('checkbox').nth(1)).not.toBeChecked();await expect(create).toBeDisabled();
   await shot(page,`synthetic-windows-consent-controls-${width}-${locale}`,windowsInventoryFixtureDisclosure);
  }
  await dialog.getByRole('checkbox').nth(0).check();await expect(create).toBeDisabled();await dialog.getByRole('checkbox').nth(1).check();await expect(create).toBeEnabled();
  await expect(dialog.locator('.enrollment-public-command')).toHaveCount(0);await page.keyboard.press('Escape');await expect(dialog).toHaveCount(0);
 }
 mark('access-loss');await page.locator('select[aria-label="Sprache"]').selectOption('en');phase='session';await page.goto(`${base}/#/devices/${windowsDeviceId}`);await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();await expect(page.locator('.windows-inventory-table')).toHaveCount(0);
 expect(unexpected).toEqual([]);expect(writes).toEqual([]);expect(external).toEqual([]);
}
