import {addWindowsServiceSoftwareControlsFixture,exerciseWindowsServiceSoftwareControls} from './windows-service-software-browser.mjs';
/** Invented Windows inventory in the existing real loopback login and compiled UI.
 * Durable enrollment/sender/storage authority has separate Go fixtures. This case
 * never collects an endpoint, creates an invitation or installs a service. */
import {windowsLogsBrowserCase,windowsLogsFixture,windowsLogsStageNames} from './windows-logs-browser.mjs';
import {createRequire} from 'node:module';
import {addWindowsProcessControlsFixture,exerciseWindowsProcessControls} from './windows-process-browser.mjs';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {build}=require('esbuild');
const fixtureModule=await build({stdin:{contents:"export * from './windows-inventory-fixture'; export * from './windows-volumes-fixture'; export * from './windows-network-fixture'; export * from './resource-history-fixture'; export {validWindowsInventoryView} from './windows-inventory-types';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {windowsNetwork,windowsVolumes,windowsDevice,windowsDeviceId,windowsNow,windowsSection,windowsView,historyFixture,validWindowsInventoryView}=await import('data:text/javascript;base64,'+Buffer.from(fixtureModule.outputFiles[0].text).toString('base64'));
export const windowsInventoryCaseName='Synthetic Windows inventory shares device charts and explicit enrollment consent without Linux reads';
export const windowsInventoryFixtureDisclosure='Real loopback HTTP-test fixture login with intercepted invented Windows inventory and resource history in the production UI. UI-only evidence; no native endpoint acceptance, collection, invitation, service installation or external request.';
let stage='setup';
const stages=new Set(['setup','login','overview','overview-history','inventory','storage','network','network-stale','network-expired','network-partial','network-empty','network-denied','network-unavailable','network-truncated','process-metrics','process-controls','service-software-controls','process-metrics-stale','process-metrics-expired','events','logs',...windowsLogsStageNames,'legacy','partial','denied','enrollment','access-loss']);
export const windowsInventoryFailureStage=()=>stages.has(stage)?stage:'setup';
const mark=value=>{stage=value;};
export function windowsBrowserFixture(now,phase='fresh',networkPhaseAt=now,logsPhaseAt=now){
 const view=windowsView(),time=Date.parse(now);view.serverNow=now;view.receivedAt=new Date(time-1000).toISOString();view.snapshot.collectedAt=new Date(time-(phase==='stale'?300000:2000)).toISOString();
 view.events={schemaVersion:'tracebolt.windows-event-metadata.v1',scope:'windows-application-system-event-headers-v1',grantId:'e'.repeat(32),generationId:view.snapshot.generationId,collectedAt:view.snapshot.collectedAt,channels:[{channel:'Application',quality:'observed',reason:'',complete:true,truncated:false,observedCount:1,rows:[{recordId:'18446744073709551615',eventId:42,level:2,provider:'Invented Event Provider',timestamp:new Date(time-60000).toISOString()}]},{channel:'System',quality:'denied',reason:'windows_events_access_denied',complete:false,truncated:false,observedCount:0,rows:[]}]};
 if(phase==='legacy')delete view.events;
 else {view.volumes=windowsVolumes();view.volumes.collectedAt=new Date(time-(phase==='stale'?300000:1500)).toISOString();}
 if(phase!=='legacy'){
  // Invented display values only. No Windows API, endpoint or host read.
  const names=['fixture.exe','synthetic-zero.exe','synthetic-first.exe','synthetic-reset.exe','synthetic-denied.exe','synthetic-unavailable.exe'];
  view.snapshot.processes=windowsSection(names.map((name,index)=>({pid:44+index,parentPid:4,name,threads:3})));
  view.processMetrics={schemaVersion:'tracebolt.windows-process-metrics.v1',scope:'windows-process-metrics-v1',grantId:'c'.repeat(32),generationId:view.snapshot.generationId,collectedAt:new Date(time-(phase==='metrics-expiring'?86400000-5000:phase==='metrics-stale'||phase==='stale'?300000:1500)).toISOString(),observedCount:6,truncated:false,rows:[
   {pid:44,cpuPercent:125.25,cpuQuality:'observed',memoryBytes:'9007199254740993',memoryQuality:'observed'},
   {pid:45,cpuPercent:0,cpuQuality:'observed',memoryBytes:'0',memoryQuality:'observed'},
   {pid:46,cpuPercent:null,cpuQuality:'first-sample',memoryBytes:'4096',memoryQuality:'observed'},
   {pid:47,cpuPercent:null,cpuQuality:'reset',memoryBytes:'8192',memoryQuality:'observed'},
   {pid:48,cpuPercent:null,cpuQuality:'denied',memoryBytes:null,memoryQuality:'denied'},
   {pid:49,cpuPercent:null,cpuQuality:'unavailable',memoryBytes:null,memoryQuality:'unavailable'},
  ]};
 }
 if(phase!=='legacy'){
  view.network=windowsNetwork();
  // A repeated reply advances server time, not this intended observation.
  const networkTime=['network-stale','network-expiring'].includes(phase)?Date.parse(networkPhaseAt):time;
  view.network.collectedAt=new Date(networkTime-(phase==='network-expiring'?86400000-5000:phase==='network-stale'||phase==='stale'?300000:1500)).toISOString();
  if(['network-stale','network-expiring'].includes(phase)){view.snapshot.collectedAt=view.network.collectedAt;view.status='stale';}
  if(phase==='network-empty')Object.assign(view.network,{rows:[],observedCount:0});
  if(['network-denied','network-unavailable','network-partial'].includes(phase))Object.assign(view.network,{quality:phase.slice('network-'.length),countExact:false,rows:[],observedCount:0});
  if(phase==='network-truncated')Object.assign(view.network,{truncated:true,observedCount:100});
 }
 if(phase==='process-controls')addWindowsProcessControlsFixture(view);
 if(phase==='service-software-controls')addWindowsServiceSoftwareControlsFixture(view);
 if(phase==='stale'){
  view.status='stale';view.snapshot.processes={...view.snapshot.processes,quality:'partial',countExact:false,complete:false,truncated:true,observedCount:200};
  view.snapshot.services={...windowsSection([]),quality:'denied',complete:false,countExact:false};
 }
 // The real wire contract omits all private sections after the base expiry.
 // A late repeat must not mint another five seconds for the same generation.
 if(phase==='network-expiring'&&time-Date.parse(view.snapshot.collectedAt)>=86400000){
  view.status='unavailable';view.snapshot=null;
  for(const key of ['events','volumes','processMetrics','network'])delete view[key];
 }
 windowsLogsFixture(view,now,phase,logsPhaseAt);
 if(!validWindowsInventoryView(view,windowsDeviceId))throw new Error('Invalid invented Windows fixture');return view;
}
function shifted(value,now){
 if(Array.isArray(value))return value.map(item=>shifted(item,now));
 if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([key,item])=>[key,shifted(item,now)]));
 if(typeof value==='string'&&/^2026-\d\d-\d\dT/.test(value))return new Date(Date.parse(value)+Date.parse(now)-Date.parse(windowsNow)).toISOString();
 return value;
}
// This fixture pauses browser time. The shared history reader yields for 500 ms
// while a foreground inventory request is pending; advance that same clock,
// preserving the fixture timestamp binding, until all three real charts exist.
export async function settleWindowsHistory(page,expect,advance){
 await expect.poll(async()=>{await advance(500);return page.locator('.resource-history').getByRole('img').count();}).toBe(3);
}
// Hash-only navigation can finish before React commits the intermediate route.
// Prove the previous device is gone before returning so expiry checks really
// start a new inventory lifetime and its existing 15-second refresh interval.
export async function remountWindowsDevice(page,expect,base){
 await page.goto(`${base}/#/devices`);
 await expect(page.locator('.device-page')).toHaveCount(0);
 await expect(page.locator('.device-table')).toBeVisible();
 await page.goto(`${base}/#/devices/${windowsDeviceId}`);
}
export async function windowsInventoryBrowserCase({pageAt,login,expect,base,shot}){
 const page=await pageAt('/devices/'+windowsDeviceId),prefix='/api/devices/'+windowsDeviceId,unexpected=[],writes=[],external=[];let phase='fresh',networkPhaseAt=null,logsPhaseAt=null;
 // A bounded virtual clock makes the five-second private-row expiry deterministic.
 let clockNow=Date.now();await page.clock.install({time:new Date(clockNow)});await page.clock.pauseAt(new Date(clockNow+1000));clockNow+=1000;
 const now=()=>new Date(clockNow).toISOString();
 await page.route('**/*',async route=>{
  const request=route.request(),url=new URL(request.url());
  if(url.origin!==base){external.push('external');return route.abort('blockedbyclient');}
  if(request.method()!=='GET'&&!(request.method()==='POST'&&url.pathname==='/api/auth/login')){writes.push('write');return route.abort('blockedbyclient');}
  const reply=data=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(data)}),at=now(),device=shifted(windowsDevice(),at);
  if(url.pathname===prefix+'/windows-inventory'){
   if(url.search||request.postData()!==null)throw new Error('Unexpected Windows query');
   if(phase==='session')return route.fulfill({status:401,contentType:'application/json',body:JSON.stringify({error:{code:'authentication_required'}})});
   return reply(windowsBrowserFixture(at,phase,networkPhaseAt??at,logsPhaseAt??at));
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
  mark('overview');await expect(page.getByRole('heading',{name:'fixture-windows',exact:true})).toBeVisible();
  mark('overview-history');await settleWindowsHistory(page,expect,async ms=>{clockNow+=ms;await page.clock.runFor(ms);});
  await expect(page.getByRole('img',{name:/^(System volume|Systemvolume)/})).toBeVisible();
  await shot(page,`synthetic-windows-overview-${width}-${locale}`,windowsInventoryFixtureDisclosure);
  mark('inventory');await page.getByRole('tab',{name:locale==='de'?'Inventar':'Inventory',exact:true}).click();
  for(const label of [locale==='de'?'Prozesse':'Processes',locale==='de'?'Dienste':'Services','Software','Hostname',locale==='de'?'Schnittstellen':'Interfaces']){
   await page.getByRole('tab',{name:label,exact:true}).click();await expect(page.locator('.windows-inventory-table')).toBeVisible();
   expect(await page.locator('.windows-inventory').evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
  }
  await expect(page.getByText('192.0.2.40',{exact:true})).toBeVisible();
  if(width===390)await page.locator('.windows-inventory-table tbody tr').first().scrollIntoViewIfNeeded();
  await shot(page,`synthetic-windows-inventory-${width}-${locale}`,windowsInventoryFixtureDisclosure);
  mark('process-metrics');await page.getByRole('tab',{name:locale==='de'?'Prozesse':'Processes',exact:true}).click();
  const table=page.locator('.windows-inventory-table'),row=name=>table.getByRole('row').filter({has:page.getByText(name,{exact:true})});
  const cpuLabel=locale==='de'?'CPU (% eines logischen Prozessors)':'CPU (% of one logical processor)',ramLabel=locale==='de'?'RAM-Arbeitssatz (Bytes)':'Working-set RAM (bytes)';
  for(const label of [cpuLabel,ramLabel]){
   if(width===1440)await expect(table.getByRole('columnheader',{name:label,exact:true})).toBeVisible();
   else {
    // Mobile headings are intentionally clipped; the visible labels are td::before.
    const cell=row('fixture.exe').locator(`td[data-label="${label}"]`);await expect(cell).toBeVisible();await expect(cell).toHaveAttribute('data-label',label);
    const before=await cell.evaluate(el=>{const style=getComputedStyle(el,'::before');return {content:style.content,display:style.display,visibility:style.visibility};});
    expect(before.content).toBe(JSON.stringify(label));expect(before.display).not.toBe('none');expect(before.visibility).toBe('visible');
   }
  }
  await expect(row('fixture.exe').getByText(locale==='de'?'125,25 %':'125.25 %',{exact:true})).toBeVisible();
  await expect(row('fixture.exe').getByText(locale==='de'?'9.007.199.254.740.993':'9,007,199,254,740,993',{exact:true})).toBeVisible();
  await expect(row('synthetic-zero.exe').getByText('0 %',{exact:true})).toBeVisible();await expect(row('synthetic-zero.exe').getByText('0',{exact:true})).toBeVisible();
  for(const [name,label] of [['synthetic-first.exe',locale==='de'?'Erste Messung; CPU-Intervall ausstehend':'First sample; waiting for CPU interval'],['synthetic-reset.exe',locale==='de'?'CPU-Intervall zurückgesetzt; nächste Messung ausstehend':'CPU interval reset; waiting for next sample'],['synthetic-denied.exe',locale==='de'?'Zugriff verweigert':'Access denied'],['synthetic-unavailable.exe',locale==='de'?'Nicht verfügbar':'Unavailable']]){
   await expect(row(name)).toContainText(label);await expect(row(name).getByText('0 %',{exact:true})).toHaveCount(0);
  }
  expect(await page.locator('.windows-inventory').evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
  await row('fixture.exe').scrollIntoViewIfNeeded();
  await shot(page,`synthetic-windows-process-metrics-${width}-${locale}`,windowsInventoryFixtureDisclosure);
  if(width===390){await row('synthetic-first.exe').scrollIntoViewIfNeeded();await shot(page,`synthetic-windows-process-metrics-null-${width}-${locale}`,windowsInventoryFixtureDisclosure);await row('synthetic-denied.exe').scrollIntoViewIfNeeded();await shot(page,`synthetic-windows-process-metrics-denied-${width}-${locale}`,windowsInventoryFixtureDisclosure);}
  mark('process-controls');phase='process-controls';await page.getByRole('button',{name:locale==='de'?'Windows-Inventar aktualisieren':'Refresh Windows inventory',exact:true}).click();
  await exerciseWindowsProcessControls({page,expect,locale,width,shot,disclosure:windowsInventoryFixtureDisclosure});
  mark('service-software-controls');phase='service-software-controls';await page.getByRole('button',{name:locale==='de'?'Windows-Inventar aktualisieren':'Refresh Windows inventory',exact:true}).click();
  await exerciseWindowsServiceSoftwareControls({page,expect,locale,width,shot,disclosure:windowsInventoryFixtureDisclosure});
  mark('process-metrics-stale');phase='metrics-stale';await page.getByRole('button',{name:locale==='de'?'Windows-Inventar aktualisieren':'Refresh Windows inventory',exact:true}).click();
  await expect(page.locator('.windows-process-metrics-note')).toContainText(locale==='de'?'Veraltete Prozessmesswerte.':'Stale process metrics.');await expect(row('fixture.exe')).toContainText(locale==='de'?'125,25 %':'125.25 %');
  await page.locator('.windows-process-metrics-note').scrollIntoViewIfNeeded();await shot(page,`synthetic-windows-process-metrics-stale-${width}-${locale}`,windowsInventoryFixtureDisclosure);
  // Remount to reset the 15-second refresh timer, then cross only the metrics TTL.
  mark('process-metrics-expired');phase='metrics-expiring';await remountWindowsDevice(page,expect,base);await page.getByRole('tab',{name:locale==='de'?'Inventar':'Inventory',exact:true}).click();await page.getByRole('tab',{name:locale==='de'?'Prozesse':'Processes',exact:true}).click();
  await expect(row('fixture.exe')).toContainText(locale==='de'?'125,25 %':'125.25 %');
  clockNow+=6000;await page.clock.runFor(6000);
  await expect(table.getByText(locale==='de'?'125,25 %':'125.25 %',{exact:true})).toHaveCount(0);await expect(row('fixture.exe')).toContainText(locale==='de'?'Nicht verfügbar':'Unavailable');
  await expect(page.locator('.windows-inventory-caution')).toContainText(locale==='de'?'fehlende Daten belegen keinen Nullverbrauch':'absent data does not establish zero usage');
  await row('fixture.exe').scrollIntoViewIfNeeded();
  await shot(page,`synthetic-windows-process-metrics-expired-${width}-${locale}`,windowsInventoryFixtureDisclosure);
  phase='fresh';await page.getByRole('button',{name:locale==='de'?'Windows-Inventar aktualisieren':'Refresh Windows inventory',exact:true}).click();
  mark('network');await page.getByRole('tab',{name:locale==='de'?'Netzwerk':'Network',exact:true}).click();
  const networkTable=page.locator('.windows-inventory-table'),networkRow=value=>networkTable.getByRole('row').filter({has:page.getByText(value,{exact:true})});
  const networkLabels=locale==='de'?['Protokoll','IP-Version','Lokaler Endpunkt','Entfernter Endpunkt','TCP-Zustand','Besitzende PID laut API']:['Protocol','IP version','Local endpoint','Remote endpoint','TCP state','API owning PID'];
  for(const label of networkLabels){
   if(width===1440)await expect(networkTable.getByRole('columnheader',{name:label,exact:true})).toBeVisible();
   else {
    const cell=networkRow('[2001:db8::40]:49152').locator(`td[data-label="${label}"]`);await expect(cell).toBeVisible();
    const before=await cell.evaluate(el=>{const style=getComputedStyle(el,'::before');return {content:style.content,display:style.display,visibility:style.visibility};});
    expect(before.content).toBe(JSON.stringify(label));expect(before.display).not.toBe('none');expect(before.visibility).toBe('visible');
   }
  }
  await expect(networkRow('0.0.0.0:135').getByText('listen',{exact:true})).toBeVisible();await expect(networkRow('0.0.0.0:135').getByText(locale==='de'?'Nicht anwendbar':'Not applicable',{exact:true})).toBeVisible();await expect(networkTable.getByText('0.0.0.0:0',{exact:true})).toHaveCount(0);
  await expect(networkRow('[2001:db8::40]:49152').getByText('[2001:db8::80]:443',{exact:true})).toBeVisible();
  await expect(networkRow('[2001:db8::40]:49152').getByText('established',{exact:true})).toBeVisible();
  for(const local of ['127.0.0.1:5353','[fe80::40%4]:5353']){
   await expect(networkRow(local).getByText('UDP',{exact:true})).toBeVisible();
   await expect(networkRow(local).getByText(locale==='de'?'Nicht anwendbar':'Not applicable',{exact:true})).toHaveCount(2);
  }
  await expect(networkRow('[fe80::40%4]:5353').getByText(locale==='de'?'Nicht verfügbar':'Unavailable',{exact:true})).toBeVisible();await expect(networkRow('[fe80::40%4]:5353').getByText('0',{exact:true})).toHaveCount(0);
  await expect(networkTable.getByText('fixture.exe',{exact:true})).toHaveCount(0);await expect(networkTable.getByRole('link')).toHaveCount(0);
  expect(await page.locator('.windows-inventory').evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
  await networkRow('0.0.0.0:135').scrollIntoViewIfNeeded();await shot(page,`synthetic-windows-network-${width}-${locale}`,windowsInventoryFixtureDisclosure);
  if(width===390){await networkRow('[fe80::40%4]:5353').scrollIntoViewIfNeeded();await shot(page,`synthetic-windows-network-udp-${width}-${locale}`,windowsInventoryFixtureDisclosure);}
  for(const state of ['empty','denied','unavailable','partial','truncated','stale']){
   mark('network-'+state);phase='network-'+state;networkPhaseAt=now();await page.getByRole('button',{name:locale==='de'?'Windows-Inventar aktualisieren':'Refresh Windows inventory',exact:true}).click();
   const panel=page.locator('.windows-inventory [role="tabpanel"]');
   if(state==='empty'){await expect(panel).toContainText(locale==='de'?'Keine Endpunkte aus den':'No endpoints returned');await expect(panel).toContainText(locale==='de'?'0 angezeigt · 0 beobachtet':'0 shown · 0 observed');}
   else if(['denied','unavailable','partial'].includes(state)){
    await expect(networkTable).toHaveCount(0);await expect(panel).toContainText(locale==='de'?'dies belegt kein leeres Netzwerk':'does not establish an empty network');
    await expect(panel).toContainText(state==='denied'?(locale==='de'?'Zugriff verweigert':'Access denied'):state==='partial'?(locale==='de'?'Teilweise aufgelistet':'Partial enumeration'):(locale==='de'?'Nicht verfügbar':'Unavailable'));
    await expect(panel.getByText(locale==='de'?'0 angezeigt · 0 beobachtet':'0 shown · 0 observed',{exact:true})).toHaveCount(0);
   } else if(state==='truncated'){await expect(panel).toContainText(locale==='de'?'Begrenzte Auflistung':'Bounded enumeration');await expect(panel).toContainText(locale==='de'?'4 angezeigt · 100 beobachtet':'4 shown · 100 observed');}
   else {await expect(panel).toContainText(locale==='de'?'Veraltete Netzwerkbeobachtung':'Stale network observation');await expect(networkTable.getByText('[2001:db8::80]:443',{exact:true})).toBeVisible();}
   await panel.scrollIntoViewIfNeeded();await shot(page,`synthetic-windows-network-${state}-${width}-${locale}`,windowsInventoryFixtureDisclosure);
  }
  mark('network-expired');phase='network-expiring';networkPhaseAt=now();await remountWindowsDevice(page,expect,base);await page.getByRole('tab',{name:locale==='de'?'Inventar':'Inventory',exact:true}).click();await page.getByRole('tab',{name:locale==='de'?'Netzwerk':'Network',exact:true}).click();
  await expect(networkTable.getByText('[2001:db8::80]:443',{exact:true})).toBeVisible();clockNow+=6000;await page.clock.runFor(6000);
  await expect(networkTable).toHaveCount(0);await expect(page.locator('.windows-inventory-empty')).toContainText(locale==='de'?'Netzwerksnapshot ist abgelaufen':'network snapshot expired');
  await shot(page,`synthetic-windows-network-expired-${width}-${locale}`,windowsInventoryFixtureDisclosure);
  // Base capture cannot follow network capture; the base 24-hour privacy envelope also expires here.
  await page.getByRole('tab',{name:locale==='de'?'Prozesse':'Processes',exact:true}).click();await expect(table).toHaveCount(0);
  phase='fresh';await page.getByRole('button',{name:locale==='de'?'Windows-Inventar aktualisieren':'Refresh Windows inventory',exact:true}).click();
  mark('storage');await page.getByRole('tab',{name:locale==='de'?'Speicher':'Storage',exact:true}).click();
  await expect(page.getByLabel('9007199254740993 '+(locale==='de'?'Bytes':'bytes'),{exact:true})).toBeVisible();
  await expect(page.getByText(locale==='de'?'Zugriff verweigert':'Access denied',{exact:true})).toBeVisible();
  expect(await page.locator('.windows-inventory').evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
  await shot(page,`synthetic-windows-storage-${width}-${locale}`,windowsInventoryFixtureDisclosure);
  mark('events');await page.getByRole('tab',{name:'Health',exact:true}).click();
  await expect(page.getByText(locale==='de'?'Zugriff verweigert':'Access denied',{exact:true})).toBeVisible();
  await page.getByText(locale==='de'?'Ereignisse ansehen':'View events',{exact:true}).click();await expect(page.getByText('Invented Event Provider',{exact:true})).toBeVisible();
  expect(await page.locator('.windows-inventory').evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
  await shot(page,`synthetic-windows-events-${width}-${locale}`,windowsInventoryFixtureDisclosure);
  mark('logs');await windowsLogsBrowserCase({page,expect,base,mark,deviceId:windowsDeviceId,locale,width,shot,disclosure:windowsInventoryFixtureDisclosure,setPhase:value=>{phase=value;logsPhaseAt=value==='logs-expiring'?now():null;},advance:async ms=>{clockNow+=ms;await page.clock.runFor(ms);}});
  await page.getByRole('tab',{name:locale==='de'?'Inventar':'Inventory',exact:true}).click();
  mark('legacy');phase='legacy';await page.getByRole('button',{name:locale==='de'?'Windows-Inventar aktualisieren':'Refresh Windows inventory',exact:true}).click();
  await page.getByRole('tab',{name:locale==='de'?'Speicher':'Storage',exact:true}).click();
  await expect(page.getByText(locale==='de'?/Eine separate lokale Zustimmung ist erforderlich/:/Separate local consent is required/)).toBeVisible();
  await expect(page.locator('.windows-inventory-table')).toHaveCount(0);
  await page.getByRole('tab',{name:locale==='de'?'Netzwerk':'Network',exact:true}).click();await expect(page.locator('.windows-inventory-empty')).toContainText(locale==='de'?'Netzwerkendpunkte sind in dieser Meldung nicht eingerichtet':'Network endpoints are not configured');await expect(page.locator('.windows-inventory-table')).toHaveCount(0);await shot(page,`synthetic-windows-network-unconfigured-${width}-${locale}`,windowsInventoryFixtureDisclosure);
  mark('partial');phase='stale';await page.getByRole('button',{name:locale==='de'?'Windows-Inventar aktualisieren':'Refresh Windows inventory',exact:true}).click();await page.getByRole('tab',{name:locale==='de'?'Prozesse':'Processes',exact:true}).click();await expect(page.locator('.windows-inventory-count').first()).toContainText(locale==='de'?'mindestens 200':'at least 200');
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
