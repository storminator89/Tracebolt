/** Inert invented transport and production-UI assertions. No browser or server
 * starts on import; the separate opt-in runner provides those. */
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..'),require=createRequire(path.join(root,'web/package.json'));
const {build}=require('esbuild');
const built=await build({stdin:{contents:"export * from './windows-storage-io-fixture'; export {windowsStorageIOMetricKeys} from './windows-storage-io-types'; export {windowsDevice,windowsDeviceId} from './windows-inventory-fixture'; export {validWindowsInventoryView} from './windows-inventory-types';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {windowsStorageIOView,unavailableWindowsStorageIO,unavailableWindowsStorageIOMetric,observedWindowsStorageIOMetric,summarizeWindowsStorageIO,windowsStorageIOMetricKeys,windowsDevice,windowsDeviceId,validWindowsInventoryView}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
export const windowsStorageIOCaseName='Private Windows PerfDisk aggregate with invented transport';
export const windowsStorageIODisclosure='Production UI in a real local browser with intercepted invented operator-session, device and PerfDisk aggregate responses. UI fixture evidence only; no real authentication, manager/store acceptance, Windows provider read, host grant, storage health verdict, disk attribution, action or AI/export.';
let stage='setup';
export const windowsStorageIOFailureStage=()=>stage;
const stamp=(at,offset=0)=>new Date(Date.parse(at)+offset).toISOString();
export function windowsStorageIOBrowserFixture({serverNow,capturedAt,phase='observed',retainedCapturedAt}){
 const view=windowsStorageIOView(),s=view.storageIO;
 view.serverNow=view.receivedAt=serverNow;view.snapshot.collectedAt=view.storageContext.collectedAt=s.collectedAt=capturedAt;view.volumes.collectedAt=stamp(capturedAt,2000);
 s.perfDisk.sampleStartedAt=stamp(capturedAt,250);s.perfDisk.sampleEndedAt=stamp(capturedAt,1250);
 const age=Date.parse(serverNow)-Date.parse(capturedAt);view.status=age<0||age>120000?'stale':'fresh';
 if(phase==='idle'){s.perfDisk.readOperationsPerSecond=observedWindowsStorageIOMetric(0);s.perfDisk.readLatencySeconds=unavailableWindowsStorageIOMetric('windows_storage_io_idle');s.perfDisk.writeLatencySeconds=observedWindowsStorageIOMetric(0);summarizeWindowsStorageIO(s);}
 if(phase==='partial'){s.perfDisk.readBytesPerSecond=unavailableWindowsStorageIOMetric('windows_storage_io_counter_missing');s.perfDisk.writeBytesPerSecond=unavailableWindowsStorageIOMetric('windows_storage_io_counter_reset');s.perfDisk.averageQueueLength=unavailableWindowsStorageIOMetric('windows_storage_io_invalid_timebase');summarizeWindowsStorageIO(s);}
 if(phase==='retained'){
  if(!Number.isFinite(Date.parse(retainedCapturedAt))||Date.parse(retainedCapturedAt)>=Date.parse(capturedAt))throw new Error('Invalid synthetic retained IO capture');
  const old=structuredClone(s);old.collectedAt=retainedCapturedAt;old.generationId=`sample_${'b'.repeat(32)}`;old.perfDisk.sampleStartedAt=stamp(retainedCapturedAt,250);old.perfDisk.sampleEndedAt=stamp(retainedCapturedAt,1250);
  Object.assign(s,unavailableWindowsStorageIO(),{collectedAt:capturedAt,generationId:view.snapshot.generationId});
  if(Date.parse(serverNow)-Date.parse(retainedCapturedAt)<86400000)view.retainedContext={storageIO:old};
 }
 const reasons={denied:'windows_storage_io_access_denied',unsupported:'windows_storage_io_unsupported_platform',timeout:'windows_storage_io_budget_exhausted'};
 if(reasons[phase])Object.assign(s,unavailableWindowsStorageIO(reasons[phase]),{collectedAt:capturedAt,generationId:view.snapshot.generationId});
 if(phase==='future'){s.perfDisk.sampleStartedAt=serverNow;s.perfDisk.sampleEndedAt=stamp(serverNow,1000);}
 if(phase==='legacy')delete view.storageIO;
 if(phase==='revoked'||age>=86400000){view.status=phase==='revoked'?'revoked':'unavailable';view.snapshot=null;delete view.storageIO;delete view.storageContext;delete view.volumes;delete view.retainedContext;}
 if(!validWindowsInventoryView(view,view.deviceId))throw new Error('Invalid synthetic Windows IO fixture');
 return view;
}
export async function windowsStorageIOBrowserCase({page,expect,base,shot}){
 const capturedAt='2026-10-11T12:00:00Z',initial=Date.parse(capturedAt)+10000;
 let phase='observed',retainedCapturedAt='2026-10-11T11:00:00Z',authenticated=true;
 const external=[],writes=[],reads=[];
 await page.clock.install({time:new Date(initial)});await page.clock.pauseAt(new Date(initial));
 const prefix='/api/devices/'+windowsDeviceId,fulfill=(route,body,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(body)});
 await page.route('**/*',async route=>{
  const req=route.request(),url=new URL(req.url());if(url.origin!==base){external.push('external');return route.abort('blockedbyclient');}
  if(!url.pathname.startsWith('/api/'))return route.continue();
  const now=new Date(await page.evaluate(()=>Date.now())).toISOString();
  if(url.pathname==='/api/auth/session')return fulfill(route,{mode:'lan',transport:'http',insecureTestMode:true,transportWarning:'unencrypted_lan_test',authenticationRequired:true,authenticated,csrfToken:authenticated?'invented-fixture-csrf':null,serverNow:now,expiresAt:authenticated?stamp(capturedAt,3600000):null,expiresInSeconds:authenticated?3600:null,loginMode:'shared',actorId:null,capabilities:authenticated?['read']:[]});
  if(url.pathname==='/api/session')return fulfill(route,{csrfToken:'invented-fixture-csrf'});
  if(url.pathname===prefix+'/windows-full-processes/query'&&req.method()==='POST')return fulfill(route,{error:{code:'synthetic_unavailable'}},404);
  if(req.method()!=='GET'){writes.push(url.pathname);return route.abort('blockedbyclient');}
  if(url.pathname===prefix)return fulfill(route,windowsDevice());
  if(url.pathname===prefix+'/windows-inventory'){reads.push(phase);if(phase==='session'){authenticated=false;return fulfill(route,{error:{code:'operator_auth_required'}},401);}return fulfill(route,windowsStorageIOBrowserFixture({serverNow:now,capturedAt,phase,retainedCapturedAt}));}
  if(url.pathname==='/api/devices')return fulfill(route,[windowsDevice()]);
  if(url.pathname.startsWith('/api/'))return fulfill(route,{error:{code:'synthetic_unavailable'}},404);
  return route.continue();
 });
 const panel=page.locator('.windows-storage-io'),current=panel.first(),details=()=>current.locator('.windows-storage-io-details');
 const mount=async locale=>{await page.goto(base+'/#/devices');await page.goto(base+'/#/devices/'+windowsDeviceId);await page.getByRole('tab',{name:locale==='de'?'Inventar':'Inventory',exact:true}).click();await page.getByRole('tab',{name:locale==='de'?'Speicher':'Storage',exact:true}).click();};
 const refresh=async locale=>{await page.getByRole('button',{name:locale==='de'?'Windows-Inventar aktualisieren':'Refresh Windows inventory',exact:true}).click();};
 stage='mount';await page.goto(base+'/#/devices/'+windowsDeviceId);await expect(page.locator('.app-shell')).toBeVisible();
 for(const locale of ['en','de'])for(const width of [1440,390]){
  const de=locale==='de';await page.setViewportSize({width,height:width===390?844:1000});await page.getByLabel(/Language|Sprache/).selectOption(locale);phase='observed';await mount(locale);
  stage='summary';await expect(current).toBeVisible();await expect(current).toContainText(de?'12.582.912 B/s':'12,582,912 B/s');await expect(current).toContainText(de?'1,25 ms':'1.25 ms');await expect(current).toContainText(de?'120,5 Vorgänge/s':'120.5 ops/s');await expect(current).toContainText(de?'Am Messende ausstehend':'Outstanding at sample end');await expect(current).toContainText(de?'Einschließlich Anfragen in Bearbeitung':'Includes requests in service');await expect(current.locator('time').first()).toHaveAttribute('datetime',stamp(capturedAt,250));await expect(current.locator('time').last()).toHaveAttribute('datetime',stamp(capturedAt,1250));await expect(details()).not.toHaveAttribute('open');
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth&&document.body.scrollWidth<=innerWidth)).toBe(true);await current.evaluate(el=>el.scrollIntoView({block:'start',behavior:'instant'}));await shot(page,`synthetic-windows-storage-io-summary-${width}-${locale}`,windowsStorageIODisclosure);
  stage='details';await details().locator('summary').click();await expect(details()).toContainText('PDH PhysicalDisk(_Total)');await expect(details()).toContainText(de?'keine einzelnen Datenträger':'does not identify individual disks');await expect(details()).toContainText('MSFT_PhysicalDisk');await expect(current.locator('a,img,iframe,button,input,form')).toHaveCount(0);await details().evaluate(el=>el.scrollIntoView({block:'start',behavior:'instant'}));await shot(page,`synthetic-windows-storage-io-details-${width}-${locale}`,windowsStorageIODisclosure);
  stage='navigation';await page.getByRole('tab',{name:'Hostname',exact:true}).click();await expect(panel).toHaveCount(0);await page.getByRole('tab',{name:de?'Speicher':'Storage',exact:true}).click();await expect(details()).not.toHaveAttribute('open');
  stage='idle';phase='idle';await refresh(locale);await expect(current).toContainText(de?'Inaktiv · keine Vorgänge':'Idle · no operations');await expect(current).toContainText('0 ms');
  stage='partial';phase='partial';await refresh(locale);await expect(current).toContainText(de?'Zähler zurückgesetzt':'Counter reset');await expect(current).toContainText(de?'Ungültige Messzeitbasis':'Invalid sample timebase');
  for(const [mode,en,deText] of [['denied','Access denied','Zugriff verweigert'],['unsupported','Source unsupported','Quelle nicht unterstützt']]){stage=mode;phase=mode;await refresh(locale);await expect(current).toContainText(de?deText:en);await expect(current).not.toContainText('0 B/s');}
  stage='retained';phase='retained';await refresh(locale);await expect(panel).toHaveCount(2);const previous=page.locator('details.windows-inventory-bounds').filter({has:page.locator('.windows-storage-io')});await expect(previous).not.toHaveAttribute('open');await expect(current).toContainText(de?'Messzeitlimit erreicht':'Sample time limit reached');await expect(current).not.toContainText('120.5 ops/s');await current.evaluate(el=>el.scrollIntoView({block:'start',behavior:'instant'}));await shot(page,`synthetic-windows-storage-io-failure-${width}-${locale}`,windowsStorageIODisclosure);
  await previous.locator('>summary').click();await expect(panel.last()).toBeVisible();await expect(panel.last().locator('time').last()).toHaveAttribute('datetime',stamp(retainedCapturedAt,1250));await expect(panel.last()).toContainText(de?'Veraltete Messung':'Stale sample');await expect(panel.last()).toContainText(de?'3.608 s':'3,608 s');await panel.last().evaluate(el=>el.scrollIntoView({block:'start',behavior:'instant'}));await shot(page,`synthetic-windows-storage-io-retained-${width}-${locale}`,windowsStorageIODisclosure);
 }
 await page.getByLabel(/Language|Sprache/).selectOption('en');
 stage='legacy';phase='legacy';await refresh('en');await expect(page.locator('.windows-storage-io-absent')).toHaveText('No disk I/O sample reported for this capture.');
 stage='expiry';phase='retained';retainedCapturedAt=new Date(initial-86400000+500).toISOString();await refresh('en');await expect(panel).toHaveCount(2);await page.clock.runFor(1000);await expect(panel).toHaveCount(1);await expect(current).toContainText('Sample time limit reached');
 stage='focus';phase='observed';await refresh('en');await expect(current).toContainText('120.5 ops/s');await page.evaluate(()=>window.dispatchEvent(new Event('blur')));await expect(panel).toHaveCount(0);await page.evaluate(()=>window.dispatchEvent(new Event('focus')));await expect(current).toContainText('120.5 ops/s');
 stage='revoked';phase='revoked';await refresh('en');await expect(panel).toHaveCount(0);
 stage='session';phase='observed';await refresh('en');await expect(current).toBeVisible();phase='session';await refresh('en');await expect(panel).toHaveCount(0);await expect(page.getByLabel('Operator password',{exact:true})).toBeVisible();
 expect(external).toEqual([]);expect(writes).toEqual([]);expect(reads.length).toBeGreaterThan(20);stage='complete';return{screens:16,sourceInterop:true,transport:'intercepted invented operator session and inventory',liveAuthenticationAcceptance:false,liveStoreAcceptance:false,nativeAcceptance:false};
}
export function requireWindowsStorageIOEvidence(rows,sourceSha){
 const fail=()=>{throw new Error('Missing or inconsistent Windows disk IO screenshots');};
 if(!Array.isArray(rows)||rows.length!==16||!/^[a-f0-9]{40}$/.test(sourceSha??''))fail();
 for(const kind of ['summary','details','failure','retained'])for(const locale of ['en','de'])for(const width of [1440,390]){
  const matches=rows.filter(row=>row.file===`synthetic-windows-storage-io-${kind}-${width}-${locale}.png`);if(matches.length!==1)fail();const row=matches[0];
  if(row.sourceSha!==sourceSha||row.test!==windowsStorageIOCaseName||row.locale!==locale||row.viewport?.width!==width||row.viewport?.height!==(width===390?844:1000)||row.fullPage!==false||row.publicSafe!==true||row.fixtureDisclosure!==windowsStorageIODisclosure)fail();
 }
 return{summary:4,details:4,failure:4,retained:4};
}
