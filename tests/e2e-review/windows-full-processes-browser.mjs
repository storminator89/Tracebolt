/** Actual Go/SQLite page vectors, intercepted at the browser transport seam.
 * This is UI interoperability evidence, not a live ledger or native host gate. */
import fs from 'node:fs';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {build}=require('esbuild');
const bundled=await build({stdin:{contents:"export {validFullProcessesPage,validFullProcessesSearch,validFullProcessesSort,validFullProcessesCursor} from './windows-full-processes-types'; export {windowsDevice,windowsView} from './windows-inventory-fixture';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {validFullProcessesPage,validFullProcessesSearch,validFullProcessesSort,validFullProcessesCursor,windowsDevice,windowsView}=await import('data:text/javascript;base64,'+Buffer.from(bundled.outputFiles[0].text).toString('base64'));
const vectors=JSON.parse(fs.readFileSync(path.join(root,'web/src/windows-full-processes-store-fixture.json'),'utf8'));
export const windowsFullProcessesCaseName='Complete process inventory UI with actual Go SQLite vectors and synthetic transport';
export const windowsFullProcessesDisclosure='Real loopback HTTP-test login and production UI; intercepted invented device data and actual exported Go SQLite process pages. Ordinary vectors advance only response time and preserve source, receipt and cursor times; the expiry scenario injects synthetic response, authority and cursor deadlines. UI interoperability evidence, not live manager/store acceptance. No native Windows read, local grant, host or service action, external request or AI export.';
let stage='setup';
const stages=new Set(['setup','login','pages','search','duplicates','pending','navigation','focus','failed-attempt','restart','expiry','session','complete']);
export const windowsFullProcessesFailureStage=()=>stages.has(stage)?stage:'setup';
export function windowsFullProcessesVector(name,elapsed=0){
 const vector=vectors.find(value=>value.name===name);
 if(!vector||!Number.isFinite(elapsed)||elapsed<0||elapsed>600000)throw new Error('Invalid process vector selection');
 const result=structuredClone(vector);result.page.serverNow=new Date(Date.parse(result.page.serverNow)+elapsed).toISOString();
 if(!validFullProcessesPage(result.page,result.page.deviceId,result.query,result.page.offset))throw new Error('Invalid Go process page vector');
 return result;
}
export function windowsFullProcessesFixtureQuery({pathname,search='',method,headers,raw},prefix){
 if(pathname!==prefix+'/windows-full-processes/query'||search||method!=='POST'||!headers?.['x-csrf-token']||typeof raw!=='string'||Buffer.byteLength(raw)>8192)return null;
 let query;try{query=JSON.parse(raw);}catch{return null;}
 if(!query||Array.isArray(query)||typeof query!=='object'||Object.keys(query).sort().join(',')!=='cursor,limit,search,sort'||JSON.stringify(query)!==raw||!validFullProcessesSearch(query.search)||!validFullProcessesSort(query.sort)||!Number.isSafeInteger(query.limit)||query.limit<1||query.limit>100||!validFullProcessesCursor(query.cursor))return null;
 return query;
}
export function windowsFullProcessesAbsentPage(deviceId,query,serverNow){
 const page={schemaVersion:'tracebolt.windows-full-processes-page.v1',deviceId,serverNow,status:'not_configured',authorityUntil:null,grantId:null,grantRevision:null,complete:null,latestAttempt:null,...query,offset:0,matchingCount:0,rows:[],nextCursor:'',cursorExpiresAt:null};delete page.cursor;
 if(!validFullProcessesPage(page,deviceId,query,0))throw new Error('Invalid unconfigured process fixture');return page;
}
async function currentToken(page,base,request){
 const session=await page.request.get(new URL('/api/session',base).href,{maxRedirects:0,timeout:5000});
 try{const value=await session.json();if(session.status()!==200||typeof value.csrfToken!=='string'||!value.csrfToken||value.csrfToken!==request.headers()['x-csrf-token'])throw new Error('Invalid process fixture session');}finally{await session.dispose();}
}
export async function windowsFullProcessesLegacyRead({route,page,base,prefix,serverNow}){
 const request=route.request(),url=new URL(request.url()),query=windowsFullProcessesFixtureQuery({pathname:url.pathname,search:url.search,method:request.method(),headers:request.headers(),raw:request.postData()},prefix);
 if(url.origin!==base||!query)throw new Error('Unexpected process fixture query');await currentToken(page,base,request);
 return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(windowsFullProcessesAbsentPage(prefix.split('/').at(-1),query,serverNow))});
}
export async function windowsFullProcessesBrowserCase({page,expect,base,login,shot}){
 stage='login';await login(page);
 const first=windowsFullProcessesVector('first2051'),deviceId=first.page.deviceId,prefix='/api/devices/'+deviceId,queryPath=prefix+'/windows-full-processes/query',began=Date.now(),queries=[],unexpected=[],external=[];
 let mode='normal',hold=null;
 const fulfill=(route,body,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(body)});
 await page.route('**/*',async route=>{
  const request=route.request(),url=new URL(request.url());
  if(url.origin!==base){external.push('external');return route.abort('blockedbyclient');}
  if(url.pathname===queryPath){
   const query=windowsFullProcessesFixtureQuery({pathname:url.pathname,search:url.search,method:request.method(),headers:request.headers(),raw:request.postData()},prefix);
   if(!query){unexpected.push('invalid-query');return route.abort('blockedbyclient');}
   await currentToken(page,base,request);queries.push(query);
   if(mode==='restart')return fulfill(route,{error:{code:'windows_full_processes_restart_required'}},409);
   if(mode==='session')return fulfill(route,{error:{code:'operator_auth_required'}},401);
   const name=mode==='duplicates'?'duplicateNamesUnavailableZero':mode==='failed-attempt'?'priorCompleteLatestFailed':query.search?'search2049':query.cursor?'second100':'first2051';
   const vector=windowsFullProcessesVector(name,Date.now()-began);
   if(JSON.stringify(query)!==JSON.stringify(vector.query)){unexpected.push('unsupported-vector-query');return route.abort('blockedbyclient');}
   if(mode==='expiry'){vector.page.serverNow=new Date(Date.parse(vector.page.complete.manifest.expiresAt)-750).toISOString();vector.page.cursorExpiresAt=vector.page.complete.manifest.expiresAt;vector.page.authorityUntil=vector.page.complete.manifest.expiresAt;}
   if(hold){const pending=hold;hold=null;pending.arrived();await pending.promise;try{return await fulfill(route,vector.page);}catch{return;}}
   return fulfill(route,vector.page);
  }
  if(request.method()!=='GET'&&!['/api/auth/login','/api/auth/logout'].includes(url.pathname)){unexpected.push('unexpected-write');return route.abort('blockedbyclient');}
  if(url.pathname===prefix){const device=windowsDevice();device.id=deviceId;device.agentCertificate.expiresAt='2027-02-15T08:00:00Z';return fulfill(route,device);}
  if(url.pathname===prefix+'/windows-inventory'){const view=windowsView();view.deviceId=deviceId;view.serverNow=new Date(Date.parse(view.serverNow)+Date.now()-began).toISOString();return fulfill(route,view);}
  if(url.pathname.startsWith(prefix+'/'))return fulfill(route,{error:{code:'synthetic_unavailable'}},404);
  return route.continue();
 });
 const panel=page.locator('.windows-full-processes'),rows=panel.locator('.windows-inventory-table-wrap').first().locator('tbody tr');
 const mount=async locale=>{await page.goto(base+'/#/devices');await expect(page.locator('.device-page')).toHaveCount(0);await page.goto(`${base}/#/devices/${deviceId}`);await page.getByRole('tab',{name:locale==='de'?'Inventar':'Inventory',exact:true}).click();};
 for(const locale of ['en','de'])for(const width of [1440,390]){
  const de=locale==='de';await page.setViewportSize({width,height:width===390?844:1000});await page.getByLabel(/Language|Sprache/).selectOption(locale);mode='normal';await mount(locale);
  stage='pages';await expect(rows).toHaveCount(100);await expect(rows.first()).toHaveAttribute('data-snapshot-pid','0');await expect(panel).toContainText('2051');await expect(panel.locator('.windows-full-processes-details')).not.toHaveAttribute('open');await expect(panel.locator('.windows-full-processes-preview')).not.toHaveAttribute('open');
  await expect(panel.locator('.windows-full-processes-preview>summary')).toContainText('128');
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth&&document.body.scrollWidth<=innerWidth)).toBe(true);
  if(width===390){const cell=rows.first().locator('td').nth(1);expect(await cell.evaluate(el=>getComputedStyle(el,'::before').content)).toBe(JSON.stringify(de?'Snapshot-PID':'Snapshot PID'));}
  await panel.scrollIntoViewIfNeeded();await shot(page,`synthetic-windows-full-processes-${width}-${locale}`,windowsFullProcessesDisclosure);
  await panel.getByRole('button',{name:de?'Nächste Prozessseite':'Next process page',exact:true}).click();await expect(rows.first()).toHaveAttribute('data-snapshot-pid','100');await expect(rows).toHaveCount(100);
  await panel.getByRole('button',{name:de?'Vorherige Prozessseite':'Previous process page',exact:true}).click();await expect(rows.first()).toHaveAttribute('data-snapshot-pid','0');
  stage='search';await panel.getByRole('searchbox',{name:de?'Erfasste Prozesse durchsuchen':'Search captured processes',exact:true}).fill(windowsFullProcessesVector('search2049').query.search);await panel.getByRole('button',{name:de?'Anwenden':'Apply',exact:true}).click();await expect(rows).toHaveCount(1);await expect(rows.first()).toContainText('InventedProcess02049');await expect(panel.locator('img,a,script')).toHaveCount(0);await shot(page,`synthetic-windows-full-processes-search-${width}-${locale}`,windowsFullProcessesDisclosure);
 }
 await page.getByLabel(/Language|Sprache/).selectOption('en');
 stage='duplicates';mode='duplicates';await mount('en');await expect(rows).toHaveCount(windowsFullProcessesVector('duplicateNamesUnavailableZero').page.rows.length);await expect(rows.first()).toHaveAttribute('data-snapshot-pid','0');await expect(rows.first()).toContainText('Unavailable');
 stage='failed-attempt';mode='failed-attempt';await mount('en');await expect(rows).toHaveCount(100);await expect(panel).toContainText('Showing earlier capture');await expect(panel.locator('.windows-full-processes-age time')).toHaveAttribute('datetime',first.page.complete.manifest.captureStartedAt);
 stage='pending';mode='normal';await mount('en');await expect(rows).toHaveCount(100);let release,arrived;const received=new Promise(resolve=>{arrived=resolve;});hold={arrived,promise:new Promise(resolve=>{release=resolve;})};await panel.getByRole('button',{name:'Refresh process inventory',exact:true}).click();await received;await expect(panel.locator('[data-snapshot-pid]')).toHaveCount(0);await expect(panel.getByRole('searchbox',{name:'Search captured processes',exact:true})).toHaveCount(0);
 stage='navigation';await page.getByRole('tab',{name:'Hostname',exact:true}).click();release();await expect(panel).toHaveCount(0);await page.getByRole('tab',{name:'Processes',exact:true}).click();await expect(rows).toHaveCount(100);expect(queries.at(-1).cursor).toBe('');
 stage='focus';await page.evaluate(()=>window.dispatchEvent(new Event('blur')));await expect(panel.locator('[data-snapshot-pid]')).toHaveCount(0);await page.evaluate(()=>window.dispatchEvent(new Event('focus')));await expect(rows).toHaveCount(100);expect(queries.at(-1).cursor).toBe('');
 stage='restart';mode='restart';await panel.getByRole('button',{name:'Refresh process inventory',exact:true}).click();await expect(panel.getByRole('alert')).toContainText('Reload latest');await expect(panel.locator('[data-snapshot-pid]')).toHaveCount(0);mode='normal';await panel.getByRole('button',{name:'Reload latest process capture',exact:true}).click();await expect(rows).toHaveCount(100);expect(queries.at(-1).cursor).toBe('');
 stage='expiry';mode='expiry';await mount('en');await expect(panel.getByRole('alert')).toContainText('expired');await expect(panel.locator('[data-snapshot-pid]')).toHaveCount(0);
 stage='session';mode='normal';await mount('en');await expect(rows).toHaveCount(100);mode='session';await panel.getByRole('button',{name:'Refresh process inventory',exact:true}).click();await expect(page.getByLabel('Operator password',{exact:true})).toBeVisible();await expect(panel).toHaveCount(0);
 expect(external).toEqual([]);expect(unexpected).toEqual([]);stage='complete';return{screens:8,sourceInterop:true,transport:'intercepted Go SQLite vectors',liveStoreAcceptance:false,nativeAcceptance:false};
}
