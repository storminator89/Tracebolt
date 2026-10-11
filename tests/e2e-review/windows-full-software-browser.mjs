/** Actual Go/SQLite page vectors, intercepted at the browser transport seam.
 * This is UI interoperability evidence, not a live ledger or native host gate. */
import fs from 'node:fs';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {build}=require('esbuild');
const bundled=await build({stdin:{contents:"export {validFullSoftwarePage,validFullSoftwareSearch,validFullSoftwareSort,validFullSoftwareCursor} from './windows-full-software-types'; export {windowsDevice,windowsView} from './windows-inventory-fixture';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {validFullSoftwarePage,validFullSoftwareSearch,validFullSoftwareSort,validFullSoftwareCursor,windowsDevice,windowsView}=await import('data:text/javascript;base64,'+Buffer.from(bundled.outputFiles[0].text).toString('base64'));
const vectors=JSON.parse(fs.readFileSync(path.join(root,'web/src/windows-full-software-store-fixture.json'),'utf8'));
export const windowsFullSoftwareCaseName='Complete machine software UI with actual Go SQLite vectors and synthetic transport';
export const windowsFullSoftwareDisclosure='Real loopback HTTP-test login and production UI; intercepted invented device data and actual exported Go SQLite software pages. Ordinary vectors advance only response time and preserve source, receipt and cursor times; the expiry scenario injects synthetic response, authority and cursor deadlines. UI interoperability evidence, not live manager/store acceptance. No native Windows read, local grant, host or service action, external request or AI export.';
let stage='setup';
const stages=new Set(['setup','login','pages','search','duplicates','byte-short','pending','navigation','focus','failed-attempt','restart','expiry','session','complete']);
export const windowsFullSoftwareFailureStage=()=>stages.has(stage)?stage:'setup';
export function windowsFullSoftwareVector(name,elapsed=0){
 const vector=vectors.find(value=>value.name===name);
 if(!vector||!Number.isFinite(elapsed)||elapsed<0||elapsed>600000)throw new Error('Invalid software vector selection');
 const result=structuredClone(vector);result.page.serverNow=new Date(Date.parse(result.page.serverNow)+elapsed).toISOString();
 if(!validFullSoftwarePage(result.page,result.page.deviceId,result.query,result.page.offset))throw new Error('Invalid Go software page vector');
 return result;
}
export function windowsFullSoftwareFixtureQuery({pathname,search='',method,headers,raw},prefix){
 if(pathname!==prefix+'/windows-full-software/query'||search||method!=='POST'||!headers?.['x-csrf-token']||typeof raw!=='string'||Buffer.byteLength(raw)>8192)return null;
 let query;try{query=JSON.parse(raw);}catch{return null;}
 if(!query||Array.isArray(query)||typeof query!=='object'||Object.keys(query).sort().join(',')!=='cursor,limit,search,sort'||JSON.stringify(query)!==raw||!validFullSoftwareSearch(query.search)||!validFullSoftwareSort(query.sort)||!Number.isSafeInteger(query.limit)||query.limit<1||query.limit>100||!validFullSoftwareCursor(query.cursor))return null;
 return query;
}
export function windowsFullSoftwareAbsentPage(deviceId,query,serverNow){
 const page={schemaVersion:'tracebolt.windows-full-software-page.v1',deviceId,serverNow,status:'not_configured',authorityUntil:null,grantId:null,grantRevision:null,complete:null,latestAttempt:null,...query,offset:0,matchingCount:0,rows:[],nextCursor:'',cursorExpiresAt:null};delete page.cursor;
 if(!validFullSoftwarePage(page,deviceId,query,0))throw new Error('Invalid unconfigured software fixture');return page;
}
async function currentToken(page,base,request){
 const session=await page.request.get(new URL('/api/session',base).href,{maxRedirects:0,timeout:5000});
 try{const value=await session.json();if(session.status()!==200||typeof value.csrfToken!=='string'||!value.csrfToken||value.csrfToken!==request.headers()['x-csrf-token'])throw new Error('Invalid software fixture session');}finally{await session.dispose();}
}
export async function windowsFullSoftwareLegacyRead({route,page,base,prefix,serverNow}){
 const request=route.request(),url=new URL(request.url()),query=windowsFullSoftwareFixtureQuery({pathname:url.pathname,search:url.search,method:request.method(),headers:request.headers(),raw:request.postData()},prefix);
 if(url.origin!==base||!query)throw new Error('Unexpected software fixture query');await currentToken(page,base,request);
 return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(windowsFullSoftwareAbsentPage(prefix.split('/').at(-1),query,serverNow))});
}
export async function windowsFullSoftwareBrowserCase({page,expect,base,login,shot}){
 stage='login';await login(page);
 const first=windowsFullSoftwareVector('first2051'),deviceId=first.page.deviceId,prefix='/api/devices/'+deviceId,queryPath=prefix+'/windows-full-software/query',began=Date.now(),queries=[],unexpected=[],external=[];
 let mode='normal',hold=null;
 const fulfill=(route,body,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(body)});
 await page.route('**/*',async route=>{
  const request=route.request(),url=new URL(request.url());
  if(url.origin!==base){external.push('external');return route.abort('blockedbyclient');}
  if(url.pathname===queryPath){
   const query=windowsFullSoftwareFixtureQuery({pathname:url.pathname,search:url.search,method:request.method(),headers:request.headers(),raw:request.postData()},prefix);
   if(!query){unexpected.push('invalid-query');return route.abort('blockedbyclient');}
   await currentToken(page,base,request);queries.push(query);
   if(mode==='restart')return fulfill(route,{error:{code:'windows_full_software_restart_required'}},409);
   if(mode==='session')return fulfill(route,{error:{code:'operator_auth_required'}},401);
   const name=mode==='duplicates'?'duplicatesMissing':mode==='byte-short'?(query.cursor?'byteShortContinuation':'byteShort'):mode==='failed-attempt'?'priorCompleteLatestFailed':query.search?'unicode2049':'first2051';
   const vector=windowsFullSoftwareVector(name,Date.now()-began);
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
 const panel=page.locator('.windows-full-software'),rows=panel.locator('tbody tr');
 const mount=async(locale)=>{await page.goto(base+'/#/devices');await expect(page.locator('.device-page')).toHaveCount(0);await page.goto(`${base}/#/devices/${deviceId}`);await page.getByRole('tab',{name:locale==='de'?'Inventar':'Inventory',exact:true}).click();await page.getByRole('tab',{name:'Software',exact:true}).click();};
 for(const locale of ['en','de'])for(const width of [1440,390]){
  const de=locale==='de';await page.setViewportSize({width,height:width===390?844:1000});await page.getByLabel(/Language|Sprache/).selectOption(locale);mode='normal';await mount(locale);
  stage='pages';await expect(rows).toHaveCount(100);await expect(rows.first()).toContainText('InventedSoftware00000');await expect(panel).toContainText('2051');await expect(panel.locator('.windows-full-software-details')).not.toHaveAttribute('open');await expect(page.locator('.windows-full-software-preview')).not.toHaveAttribute('open');
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth&&document.body.scrollWidth<=innerWidth)).toBe(true);
  if(width===390){const cell=rows.first().locator('td').first();expect(await cell.evaluate(el=>getComputedStyle(el,'::before').content)).toBe(JSON.stringify('Name'));}
  await panel.scrollIntoViewIfNeeded();await shot(page,`synthetic-windows-full-software-${width}-${locale}`,windowsFullSoftwareDisclosure);
  stage='search';await panel.getByRole('searchbox').fill(windowsFullSoftwareVector('unicode2049').query.search);await panel.getByRole('button',{name:de?'Anwenden':'Apply',exact:true}).click();await expect(rows).toHaveCount(1);await expect(rows.first()).toContainText('InventedSoftware02049');await expect(panel.locator('img,a,script')).toHaveCount(0);await shot(page,`synthetic-windows-full-software-search-${width}-${locale}`,windowsFullSoftwareDisclosure);
 }
 await page.getByLabel(/Language|Sprache/).selectOption('en');
 stage='duplicates';mode='duplicates';await mount('en');await expect(rows).toHaveCount(4);await expect(panel.getByText('Unavailable',{exact:true})).toHaveCount(3);await expect(panel.getByText('Empty value',{exact:true})).toHaveCount(3);
 stage='byte-short';mode='byte-short';await mount('en');await expect(rows).toHaveCount(26);await panel.getByRole('button',{name:'Next software page',exact:true}).click();await expect(rows.first()).toHaveAttribute('data-registration-id',windowsFullSoftwareVector('byteShortContinuation').page.rows[0].registrationId);await expect(rows).toHaveCount(26);
 stage='failed-attempt';mode='failed-attempt';await mount('en');await expect(rows).toHaveCount(100);await expect(panel).toContainText('Showing earlier capture');
 stage='pending';mode='normal';await mount('en');await expect(rows).toHaveCount(100);let release,arrived;const received=new Promise(resolve=>{arrived=resolve;});hold={arrived,promise:new Promise(resolve=>{release=resolve;})};await panel.getByRole('button',{name:'Refresh software page',exact:true}).click();await received;await expect(rows).toHaveCount(0);await expect(panel.getByRole('searchbox')).toHaveCount(0);
 stage='navigation';await page.getByRole('tab',{name:'Hostname',exact:true}).click();release();await expect(panel).toHaveCount(0);await page.getByRole('tab',{name:'Software',exact:true}).click();await expect(rows).toHaveCount(100);expect(queries.at(-1).cursor).toBe('');
 stage='focus';await page.evaluate(()=>window.dispatchEvent(new Event('blur')));await expect(rows).toHaveCount(0);await page.evaluate(()=>window.dispatchEvent(new Event('focus')));await expect(rows).toHaveCount(100);expect(queries.at(-1).cursor).toBe('');
 stage='restart';mode='restart';await panel.getByRole('button',{name:'Refresh software page',exact:true}).click();await expect(panel.getByRole('alert')).toContainText('Reload latest');await expect(rows).toHaveCount(0);mode='normal';await panel.getByRole('button',{name:'Reload latest software capture',exact:true}).click();await expect(rows).toHaveCount(100);expect(queries.at(-1).cursor).toBe('');
 stage='expiry';mode='expiry';await mount('en');await expect(panel.getByRole('alert')).toContainText('expired');await expect(rows).toHaveCount(0);await expect(panel.getByRole('searchbox')).toHaveCount(0);
 stage='session';mode='normal';await mount('en');await expect(rows).toHaveCount(100);mode='session';await panel.getByRole('button',{name:'Refresh software page',exact:true}).click();await expect(page.getByLabel('Operator password',{exact:true})).toBeVisible();await expect(panel).toHaveCount(0);
 expect(external).toEqual([]);expect(unexpected).toEqual([]);stage='complete';return{screens:8,sourceInterop:true,transport:'intercepted Go SQLite vectors',liveStoreAcceptance:false,nativeAcceptance:false};
}
