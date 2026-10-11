import {windowsFullProcessesFixtureQuery} from './windows-full-processes-browser.mjs';
/** Source-only browser gate for real SQLite-backed operator pages. Native Windows
 * capture, endpoint consent and host/service operations are outside this gate. */
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {windowsFullSoftwareFixtureQuery} from './windows-full-software-browser.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {build}=require('esbuild');
const bundled=await build({stdin:{contents:"export {validFullServicesPage,validFullServicesSearch,validFullServicesSort} from './windows-full-services-types';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {validFullServicesPage,validFullServicesSearch,validFullServicesSort}=await import('data:text/javascript;base64,'+Buffer.from(bundled.outputFiles[0].text).toString('base64'));
export const windowsFullServicesCaseName='Real SQLite-backed complete Windows service operator paging with synthetic generations';
export const windowsFullServicesDisclosure='Real loopback HTTP-test login, production operator API and SQLite generation/cursor authority with invented Win32 services, backdated synthetic enrollment/consent and an original near-expiry capture. Live operator sessions and source-expiry checks use real time. Source-only browser evidence; no native Windows read, local grant, host or service action, external request or AI export.';
const stages=new Set(['setup','login','pages','search','sort','cursor-binding','repeat','navigation','visibility','replacement','failed-attempt','byte-short','empty','disabled','expiry','session','revoked','revoked-control','revoked-refresh','revoked-alert','revoked-clear','final-external','final-writes','final-query-limits','final-storage','final-cursor-count','complete']);
let stage='setup';
export const windowsFullServicesFailureStage=()=>stages.has(stage)?stage:'setup';
export function windowsFullServicesFixtureQuery({pathname,search='',method,headers,raw},prefix){
 if(pathname!==prefix+'/windows-full-services/query'||search||method!=='POST'||!headers?.['x-csrf-token']||typeof raw!=='string'||Buffer.byteLength(raw)>8192)return null;
 let query;try{query=JSON.parse(raw);}catch{return null;}
 if(!query||Array.isArray(query)||typeof query!=='object'||Object.keys(query).sort().join(',')!=='cursor,limit,search,sort'||JSON.stringify(query)!==raw||!validFullServicesSearch(query.search)||!validFullServicesSort(query.sort)||!Number.isSafeInteger(query.limit)||query.limit<1||query.limit>100||typeof query.cursor!=='string'||query.cursor.length>4096||!/^[a-zA-Z0-9_.-]*$/.test(query.cursor))return null;
 return query;
}
export function windowsFullServicesAbsentPage(deviceId,query,serverNow){
 const page={schemaVersion:'tracebolt.windows-full-services-page.v1',deviceId,serverNow,status:'not_configured',authorityUntil:null,grantId:null,grantRevision:null,complete:null,latestAttempt:null,...query,offset:0,matchingCount:0,rows:[],nextCursor:'',cursorExpiresAt:null};
 delete page.cursor;
 if(!validFullServicesPage(page,deviceId,query,0))throw new Error('Invalid unconfigured full-services fixture');
 return page;
}
/** Older intercepted Windows preview cases have no full-generation scope. This
 * exact read seam verifies the real current session token before returning only
 * a truthful unconfigured status. It never intercepts the new real-store gate. */
export async function windowsFullServicesLegacyRead({route,page,base,prefix,serverNow}){
 const request=route.request(),url=new URL(request.url());
 const query=windowsFullServicesFixtureQuery({pathname:url.pathname,search:url.search,method:request.method(),headers:request.headers(),raw:request.postData()},prefix);
 if(url.origin!==base||!query)throw new Error('Unexpected full-services fixture query');
 const session=await page.request.get(new URL('/api/session',base).href,{maxRedirects:0,timeout:5000});
 try{
  if(session.status()!==200)throw new Error('Unavailable full-services fixture session');
  const value=await session.json();
  if(typeof value.csrfToken!=='string'||!value.csrfToken||value.csrfToken!==request.headers()['x-csrf-token'])throw new Error('Invalid full-services fixture token');
 }finally{await session.dispose();}
 return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(windowsFullServicesAbsentPage(prefix.split('/').at(-1),query,serverNow))});
}
const fixturePath='/__fixture/windows-full-services';
const fixtureActions=new Set(['replace','fail','byte-short','empty','disable','enable','near-expiry','revoke']);
export async function windowsFullServicesFixtureControl(page,base,action=null){
 const url=new URL(fixturePath,base);
 if(url.origin!==base||url.protocol!=='http:'||url.hostname!=='127.0.0.1'||action!==null&&!fixtureActions.has(action))throw new Error('Invalid full-services fixture control');
 let headers={};
 if(action!==null){
  const session=await page.request.get(new URL('/api/session',base).href,{maxRedirects:0,timeout:5000});
  try{const value=await session.json();if(session.status()!==200||typeof value.csrfToken!=='string'||!value.csrfToken)throw new Error();headers={'Origin':base,'X-CSRF-Token':value.csrfToken};}
  catch{throw new Error('Unavailable full-services fixture session');}finally{await session.dispose();}
 }
 const reply=action===null?await page.request.get(url.href,{maxRedirects:0,timeout:5000}):await page.request.post(url.href,{headers,data:{action},maxRedirects:0,timeout:5000});
 try{
  if(reply.status()!==200)throw new Error();const value=await reply.json();
  if(!value||Object.keys(value).sort().join(',')!=='deviceId,firstName,laterName,laterSearch,rowCount'||!/^agent_[a-f0-9]{32}$/.test(value.deviceId)||!Number.isSafeInteger(value.rowCount)||value.rowCount<0||value.rowCount>8192||['firstName','laterName','laterSearch'].some(key=>typeof value[key]!=='string'||value[key].length>1024))throw new Error();
  return value;
 }catch{throw new Error('Invalid full-services fixture response');}finally{await reply.dispose();}
}
export async function windowsFullServicesBrowserCase({page,expect,base,login,shot}){
 stage='login';await login(page);let info=await windowsFullServicesFixtureControl(page,base);
 const prefix='/api/devices/'+info.deviceId,queryPath=prefix+'/windows-full-services/query',external=[],unexpected=[],queries=[];let hold=null,bindingRejects=0;
 await page.route('**/*',async route=>{
  const request=route.request(),url=new URL(request.url());
  if(url.origin!==base){external.push('external');return route.abort('blockedbyclient');}
  if(url.pathname===queryPath){
   const query=windowsFullServicesFixtureQuery({pathname:url.pathname,search:url.search,method:request.method(),headers:request.headers(),raw:request.postData()},prefix);
   if(!query){unexpected.push('invalid-query');return route.abort('blockedbyclient');}
   queries.push({search:query.search,sort:query.sort,limit:query.limit,cursor:query.cursor});
   if(hold){const current=hold;hold=null;const response=await route.fetch({timeout:5000});current.arrived();await current.promise;try{return await route.fulfill({response});}catch{if(!current.canceled)throw new Error('Unexpected held-read failure');return;}}
   return route.continue();
  }
  // Navigation visits Software while retiring a held service page. Its exact
  // protected query is a read, not an unexpected mutation; production still
  // enforces the real session/CSRF and independent software scope.
  if(url.pathname===prefix+'/windows-full-processes/query'){
   const query=windowsFullProcessesFixtureQuery({pathname:url.pathname,search:url.search,method:request.method(),headers:request.headers(),raw:request.postData()},prefix);
   if(!query){unexpected.push('invalid-process-navigation-query');return route.abort('blockedbyclient');}
   return route.continue();
  }
  if(url.pathname===prefix+'/windows-full-software/query'){
   const query=windowsFullSoftwareFixtureQuery({pathname:url.pathname,search:url.search,method:request.method(),headers:request.headers(),raw:request.postData()},prefix);
   if(!query){unexpected.push('invalid-navigation-query');return route.abort('blockedbyclient');}
   return route.continue();
  }
  if(request.method()!=='GET'&&!['/api/auth/login','/api/auth/logout'].includes(url.pathname)){unexpected.push('unexpected-write');return route.abort('blockedbyclient');}
  return route.continue();
 });
 const panel=page.locator('.windows-full-services'),rows=panel.locator('tbody tr');
 const mount=async(locale,empty=false)=>{
  await page.goto(`${base}/#/devices`);await expect(page.locator('.device-page')).toHaveCount(0);
  await page.goto(`${base}/#/devices/${info.deviceId}`);
  await page.getByRole('tab',{name:locale==='de'?'Inventar':'Inventory',exact:true}).click();
  await page.getByRole('tab',{name:locale==='de'?'Dienste':'Services',exact:true}).click();if(empty)await expect(panel).toContainText('Successful complete enumeration returned zero caller-visible Win32 services.');else await expect(panel.getByRole('table')).toBeVisible();
 };
 for(const locale of ['en','de'])for(const width of [1440,390]){
  const de=locale==='de';await page.setViewportSize({width,height:width===390?844:1000});await page.getByLabel(/Language|Sprache/).selectOption(locale);
  info=await windowsFullServicesFixtureControl(page,base,'replace');await mount(locale);
  const next=panel.getByRole('button',{name:de?'Nächste Dienstseite':'Next service page',exact:true}),previous=panel.getByRole('button',{name:de?'Vorherige Dienstseite':'Previous service page',exact:true}),refresh=panel.getByRole('button',{name:de?'Dienstseite aktualisieren':'Refresh service page',exact:true}),apply=panel.getByRole('button',{name:de?'Suche und Sortierung anwenden':'Apply search and sort',exact:true});
  const search=panel.getByRole('searchbox'),sort=panel.getByRole('combobox');
  stage='pages';await expect(rows).toHaveCount(100);await expect(rows.first()).toContainText(info.firstName);await expect(previous).toBeDisabled();
  const capture=await panel.locator('time').evaluateAll(nodes=>nodes.map(node=>node.getAttribute('datetime')));
  for(let pageNumber=1;pageNumber<=7;pageNumber++){await next.click();await expect(rows).toHaveCount(100);await expect(panel).toContainText(de?`Zeilen ${pageNumber*100+1}–${pageNumber*100+100} von 2051 Treffern`:`Rows ${pageNumber*100+1}–${pageNumber*100+100} of 2051 matching`);}
  const eighthFirst=await rows.first().textContent();await previous.click();await expect(panel).toContainText(de?'Zeilen 601–700 von 2051 Treffern':'Rows 601–700 of 2051 matching');await next.click();await expect(panel).toContainText(de?'Zeilen 701–800 von 2051 Treffern':'Rows 701–800 of 2051 matching');await expect(rows.first()).toHaveText(eighthFirst);
  expect(await panel.locator('time').evaluateAll(nodes=>nodes.map(node=>node.getAttribute('datetime')))).toEqual(capture);await rows.first().scrollIntoViewIfNeeded();expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth&&document.body.scrollWidth<=innerWidth)).toBe(true);
  await shot(page,`synthetic-windows-full-services-${width}-${locale}`,windowsFullServicesDisclosure);
  stage='cursor-binding';const continuation=queries.at(-1);expect(Boolean(continuation.cursor)).toBe(true);const session=await page.request.get(base+'/api/session',{maxRedirects:0,timeout:5000});let csrf;try{expect(session.status()).toBe(200);csrf=(await session.json()).csrfToken;expect(typeof csrf).toBe('string');expect(csrf.length).toBeGreaterThan(0);}finally{await session.dispose();}
  for(const changed of [{search:'different literal query'},{sort:'name-desc'},{limit:99}]){const response=await page.request.post(base+queryPath,{headers:{Origin:base,'X-CSRF-Token':csrf},data:{...continuation,...changed},maxRedirects:0,timeout:5000});try{expect(response.status()).toBe(409);expect((await response.json()).error.code).toBe('windows_full_services_restart_required');bindingRejects++;}finally{await response.dispose();}}
  stage='search';await search.fill(info.laterSearch);await apply.click();await expect(rows).toHaveCount(1);await expect(rows.first()).toContainText(info.laterName);await expect(next).toBeDisabled();await expect(panel.locator('img,a,script')).toHaveCount(0);await shot(page,`synthetic-windows-full-services-search-${width}-${locale}`,windowsFullServicesDisclosure);
  await search.fill('[.*]');await apply.click();await expect(rows).toHaveCount(0);await expect(panel).toContainText(de?'Keine Dienste der vollständig erfassten Generation entsprechen dieser Suche.':'No services in the complete captured generation match this search.');
  if(de){await search.fill('Läuft');await apply.click();await expect(rows).toHaveCount(0);await search.fill('running');await apply.click();await expect(rows).toHaveCount(100);await expect(rows.first()).toContainText('Läuft (running)');}
  stage='sort';await search.fill('');for(const order of ['pid-asc','pid-desc','state-asc','state-desc','name-asc','name-desc']){await sort.selectOption(order);await apply.click();await expect(rows).toHaveCount(100);const heading=order.startsWith('pid')?'PID':order.startsWith('state')?(de?'Zustand':'State'):(de?'Dienstname':'Service name');await expect(panel.getByRole('columnheader',{name:heading,exact:true})).toHaveAttribute('aria-sort',order.endsWith('desc')?'descending':'ascending');await expect(previous).toBeDisabled();}
  await expect(rows.first()).not.toContainText(info.firstName);
  stage='repeat';let reached;const arrived=new Promise(resolve=>reached=resolve);let release;const gate=new Promise(resolve=>release=resolve);hold={promise:gate,arrived:reached,canceled:false};const before=queries.length;
  await refresh.click();await arrived;await expect(refresh).toBeDisabled();await expect(rows).toHaveCount(0);await expect(search).toHaveCount(0);await refresh.evaluate(button=>button.click());expect(queries.length).toBe(before+1);release();await expect(rows).toHaveCount(100);await expect(sort).toHaveValue('name-desc');
  stage='replacement';await windowsFullServicesFixtureControl(page,base,'replace');await next.click();await expect(panel.getByRole('alert')).toContainText(de?'neu beginnen':'Restart explicitly');await expect(rows).toHaveCount(0);await panel.getByRole('button',{name:de?'Mit neuester Dienstgeneration neu beginnen':'Restart with latest service generation'}).click();await expect(rows).toHaveCount(100);await expect(search).toHaveValue('');
  stage='failed-attempt';const originalSourceTimes=(await panel.locator('.windows-full-services-facts time').evaluateAll(nodes=>nodes.map(node=>node.getAttribute('datetime')))).slice(0,4);await windowsFullServicesFixtureControl(page,base,'fail');await panel.getByRole('button',{name:de?'Dienstseite aktualisieren':'Refresh service page',exact:true}).click();await expect(panel).toContainText(de?'Erfassung fehlgeschlagen':'Collection failed');await expect(rows).toHaveCount(100);const currentTimes=(await panel.locator('.windows-full-services-facts time').evaluateAll(nodes=>nodes.map(node=>node.getAttribute('datetime')))).slice(0,4);expect(currentTimes).toEqual(originalSourceTimes);
 }
 await page.setViewportSize({width:1440,height:1000});await page.getByLabel(/Language|Sprache/).selectOption('en');
 stage='navigation';let release,arrived;const reached=new Promise(resolve=>arrived=resolve),promise=new Promise(resolve=>release=resolve),held={promise,arrived,canceled:true};hold=held;await panel.getByRole('button',{name:'Refresh service page',exact:true}).click();await reached;await page.getByRole('tab',{name:'Software',exact:true}).click();release();await expect(panel).toHaveCount(0);await page.getByRole('tab',{name:'Services',exact:true}).click();await expect(rows).toHaveCount(100);await expect(panel.getByRole('searchbox')).toHaveValue('');
 stage='visibility';await panel.getByRole('searchbox').fill('private fixture query');await page.evaluate(()=>{Object.defineProperty(document,'visibilityState',{configurable:true,get:()=> 'hidden'});document.dispatchEvent(new Event('visibilitychange'));});await expect(rows).toHaveCount(0);await expect(panel.getByRole('searchbox')).toHaveCount(0);await page.evaluate(()=>{delete document.visibilityState;document.dispatchEvent(new Event('visibilitychange'));window.dispatchEvent(new Event('focus'));});await expect(rows).toHaveCount(100);await expect(panel.getByRole('searchbox')).toHaveValue('');
 stage='byte-short';info=await windowsFullServicesFixtureControl(page,base,'byte-short');await mount('en');const firstCount=await rows.count();expect(firstCount).toBeGreaterThan(0);expect(firstCount).toBeLessThan(100);await panel.getByRole('button',{name:'Next service page',exact:true}).click();await expect(panel.getByRole('button',{name:'Next service page',exact:true})).toBeDisabled();expect(firstCount+await rows.count()).toBe(128);await expect(panel.locator('img,a,script')).toHaveCount(0);
 stage='empty';await windowsFullServicesFixtureControl(page,base,'empty');await mount('en',true);await expect(rows).toHaveCount(0);
 stage='expiry';await windowsFullServicesFixtureControl(page,base,'near-expiry');await mount('en');await expect(panel.getByRole('alert')).toContainText('expired',{timeout:10000});await expect(rows).toHaveCount(0);await expect(panel.getByRole('searchbox')).toHaveCount(0);
 info=await windowsFullServicesFixtureControl(page,base,'replace');await mount('en');
 stage='disabled';await windowsFullServicesFixtureControl(page,base,'disable');await panel.getByRole('button',{name:'Refresh service page',exact:true}).click();await expect(panel).toContainText('The last acknowledged local scope is disabled.');await expect(panel.getByRole('searchbox')).toHaveCount(0);info=await windowsFullServicesFixtureControl(page,base,'enable');await mount('en');
 stage='session';await panel.getByRole('button',{name:'Next service page',exact:true}).click();await expect(panel).toContainText('Rows 101–200 of 2051 matching');const retiredSessionQuery=queries.at(-1);expect(Boolean(retiredSessionQuery.cursor)).toBe(true);await page.getByRole('button',{name:'Sign out',exact:true}).click();await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();await expect(panel).toHaveCount(0);const stopped=queries.length;await login(page);await mount('en');expect(queries.slice(stopped).every(query=>query.cursor==='')).toBe(true);
 const newSession=await page.request.get(base+'/api/session',{maxRedirects:0,timeout:5000});let newCSRF;try{expect(newSession.status()).toBe(200);newCSRF=(await newSession.json()).csrfToken;}finally{await newSession.dispose();}const retired=await page.request.post(base+queryPath,{headers:{Origin:base,'X-CSRF-Token':newCSRF},data:retiredSessionQuery,maxRedirects:0,timeout:5000});try{expect(retired.status()).toBe(409);expect((await retired.json()).error.code).toBe('windows_full_services_restart_required');bindingRejects++;}finally{await retired.dispose();}
 stage='revoked';stage='revoked-control';await windowsFullServicesFixtureControl(page,base,'revoke');stage='revoked-refresh';await panel.getByRole('button',{name:'Refresh service page',exact:true}).click();stage='revoked-alert';await expect(panel.getByRole('alert')).toContainText('no longer authorized');stage='revoked-clear';await expect(rows).toHaveCount(0);
 stage='final-external';expect(external).toEqual([]);stage='final-writes';expect(unexpected).toEqual([]);stage='final-query-limits';expect(queries.every(query=>query.limit===100)).toBe(true);
 stage='final-storage';const stored=await page.evaluate(()=>JSON.stringify({local:{...localStorage},session:{...sessionStorage}}));expect(stored.includes('private fixture query')||stored.includes(info.laterName)||queries.some(query=>query.cursor&&stored.includes(query.cursor))).toBe(false);
 stage='final-cursor-count';expect(bindingRejects).toBe(13);stage='complete';return {protectedPageReads:queries.length,cursorBindingRejects:bindingRejects,viewports:4,realProductionPages:true};
}
