/** Invented route/counter pages intercepted at the production UI transport seam.
 * Inert exports never open sockets or browsers; the separate hosted runner does. */
import {windowsFullProcessesLegacyRead} from './windows-full-processes-browser.mjs';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {build}=require('esbuild');
const bundled=await build({stdin:{contents:"export * from './windows-network-context-types'; export * from './windows-network-context-fixtures'; export {windowsDevice,windowsView} from './windows-inventory-fixture';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {validNetworkContextPage,validNetworkContextSearch,validNetworkContextSort,validNetworkContextKind,validNetworkContextCursor,networkContextDevice,networkContextNow,networkContextComplete,networkContextRows,networkContextPage,networkContextUnavailable,windowsDevice,windowsView}=await import('data:text/javascript;base64,'+Buffer.from(bundled.outputFiles[0].text).toString('base64'));
export const windowsNetworkContextCaseName='Route and exact raw counter UI with invented private page transport';
export const windowsNetworkContextDisclosure='Real loopback HTTP-test login and production UI; intercepted invented device, route and raw counter pages. Capture and receipt times stay original; only response time advances, except explicit synthetic deadline scenarios. UI fixture evidence, not live manager/store or native Windows acceptance. No native reads, host grants, probes, DNS, packets, service actions, external requests or AI export.';
let stage='setup';
const stages=new Set(['setup','login','routes','search','counters','source-switch','failed-attempt','pending','navigation','focus','restart','expiry','session','complete']);
export const windowsNetworkContextFailureStage=()=>stages.has(stage)?stage:'setup';
export function windowsNetworkContextFixtureQuery({pathname,search='',method,headers,raw},prefix){
 if(pathname!==prefix+'/windows-network-context/query'||search||method!=='POST'||!headers?.['x-csrf-token']||typeof raw!=='string'||Buffer.byteLength(raw)>8192)return null;
 let query;try{query=JSON.parse(raw);}catch{return null;}
 if(!query||Array.isArray(query)||typeof query!=='object'||Object.keys(query).sort().join(',')!=='cursor,kind,limit,search,sort'||JSON.stringify(query)!==raw||!validNetworkContextKind(query.kind)||!validNetworkContextSearch(query.search)||!validNetworkContextSort(query.sort)||!Number.isSafeInteger(query.limit)||query.limit<1||query.limit>100||!validNetworkContextCursor(query.cursor))return null;
 return query;
}
/** Session-local synthetic cursor bindings mirror only the private page boundary. */
export function windowsNetworkContextFixtureServer(){
 const complete=networkContextComplete(),rows=networkContextRows(),issued=new Map();
 return {deviceId:networkContextDevice,complete,rows,read(query,{elapsed=0,mode='normal'}={}){
  if(!Number.isFinite(elapsed)||elapsed<0||elapsed>600000)throw new Error('Invalid fixture time');
  const old=issued.get(query.cursor);
  if(query.cursor&&(!old||old.kind!==query.kind||old.search!==query.search||old.sort!==query.sort||old.limit!==query.limit))return{status:409,body:{error:{code:'windows_network_context_restart_required'}}};
  if(mode==='restart')return{status:409,body:{error:{code:'windows_network_context_restart_required'}}};
  if(mode==='session')return{status:401,body:{error:{code:'operator_auth_required'}}};
  const page=mode==='not_configured'?networkContextUnavailable('not_configured',query):networkContextPage(query,rows,complete,old?.offset??0);
  page.serverNow=new Date(Date.parse(networkContextNow)+elapsed).toISOString();
  if(page.status==='ready'){
   page.cursorExpiresAt=old?.expiry??new Date(Date.parse(page.serverNow)+900000).toISOString();
   if(page.nextCursor){page.nextCursor=`cursor_${issued.size}_${page.offset+page.rows.length}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`;issued.set(page.nextCursor,{...query,offset:page.offset+page.rows.length,expiry:page.cursorExpiresAt});}
   if(mode==='failed-attempt')page.latestAttempt={sequence:2,attemptedAt:'2026-10-11T06:00:09Z',status:'source_failed',reason:'resource_limit'};
   if(mode==='expiry'){page.serverNow=new Date(Date.parse(complete.manifest.expiresAt)-750).toISOString();page.cursorExpiresAt=complete.manifest.expiresAt;page.authorityUntil=complete.manifest.expiresAt;}
  }
  if(!validNetworkContextPage(page,networkContextDevice,query,old?.offset??0))throw new Error('Invalid invented network page');
  return{status:200,body:page};
 }};
}
async function currentToken(page,base,request){
 const session=await page.request.get(new URL('/api/session',base).href,{maxRedirects:0,timeout:5000});
 try{const value=await session.json();if(session.status()!==200||typeof value.csrfToken!=='string'||!value.csrfToken||value.csrfToken!==request.headers()['x-csrf-token'])throw new Error('Invalid network fixture session');}finally{await session.dispose();}
}
export async function windowsNetworkContextBrowserCase({page,expect,base,login,shot}){
 stage='login';await login(page);
 const fixture=windowsNetworkContextFixtureServer(),deviceId=fixture.deviceId,prefix='/api/devices/'+deviceId,queryPath=prefix+'/windows-network-context/query',began=Date.now(),queries=[],unexpected=[],external=[];
 let mode='normal',hold=null;
 const fulfill=(route,body,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(body)});
 await page.route('**/*',async route=>{
  const request=route.request(),url=new URL(request.url());
  if(url.origin!==base){external.push('external');return route.abort('blockedbyclient');}
  if(url.pathname===queryPath){
   const query=windowsNetworkContextFixtureQuery({pathname:url.pathname,search:url.search,method:request.method(),headers:request.headers(),raw:request.postData()},prefix);
   if(!query){unexpected.push('invalid-query');return route.abort('blockedbyclient');}
   await currentToken(page,base,request);queries.push(query);
   const result=fixture.read(query,{elapsed:Date.now()-began,mode});
   if(hold){const pending=hold;hold=null;pending.arrived();await pending.promise;try{return await fulfill(route,result.body,result.status);}catch{return;}}
   return fulfill(route,result.body,result.status);
  }
  if(url.pathname===prefix+'/windows-full-processes/query'){try{return await windowsFullProcessesLegacyRead({route,page,base,prefix,serverNow:networkContextNow});}catch{unexpected.push('unexpected-process-query');return route.abort('blockedbyclient');}}
  if(request.method()!=='GET'&&!['/api/auth/login','/api/auth/logout'].includes(url.pathname)){unexpected.push('unexpected-write');return route.abort('blockedbyclient');}
  if(url.pathname===prefix){const device=windowsDevice();device.id=deviceId;device.agentCertificate.expiresAt='2027-02-15T08:00:00Z';return fulfill(route,device);}
  if(url.pathname===prefix+'/windows-inventory'){const view=windowsView();view.deviceId=deviceId;view.serverNow=new Date(Date.parse(view.serverNow)+Date.now()-began).toISOString();return fulfill(route,view);}
  if(url.pathname.startsWith(prefix+'/'))return fulfill(route,{error:{code:'synthetic_unavailable'}},404);
  return route.continue();
 });
 const panel=page.locator('.windows-network-context'),rows=panel.locator('tbody tr');
 const source=()=>page.getByRole('combobox',{name:/^(Network source|Netzwerkquelle)$/});
 const mount=async locale=>{await page.goto(base+'/#/devices');await expect(page.locator('.device-page')).toHaveCount(0);await page.goto(`${base}/#/devices/${deviceId}`);await page.getByRole('tab',{name:locale==='de'?'Inventar':'Inventory',exact:true}).click();await page.getByRole('tab',{name:locale==='de'?'Netzwerk':'Network',exact:true}).click();await source().selectOption('route');};
 for(const locale of ['en','de'])for(const width of [1440,390]){
  const de=locale==='de';await page.setViewportSize({width,height:width===390?844:1000});await page.getByLabel(/Language|Sprache/).selectOption(locale);mode='normal';await mount(locale);
  stage='routes';await expect(rows).toHaveCount(100);await expect(rows.first()).toHaveAttribute('data-network-row','1');await expect(panel.locator('.windows-network-context-details')).not.toHaveAttribute('open');
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth&&document.body.scrollWidth<=innerWidth)).toBe(true);
  if(width===390)expect(await rows.first().locator('td').first().evaluate(el=>getComputedStyle(el,'::before').content)).toBe(JSON.stringify(de?'Zielpräfix':'Destination'));
  await panel.scrollIntoViewIfNeeded();await shot(page,`synthetic-windows-network-context-routes-${width}-${locale}`,windowsNetworkContextDisclosure);
  await panel.getByRole('button',{name:de?'Nächste Netzwerkseite':'Next network page',exact:true}).click();await expect(rows.first()).toHaveAttribute('data-network-row','101');
  stage='search';await panel.getByRole('searchbox').fill('2001:db8::');await panel.getByRole('button',{name:de?'Anwenden':'Apply',exact:true}).click();await expect(rows).toHaveCount(1);await expect(rows.first()).toContainText('fe80::1%7');await expect(rows.first()).toContainText(de?'Nicht verwendet':'Not used');await rows.first().locator('summary').click();await expect(rows.first()).toContainText(de?'Ziel-Scope-ID: 7':'Destination scope ID: 7');
  stage='counters';await source().selectOption('interface');await expect(rows).toHaveCount(2);await expect(panel).toContainText('18446744073709551615');await expect(panel).toContainText('9007199254740993');await expect(panel).toContainText('Fixture <adapter> [.*]');await expect(panel.locator('adapter,img,a,script')).toHaveCount(0);await expect(panel.getByRole('searchbox')).toHaveValue('');expect(queries.at(-1).kind).toBe('interface');expect(queries.at(-1).cursor).toBe('');
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth&&document.body.scrollWidth<=innerWidth)).toBe(true);
  await panel.scrollIntoViewIfNeeded();await shot(page,`synthetic-windows-network-context-counters-${width}-${locale}`,windowsNetworkContextDisclosure);
  stage='source-switch';await source().selectOption('legacy');await expect(panel).toHaveCount(0);
 }
 await page.getByLabel(/Language|Sprache/).selectOption('en');
 stage='failed-attempt';mode='failed-attempt';await mount('en');await expect(rows).toHaveCount(100);await expect(panel).toContainText('Showing earlier capture');await expect(panel.locator('.windows-network-context-age time')).toHaveAttribute('datetime',fixture.complete.manifest.captureStartedAt);
 stage='pending';mode='normal';await mount('en');await expect(rows).toHaveCount(100);let release,arrived;const received=new Promise(resolve=>{arrived=resolve;});hold={arrived,promise:new Promise(resolve=>{release=resolve;})};await panel.getByRole('button',{name:'Refresh routes and counters',exact:true}).click();await received;await expect(rows).toHaveCount(0);await expect(panel.getByRole('searchbox')).toHaveCount(0);
 stage='navigation';await page.getByRole('tab',{name:'Hostname',exact:true}).click();release();await expect(panel).toHaveCount(0);await page.getByRole('tab',{name:'Network',exact:true}).click();await expect(source()).toHaveValue('legacy');await source().selectOption('route');await expect(rows).toHaveCount(100);expect(queries.at(-1).cursor).toBe('');
 stage='focus';await page.evaluate(()=>window.dispatchEvent(new Event('blur')));await expect(rows).toHaveCount(0);await page.evaluate(()=>window.dispatchEvent(new Event('focus')));await expect(rows).toHaveCount(100);expect(queries.at(-1).cursor).toBe('');
 stage='restart';mode='restart';await panel.getByRole('button',{name:'Refresh routes and counters',exact:true}).click();await expect(panel.getByRole('alert')).toContainText('Reload latest');await expect(rows).toHaveCount(0);mode='normal';await panel.getByRole('button',{name:'Reload latest network capture',exact:true}).click();await expect(rows).toHaveCount(100);
 stage='expiry';mode='expiry';await mount('en');await expect(panel.getByRole('alert')).toContainText('expired');await expect(rows).toHaveCount(0);
 stage='session';mode='normal';await mount('en');await expect(rows).toHaveCount(100);mode='session';await panel.getByRole('button',{name:'Refresh routes and counters',exact:true}).click();await expect(page.getByLabel('Operator password',{exact:true})).toBeVisible();await expect(panel).toHaveCount(0);
 expect(external).toEqual([]);expect(unexpected).toEqual([]);stage='complete';return{screens:8,sourceInterop:false,transport:'intercepted invented pages',liveStoreAcceptance:false,nativeAcceptance:false};
}
