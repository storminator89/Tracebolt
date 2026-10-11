/** Inert fixture/production-UI assertions. Importing this file starts no browser
 * or server. The separately registered hosted runner supplies real browser QA. */
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {windowsFullSoftwareLegacyRead} from './windows-full-software-browser.mjs';
import {windowsFullProcessesLegacyRead} from './windows-full-processes-browser.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..'),require=createRequire(path.join(root,'web/package.json'));
const {build}=require('esbuild');
const built=await build({stdin:{contents:"export * from './windows-software-history-fixtures'; export {validSoftwareHistoryPage,validSoftwareHistoryQuery} from './windows-software-history-types'; export {windowsDevice,windowsView} from './windows-inventory-fixture';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {softwareHistoryDevice,softwareHistoryNow,softwareHistoryQuery,softwareHistoryScenario,validSoftwareHistoryPage,validSoftwareHistoryQuery,windowsDevice,windowsView}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
export const windowsSoftwareHistoryCaseName='Private Windows software change history with synthetic transport';
export const windowsSoftwareHistoryDisclosure='Real loopback HTTP-test login and production UI; intercepted invented HKLM software-history pages. Browser UI fixture evidence, not live manager/store acceptance. No native Windows read, local grant, host or service action, external request, AI or export.';
let stage='setup';
const stages=new Set(['setup','login','summary','details','baseline','default-off','gap','pagination','search','pending','navigation','focus','visibility','restart','expiry','session','complete']);
export const windowsSoftwareHistoryFailureStage=()=>stages.has(stage)?stage:'setup';
export function windowsSoftwareHistoryFixtureQuery({pathname,search='',method,headers,raw},prefix){
 if(pathname!==prefix+'/windows-software-history/query'||search||method!=='POST'||!headers?.['x-csrf-token']||typeof raw!=='string'||Buffer.byteLength(raw)>8192)return null;
 let q;try{q=JSON.parse(raw);}catch{return null;}
 if(!q||typeof q!=='object'||Array.isArray(q)||Object.keys(q).sort().join(',')!=='cursor,limit,search,sort'||JSON.stringify(q)!==raw||!validSoftwareHistoryQuery(q))return null;
 return q;
}
export function windowsSoftwareHistoryFixture(name='normal',query=softwareHistoryQuery,elapsed=0){
 if(!['normal','not_configured','disabled','awaiting','baseline','source_gap','incomparable','resource_limit','expired-counts'].includes(name)||!Number.isFinite(elapsed)||elapsed<0||elapsed>600000)throw new Error('Invalid synthetic software history selection');
 const offset=query.cursor?Number(/^history_(\d+)\.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA$/.exec(query.cursor)?.[1]):0;
 if(!Number.isSafeInteger(offset)||offset<0)throw new Error('Invalid synthetic history cursor');
 const p=softwareHistoryScenario(name,query,offset);p.serverNow=new Date(Date.parse(softwareHistoryNow)+elapsed).toISOString();
 if(!validSoftwareHistoryPage(p,softwareHistoryDevice,query,offset))throw new Error('Invalid synthetic software history page');
 return p;
}
async function currentToken(page,base,request){
 const session=await page.request.get(new URL('/api/session',base).href,{maxRedirects:0,timeout:5000});
 try{const value=await session.json();if(session.status()!==200||!value.csrfToken||value.csrfToken!==request.headers()['x-csrf-token'])throw new Error('Invalid software history fixture session');}finally{await session.dispose();}
}
export async function windowsSoftwareHistoryBrowserCase({page,expect,base,login,shot}){
 stage='login';await login(page);
 const deviceId=softwareHistoryDevice,prefix='/api/devices/'+deviceId,began=Date.now(),queries=[],unexpected=[],external=[];
 let mode='normal',hold=null;
 const fulfill=(route,value,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(value)});
 await page.route('**/*',async route=>{
  const request=route.request(),url=new URL(request.url());if(url.origin!==base){external.push('external');return route.abort('blockedbyclient');}
  if(url.pathname===prefix+'/windows-software-history/query'){
   const q=windowsSoftwareHistoryFixtureQuery({pathname:url.pathname,search:url.search,method:request.method(),headers:request.headers(),raw:request.postData()},prefix);
   if(!q){unexpected.push('invalid-history-query');return route.abort('blockedbyclient');}await currentToken(page,base,request);queries.push(q);
   if(mode==='restart')return fulfill(route,{error:{code:'windows_software_history_restart_required'}},409);
   if(mode==='session')return fulfill(route,{error:{code:'operator_auth_required'}},401);
   const p=windowsSoftwareHistoryFixture(mode==='expiry'?'normal':mode,q,Date.now()-began);
   if(mode==='expiry')p.cursorExpiresAt=new Date(Date.parse(p.serverNow)+750).toISOString();
   if(hold){const pending=hold;hold=null;pending.arrived();await pending.promise;try{return await fulfill(route,p);}catch{return;}}
   return fulfill(route,p);
  }
  const legacy={route,page,base,prefix,serverNow:new Date(Date.parse(softwareHistoryNow)+Date.now()-began).toISOString()};
  if(url.pathname===prefix+'/windows-full-software/query')try{return await windowsFullSoftwareLegacyRead(legacy);}catch{unexpected.push('invalid-current-software-query');return route.abort('blockedbyclient');}
  if(url.pathname===prefix+'/windows-full-processes/query')try{return await windowsFullProcessesLegacyRead(legacy);}catch{unexpected.push('invalid-process-query');return route.abort('blockedbyclient');}
  if(request.method()!=='GET'&&!['/api/auth/login','/api/auth/logout'].includes(url.pathname)){unexpected.push('unexpected-write');return route.abort('blockedbyclient');}
  if(url.pathname===prefix){const device=windowsDevice();device.id=deviceId;device.agentCertificate.expiresAt='2027-02-15T08:00:00Z';return fulfill(route,device);}
  if(url.pathname===prefix+'/windows-inventory'){const view=windowsView();view.deviceId=deviceId;view.serverNow=new Date(Date.parse(view.serverNow)+Date.now()-began).toISOString();return fulfill(route,view);}
  if(url.pathname.startsWith(prefix+'/'))return fulfill(route,{error:{code:'synthetic_unavailable'}},404);
  return route.continue();
 });
 const panel=page.locator('.windows-software-history'),rows=panel.locator('tbody>tr');
 const mount=async locale=>{await page.goto(base+'/#/devices');await expect(page.locator('.device-page')).toHaveCount(0);await page.goto(base+'/#/devices/'+deviceId);await page.getByRole('tab',{name:locale==='de'?'Inventar':'Inventory',exact:true}).click();await page.getByRole('tab',{name:'Software',exact:true}).click();await page.getByRole('button',{name:locale==='de'?'Änderungsverlauf':'Change history',exact:true}).click();};
 const shotKind=async(kind,width,locale)=>{expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth&&document.body.scrollWidth<=innerWidth)).toBe(true);await panel.evaluate(el=>el.scrollIntoView({block:'start',behavior:'instant'}));await shot(page,`synthetic-windows-software-history-${kind}-${width}-${locale}`,windowsSoftwareHistoryDisclosure);};
 for(const locale of ['en','de'])for(const width of [1440,390]){
  const de=locale==='de';await page.setViewportSize({width,height:width===390?844:1000});await page.getByLabel(/Language|Sprache/).selectOption(locale);mode='normal';await mount(locale);
  stage='summary';await expect(rows).toHaveCount(100);await expect(rows.nth(1)).toContainText(de?'Registrierung entfernt':'Registration removed');await expect(rows.nth(3).locator('td').nth(1)).not.toContainText('Version');await expect(panel.locator('.windows-history-scope')).not.toHaveAttribute('open');await expect(rows.first().locator('details')).not.toHaveAttribute('open');await expect(panel).toContainText('205');await shotKind('summary',width,locale);
  stage='details';await rows.nth(3).locator('summary').click();await expect(rows.nth(3).locator('details')).toContainText(de?'Vorher: Nicht verfügbar':'Before: Unavailable');await expect(rows.nth(3).locator('details')).toContainText(de?'Nachher: 2.0':'After: 2.0');await expect(rows.nth(3).locator('details')).toContainText(de?'keine Installations- oder Deinstallationszeiten':'not installation or uninstall times');await rows.nth(3).evaluate(el=>el.scrollIntoView({block:'start',behavior:'instant'}));await shot(page,`synthetic-windows-software-history-details-${width}-${locale}`,windowsSoftwareHistoryDisclosure);
  stage='baseline';mode='baseline';await mount(locale);await expect(rows).toHaveCount(0);await expect(panel).toContainText(de?'Ausgangserfassung vorhanden':'Baseline captured');await shotKind('baseline',width,locale);
  stage='default-off';mode='not_configured';await mount(locale);await expect(panel).toContainText(de?'Verlauf ist aus':'History is off');await expect(panel.locator('form')).toHaveCount(0);await expect(panel.getByRole('button')).toHaveCount(1);await shotKind('default-off',width,locale);
  stage='gap';mode='resource_limit';await mount(locale);await expect(panel).toContainText(de?'Vergleichslücke':'Comparison gap');await expect(panel).toContainText('1500');await expect(rows).toHaveCount(100);await shotKind('gap',width,locale);
 }
 await page.getByLabel(/Language|Sprache/).selectOption('en');mode='normal';await mount('en');await expect(rows).toHaveCount(100);
 stage='pagination';await panel.getByRole('button',{name:'Next history page',exact:true}).click();await expect(rows.first()).toContainText('Fixture Software 0101');await panel.getByRole('button',{name:'Next history page',exact:true}).click();await expect(rows).toHaveCount(5);await expect(panel.getByRole('button',{name:'Next history page',exact:true})).toBeDisabled();await panel.getByRole('button',{name:'Previous history page',exact:true}).click();await expect(rows.first()).toContainText('Fixture Software 0101');
 stage='search';await panel.getByRole('searchbox').fill('[.*]');await expect(rows).toHaveCount(0);await panel.getByRole('button',{name:'Apply',exact:true}).click();await expect(rows).toHaveCount(1);await rows.first().locator('summary').click();await expect(rows.first()).toContainText('<img src=x onerror=alert(1)> [.*] ÄÖÜ 東京');await expect(panel.locator('img,a,script')).toHaveCount(0);expect(queries.at(-1).cursor).toBe('');
 stage='pending';let release,arrived;const received=new Promise(resolve=>{arrived=resolve;});hold={arrived,promise:new Promise(resolve=>{release=resolve;})};await panel.getByRole('button',{name:'Refresh software history',exact:true}).click();await received;await expect(rows).toHaveCount(0);await expect(panel.getByRole('searchbox')).toHaveCount(0);
 stage='navigation';await page.getByRole('button',{name:'Current inventory',exact:true}).click();release();await expect(panel).toHaveCount(0);await page.getByRole('button',{name:'Change history',exact:true}).click();await expect(rows).toHaveCount(100);expect(queries.at(-1)).toEqual(softwareHistoryQuery);
 stage='focus';await page.evaluate(()=>window.dispatchEvent(new Event('blur')));await expect(rows).toHaveCount(0);await page.evaluate(()=>window.dispatchEvent(new Event('focus')));await expect(rows).toHaveCount(100);expect(queries.at(-1).cursor).toBe('');
 stage='visibility';await page.evaluate(()=>{Object.defineProperty(document,'visibilityState',{configurable:true,value:'hidden'});document.dispatchEvent(new Event('visibilitychange'));});await expect(rows).toHaveCount(0);await page.evaluate(()=>{Object.defineProperty(document,'visibilityState',{configurable:true,value:'visible'});document.dispatchEvent(new Event('visibilitychange'));});await expect(rows).toHaveCount(100);
 stage='restart';mode='restart';await panel.getByRole('button',{name:'Refresh software history',exact:true}).click();await expect(panel.getByRole('alert')).toContainText('Reload history');await expect(rows).toHaveCount(0);mode='normal';await panel.getByRole('button',{name:'Reload history',exact:true}).click();await expect(rows).toHaveCount(100);expect(queries.at(-1).cursor).toBe('');
 stage='expiry';mode='expiry';await mount('en');await expect(panel.getByRole('alert')).toContainText('expired');await expect(rows).toHaveCount(0);await expect(panel.getByRole('searchbox')).toHaveCount(0);
 stage='session';mode='normal';await mount('en');await expect(rows).toHaveCount(100);mode='session';await panel.getByRole('button',{name:'Refresh software history',exact:true}).click();await expect(page.getByLabel('Operator password',{exact:true})).toBeVisible();await expect(panel).toHaveCount(0);
 expect(external).toEqual([]);expect(unexpected).toEqual([]);stage='complete';return{screens:20,transport:'intercepted invented history pages',liveStoreAcceptance:false,nativeAcceptance:false};
}
export function requireWindowsSoftwareHistoryEvidence(rows,sourceSha){
 const fail=()=>{throw new Error('Missing or inconsistent Windows software history screenshots');};
 if(!Array.isArray(rows)||rows.length!==20||!/^[a-f0-9]{40}$/.test(sourceSha??''))fail();
 for(const kind of ['summary','details','baseline','default-off','gap'])for(const locale of ['en','de'])for(const width of [1440,390]){
  const matches=rows.filter(row=>row.file===`synthetic-windows-software-history-${kind}-${width}-${locale}.png`);if(matches.length!==1)fail();const row=matches[0];
  if(row.sourceSha!==sourceSha||row.test!==windowsSoftwareHistoryCaseName||row.locale!==locale||row.viewport?.width!==width||row.viewport?.height!==(width===390?844:1000)||row.fullPage!==false||row.publicSafe!==true||row.fixtureDisclosure!==windowsSoftwareHistoryDisclosure)fail();
 }
 return{summary:4,details:4,baseline:4,defaultOff:4,gap:4};
}
