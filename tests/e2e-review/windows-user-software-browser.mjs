/** Inert fixture imports. Only the separately registered hosted runner starts
 * the production App, disposable login server and browser. */
import assert from 'node:assert/strict';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {windowsFullSoftwareLegacyRead} from './windows-full-software-browser.mjs';
import {windowsFullProcessesLegacyRead} from './windows-full-processes-browser.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..'),require=createRequire(path.join(root,'web/package.json'));
const built=await require('esbuild').build({stdin:{contents:"export * from './windows-user-software-fixtures'; export {validUserSoftwarePage,validUserSoftwareSearch,validUserSoftwareSort,validUserSoftwareCursor} from './windows-user-software-types'; export {windowsDevice,windowsView} from './windows-inventory-fixture';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {userSoftwareDevice,userSoftwarePage,userSoftwareQuery,userSoftwareVector,validUserSoftwarePage,validUserSoftwareSearch,validUserSoftwareSort,validUserSoftwareCursor,windowsDevice,windowsView}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
export const windowsUserSoftwareCaseName='Selected-account software in production App with synthetic transport';
export const windowsUserSoftwareDisclosure='Real disposable loopback HTTP-test login and production App; intercepted invented selected-account rows built from exact Go SQLite JSON metadata and existing UI fixtures. Source, receipt and expiry timestamps stay original. UI fixture evidence, not live manager/store or native Windows acceptance. No account enumeration, foreground helper execution, grant, host read, software action, external request, AI or export.';
let stage='setup',failures=0,pending=0;
export const windowsUserSoftwareRouteState=()=>({failures,pending});
export const windowsUserSoftwareFailureStage=()=>new Set(['setup','login','account','paging','source','search','unavailable','access-loss','complete']).has(stage)?stage:'setup';
export function guardWindowsUserSoftwareRoute(route,handler){pending++;return Promise.resolve().then(()=>handler(route)).catch(async()=>{failures++;try{await route.abort('failed');}catch{/* Teardown has already ended this intercepted read. */}}).finally(()=>{pending--;});}
export function windowsUserSoftwareFixtureQuery({pathname,search='',method,headers,raw},prefix){
 if(pathname!==prefix+'/windows-selected-user-software/query'||search||method!=='POST'||!headers?.['x-csrf-token']||typeof raw!=='string'||Buffer.byteLength(raw)>8192)return null;
 let q;try{q=JSON.parse(raw);}catch{return null;}
 if(!q||typeof q!=='object'||Array.isArray(q)||Object.keys(q).sort().join(',')!=='accountContextId,cursor,limit,search,sort,source'||JSON.stringify(q)!==raw||typeof q.accountContextId!=='string'||q.accountContextId!==''&&!/^[a-f0-9]{64}$/.test(q.accountContextId)||!['','hkcu','msix'].includes(q.source)||!validUserSoftwareSearch(q.search)||!validUserSoftwareSort(q.sort)||q.limit!==100||!validUserSoftwareCursor(q.cursor))return null;
 return q;
}
export function windowsUserSoftwareFixture(name='complete',query=userSoftwareQuery,elapsed=0){
 assert.ok(['complete','bothUnavailable'].includes(name));assert.ok(Number.isFinite(elapsed)&&elapsed>=0&&elapsed<=600000);
 const offset=query.cursor?Number(/^cursor_(\d+)\.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA$/.exec(query.cursor)?.[1]):0;
 assert.ok(Number.isSafeInteger(offset)&&offset>=0&&offset<=4096);
 const p=name==='complete'?userSoftwarePage(query,undefined,undefined,offset):userSoftwareVector('bothUnavailable');
 if(name==='bothUnavailable'){assert.equal(query.cursor,'');p.source=query.source;p.search=query.search;p.sort=query.sort;p.limit=query.limit;}
 p.serverNow=new Date(Date.parse(p.serverNow)+elapsed).toISOString();assert.ok(validUserSoftwarePage(p,userSoftwareDevice,query,offset));return p;
}
async function currentToken(page,base,request){
 const response=await page.request.get(base+'/api/session',{maxRedirects:0,timeout:5000});
 try{assert.equal(response.status(),200);const session=await response.json();assert.equal(typeof session.csrfToken,'string');assert.ok(session.csrfToken);assert.equal(request.headers()['x-csrf-token'],session.csrfToken);}finally{await response.dispose();}
}
export async function windowsUserSoftwareBrowserCase({page,expect,base,login,shot}){
 stage='login';failures=0;pending=0;await login(page);
 const deviceId=userSoftwareDevice,prefix='/api/devices/'+deviceId,began=Date.now(),queries=[],unexpected=[],external=[];
 let mode='complete';
 const fulfill=(route,value,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(value)});
 const handle=async route=>{
  const request=route.request(),url=new URL(request.url());if(url.origin!==base){external.push('external');return route.abort('blockedbyclient');}
  if(url.pathname===prefix+'/windows-selected-user-software/query'){
   const q=windowsUserSoftwareFixtureQuery({pathname:url.pathname,search:url.search,method:request.method(),headers:request.headers(),raw:request.postData()},prefix);assert.ok(q);await currentToken(page,base,request);queries.push(q);
   if(mode==='access-loss')return fulfill(route,{error:{code:'operator_auth_required'}},401);
   return fulfill(route,windowsUserSoftwareFixture(mode,q,Date.now()-began));
  }
  const legacy={route,page,base,prefix,serverNow:new Date(Date.parse(userSoftwareVector('completeFirst').serverNow)+Date.now()-began).toISOString()};
  if(url.pathname===prefix+'/windows-full-software/query')return windowsFullSoftwareLegacyRead(legacy);
  if(url.pathname===prefix+'/windows-full-processes/query')return windowsFullProcessesLegacyRead(legacy);
  if(request.method()!=='GET'){unexpected.push('unexpected-write');return route.abort('blockedbyclient');}
  if(url.pathname===prefix){assert.equal(url.search,'');const device=windowsDevice();device.id=deviceId;device.agentCertificate.expiresAt='2027-02-15T08:00:00Z';return fulfill(route,device);}
  if(url.pathname===prefix+'/windows-inventory'){assert.equal(url.search,'');const view=windowsView();view.deviceId=deviceId;view.serverNow=new Date(Date.parse(view.serverNow)+Date.now()-began).toISOString();return fulfill(route,view);}
  if(url.pathname.startsWith(prefix+'/'))return fulfill(route,{error:{code:'synthetic_unavailable'}},404);
  if(!url.pathname.startsWith('/api/')||['/api/session','/api/auth/session','/api/overview','/api/enrollment','/api/windows/enrollment','/api/fleet/identities'].includes(url.pathname)&&!url.search)return route.continue();
  unexpected.push('unexpected-route');return route.abort('blockedbyclient');
 };
 await page.route('**/*',route=>guardWindowsUserSoftwareRoute(route,handle));
 const panel=page.locator('.windows-full-software'),rows=panel.locator('tbody tr');
 const mount=async locale=>{await page.goto(base+'/#/devices');await expect(page.locator('.device-page')).toHaveCount(0);await page.goto(base+'/#/devices/'+deviceId);await page.getByRole('tab',{name:locale==='de'?'Inventar':'Inventory',exact:true}).click();await page.getByRole('tab',{name:'Software',exact:true}).click();await page.getByRole('combobox',{name:locale==='de'?'Konto':'Account',exact:true}).selectOption('selected');};
 for(const locale of ['en','de'])for(const width of [1440,390]){
  const de=locale==='de';await page.setViewportSize({width,height:width===390?844:1000});await page.getByLabel(/Language|Sprache/).selectOption(locale);mode='complete';await mount(locale);
  stage='account';await expect(panel.getByRole('heading',{name:de?'Software des ausgewählten Kontos':'Selected-account software',exact:true})).toBeVisible();await expect(panel).toContainText('Selected account dddddddddddd');await expect(rows).toHaveCount(100);await expect(rows.first()).toContainText('Selected App 0000');await expect(panel).toContainText('205');await expect(panel.locator('.windows-full-software-details')).not.toHaveAttribute('open');
  stage='paging';await panel.getByRole('button',{name:de?'Nächste Softwareseite':'Next software page',exact:true}).click();await expect(rows.first()).toContainText('Selected App 0100');expect(queries.at(-1).accountContextId).toBe('d'.repeat(64));expect(queries.at(-1).cursor).not.toBe('');
  stage='source';await panel.getByRole('combobox',{name:de?'Quellen':'Sources',exact:true}).selectOption('msix');await expect(rows).toHaveCount(0);await panel.getByRole('button',{name:de?'Anwenden':'Apply',exact:true}).click();await expect(rows).toHaveCount(100);await expect(rows.first()).toContainText('Selected App 0001');expect(queries.at(-1).source).toBe('msix');expect(queries.at(-1).cursor).toBe('');
  stage='search';await panel.getByRole('searchbox').fill('0203');await panel.getByRole('button',{name:de?'Anwenden':'Apply',exact:true}).click();await expect(rows).toHaveCount(1);await expect(rows.first()).toContainText('Selected App 0203');expect(queries.at(-1).accountContextId).toBe('d'.repeat(64));expect(queries.at(-1).search).toBe('0203');await expect(panel.locator('img,a,script')).toHaveCount(0);expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth&&document.body.scrollWidth<=innerWidth)).toBe(true);if(width===390)expect(await rows.first().locator('td').first().evaluate(el=>getComputedStyle(el,'::before').content)).toBe(JSON.stringify('Name'));await panel.scrollIntoViewIfNeeded();await shot(page,`synthetic-windows-user-software-capture-${width}-${locale}`,windowsUserSoftwareDisclosure);
  stage='unavailable';mode='bothUnavailable';await mount(locale);await expect(rows).toHaveCount(0);await expect(panel).toContainText(de?'Keine Quelle war verfügbar; ein leeres Inventar ist damit nicht belegt.':'Neither source was available; no empty inventory is established.');await expect(panel).toContainText(de?'Teilweise Abdeckung':'Partial coverage');expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth&&document.body.scrollWidth<=innerWidth)).toBe(true);await panel.scrollIntoViewIfNeeded();await shot(page,`synthetic-windows-user-software-unavailable-${width}-${locale}`,windowsUserSoftwareDisclosure);
 }
 await page.getByLabel(/Language|Sprache/).selectOption('en');mode='complete';await mount('en');await expect(rows).toHaveCount(100);stage='access-loss';mode='access-loss';const count=queries.length;await panel.getByRole('button',{name:'Refresh captured software',exact:true}).click();await expect(page.getByLabel('Operator password',{exact:true})).toBeVisible();await expect(panel).toHaveCount(0);expect(queries.length).toBe(count+1);
 await expect.poll(()=>windowsUserSoftwareRouteState().pending).toBe(0);expect(external).toEqual([]);expect(unexpected).toEqual([]);expect(failures).toBe(0);stage='complete';return{screens:8,readQueries:queries.length,sourceInterop:true,nativeAcceptance:false,liveStoreAcceptance:false};
}
export function requireWindowsUserSoftwareEvidence(rows,sourceSha){
 assert.match(sourceSha??'',/^[a-f0-9]{40}$/);assert.ok(Array.isArray(rows));assert.equal(rows.length,8);
 for(const kind of ['capture','unavailable'])for(const locale of ['en','de'])for(const width of [1440,390]){
  const matches=rows.filter(row=>row.file===`synthetic-windows-user-software-${kind}-${width}-${locale}.png`);assert.equal(matches.length,1);const row=matches[0];assert.deepEqual(Object.keys(row).sort(),['file','fixtureDisclosure','fullPage','locale','publicSafe','sourceSha','test','viewport']);assert.deepEqual(Object.keys(row.viewport).sort(),['height','width']);assert.equal(row.sourceSha,sourceSha);assert.equal(row.test,windowsUserSoftwareCaseName);assert.equal(row.locale,locale);assert.equal(row.viewport.width,width);assert.equal(row.viewport.height,width===390?844:1000);assert.equal(row.fullPage,false);assert.equal(row.publicSafe,true);assert.equal(row.fixtureDisclosure,windowsUserSoftwareDisclosure);
 }
 return{capture:4,unavailable:4};
}
