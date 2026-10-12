/** Inert production-UI fixture helper. Importing starts no browser or server. */
import assert from 'node:assert/strict';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..'),require=createRequire(path.join(root,'web/package.json'));
const built=await require('esbuild').build({stdin:{contents:"export {windowsCapacityDevice} from './windows-capacity-fixture'; export {validWindowsIncidentInboxView,validWindowsIncidentAcknowledgement} from './windows-incident-inbox-types'; export {default as wire} from '../../tests/fixtures/windows-incident-inbox-view.json';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {windowsCapacityDevice,validWindowsIncidentInboxView,validWindowsIncidentAcknowledgement,wire}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
export const windowsIncidentInboxCaseName='Windows incident inbox and explicit acknowledgement readback';
export const windowsIncidentInboxDisclosure='Production UI and real disposable loopback login with intercepted invented Windows incidents and one explicitly clicked acknowledgement per locale/viewport. GET readback records seen while the incident remains active. Hosted browser fixture evidence only; no live acknowledgement, native endpoint read/action, new grant, AI, notification or deployment.';
export const windowsIncidentInboxTargetKey=wire.active.items.find(item=>item.domain==='disk').key;
export const windowsIncidentInboxQuery='?scope=active&ack=all&offset=0&limit=25';
let stage='setup',failures=0,pending=0;
export const windowsIncidentInboxRouteState=()=>({failures,pending});
export const windowsIncidentInboxFailureStage=()=>new Set(['setup','login','locale','list','acknowledge','readback','layout','complete']).has(stage)?stage:'setup';
export function guardWindowsIncidentInboxRoute(route,handler){pending++;return Promise.resolve().then(()=>handler(route)).catch(async()=>{failures++;try{await route.abort('failed');}catch{/* Teardown already ended the request. */}}).finally(()=>{pending--;});}
function shifted(value,origin){
 if(Array.isArray(value))return value.map(row=>shifted(row,origin));
 if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([key,row])=>[key,shifted(row,origin)]));
 return typeof value==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/.test(value)?new Date(Date.parse(value)+Date.parse(origin)-Date.parse(wire.active.serverNow)).toISOString():value;
}
export function windowsIncidentInboxBrowserFixture(serverNow,expiresAt,origin=serverNow,acknowledgedAt=null){
 const view=shifted(wire.active,origin);view.serverNow=serverNow;view.authorityExpiresAt=expiresAt;
 for(const item of view.items){
  if(item.key===windowsIncidentInboxTargetKey&&acknowledgedAt!==null)item.acknowledgedAt=acknowledgedAt;
  if(item.statusValidUntil!==null){item.statusValidUntil=new Date(Math.min(Date.parse(item.statusValidUntil),Date.parse(expiresAt))).toISOString();if(Date.parse(item.statusValidUntil)<=Date.parse(serverNow)){item.status='unknown';item.statusValidUntil=null;}}
 }
 view.counts.acknowledged=view.items.filter(item=>item.acknowledgedAt!==null).length;view.counts.unacknowledged=view.counts.total-view.counts.acknowledged;
 assert.ok(validWindowsIncidentInboxView(view,'active','all',0));
 const source=windowsCapacityDevice(),metadata={...source,id:view.items[0].deviceId,name:'Synthetic Windows Desk',status:'unknown',agentCertificate:{source:'guided-enrollment',expiresAt,checkedAt:serverNow}};
 return {view,metadata};
}
export async function windowsIncidentInboxBrowserCase({page,expect,base,login,shot}){
 stage='login';failures=0;pending=0;await login(page);
 let origin=null,acknowledgedAt=null,postCount=0,readCount=0,readbackCount=0,postKey=null,readback=null;
 const external=[],unexpected=[],cases=[];
 const getSession=async()=>{const response=await page.request.get(base+'/api/auth/session',{maxRedirects:0,timeout:5000});try{assert.equal(response.status(),200);const session=await response.json();assert.equal(session.authenticated,true);assert.equal(session.loginMode,'shared');return session;}finally{await response.dispose();}};
 const fulfill=(route,value)=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(value)});
 const handle=async route=>{
  const req=route.request(),url=new URL(req.url());if(url.origin!==base){external.push('external');return route.abort('blockedbyclient');}
  if(url.pathname==='/api/overview'){
   assert.equal(req.method(),'GET');assert.equal(url.search,'');const response=await route.fetch({maxRedirects:0,timeout:5000});let value;try{assert.equal(response.status(),200);value=await response.json();}finally{await response.dispose();}
   const session=await getSession(),fixture=windowsIncidentInboxBrowserFixture(session.serverNow,session.expiresAt);return fulfill(route,{...value,devices:[fixture.metadata],stats:{...value.stats,totalDevices:1,healthyDevices:0,attentionDevices:0},generatedAt:session.serverNow});
  }
  if(url.pathname==='/api/fleet/windows-incidents'){
   assert.equal(req.method(),'GET');assert.equal(url.search,windowsIncidentInboxQuery);const session=await getSession();origin??=session.serverNow;readCount++;
   const {view}=windowsIncidentInboxBrowserFixture(session.serverNow,session.expiresAt,origin,acknowledgedAt);
   if(postKey!==null){const item=view.items.find(row=>row.key===postKey);assert.ok(item);assert.equal(item.acknowledgedAt,acknowledgedAt);assert.equal(item.resolvedAt,null);assert.equal(view.scope,'active');readbackCount++;readback={key:item.key,acknowledgedAt:item.acknowledgedAt,resolvedAt:item.resolvedAt,scope:view.scope};}
   return fulfill(route,view);
  }
  if(url.pathname==='/api/fleet/windows-incidents/acknowledge'){
   assert.equal(req.method(),'POST');assert.equal(url.search,'');const session=await getSession();assert.equal(req.headers()['x-csrf-token'],session.csrfToken);assert.match(req.headers()['content-type']??'',/^application\/json(?:;|$)/);
   const body=JSON.parse(req.postData());assert.deepEqual(body,{key:windowsIncidentInboxTargetKey});assert.equal(postCount,0);assert.equal(acknowledgedAt,null);assert.equal(readCount,1);
   postCount++;postKey=body.key;acknowledgedAt=session.serverNow;
   const value={schemaVersion:'tracebolt.windows-incident-ack.v1',serverNow:session.serverNow,key:postKey,acknowledgedAt};assert.ok(validWindowsIncidentAcknowledgement(value,postKey));return fulfill(route,value);
  }
  const allowedRead=['/api/auth/session','/api/session','/api/enrollment','/api/windows/enrollment','/api/fleet/identities'];
  if(req.method()==='GET'&&!url.pathname.startsWith('/api/'))return route.continue();
  if(req.method()==='GET'&&allowedRead.includes(url.pathname)&&!url.search)return route.continue();
  unexpected.push('unexpected-route');return route.abort('blockedbyclient');
 };
 await page.route('**/*',route=>guardWindowsIncidentInboxRoute(route,handle));
 for(const locale of ['en','de'])for(const width of [1440,390]){
  stage='locale';const de=locale==='de';await page.setViewportSize({width,height:width===390?844:1000});await page.getByLabel(/Language|Sprache/).selectOption(locale);
  origin=null;acknowledgedAt=null;postCount=0;readCount=0;readbackCount=0;postKey=null;readback=null;await page.reload();await expect(page.locator('.app-shell')).toBeVisible();
  const panel=page.locator('.windows-incident-inbox'),toggle=panel.getByRole('button',{name:de?'Windows-Vorfälle':'Windows incidents',exact:true});
  await expect(toggle).toHaveAttribute('aria-expanded','false');expect(readCount).toBe(0);expect(postCount).toBe(0);
  stage='list';await toggle.click();await expect(panel.locator('.windows-incident-row')).toHaveCount(5);expect(readCount).toBe(1);expect(postCount).toBe(0);
  const target=panel.locator('.windows-incident-row').filter({has:page.getByRole('button',{name:de?'Als gesehen markieren: Synthetic Windows Desk · Kapazität des Systemvolumes':'Mark seen: Synthetic Windows Desk · System-volume capacity',exact:true})});
  await expect(target).toHaveCount(1);await expect(target.getByText(de?'Aktiv':'Active',{exact:true})).toBeVisible();await expect(target.getByRole('link')).toHaveAttribute('href',`#/devices/${wire.active.items[0].deviceId}/health`);
  const verifyLayout=async()=>{stage='layout';expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);const overflows=await panel.locator('.windows-incident-row').evaluateAll(rows=>rows.map(row=>row.scrollWidth-row.clientWidth));for(const overflow of overflows)expect(overflow).toBeLessThanOrEqual(1);};
  await verifyLayout();await panel.evaluate(el=>el.scrollIntoView({block:'start'}));await shot(page,`synthetic-windows-incident-inbox-list-${width}-${locale}`,windowsIncidentInboxDisclosure);
  stage='acknowledge';await target.getByRole('button').click();
  stage='readback';await expect.poll(()=>readbackCount).toBe(1);const seenRow=panel.locator('.windows-incident-row').filter({hasText:de?'Kapazität des Systemvolumes':'System-volume capacity'});
  await expect(seenRow.getByText(de?'Gesehen':'Seen',{exact:true})).toBeVisible();await expect(seenRow.getByText(de?'Aktiv':'Active',{exact:true})).toBeVisible();await expect(seenRow.getByRole('button')).toHaveCount(0);expect(postCount).toBe(1);expect(readCount).toBe(2);assert.ok(readback);assert.equal(readback.key,postKey);assert.equal(readback.acknowledgedAt,acknowledgedAt);assert.equal(readback.resolvedAt,null);
  await verifyLayout();await seenRow.scrollIntoViewIfNeeded();await shot(page,`synthetic-windows-incident-inbox-seen-${width}-${locale}`,windowsIncidentInboxDisclosure);
  cases.push({locale,width,postKey,postCount,readbackKey:readback.key,acknowledgedAt,readbackAcknowledgedAt:readback.acknowledgedAt,readbackResolvedAt:readback.resolvedAt,readbackScope:readback.scope,readbackCount});
  await panel.getByRole('button',{name:new RegExp(de?'^Windows-Vorfälle':'^Windows incidents')}).click();await expect(panel.locator('.windows-incident-row')).toHaveCount(0);
 }
 await expect.poll(()=>windowsIncidentInboxRouteState().pending).toBe(0);expect(external).toEqual([]);expect(unexpected).toEqual([]);expect(failures).toBe(0);stage='complete';return {screens:8,cases,nativeAcceptance:false,liveStoreAcceptance:false};
}
export function requireWindowsIncidentInboxEvidence(rows,sourceSha,details){
 assert.match(sourceSha??'',/^[a-f0-9]{40}$/);assert.equal(rows.length,8);assert.equal(details?.screens,8);assert.equal(details.cases?.length,4);assert.equal(details.nativeAcceptance,false);assert.equal(details.liveStoreAcceptance,false);
 for(const locale of ['en','de'])for(const width of [1440,390]){
  for(const kind of ['list','seen']){const matches=rows.filter(row=>row.file===`synthetic-windows-incident-inbox-${kind}-${width}-${locale}.png`);assert.equal(matches.length,1);const row=matches[0];assert.equal(row.sourceSha,sourceSha);assert.equal(row.test,windowsIncidentInboxCaseName);assert.equal(row.locale,locale);assert.deepEqual(row.viewport,{width,height:width===390?844:1000});assert.equal(row.fullPage,false);assert.equal(row.publicSafe,true);assert.equal(row.fixtureDisclosure,windowsIncidentInboxDisclosure);}
  const matches=details.cases.filter(row=>row.locale===locale&&row.width===width);assert.equal(matches.length,1);const row=matches[0];assert.equal(row.postCount,1);assert.equal(row.readbackCount,1);assert.equal(row.postKey,windowsIncidentInboxTargetKey);assert.equal(row.readbackKey,row.postKey);assert.ok(Number.isFinite(Date.parse(row.acknowledgedAt)));assert.equal(row.readbackAcknowledgedAt,row.acknowledgedAt);assert.equal(row.readbackResolvedAt,null);assert.equal(row.readbackScope,'active');
 }
 return {list:4,seen:4,explicitAcknowledgements:4};
}
