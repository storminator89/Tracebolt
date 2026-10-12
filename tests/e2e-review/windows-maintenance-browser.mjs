/** Inert production-UI fixture helper. Importing starts no browser or server. */
import assert from 'node:assert/strict';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {windowsIncidentInboxBrowserFixture,windowsIncidentInboxQuery} from './windows-incident-inbox-browser.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..'),require=createRequire(path.join(root,'web/package.json'));
const built=await require('esbuild').build({stdin:{contents:"export {windowsCapacityDevice} from './windows-capacity-fixture'; export {validWindowsMaintenanceView,validWindowsMaintenanceTime} from './windows-maintenance-types'; export {default as wire} from '../../tests/fixtures/windows-maintenance-view.json';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {windowsCapacityDevice,validWindowsMaintenanceView,validWindowsMaintenanceTime,wire}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
export const windowsMaintenanceCaseName='Bounded Windows maintenance review, start and early-end readback';
export const windowsMaintenanceDisclosure='Production UI and real disposable loopback login with intercepted invented maintenance metadata. One explicitly reviewed start and early end per locale/viewport; original end and existing incident/source/seen/count text remain unchanged. Hosted synthetic browser evidence only; no live metadata write, native host action, AI, notifications, alarm suppression, grant or deployment.';
export const windowsMaintenanceTargetKey=wire.empty.targets.find(target=>target.domain==='disk').key;
export const windowsMaintenanceDeviceKey=wire.empty.targets.find(target=>target.domain==='all').key;
export const canonicalWindowsMaintenanceTime=value=>new Date(value).toISOString().replace(/\.000Z$/,'Z').replace(/(\.\d*?[1-9])0+Z$/,'$1Z');
let stage='setup',failures=0,pending=0;
export const windowsMaintenanceRouteState=()=>({failures,pending});
export const windowsMaintenanceFailureStage=()=>new Set(['setup','login','locale','review','start','end','readback','layout','complete']).has(stage)?stage:'setup';
export function guardWindowsMaintenanceRoute(route,handler){pending++;return Promise.resolve().then(()=>handler(route)).catch(async()=>{failures++;try{await route.abort('failed');}catch{/* Teardown already ended the request. */}}).finally(()=>{pending--;});}
export function windowsMaintenanceBrowserFixture(serverNow,expiresAt,record=null){
 const view=structuredClone(wire.empty);view.serverNow=canonicalWindowsMaintenanceTime(serverNow);view.authorityExpiresAt=canonicalWindowsMaintenanceTime(expiresAt);
 if(record)view.targets=view.targets.map(target=>target.key===windowsMaintenanceTargetKey?{...target,...structuredClone(record)}:target);
 assert.ok(validWindowsMaintenanceView(view));
 const source=windowsCapacityDevice(),metadata={...source,id:view.targets[0].deviceId,name:'Synthetic Windows Desk',status:'unknown',agentCertificate:{source:'guided-enrollment',expiresAt,checkedAt:serverNow}};
 return {view,metadata};
}
export function windowsMaintenanceBrowserChange(record,kind,body,now){
 now=canonicalWindowsMaintenanceTime(now);
 if(kind==='start'){
  assert.equal(record,null);assert.deepEqual(Object.keys(body).sort(),['endsAt','intent','key','revision']);assert.equal(body.key,windowsMaintenanceTargetKey);assert.equal(body.revision,0);assert.equal(body.intent,'planned-work');assert.ok(validWindowsMaintenanceTime(body.endsAt));assert.ok(Date.parse(body.endsAt)-Date.parse(now)>=60000&&Date.parse(body.endsAt)-Date.parse(now)<=86400000);
  return {revision:1,changedAt:now,windows:[{id:1,startedAt:now,endsAt:body.endsAt,endedAt:null,intent:body.intent}]};
 }
 assert.equal(kind,'end');assert.deepEqual(body,{key:windowsMaintenanceTargetKey,revision:1,windowId:1});assert.equal(record?.revision,1);assert.equal(record.windows[0].endedAt,null);assert.ok(Date.parse(now)>=Date.parse(record.windows[0].startedAt)&&Date.parse(now)<Date.parse(record.windows[0].endsAt));
 return {...record,revision:2,changedAt:now,windows:[{...record.windows[0],endedAt:now}]};
}
export async function windowsMaintenanceBrowserCase({page,expect,base,login,shot}){
 stage='login';failures=0;pending=0;await login(page);
 let record=null,origin=null,startCount=0,endCount=0,readCount=0,startReadback=0,endReadback=0,reviewedEnd=null;
 const external=[],unexpected=[],cases=[];
 const getSession=async()=>{const response=await page.request.get(base+'/api/auth/session',{maxRedirects:0,timeout:5000});try{assert.equal(response.status(),200);const session=await response.json();assert.equal(session.authenticated,true);assert.equal(session.loginMode,'shared');return session;}finally{await response.dispose();}};
 const fulfill=(route,value)=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(value)});
 const handle=async route=>{
  const req=route.request(),url=new URL(req.url());if(url.origin!==base){external.push('external');return route.abort('blockedbyclient');}
  if(url.pathname==='/api/overview'){
   assert.equal(req.method(),'GET');assert.equal(url.search,'');const response=await route.fetch({maxRedirects:0,timeout:5000});let value;try{assert.equal(response.status(),200);value=await response.json();}finally{await response.dispose();}
   const session=await getSession(),fixture=windowsMaintenanceBrowserFixture(session.serverNow,session.expiresAt);return fulfill(route,{...value,devices:[fixture.metadata],stats:{...value.stats,totalDevices:1,healthyDevices:0,attentionDevices:0},generatedAt:session.serverNow});
  }
  if(url.pathname==='/api/fleet/windows-incidents'){
   assert.equal(req.method(),'GET');assert.equal(url.search,windowsIncidentInboxQuery);const session=await getSession();origin??=session.serverNow;return fulfill(route,windowsIncidentInboxBrowserFixture(session.serverNow,session.expiresAt,origin).view);
  }
  if(url.pathname==='/api/fleet/windows-maintenance'){
   assert.equal(req.method(),'GET');assert.equal(url.search,'');const session=await getSession();readCount++;if(record?.revision===1)startReadback++;if(record?.revision===2)endReadback++;return fulfill(route,windowsMaintenanceBrowserFixture(session.serverNow,session.expiresAt,record).view);
  }
  if(url.pathname==='/api/fleet/windows-maintenance/start'||url.pathname==='/api/fleet/windows-maintenance/end'){
   assert.equal(req.method(),'POST');assert.equal(url.search,'');const session=await getSession();assert.equal(req.headers()['x-csrf-token'],session.csrfToken);assert.match(req.headers()['content-type']??'',/^application\/json(?:;|$)/);const body=JSON.parse(req.postData());
   if(url.pathname.endsWith('/start')){assert.equal(startCount,0);assert.equal(endCount,0);assert.equal(readCount,1);assert.equal(body.endsAt,reviewedEnd);record=windowsMaintenanceBrowserChange(record,'start',body,session.serverNow);startCount++;}
   else{assert.equal(startCount,1);assert.equal(endCount,0);assert.equal(startReadback,1);record=windowsMaintenanceBrowserChange(record,'end',body,session.serverNow);endCount++;}
   return fulfill(route,windowsMaintenanceBrowserFixture(session.serverNow,session.expiresAt,record).view);
  }
  const allowedRead=['/api/auth/session','/api/session','/api/enrollment','/api/windows/enrollment','/api/fleet/identities'];
  if(req.method()==='GET'&&!url.pathname.startsWith('/api/'))return route.continue();
  if(req.method()==='GET'&&allowedRead.includes(url.pathname)&&!url.search)return route.continue();
  unexpected.push('unexpected-route');return route.abort('blockedbyclient');
 };
 await page.route('**/*',route=>guardWindowsMaintenanceRoute(route,handle));
 for(const locale of ['en','de'])for(const width of [1440,390]){
  stage='locale';const de=locale==='de';await page.setViewportSize({width,height:width===390?844:1000});await page.getByLabel(/Language|Sprache/).selectOption(locale);
  record=null;origin=null;startCount=0;endCount=0;readCount=0;startReadback=0;endReadback=0;reviewedEnd=null;await page.reload();await expect(page.locator('.app-shell')).toBeVisible();
  const inbox=page.locator('.windows-incident-inbox');await inbox.getByRole('button',{name:de?'Windows-Vorfälle':'Windows incidents',exact:true}).click();await expect(inbox.locator('.windows-incident-row')).toHaveCount(5);const incidentText=await inbox.innerText();
  const panel=page.locator('.windows-maintenance'),toggle=panel.getByRole('button',{name:de?'Windows-Wartung':'Windows maintenance',exact:true});await expect(toggle).toHaveAttribute('aria-expanded','false');expect(readCount).toBe(0);expect(startCount).toBe(0);expect(endCount).toBe(0);
  stage='review';await toggle.click();await panel.getByLabel(de?'Exaktes Windows-Gerät':'Exact Windows device',{exact:true}).selectOption(windowsMaintenanceDeviceKey);await panel.getByLabel(de?'Wartungsumfang':'Maintenance scope',{exact:true}).selectOption('disk');
  await expect(panel.getByRole('button',{name:de?'Wartungsstart prüfen':'Review maintenance start',exact:true})).toBeDisabled();await panel.getByLabel(de?'Absicht des Operators':'Operator intent',{exact:true}).selectOption('planned-work');await panel.getByRole('button',{name:de?'Wartungsstart prüfen':'Review maintenance start',exact:true}).click();
  const review=panel.getByRole('region',{name:de?'Exakte Wartungsänderung prüfen':'Review exact maintenance change',exact:true});reviewedEnd=await review.locator('.windows-local-time').getAttribute('datetime');assert.ok(validWindowsMaintenanceTime(reviewedEnd));expect(startCount).toBe(0);expect(endCount).toBe(0);
  await expect(review.locator('.windows-local-time')).toContainText('GMT');const exact=review.locator('.windows-maintenance-details');await expect(exact.locator('.windows-exact-time')).toBeHidden();await exact.locator('summary').press('Enter');await expect(exact.locator('.windows-exact-time')).toBeVisible();await expect(exact.locator('.windows-maintenance-identity')).toBeVisible();await expect(exact.locator('.windows-exact-time')).toHaveText(reviewedEnd);await expect(exact.locator('.windows-maintenance-identity')).toHaveText(wire.empty.targets[0].deviceId);await exact.locator('summary').press('Enter');await expect(exact.locator('.windows-exact-time')).toBeHidden();
  const verifyLayout=async()=>{stage='layout';expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);const overflows=await panel.locator('select,.windows-maintenance-review,.windows-maintenance-active li').evaluateAll(rows=>rows.map(row=>row.scrollWidth-row.clientWidth));for(const overflow of overflows)expect(overflow).toBeLessThanOrEqual(1);};
  await verifyLayout();await review.scrollIntoViewIfNeeded();await shot(page,`synthetic-windows-maintenance-review-${width}-${locale}`,windowsMaintenanceDisclosure);
  stage='start';await review.getByRole('button',{name:de?'Wartung starten':'Start maintenance',exact:true}).click();stage='readback';await expect.poll(()=>startReadback).toBe(1);await expect(panel.getByRole('list',{name:de?'Aktuelle Wartungsmarkierungen':'Current maintenance labels',exact:true})).toContainText(de?'Wartung jetzt · bis':'Maintenance now · until');expect(await inbox.innerText()).toBe(incidentText);expect(startCount).toBe(1);expect(endCount).toBe(0);expect(record.windows[0].endsAt).toBe(reviewedEnd);
  await verifyLayout();await panel.evaluate(el=>el.scrollIntoView({block:'start'}));await shot(page,`synthetic-windows-maintenance-active-${width}-${locale}`,windowsMaintenanceDisclosure);
  stage='end';await panel.getByRole('button',{name:de?'Vorzeitiges Ende prüfen':'Review early end',exact:true}).click();expect(endCount).toBe(0);await panel.getByRole('button',{name:de?'Wartung jetzt beenden':'End maintenance now',exact:true}).click();stage='readback';await expect.poll(()=>endReadback).toBe(1);await panel.locator('.windows-maintenance-history > summary').click();await expect(panel.getByText(de?'Vorzeitig beendet':'Ended early',{exact:true})).toBeVisible();expect(await inbox.innerText()).toBe(incidentText);expect(startCount).toBe(1);expect(endCount).toBe(1);expect(readCount).toBe(3);expect(record.windows[0].endsAt).toBe(reviewedEnd);assert.ok(record.windows[0].endedAt);
  await verifyLayout();await panel.locator('.windows-maintenance-history').scrollIntoViewIfNeeded();await shot(page,`synthetic-windows-maintenance-ended-${width}-${locale}`,windowsMaintenanceDisclosure);
  cases.push({locale,width,key:windowsMaintenanceTargetKey,startCount,endCount,startReadback,endReadback,reviewedEnd,retainedEnd:record.windows[0].endsAt,endedAt:record.windows[0].endedAt,revision:record.revision,incidentUnchanged:true});
  await toggle.click();await expect(panel.locator('select')).toHaveCount(0);await inbox.getByRole('button',{name:new RegExp(de?'^Windows-Vorfälle':'^Windows incidents')}).click();
 }
 await expect.poll(()=>windowsMaintenanceRouteState().pending).toBe(0);expect(external).toEqual([]);expect(unexpected).toEqual([]);expect(failures).toBe(0);stage='complete';return {screens:12,cases,nativeAcceptance:false,liveStoreAcceptance:false};
}
export function requireWindowsMaintenanceEvidence(rows,sourceSha,details){
 assert.match(sourceSha??'',/^[a-f0-9]{40}$/);assert.equal(rows.length,12);assert.equal(details?.screens,12);assert.equal(details.cases?.length,4);assert.equal(details.nativeAcceptance,false);assert.equal(details.liveStoreAcceptance,false);
 for(const locale of ['en','de'])for(const width of [1440,390]){
  for(const kind of ['review','active','ended']){const matches=rows.filter(row=>row.file===`synthetic-windows-maintenance-${kind}-${width}-${locale}.png`);assert.equal(matches.length,1);const row=matches[0];assert.equal(row.sourceSha,sourceSha);assert.equal(row.test,windowsMaintenanceCaseName);assert.equal(row.locale,locale);assert.deepEqual(row.viewport,{width,height:width===390?844:1000});assert.equal(row.fullPage,false);assert.equal(row.publicSafe,true);assert.equal(row.fixtureDisclosure,windowsMaintenanceDisclosure);}
  const matches=details.cases.filter(row=>row.locale===locale&&row.width===width);assert.equal(matches.length,1);const row=matches[0];assert.equal(row.key,windowsMaintenanceTargetKey);assert.equal(row.startCount,1);assert.equal(row.endCount,1);assert.equal(row.startReadback,1);assert.equal(row.endReadback,1);assert.ok(validWindowsMaintenanceTime(row.reviewedEnd));assert.equal(row.retainedEnd,row.reviewedEnd);assert.ok(validWindowsMaintenanceTime(row.endedAt));assert.ok(Date.parse(row.endedAt)<Date.parse(row.retainedEnd));assert.equal(row.revision,2);assert.equal(row.incidentUnchanged,true);
 }
 return {review:4,active:4,ended:4,explicitStarts:4,explicitEarlyEnds:4};
}
