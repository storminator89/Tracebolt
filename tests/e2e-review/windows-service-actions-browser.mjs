import {settlePausedDetailRoute} from './paused-detail-route.mjs';
/** Entirely intercepted browser fixture, including named-session metadata.
 * Real manager/broker persistence and fake SCM execution remain separate Go tests.
 * Importing this module never starts a browser, server, host action or grant. */
import fs from 'node:fs';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {windowsFullServicesAbsentPage,windowsFullServicesFixtureQuery} from './windows-full-services-browser.mjs';
import {windowsFullProcessesAbsentPage,windowsFullProcessesFixtureQuery} from './windows-full-processes-browser.mjs';
const require=createRequire(new URL('../../web/package.json',import.meta.url));
const built=require('esbuild').buildSync({stdin:{contents:"export {windowsView,windowsNow} from './windows-inventory-fixture'; export {windowsHealthDevice} from './windows-health-fixture'; export {validWindowsActionView} from './windows-service-action-types';",resolveDir:fileURLToPath(new URL('../../web/src/',import.meta.url)),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {windowsView,windowsNow,windowsHealthDevice,validWindowsActionView}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
const golden=JSON.parse(fs.readFileSync(new URL('../fixtures/windows-service-action-view.json',import.meta.url),'utf8'));
export const windowsServiceActionsCaseName='Synthetic Windows service review, explicit approval and saved-result readback in the compiled UI';
export const windowsServiceActionsDisclosure='Entirely intercepted invented named-session, inventory and action responses using Go API golden vectors. Browser review, explicit approval and saved-status GET survive page reload in an in-memory fixture only. No real login, durable manager/broker write, SCM control, local grant, installation, credential, external request or native acceptance; real HTTP/store/fake-SCM evidence is separate.';
const stages=new Set(['detail-route-readiness','reload-detail-route-readiness','setup','document','review','approve','saved-status','reload','capture','complete']);let stage='setup';
export const windowsServiceActionsFailureStage=()=>stages.has(stage)?stage:'setup';
const csrf='PUBLIC_SYNTHETIC_WINDOWS_ACTION_CSRF';
const stamp=(value,from,to)=>{
 if(Array.isArray(value))return value.map(item=>stamp(item,from,to));
 if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([key,item])=>[key,key==='deadline'?item+(Date.parse(to)-Date.parse(from))/1000:stamp(item,from,to)]));
 return typeof value==='string'&&/^2026-\d\d-\d\dT/.test(value)?new Date(Date.parse(value)+Date.parse(to)-Date.parse(from)).toISOString():value;
};
export function createWindowsServiceActionsFixture(now='2026-10-11T10:00:00Z'){
 if(!Number.isFinite(Date.parse(now))||Date.parse(now)%1000!==0)throw new Error('Invalid synthetic clock');
 const item=golden.cases.find(value=>value.operation==='restart'),source=item.preview.serverNow;
 const preview=stamp(item.preview,source,now),approved=stamp(item.approved,source,now),complete=stamp(item.complete,source,now),ready={...structuredClone(preview),preview:null};
 for(const value of [ready,preview,approved,complete])if(!validWindowsActionView(value,golden.deviceId,golden.actorId))throw new Error('Invalid synthetic action vector');
 const inventory=stamp(windowsView(),windowsNow,now);inventory.deviceId=golden.deviceId;
 const device={...stamp(windowsHealthDevice(),windowsNow,now),id:golden.deviceId,name:'SYNTHETIC · Windows service control',status:'unknown'};
 const session={mode:'lan',transport:'http',insecureTestMode:true,transportWarning:'unencrypted_lan_test',authenticationRequired:true,authenticated:true,csrfToken:csrf,serverNow:now,expiresAt:new Date(Date.parse(now)+3600000).toISOString(),expiresInSeconds:3600,loginMode:'named',actorId:golden.actorId,capabilities:['read','windows_service_control']};
 let phase='ready';const counts={preview:0,approve:0,status:0};
 return {device,inventory,session,now,preview,approved,complete,counts,
  view(){counts.status++;return structuredClone(phase==='approved'||phase==='complete'?complete:ready);},
  previewAction(raw){if(phase!=='ready'||raw!==JSON.stringify({target:ready.target,operation:'restart'}))return null;phase='preview';counts.preview++;return structuredClone(preview);},
  approveAction(raw){const p=preview.preview;if(phase!=='preview'||raw!==JSON.stringify({previewId:p.id,previewDigest:p.digest}))return null;phase='approved';counts.approve++;return structuredClone(approved);},
 };
}
/** Only these two fixed synthetic POSTs can advance the in-memory fixture.
 * No action request ever continues to the static server or a real manager. */
export function windowsServiceActionsRoute({base,fixture,state}){
 const origin=new URL(base);if(origin.origin!==base||origin.protocol!=='http:'||origin.hostname!=='127.0.0.1')throw new Error('Invalid synthetic origin');
 const prefix='/api/devices/'+fixture.device.id,actionPath=prefix+'/windows-service-actions';
 return async route=>{
  const request=route.request(),url=new URL(request.url()),method=request.method(),raw=request.postData();
  const block=reason=>{state.blocked.push(reason);return route.abort('blockedbyclient');};
  if(url.origin!==base){state.external.push('external');return route.abort('blockedbyclient');}
  const reply=value=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(value)});
  if(url.pathname.startsWith('/api/')&&url.search)return block('query');
  if(url.pathname===actionPath+'/preview'||url.pathname===actionPath+'/approve'){
   if(method!=='POST'||request.headers()['x-csrf-token']!==csrf||request.headers()['origin']!==base||request.headers()['content-type']!=='application/json'||typeof raw!=='string'||Buffer.byteLength(raw)>1024)return block('action-shape');
   const value=url.pathname.endsWith('/preview')?fixture.previewAction(raw):fixture.approveAction(raw);
   return value?reply(value):block('action-binding-or-replay');
  }
  if(url.pathname===prefix+'/windows-full-services/query'){
   const query=windowsFullServicesFixtureQuery({pathname:url.pathname,search:url.search,method,headers:request.headers(),raw},prefix);
   if(!query||request.headers()['x-csrf-token']!==csrf||request.headers()['origin']!==base)return block('inventory-query');
   return reply(windowsFullServicesAbsentPage(fixture.device.id,query,fixture.now));
  }
  // The initial inventory tab can read its independent process scope before
  // the operator selects Services. This synthetic identity has no such grant.
  if(url.pathname===prefix+'/windows-full-processes/query'){
   const query=windowsFullProcessesFixtureQuery({pathname:url.pathname,search:url.search,method,headers:request.headers(),raw},prefix);
   if(!query||request.headers()['x-csrf-token']!==csrf||request.headers()['origin']!==base||request.headers()['content-type']!=='application/json')return block('process-inventory-query');
   return reply(windowsFullProcessesAbsentPage(fixture.device.id,query,fixture.now));
  }
  if(method!=='GET'||raw!==null)return block('unexpected-write');
  if(url.pathname==='/api/auth/session')return reply(fixture.session);
  if(url.pathname==='/api/session')return reply({csrfToken:csrf});
  if(url.pathname===prefix)return reply(fixture.device);
  if(url.pathname===prefix+'/windows-inventory')return reply(fixture.inventory);
  if(url.pathname===actionPath)return reply(fixture.view());
  // Unavailable siblings are explicit and never evidence of a granted scope.
  if(url.pathname.startsWith('/api/'))return route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({error:{code:'synthetic_unavailable'}})});
  return route.continue();
 };
}
const text={
 en:{inventory:'Inventory',services:'Services',select:'Select service: FixtureService',review:'Review action',approve:'Approve this action once',refresh:'Read saved status',ack:'I approve this exact operation and its possible interruption.',outcome:'Running observed',receipt:'Action receipt',flags:'Stop: Attempted / requested / observed yes / yes / yes',approved:'Approved; awaiting one-time claim'},
 de:{inventory:'Inventar',services:'Dienste',select:'Dienst auswählen: FixtureService',review:'Aktion prüfen',approve:'Diese Aktion einmal freigeben',refresh:'Gespeicherten Status lesen',ack:'Ich genehmige genau diese Aktion und ihre mögliche Unterbrechung.',outcome:'Laufender Zustand beobachtet',receipt:'Aktionsbeleg',flags:'Stoppen: Versucht / angefordert / beobachtet ja / ja / ja',approved:'Freigegeben; einmalige Abholung ausstehend'},
};
export async function exerciseWindowsServiceActions({page,expect,base,fixture,locale,width,shot}){
 const c=text[locale],panel=page.locator('.windows-service-actions');
 const open=async()=>{await page.getByRole('tab',{name:c.inventory,exact:true}).click();await page.getByRole('tab',{name:c.services,exact:true}).click();await expect(panel).toBeVisible();};
 stage='document';await page.goto(base+'/#/devices/'+fixture.device.id);await page.getByLabel(/Language|Sprache/).selectOption(locale);await expect(page.locator('html')).toHaveAttribute('lang',locale);stage='detail-route-readiness';await settlePausedDetailRoute(page,expect,page.getByRole('tab',{name:locale==='de'?'Inventar':'Inventory',exact:true}));stage='document';await open();
 stage='review';await panel.getByRole('button',{name:c.select,exact:true}).click();await panel.getByRole('combobox').selectOption('restart');await panel.getByRole('button',{name:c.review,exact:true}).click();
 const review=panel.getByRole('group',{name:c.review,exact:true}),approve=review.getByRole('button',{name:c.approve,exact:true});
 await expect(review).toContainText('FixtureService');await expect(approve).toBeDisabled();await expect(review.getByRole('checkbox',{name:c.ack,exact:true})).not.toBeChecked();expect(fixture.counts).toEqual({preview:1,approve:0,status:1});
 stage='approve';await review.getByRole('checkbox',{name:c.ack,exact:true}).check();await expect(approve).toBeEnabled();
 // Same-task repeated clicks hit the production synchronous one-request lock.
 await approve.evaluate(button=>{button.click();button.click();});await expect(panel.getByRole('status')).toContainText(c.approved);await expect(review).toHaveCount(0);expect(fixture.counts.approve).toBe(1);
 stage='saved-status';await panel.getByRole('button',{name:c.refresh,exact:true}).click();await expect(panel.getByRole('status').locator('strong')).toHaveText(c.outcome);const receipt=panel.locator('.windows-service-action-receipt');await expect(receipt).not.toHaveAttribute('open');await expect(panel.getByText(c.flags,{exact:true})).toBeHidden();
 await receipt.getByText(c.receipt,{exact:true}).click();await expect(panel.getByText(c.flags,{exact:true})).toBeVisible();
 const deadline=await receipt.locator('time').getAttribute('datetime');expect(deadline).toBe(fixture.complete.job.startDeadline);
 stage='reload';await page.reload();stage='reload-detail-route-readiness';await settlePausedDetailRoute(page,expect,page.getByRole('tab',{name:locale==='de'?'Inventar':'Inventory',exact:true}));stage='reload';await open();await expect(panel.getByRole('status').locator('strong')).toHaveText(c.outcome);await expect(receipt).not.toHaveAttribute('open');await expect(receipt.locator('time')).toHaveAttribute('datetime',deadline);await expect(panel.getByRole('checkbox')).toHaveCount(0);expect(fixture.counts).toEqual({preview:1,approve:1,status:3});
 stage='capture';await panel.evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);await expect(panel.getByText(c.outcome,{exact:true})).toBeInViewport();await expect(receipt.getByText(c.receipt,{exact:true})).toBeInViewport();
 await shot(page,`synthetic-windows-service-actions-${width}-${locale}`,windowsServiceActionsDisclosure);
 stage='complete';return {preview:1,approve:1,status:3,reloadReadback:true,durableStoreAcceptance:false,nativeAcceptance:false};
}
export function requireWindowsServiceActionsEvidence(screenshots,sourceSha){
 const fail=()=>{throw new Error('Windows service action evidence missing or inconsistent');};
 if(!Array.isArray(screenshots)||!/^[a-f0-9]{40}$/.test(sourceSha??'')||screenshots.length!==4)fail();
 for(const locale of ['en','de'])for(const width of [1440,390]){
  const matches=screenshots.filter(item=>item?.file===`synthetic-windows-service-actions-${width}-${locale}.png`);if(matches.length!==1)fail();const item=matches[0];
  if(item.sourceSha!==sourceSha||item.test!==windowsServiceActionsCaseName||item.locale!==locale||item.viewport?.width!==width||item.viewport?.height!==(width===390?844:1000)||item.publicSafe!==true||item.fullPage!==false||item.fixtureDisclosure!==windowsServiceActionsDisclosure)fail();
 }
 return {screens:4,durableStoreAcceptance:false,nativeAcceptance:false};
}
