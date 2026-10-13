/** Inert production-UI fixture helper. Importing starts no browser or server. */
import assert from 'node:assert/strict';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..'),require=createRequire(path.join(root,'web/package.json'));
const built=await require('esbuild').build({stdin:{contents:"export {windowsCapacityDevice} from './windows-capacity-fixture'; export {validWindowsIncidentInboxView,validWindowsIncidentAcknowledgement} from './windows-incident-inbox-types'; export {default as wire} from '../../tests/fixtures/windows-incident-inbox-view.json'; export {default as reviewWire} from '../../tests/fixtures/windows-service-incident-review.json'; export {validWindowsServiceIncidentReview} from './windows-service-incident-review-types'; export {validWindowsActionView} from './windows-service-action-types';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {windowsCapacityDevice,validWindowsIncidentInboxView,validWindowsIncidentAcknowledgement,wire,reviewWire,validWindowsServiceIncidentReview,validWindowsActionView}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
export const windowsIncidentInboxCaseName='Windows incident inbox and explicit acknowledgement readback';
export const windowsIncidentInboxDisclosure='Production UI and real disposable loopback login with intercepted invented Windows incidents and one explicitly clicked acknowledgement per locale/viewport. GET readback records seen while the incident remains active. Hosted browser fixture evidence only; no live acknowledgement, native endpoint read/action, new grant, AI, notification or deployment.';
export const windowsServiceIncidentReviewDisclosure='Entirely intercepted invented named session, exact service incident and binding-pinned control responses in the compiled production App. Opening reviews performs GET only; one deliberately selected restart preview per locale/viewport remains unchecked and unapproved. No approval, acknowledgement, collection, live manager/broker write, grant, SCM action or native acceptance.';
export const windowsIncidentInboxScenes=[...['en','de'].flatMap(locale=>[1440,390].flatMap(width=>['list','seen'].map(kind=>({name:`synthetic-windows-incident-inbox-${kind}-${width}-${locale}`,locale,width,fixtureDisclosure:windowsIncidentInboxDisclosure})))),...[["en",1440],["de",390]].flatMap(([locale,width])=>['service-review','service-preview'].map(kind=>({name:`synthetic-windows-incident-inbox-${kind}-${width}-${locale}`,locale,width,fixtureDisclosure:windowsServiceIncidentReviewDisclosure})))];
export const windowsIncidentInboxTargetKey=wire.active.items.find(item=>item.domain==='disk').key;
export const windowsIncidentInboxQuery='?scope=active&ack=all&offset=0&limit=25';
let stage='setup',failures=0,pending=0;
export const windowsIncidentInboxRouteState=()=>({failures,pending});
export const windowsIncidentInboxFailureStage=()=>new Set(['setup','login','locale','list','acknowledge','readback','service-review','service-preview','layout','complete']).has(stage)?stage:'setup';
export function guardWindowsIncidentInboxRoute(route,handler){pending++;return Promise.resolve().then(()=>handler(route)).catch(async()=>{failures++;try{await route.abort('failed');}catch{/* Teardown already ended the request. */}}).finally(()=>{pending--;});}
function shifted(value,origin,from=wire.active.serverNow){
 if(Array.isArray(value))return value.map(row=>shifted(row,origin,from));
 if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([key,row])=>[key,shifted(row,origin,from)]));
 return typeof value==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/.test(value)?new Date(Date.parse(value)+Date.parse(origin)-Date.parse(from)).toISOString():value;
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
 let origin=null,acknowledgedAt=null,postCount=0,readCount=0,readbackCount=0,postKey=null,readback=null,serviceFixture=null;
 const external=[],unexpected=[],cases=[];
 const getSession=async()=>{const response=await page.request.get(base+'/api/auth/session',{maxRedirects:0,timeout:5000});try{assert.equal(response.status(),200);const session=await response.json();assert.equal(session.authenticated,true);assert.equal(session.loginMode,'shared');return session;}finally{await response.dispose();}};
 const fulfill=(route,value)=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(value)});
 const handle=async route=>{
  if(serviceFixture)return windowsServiceIncidentReviewRoute({base,fixture:serviceFixture,external,unexpected})(route);
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
 const serviceReviewCases=[];
 for(const [locale,width] of [['en',1440],['de',390]]){
  const source=await getSession();serviceFixture=windowsServiceIncidentReviewFixture(source);
  serviceReviewCases.push(await exerciseWindowsServiceIncidentReview({page,expect,base,fixture:serviceFixture,locale,width,shot}));
 }
 await expect.poll(()=>windowsIncidentInboxRouteState().pending).toBe(0);expect(external).toEqual([]);expect(unexpected).toEqual([]);expect(failures).toBe(0);stage='complete';return {screens:12,cases,serviceReviewCases,nativeAcceptance:false,liveStoreAcceptance:false};
}
export function requireWindowsIncidentInboxEvidence(rows,sourceSha,details){
 assert.match(sourceSha??'',/^[a-f0-9]{40}$/);assert.equal(rows.length,12);assert.equal(details?.screens,12);assert.equal(details.cases?.length,4);assert.equal(details.nativeAcceptance,false);assert.equal(details.liveStoreAcceptance,false);
 for(const locale of ['en','de'])for(const width of [1440,390]){
  for(const kind of ['list','seen']){const matches=rows.filter(row=>row.file===`synthetic-windows-incident-inbox-${kind}-${width}-${locale}.png`);assert.equal(matches.length,1);const row=matches[0];assert.equal(row.sourceSha,sourceSha);assert.equal(row.test,windowsIncidentInboxCaseName);assert.equal(row.locale,locale);assert.deepEqual(row.viewport,{width,height:width===390?844:1000});assert.equal(row.fullPage,false);assert.equal(row.publicSafe,true);assert.equal(row.fixtureDisclosure,windowsIncidentInboxDisclosure);}
  const matches=details.cases.filter(row=>row.locale===locale&&row.width===width);assert.equal(matches.length,1);const row=matches[0];assert.equal(row.postCount,1);assert.equal(row.readbackCount,1);assert.equal(row.postKey,windowsIncidentInboxTargetKey);assert.equal(row.readbackKey,row.postKey);assert.ok(Number.isFinite(Date.parse(row.acknowledgedAt)));assert.equal(row.readbackAcknowledgedAt,row.acknowledgedAt);assert.equal(row.readbackResolvedAt,null);assert.equal(row.readbackScope,'active');
 }
 assert.equal(details.serviceReviewCases?.length,2);
 for(const [locale,width] of [['en',1440],['de',390]]){
  for(const kind of ['service-review','service-preview']){const name=`synthetic-windows-incident-inbox-${kind}-${width}-${locale}`,matches=rows.filter(row=>row.file===name+'.png');assert.equal(matches.length,1);const row=matches[0];assert.equal(row.sourceSha,sourceSha);assert.equal(row.test,windowsIncidentInboxCaseName);assert.equal(row.locale,locale);assert.deepEqual(row.viewport,{width,height:width===390?844:1000});assert.equal(row.fullPage,false);assert.equal(row.publicSafe,true);assert.equal(row.fixtureDisclosure,windowsServiceIncidentReviewDisclosure);}
  const matches=details.serviceReviewCases.filter(row=>row.locale===locale&&row.width===width);assert.equal(matches.length,1);const row=matches[0];
  assert.equal(row.key,reviewWire.matched.incident.key);assert.equal(row.target,reviewWire.matched.incident.serviceName);assert.equal(row.bindingDigest,reviewWire.matched.control.bindingDigest);
  assert.deepEqual(row.counts,{inbox:1,review:1,status:1,preview:1,approve:0,acknowledge:0,collection:0});assert.equal(row.initialPreviewCount,0);assert.equal(row.operationInitiallyBlank,true);assert.equal(row.approvalChecked,false);
 }
 return {list:4,seen:4,explicitAcknowledgements:4,serviceReview:2,servicePreview:2,explicitPreviews:2,serviceApprovals:0};
}


/** A separate synthetic named session for changed-view captures. No API falls
 * through to the loopback manager in this phase, including status/preview. */
export function windowsServiceIncidentReviewFixture(source){
 assert.equal(source.mode,'lan');assert.equal(source.authenticated,true);assert.equal(source.loginMode,'shared');assert.ok(Number.isFinite(Date.parse(source.serverNow)));assert.ok(Date.parse(source.expiresAt)>Date.parse(source.serverNow));assert.equal(typeof source.csrfToken,'string');
 const review=shifted(reviewWire.matched,source.serverNow,reviewWire.matched.serverNow),item=review.incident;
 review.authorityExpiresAt=new Date(Math.min(Date.parse(review.authorityExpiresAt),Date.parse(source.expiresAt))).toISOString();item.statusValidUntil=new Date(Math.min(Date.parse(item.statusValidUntil),Date.parse(review.authorityExpiresAt))).toISOString();
 const actorId=`operator_${'6'.repeat(32)}`,session={...source,loginMode:'named',actorId,capabilities:['read','windows_service_control']};
 const view={schemaVersion:'tracebolt.windows-incident-inbox.v1',serverNow:review.serverNow,authorityExpiresAt:review.authorityExpiresAt,scope:'active',ack:'all',offset:0,limit:25,total:1,nextOffset:null,counts:{active:1,resolved:0,acknowledged:0,unacknowledged:1,total:1},coverage:{devices:1,unavailableDevices:0,unknownChecks:0,disabledChecks:0},items:[item]};
 const metadata={...windowsCapacityDevice(),id:item.deviceId,name:'Synthetic Windows Desk',status:'unknown',agentCertificate:{source:'guided-enrollment',expiresAt:source.expiresAt,checkedAt:source.serverNow}};
 const ready={schemaVersion:'tracebolt.windows-service-action-view.v1',deviceId:item.deviceId,serverNow:review.serverNow,configured:true,available:true,reason:'ready',target:item.serviceName,preview:null,job:null};
 const preview={...ready,preview:{version:'tracebolt.windows-service-action-preview.v1',id:`action_${'5'.repeat(32)}`,binding:review.control.binding,operation:'restart',actorId,sequence:'1',createdAt:review.serverNow,expiresAt:new Date(Date.parse(review.serverNow)+60000).toISOString(),digest:`sha256:${'9'.repeat(64)}`}};
 assert.ok(validWindowsIncidentInboxView(view,'active','all',0));assert.ok(validWindowsServiceIncidentReview(review,item.key,item.deviceId,item.serviceName));for(const value of [ready,preview])assert.ok(validWindowsActionView(value,item.deviceId,actorId));
 const overview={product:'Tracebolt',mode:'lan',generatedAt:review.serverNow,stats:{totalDevices:1,healthyDevices:0,attentionDevices:0,unknownDevices:1,openCases:0,criticalCases:0},devices:[metadata],cases:[],activity:[]};
 return {review,view,metadata,session,ready,preview,overview,counts:{inbox:0,review:0,status:0,preview:0,approve:0,acknowledge:0,collection:0}};
}
export function windowsServiceIncidentReviewRoute({base,fixture,external,unexpected}){
 const origin=new URL(base);assert.equal(origin.origin,base);assert.equal(origin.hostname,'127.0.0.1');assert.equal(origin.protocol,'http:');
 const item=fixture.review.incident,actionPath=`/api/devices/${item.deviceId}/windows-service-actions`,reviewPath=`/api/fleet/windows-incidents/${item.key}/service-review`;
 return async route=>{
  const req=route.request(),url=new URL(req.url()),method=req.method(),raw=req.postData();
  if(url.origin!==base){external.push('external');return route.abort('blockedbyclient');}
  const block=()=>{unexpected.push('unexpected-service-review-route');return route.abort('blockedbyclient');},reply=value=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(value)});
  const pinned=()=>assert.equal(req.headers()['x-tracebolt-windows-service-review'],fixture.review.control.bindingDigest);
  if(url.pathname===actionPath+'/preview'){
   assert.equal(url.search,'');assert.equal(method,'POST');assert.equal(req.headers()['origin'],base);assert.equal(req.headers()['x-csrf-token'],fixture.session.csrfToken);assert.equal(req.headers()['content-type'],'application/json');pinned();
   assert.equal(raw,JSON.stringify({target:item.serviceName,operation:'restart'}));assert.equal(fixture.counts.review,1);assert.equal(fixture.counts.status,1);assert.equal(fixture.counts.preview,0);fixture.counts.preview++;return reply(fixture.preview);
  }
  if(method!=='GET'||raw!==null){if(url.pathname===actionPath+'/approve')fixture.counts.approve++;else if(url.pathname.endsWith('/acknowledge'))fixture.counts.acknowledge++;else fixture.counts.collection++;return block();}
  if(url.pathname==='/api/fleet/windows-incidents'){assert.equal(url.search,windowsIncidentInboxQuery);assert.equal(fixture.counts.inbox,0);fixture.counts.inbox++;return reply(fixture.view);}
  if(url.search)return block();
  if(url.pathname==='/api/auth/session')return reply(fixture.session);
  if(url.pathname==='/api/session')return reply({csrfToken:fixture.session.csrfToken});
  if(url.pathname==='/api/overview')return reply(fixture.overview);
  if(url.pathname===reviewPath){assert.equal(fixture.counts.review,0);fixture.counts.review++;return reply(fixture.review);}
  if(url.pathname===actionPath){pinned();assert.equal(fixture.counts.status,0);fixture.counts.status++;return reply(fixture.ready);}
  if(url.pathname==='/api/fleet/identities')return reply({schemaVersion:'tracebolt.fleet-identities.v2',serverNow:fixture.session.serverNow,items:[]});
  if(url.pathname==='/api/fleet/groups')return reply({schemaVersion:'tracebolt.fleet-groups.v1',serverNow:fixture.session.serverNow,groups:[],devices:[{id:item.deviceId,name:fixture.metadata.name,platform:'windows'}]});
  if(!url.pathname.startsWith('/api/'))return route.continue();
  return block();
 };
}
export async function exerciseWindowsServiceIncidentReview({page,expect,base,fixture,locale,width,shot}){
 assert.ok(locale==='en'&&width===1440||locale==='de'&&width===390);const de=locale==='de';
 stage='service-review';await page.setViewportSize({width,height:width===390?844:1000});await page.goto(base+'/#/devices');await page.reload();await expect(page.locator('.app-shell')).toBeVisible();await page.getByLabel(/Language|Sprache/).selectOption(locale);await expect(page.locator('html')).toHaveAttribute('lang',locale);
 const panel=page.locator('.windows-incident-inbox');await panel.getByRole('button',{name:de?'Windows-Vorfälle':'Windows incidents',exact:true}).click();await expect(panel.locator('.windows-incident-row')).toHaveCount(1);
 await panel.getByRole('button',{name:`${de?'Dienst prüfen':'Review service'}: Synthetic Windows Desk · ${fixture.review.incident.serviceName}`,exact:true}).click();
 const review=panel.getByRole('region',{name:de?'Vorfallsdienst prüfen':'Review incident service',exact:true}),controls=review.locator('.windows-service-actions');
 await expect(review).toBeVisible();await expect(controls.getByRole('button',{name:`${de?'Dienst auswählen':'Select service'}: ${fixture.review.incident.serviceName}`,exact:true})).toBeVisible();await expect(review.locator('time').first()).toHaveAttribute('datetime',fixture.review.incident.openedAt);
 await expect(controls.getByRole('combobox')).toHaveCount(0);await expect(controls.getByRole('checkbox')).toHaveCount(0);expect(fixture.counts).toEqual({inbox:1,review:1,status:1,preview:0,approve:0,acknowledge:0,collection:0});
 const layout=async()=>{expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);expect(await review.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);};
 await layout();await review.scrollIntoViewIfNeeded();await shot(page,`synthetic-windows-incident-inbox-service-review-${width}-${locale}`,windowsServiceIncidentReviewDisclosure);
 stage='service-preview';await controls.getByRole('button',{name:`${de?'Dienst auswählen':'Select service'}: ${fixture.review.incident.serviceName}`,exact:true}).click();const choose=controls.getByRole('combobox'),makePreview=controls.getByRole('button',{name:de?'Aktion prüfen':'Review action',exact:true});await expect(choose).toHaveValue('');await expect(makePreview).toBeDisabled();expect(fixture.counts.preview).toBe(0);
 await choose.selectOption('restart');await makePreview.click();const preview=controls.getByRole('group',{name:de?'Aktion prüfen':'Review action',exact:true});await expect(preview).toContainText(`${de?'Neu starten':'Restart'}: ${fixture.review.incident.serviceName}`);await expect(preview.getByRole('checkbox')).not.toBeChecked();await expect(preview.getByRole('button',{name:de?'Diese Aktion einmal freigeben':'Approve this action once',exact:true})).toBeDisabled();
 expect(fixture.counts).toEqual({inbox:1,review:1,status:1,preview:1,approve:0,acknowledge:0,collection:0});await layout();await preview.scrollIntoViewIfNeeded();await shot(page,`synthetic-windows-incident-inbox-service-preview-${width}-${locale}`,windowsServiceIncidentReviewDisclosure);
 await review.getByRole('button',{name:de?'Dienstprüfung schließen':'Close service review',exact:true}).click();await expect(review).toHaveCount(0);await expect.poll(()=>windowsIncidentInboxRouteState().pending).toBe(0);
 return {locale,width,key:fixture.review.incident.key,target:fixture.review.incident.serviceName,bindingDigest:fixture.review.control.bindingDigest,counts:{...fixture.counts},initialPreviewCount:0,operationInitiallyBlank:true,approvalChecked:false};
}
