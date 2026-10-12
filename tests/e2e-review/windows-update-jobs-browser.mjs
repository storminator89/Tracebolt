/** Inert synthetic UI controller. Importing starts no browser, listener or WUA. */
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {createWindowsServiceActionsFixture} from './windows-service-actions-browser.mjs';
import {windowsFullProcessesAbsentPage,windowsFullProcessesFixtureQuery} from './windows-full-processes-browser.mjs';
import {windowsUpdatesBrowserFixture} from './windows-updates-browser.mjs';
const require=createRequire(new URL('../../web/package.json',import.meta.url));
const built=require('esbuild').buildSync({stdin:{contents:"export {validUpdateJobView} from './windows-update-jobs-types';",resolveDir:fileURLToPath(new URL('../../web/src/',import.meta.url)),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {validUpdateJobView}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
export const windowsUpdateJobsOrigin='https://windows-update-jobs.invalid';
export const windowsUpdateJobsCaseName='Synthetic Windows update readiness, explicit approval and saved result in the compiled UI';
export const windowsUpdateJobsDisclosure='Entirely intercepted invented TLS-session, cached update, readiness and result metadata in the compiled UI. Manual unchecked approval and saved readback only in an in-memory fixture. No actual TLS authority, host grant, elevated executor, native WUA, real manager write, download, EULA acceptance, installation or reboot. Source/browser evidence is not native patching.';
const stages=new Set(['setup','document','request','readiness','review','approve','saved-result','reload','complete']);let stage='setup';
export const windowsUpdateJobsFailureStage=()=>stages.has(stage)?stage:'setup';
export function createWindowsUpdateJobsFixture(){
 const fixture=createWindowsServiceActionsFixture(),at=Date.parse(fixture.now)/1000;
 fixture.session={...fixture.session,transport:'https',insecureTestMode:false,transportWarning:null,capabilities:['read','windows_update_install']};
 fixture.device={...fixture.device,name:'SYNTHETIC · Selected cached Windows update'};
 fixture.inventory=windowsUpdatesBrowserFixture({serverNow:fixture.now,capturedAt:fixture.now,count:1,phase:'observed'});fixture.inventory.deviceId=fixture.device.id;
 const {updateId,revision}=fixture.inventory.updates.rows[0],selection={updateId,revision},digest='sha256:'+'3'.repeat(64),counts={request:0,preview:0,approve:0,status:0};
 let phase='ready',id=null,preview=null;
 const view=(state=phase)=>{
  const value={version:'tracebolt.windows-selected-update-job.v1',deviceId:fixture.device.id,serverNow:at,available:state==='ready',reason:state==='ready'?'ready':'job_pending_or_intervention',job:state==='ready'?null:{id,selection,state,reason:state==='requested'?'readiness_pending':'ready',preview:state==='preview'?preview:null,result:state==='complete'?{jobId:id,envelopeDigest:'sha256:'+'7'.repeat(64),attempted:true,outcome:'succeeded',operationResult:2,hresult:0,rebootRequired:'yes',completedAt:at}:null}};
  if(!validUpdateJobView(value,fixture.device.id,fixture.session.actorId))throw new Error('Invalid synthetic update view');return structuredClone(value);
 };
 return {...fixture,selection,updateCounts:counts,previewAction(){return null;},approveAction(){return null;},
  updateView(){counts.status++;if(phase==='requested')phase='preview';else if(phase==='approved')phase='complete';return view();},
  updateMutation(op,raw){let input;try{input=JSON.parse(raw);}catch{return null;}
   if(op==='request'){
    if(phase!=='ready'||!/^update_[a-f0-9]{32}$/.test(input?.requestId)||raw!==JSON.stringify({requestId:input.requestId,...selection}))return null;
    id=input.requestId;preview={id,actorId:fixture.session.actorId,binding:{managerId:'manager_'+'1'.repeat(32),deviceId:fixture.device.id,incarnationDigest:'sha256:'+'2'.repeat(64),executorId:'executor_'+'4'.repeat(32),executorKeyId:'sha256:'+'5'.repeat(64),grantId:'grant_'+'6'.repeat(32),keyId:'sha256:'+'8'.repeat(64)},readiness:{selection,capturedAt:at,software:'yes',installed:'no',hidden:'no',downloaded:'yes',eulaAccepted:'yes',canRequestUserInput:'no',canRequireSource:'no',requiresNetwork:'no',bundledCount:0,installerBusy:'no',rebootRequiredBefore:'no',rebootBehavior:'can',offlineVerified:'yes'},createdAt:at,expiresAt:at+60,digest};phase='requested';counts.request++;return view();
   }
   if(op==='preview'&&phase==='preview'&&counts.preview===0&&raw===JSON.stringify({requestId:id})){counts.preview++;return view();}
   if(op==='approve'&&phase==='preview'&&counts.preview===1&&raw===JSON.stringify({previewId:id,previewDigest:digest,acknowledged:true})){phase='approved';counts.approve++;return view();}
   return null;
  },savedID(){return id;},digest,
 };
}
export function windowsUpdateJobsRoute({base,fixture,state,asset}){
 if(base!==windowsUpdateJobsOrigin)throw new Error('Invalid synthetic update origin');
 const prefix='/api/devices/'+fixture.device.id,path=prefix+'/windows-update-jobs';
 return async route=>{
  const request=route.request(),url=new URL(request.url()),method=request.method(),raw=request.postData(),headers=request.headers();
  const block=()=>{state.blocked.push('update-job-shape-or-binding');return route.abort('blockedbyclient');};
  if(url.origin!==base){state.external.push('external');return route.abort('blockedbyclient');}
  const reply=value=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(value)});
  if(url.search)return block();
  if(url.pathname.startsWith(path)){
   let value;
   if(url.pathname===path&&method==='GET'&&raw===null)value=fixture.updateView();
   else {
    const op=url.pathname.slice(path.length+1);
    if(!['request','preview','approve'].includes(op)||url.pathname!==path+'/'+op||method!=='POST'||typeof raw!=='string'||Buffer.byteLength(raw)>1024||headers['x-csrf-token']!==fixture.session.csrfToken||headers.origin!==base||headers['content-type']!=='application/json')return block();
    value=fixture.updateMutation(op,raw);
   }
   return value?reply(value):block();
  }
  if(url.pathname===prefix+'/windows-full-processes/query'){
   const query=windowsFullProcessesFixtureQuery({pathname:url.pathname,search:url.search,method,headers,raw},prefix);
   if(!query||headers['x-csrf-token']!==fixture.session.csrfToken||headers.origin!==base||headers['content-type']!=='application/json')return block();
   return reply(windowsFullProcessesAbsentPage(fixture.device.id,query,fixture.now));
  }
  if(method!=='GET'||raw!==null)return block();
  if(url.pathname==='/api/auth/session')return reply(fixture.session);
  if(url.pathname==='/api/session')return reply({csrfToken:fixture.session.csrfToken});
  if(url.pathname===prefix)return reply(fixture.device);
  if(url.pathname===prefix+'/windows-inventory')return reply(fixture.inventory);
  if(url.pathname.startsWith('/api/'))return route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({error:{code:'synthetic_unavailable'}})});
  // The HTTPS origin is entirely virtual. Never continue to DNS/TLS/network;
  // the hosted owner may fulfill only files from its verified compiled dist.
  if(typeof asset!=='function')return block();
  return asset(route,url.pathname);
 };
}
export async function exerciseWindowsUpdateJobs({page,expect,base,fixture,locale,width,shot}){
 const de=locale==='de',panel=page.locator('.windows-update-jobs'),check=de?'Bereitschaft prüfen':'Check readiness',read=de?'Gespeicherten Status lesen':'Read saved status',approveLabel=de?'Dieses Update einmal freigeben':'Approve this update once',receiptLabel=de?'Auftragsdetails':'Job details';
 const open=async()=>{await page.getByRole('tab',{name:de?'Inventar':'Inventory',exact:true}).click();await page.getByRole('tab',{name:'Updates',exact:true}).click();await expect(panel).toBeVisible();};
 const capture=async kind=>{await panel.evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);await shot(page,`synthetic-windows-update-jobs-${kind}-${width}-${locale}`,windowsUpdateJobsDisclosure);};
 stage='document';await page.goto(base+'/#/devices/'+fixture.device.id);await page.getByLabel(/Language|Sprache/).selectOption(locale);await expect(page.locator('html')).toHaveAttribute('lang',locale);await open();
 stage='request';await panel.getByRole('combobox').selectOption(`${fixture.selection.updateId}:${fixture.selection.revision}`);await panel.getByRole('button',{name:check,exact:true}).click();await expect(panel.getByRole('status')).toContainText(de?'Bereitschaft ausstehend':'Readiness pending');await expect(panel.getByRole('checkbox')).toHaveCount(0);expect(fixture.updateCounts.request).toBe(1);
 stage='readiness';await panel.getByRole('button',{name:read,exact:true}).click();await expect(panel.getByRole('button',{name:check,exact:true})).toBeVisible();await expect(panel.getByRole('checkbox')).toHaveCount(0);expect(fixture.updateCounts.approve).toBe(0);
 stage='review';await panel.getByRole('button',{name:check,exact:true}).click();const review=panel.getByRole('group',{name:check,exact:true}),approve=review.getByRole('button',{name:approveLabel,exact:true});await expect(review).toContainText(fixture.selection.updateId);await expect(approve).toBeDisabled();await expect(review.getByRole('checkbox')).not.toBeChecked();await expect(review.locator('details')).not.toHaveAttribute('open');await capture('review');await expect(approve).toBeInViewport();
 stage='approve';await review.getByRole('checkbox').check();await approve.evaluate(button=>{button.click();button.click();});await expect(panel.getByRole('status')).toContainText(de?'Freigegeben; einmalige Abholung ausstehend':'Approved; awaiting one-time claim');await expect(panel.getByRole('checkbox')).toHaveCount(0);expect(fixture.updateCounts.approve).toBe(1);
 stage='saved-result';await panel.getByRole('button',{name:read,exact:true}).click();await expect(panel.getByRole('status')).toContainText(de?'WUA hat Erfolg gemeldet':'WUA reported success');await expect(panel.getByRole('status')).toContainText(de?'Neustart':'restart');const receipt=panel.getByRole('status').locator('details');await expect(receipt).not.toHaveAttribute('open');await receipt.getByText(receiptLabel,{exact:true}).click();await expect(receipt).toContainText(fixture.savedID());await expect(receipt).toContainText(fixture.selection.updateId);
 stage='reload';await page.reload();await open();await expect(panel.getByRole('status')).toContainText(de?'WUA hat Erfolg gemeldet':'WUA reported success');await expect(receipt).not.toHaveAttribute('open');await expect(panel.getByRole('checkbox')).toHaveCount(0);expect(fixture.updateCounts).toEqual({request:1,preview:1,approve:1,status:4});await capture('result');await expect(receipt.getByText(receiptLabel,{exact:true})).toBeInViewport();
 stage='complete';return {...fixture.updateCounts,explicitUncheckedApproval:true,reloadReadback:true,nativeAcceptance:false};
}
export function requireWindowsUpdateJobsEvidence(rows,sourceSha){
 const fail=()=>{throw new Error('Synthetic update UI evidence missing or mismatched');};if(!Array.isArray(rows)||rows.length!==8||!/^[a-f0-9]{40}$/.test(sourceSha??''))fail();
 for(const kind of ['review','result'])for(const locale of ['en','de'])for(const width of [1440,390]){
  const matches=rows.filter(row=>row?.file===`synthetic-windows-update-jobs-${kind}-${width}-${locale}.png`);if(matches.length!==1)fail();const row=matches[0];
  if(row.sourceSha!==sourceSha||row.test!==windowsUpdateJobsCaseName||row.locale!==locale||row.viewport?.width!==width||row.viewport?.height!==(width===390?844:1000)||row.publicSafe!==true||row.fullPage!==false||row.fixtureDisclosure!==windowsUpdateJobsDisclosure)fail();
 }
 return {screens:8,nativeAcceptance:false};
}
