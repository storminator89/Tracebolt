/** Inert synthetic UI controller. Importing starts no browser, listener or WUA. */
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {createWindowsServiceActionsFixture} from './windows-service-actions-browser.mjs';
import {windowsFullProcessesAbsentPage,windowsFullProcessesFixtureQuery} from './windows-full-processes-browser.mjs';
import {windowsUpdatesBrowserFixture} from './windows-updates-browser.mjs';
const require=createRequire(new URL('../../web/package.json',import.meta.url));
const built=require('esbuild').buildSync({stdin:{contents:"export {validUpdateJobView,validUpdateJobHistory} from './windows-update-jobs-types';",resolveDir:fileURLToPath(new URL('../../web/src/',import.meta.url)),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {validUpdateJobView,validUpdateJobHistory}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
export const windowsUpdateJobsOrigin='https://windows-update-jobs.invalid';
export const windowsUpdateJobsCaseName='Synthetic Windows update readiness, explicit approval and saved result in the compiled UI';
export const windowsUpdateJobsDisclosure='Entirely intercepted invented TLS-session, cached update, readiness and result metadata in the compiled UI. Manual unchecked approval and saved readback only in an in-memory fixture. No actual TLS authority, host grant, elevated executor, native WUA, real manager write, download, EULA acceptance, installation or reboot. Source/browser evidence is not native patching.';
const stages=new Set(['setup','document','request','readiness','review','approve','saved-result','reload','worklist','complete']);let stage='setup';
export const windowsUpdateJobsFailureStage=()=>stages.has(stage)?stage:'setup';
export function createWindowsUpdateJobsFixture(){
 const fixture=createWindowsServiceActionsFixture(),at=Date.parse(fixture.now)/1000;
 fixture.session={...fixture.session,transport:'https',insecureTestMode:false,transportWarning:null,capabilities:['read','windows_update_install']};
 fixture.device={...fixture.device,name:'SYNTHETIC · Selected cached Windows update'};
 fixture.inventory=windowsUpdatesBrowserFixture({serverNow:fixture.now,capturedAt:fixture.now,count:1,phase:'observed'});fixture.inventory.deviceId=fixture.device.id;
 const {updateId,revision}=fixture.inventory.updates.rows[0],selection={updateId,revision},digest='sha256:'+'3'.repeat(64),counts={request:0,preview:0,approve:0,status:0};
 // A second admitted DTO represents saved claimed evidence only. Its metadata
 // is invented, never a host grant or permission to advance another device.
 const secondDevice={...structuredClone(fixture.device),id:'agent_'+'b'.repeat(32),name:'SYNTHETIC · Pending Windows update'},secondInventory=structuredClone(fixture.inventory);
 secondInventory.deviceId=secondDevice.id;secondInventory.updates.rows[0]={...secondInventory.updates.rows[0],updateId:'00000002-0000-0000-0000-000000000002',revision:11,title:'Synthetic pending cached update'};
 const secondSelection={updateId:secondInventory.updates.rows[0].updateId,revision:secondInventory.updates.rows[0].revision},secondSavedID='update_'+'b'.repeat(32);
 const secondUpdateCounts={request:0,preview:0,approve:0,status:0},secondPostAttempts={request:0,preview:0,approve:0,other:0},updateReads={current:0,history:0,exact:0},secondUpdateReads={current:0,history:0,exact:0};
 const secondView={version:'tracebolt.windows-selected-update-job.v1',deviceId:secondDevice.id,serverNow:at,available:false,reason:'job_pending_or_intervention',job:{id:secondSavedID,selection:secondSelection,state:'claimed',reason:'ready',preview:null,result:null}};
 const secondHistory={version:'tracebolt.windows-selected-update-history.v1',deviceId:secondDevice.id,serverNow:at,available:false,reason:'job_pending_or_intervention',remainingCapacity:31,jobs:[{id:secondSavedID,selection:secondSelection,state:'claimed',reason:'ready',result:null,requestedAt:at-30,approvedAt:at-20,claimedAt:at-10}]};
 if(secondDevice.id===fixture.device.id||!validUpdateJobView(secondView,secondDevice.id,fixture.session.actorId)||!validUpdateJobHistory(secondHistory,secondDevice.id,fixture.session.actorId))throw new Error('Invalid synthetic pending update evidence');
 let phase='ready',id=null,preview=null;
 const view=(state=phase)=>{
  const value={version:'tracebolt.windows-selected-update-job.v1',deviceId:fixture.device.id,serverNow:at,available:state==='ready',reason:state==='ready'?'ready':'job_pending_or_intervention',job:state==='ready'?null:{id,selection,state,reason:state==='requested'?'readiness_pending':'ready',preview:state==='preview'?preview:null,result:state==='complete'?{jobId:id,envelopeDigest:'sha256:'+'7'.repeat(64),attempted:true,outcome:'succeeded',operationResult:2,hresult:0,rebootRequired:'yes',completedAt:at}:null}};
  if(!validUpdateJobView(value,fixture.device.id,fixture.session.actorId))throw new Error('Invalid synthetic update view');return structuredClone(value);
 };
 return {...fixture,selection,updateCounts:counts,updateReads,secondDevice,secondInventory,secondSelection,secondSavedID,secondUpdateCounts,secondPostAttempts,secondUpdateReads,secondUpdateView(){secondUpdateCounts.status++;return structuredClone(secondView);},secondUpdateHistory(){return structuredClone(secondHistory);},previewAction(){return null;},approveAction(){return null;},
  updateHistory(){const v=view();return {version:'tracebolt.windows-selected-update-history.v1',deviceId:fixture.device.id,serverNow:at,available:v.available,reason:v.reason,remainingCapacity:counts.approve?31:32,jobs:v.job?[{id:v.job.id,selection:v.job.selection,state:v.job.state,reason:v.job.reason,result:v.job.result,requestedAt:at,approvedAt:counts.approve?at:0,claimedAt:phase==='complete'?at:0}]:[]};},
  updateView(){counts.status++;if(phase==='requested')phase='preview';else if(phase==='approved')phase='complete';return view();},
  updateMutation(op,raw){let input;try{input=JSON.parse(raw);}catch{return null;}
   if(op==='request'){
    if(phase!=='ready'||input?.requestId===secondSavedID||!/^update_[a-f0-9]{32}$/.test(input?.requestId)||raw!==JSON.stringify({requestId:input.requestId,...selection}))return null;
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
 const prefix='/api/devices/'+fixture.device.id,path=prefix+'/windows-update-jobs',secondPrefix='/api/devices/'+fixture.secondDevice.id,secondPath=secondPrefix+'/windows-update-jobs';
 return async route=>{
  const request=route.request(),url=new URL(request.url()),method=request.method(),raw=request.postData(),headers=request.headers();
  const block=()=>{state.blocked.push('update-job-shape-or-binding');return route.abort('blockedbyclient');};
  if(url.origin!==base){state.external.push('external');return route.abort('blockedbyclient');}
  const reply=value=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(value)});
  const second=url.pathname===secondPrefix||url.pathname.startsWith(secondPrefix+'/');
  // Count even rejected POST attempts: a silent automatic next-device request
  // must fail the hosted completion gate, not disappear behind interception.
  if(second&&method!=='GET'){
   if(method==='POST'){const op=url.pathname.slice(secondPath.length+1);fixture.secondPostAttempts[url.pathname===secondPath+'/'+op&&['request','preview','approve'].includes(op)?op:'other']++;}
   return block();
  }
  if(second){
   if(raw!==null||url.search&&!(url.pathname===secondPath&&(url.search==='?history=1'||url.search==='?jobId='+fixture.secondSavedID)))return block();
   if(url.pathname.startsWith(secondPath)){
    if(url.pathname!==secondPath)return block();
    fixture.secondUpdateReads[url.search==='?history=1'?'history':url.search?'exact':'current']++;
    return reply(url.search==='?history=1'?fixture.secondUpdateHistory():fixture.secondUpdateView());
   }
   if(url.pathname===secondPrefix)return reply(fixture.secondDevice);
   if(url.pathname===secondPrefix+'/windows-inventory')return reply(fixture.secondInventory);
  }
  if(url.search&&!(url.pathname===path&&method==='GET'&&raw===null&&(url.search==='?history=1'||fixture.savedID()&&url.search==='?jobId='+fixture.savedID())))return block();
  if(url.pathname.startsWith(path)){
   let value;
   if(url.pathname===path&&method==='GET'&&raw===null){fixture.updateReads[url.search==='?history=1'?'history':url.search?'exact':'current']++;value=url.search==='?history=1'?fixture.updateHistory():fixture.updateView();}
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
  if(url.pathname==='/api/overview')return reply({product:'Tracebolt',mode:'lan',generatedAt:fixture.now,stats:{totalDevices:2,healthyDevices:0,attentionDevices:0,unknownDevices:2,openCases:0,criticalCases:0},devices:[fixture.device,fixture.secondDevice],cases:[],activity:[]});
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
 stage='reload';await page.reload();await open();await expect(panel.getByRole('status')).toContainText(de?'WUA hat Erfolg gemeldet':'WUA reported success');await expect(receipt).not.toHaveAttribute('open');await expect(panel.getByRole('checkbox')).toHaveCount(0);expect(fixture.updateCounts).toEqual({request:1,preview:1,approve:1,status:4});await expect(receipt.getByText(receiptLabel,{exact:true})).toBeVisible();
 await capture('result');
 stage='worklist';await page.goto(base+'/#/devices');
 const worklist=page.getByRole('region',{name:de?'Windows-Updatearbeitsliste':'Windows update worklist',exact:true}),title=worklist.getByRole('button',{name:de?'Windows-Updatearbeitsliste':'Windows update worklist',exact:true});
 await title.click();const choices=worklist.getByRole('group',{name:de?'Geräte auswählen':'Select devices',exact:true}),freeze=worklist.getByRole('button',{name:de?'Geräteauswahl festhalten':'Freeze device selection',exact:true});
 await expect(choices.getByRole('checkbox')).toHaveCount(2);await expect(freeze).toBeDisabled();
 for(const device of [fixture.device,fixture.secondDevice]){const choice=choices.getByRole('checkbox',{name:new RegExp(device.name)});await expect(choice).not.toBeChecked();await choice.check();}
 await freeze.click();await expect(choices).toHaveCount(0);await expect(worklist.locator('.windows-fleet-update-heading')).toContainText((de?'Festgehaltene Auswahl':'Frozen selection')+' · 2');
 const rows=worklist.locator('.windows-fleet-update-list > li'),firstRow=rows.filter({hasText:fixture.device.name}),secondRow=rows.filter({hasText:fixture.secondDevice.name}),firstSummary=firstRow.locator('.windows-fleet-update-row'),secondSummary=secondRow.locator('.windows-fleet-update-row');
 const openDevice=(row,device)=>row.getByRole('button',{name:(de?'Gerät öffnen: ':'Open device: ')+device.name,exact:true}),closeDevice=(row,device)=>row.getByRole('button',{name:(de?'Gerät schließen: ':'Close device: ')+device.name,exact:true});
 const resultText=de?'WUA hat Erfolg gemeldet':'WUA reported success',pendingText=de?'Abgeholt; Installation unbestätigt':'Claimed; installation unconfirmed';
 const saved=async(row,id,status)=>{const selected=row.locator('.windows-update-jobs');await expect(selected.getByRole('status')).toContainText(status);await selected.getByText(de?'Gespeicherte Updateaufträge':'Saved update jobs',{exact:true}).click();await selected.getByRole('button',{name:de?'Gespeicherte Aufträge lesen':'Read saved jobs',exact:true}).click();await selected.getByRole('button',{name:(de?'Gespeicherten Auftrag öffnen':'Open saved job')+' · '+id,exact:true}).click();await expect(selected.getByRole('status')).toContainText(status);await expect(selected.getByRole('checkbox')).toHaveCount(0);await expect(selected.getByRole('combobox')).toHaveCount(0);};
 await expect(rows).toHaveCount(2);await expect(worklist.locator('.windows-update-jobs')).toHaveCount(0);expect(fixture.secondUpdateCounts.status).toBe(0);expect(fixture.secondPostAttempts).toEqual({request:0,preview:0,approve:0,other:0});
 await openDevice(firstRow,fixture.device).click();await saved(firstRow,fixture.savedID(),resultText);await expect(firstSummary).toContainText(resultText);await expect(firstSummary).toContainText(de?'Neustart erforderlich':'Restart required');await expect(secondSummary).toContainText(de?'Nicht begonnen':'Not started');expect(fixture.secondUpdateCounts.status).toBe(0);
 await openDevice(secondRow,fixture.secondDevice).click();await expect(firstRow.locator('.windows-update-jobs')).toHaveCount(0);await expect(openDevice(firstRow,fixture.device)).toHaveAttribute('aria-expanded','false');await saved(secondRow,fixture.secondSavedID,pendingText);await expect(secondSummary).toContainText(pendingText);await expect(firstSummary).toContainText(resultText);await expect(secondSummary).not.toContainText(resultText);await expect(secondSummary).toContainText(fixture.secondSelection.updateId);
 // Reopening the first target is another exact-ID GET, not a replay or a
 // replacement of the second target's independent pending receipt.
 await openDevice(firstRow,fixture.device).click();await expect(secondRow.locator('.windows-update-jobs')).toHaveCount(0);await expect(firstRow.locator('.windows-update-jobs').getByRole('status')).toContainText(resultText);await expect(secondSummary).toContainText(pendingText);await closeDevice(firstRow,fixture.device).click();await expect(worklist.locator('.windows-update-jobs')).toHaveCount(0);
 expect(fixture.updateCounts.request).toBe(1);expect(fixture.updateCounts.preview).toBe(1);expect(fixture.updateCounts.approve).toBe(1);expect(fixture.updateReads.history).toBe(1);expect(fixture.updateReads.exact).toBeGreaterThan(0);expect(fixture.secondUpdateReads).toEqual({current:1,history:1,exact:1});expect(fixture.secondUpdateCounts).toEqual({request:0,preview:0,approve:0,status:2});expect(fixture.secondPostAttempts).toEqual({request:0,preview:0,approve:0,other:0});
 // Capture the normal compact whole-worklist layout with both rows closed.
 // Never scroll the nested selected-job panel, resize, or alter production CSS.
 await worklist.evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));expect(await worklist.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);
 await expect(title).toBeInViewport();for(const summary of [firstSummary,secondSummary])await expect(summary).toBeInViewport({ratio:1});await expect(firstSummary.getByText(resultText,{exact:false})).toBeInViewport({ratio:1});await expect(secondSummary.getByText(pendingText,{exact:true})).toBeInViewport({ratio:1});
 await shot(page,`synthetic-windows-update-jobs-worklist-${width}-${locale}`,windowsUpdateJobsDisclosure);
 stage='complete';return {...fixture.updateCounts,explicitUncheckedApproval:true,reloadReadback:true,frozenWorklistReadback:true,exactSavedHistory:true,frozenTargetCount:2,independentResultReadback:true,independentPendingReadback:true,compactWorklistCapture:true,secondDeviceMutations:{request:fixture.secondUpdateCounts.request,preview:fixture.secondUpdateCounts.preview,approve:fixture.secondUpdateCounts.approve},secondDevicePOSTs:Object.values(fixture.secondPostAttempts).reduce((sum,count)=>sum+count,0),nativeAcceptance:false};
}
export function requireWindowsUpdateJobsEvidence(rows,sourceSha){
 const fail=()=>{throw new Error('Synthetic update UI evidence missing or mismatched');};if(!Array.isArray(rows)||rows.length!==12||!/^[a-f0-9]{40}$/.test(sourceSha??''))fail();
 for(const kind of ['review','result','worklist'])for(const locale of ['en','de'])for(const width of [1440,390]){
  const matches=rows.filter(row=>row?.file===`synthetic-windows-update-jobs-${kind}-${width}-${locale}.png`);if(matches.length!==1)fail();const row=matches[0];
  if(row.sourceSha!==sourceSha||row.test!==windowsUpdateJobsCaseName||row.locale!==locale||row.viewport?.width!==width||row.viewport?.height!==(width===390?844:1000)||row.publicSafe!==true||row.fullPage!==false||row.fixtureDisclosure!==windowsUpdateJobsDisclosure)fail();
 }
 return {screens:12,nativeAcceptance:false};
}

/** The hosted owner must reject incomplete behavior even with 12 image files. */
export function requireWindowsUpdateWorklistDetails(details){
 if(!details||details.frozenTargetCount!==2||details.frozenWorklistReadback!==true||details.exactSavedHistory!==true||details.independentResultReadback!==true||details.independentPendingReadback!==true||details.compactWorklistCapture!==true||details.secondDevicePOSTs!==0||details.nativeAcceptance!==false||!details.secondDeviceMutations||Object.keys(details.secondDeviceMutations).length!==3||['request','preview','approve'].some(op=>details.secondDeviceMutations[op]!==0))throw new Error('Synthetic update worklist evidence missing or mismatched');
 return {frozenTargets:2,secondDevicePOSTs:0,nativeAcceptance:false};
}
