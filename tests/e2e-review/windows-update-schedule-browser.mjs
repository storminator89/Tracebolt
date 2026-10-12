/** Inert prospective scheduling fixture. Imports start no browser, listener or host operation. */
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {createWindowsUpdateJobsFixture,windowsUpdateJobsRoute,windowsUpdateJobsOrigin} from './windows-update-jobs-browser.mjs';
const require=createRequire(new URL('../../web/package.json',import.meta.url));
const built=require('esbuild').buildSync({stdin:{contents:"export {validUpdateJobView,validUpdateJobHistory} from './windows-update-jobs-types';",resolveDir:fileURLToPath(new URL('../../web/src/',import.meta.url)),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {validUpdateJobView,validUpdateJobHistory}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
export const windowsUpdateScheduleCaseName='Synthetic Windows prospective schedule, exact UTC window and cancellation in the compiled UI';
export const windowsUpdateScheduleDisclosure='Entirely intercepted invented TLS-session, cached readiness and scheduling metadata in the compiled UI. Separate unchecked prospective consent, one fixed UTC window and cancel/readback exist only in an in-memory fixture. Zero immediate-install writes. No actual TLS authority, local grant, elevated executor, native WUA, real manager write, download, EULA acceptance, installation, reboot or exact-time guarantee. Source/browser evidence is not native acceptance.';
const stages=new Set(['setup','document','request','readiness','review','schedule','pending','cancel','reload','complete']);let stage='setup';
export const windowsUpdateScheduleFailureStage=()=>stages.has(stage)?stage:'setup';

export function createWindowsUpdateScheduleFixture(){
 const manual=createWindowsUpdateJobsFixture(),at=Date.parse(manual.now)/1000,window=Object.freeze({startAt:at+120,endAt:at+420});
 const counts={schedule:0,cancel:0,immediateInstallWrites:0},scheduleDigest='sha256:'+'b'.repeat(64);
 let last=null,saved=null;
 const validate=value=>{
  if(!validUpdateJobView(value,manual.device.id,manual.session.actorId))throw new Error('Invalid synthetic schedule view');
  return structuredClone(value);
 };
 const publicView=()=>validate({...saved,available:saved.job.state==='schedule_canceled',reason:saved.job.state==='schedule_canceled'?'ready':'job_pending_or_intervention'});
 const fixture={...manual,device:{...manual.device,name:'SYNTHETIC · Selected cached update schedule'},session:{...manual.session,capabilities:['read','windows_update_install','windows_update_schedule']},scheduleCounts:counts,scheduleWindow:window,scheduleDigest,
  updateView(){if(saved){manual.updateCounts.status++;return publicView();}last={...manual.updateView(),schedulingAvailable:true};return validate(last);},
  updateMutation(op,raw){
   // Reusing manual readiness never admits its immediate-install approval route.
   if(op==='approve'){counts.immediateInstallWrites++;return null;}
   if(saved)return null;
   const value=manual.updateMutation(op,raw);if(!value)return null;last={...value,schedulingAvailable:true};return validate(last);
  },
  updateHistory(){
   if(!saved)return manual.updateHistory();
   const value=publicView(),j=value.job,history={version:'tracebolt.windows-selected-update-history.v1',deviceId:manual.device.id,serverNow:at,available:value.available,reason:value.reason,remainingCapacity:31,jobs:[{id:j.id,selection:j.selection,state:j.state,reason:j.reason,result:null,requestedAt:at,approvedAt:0,claimedAt:0,schedule:j.schedule}]};
   if(!validUpdateJobHistory(history,manual.device.id,manual.session.actorId))throw new Error('Invalid synthetic schedule history');return structuredClone(history);
  },
  scheduleMutation(op,raw){
   if(op==='schedule'){
    if(saved||!last?.job?.preview||manual.updateCounts.preview!==1||raw!==JSON.stringify({previewId:last.job.id,previewDigest:manual.digest,acknowledged:true,...window}))return null;
    saved={...last,available:false,reason:'job_pending_or_intervention',job:{...last.job,state:'scheduled',reason:'schedule_waiting',preview:null,result:null,schedule:{version:'tracebolt.windows-selected-update-schedule.v1',digest:scheduleDigest,approvedAt:at,...window,permitIssuedAt:0,revoked:false}}};counts.schedule++;return publicView();
   }
   if(op==='cancel-schedule'&&saved?.job.state==='scheduled'&&raw===JSON.stringify({scheduleId:saved.job.id,scheduleDigest})){
    saved.job.state='schedule_canceled';saved.job.reason='schedule_canceled';counts.cancel++;return publicView();
   }
   return null;
  },
  savedSchedule(){return saved?publicView():null;},
 };
 return fixture;
}

/** Wrap only the two new exact synthetic mutations; all reads/readiness/assets
 * retain the existing wholly intercepted selected-update controller. */
export function windowsUpdateScheduleRoute({base,fixture,state,asset}){
 const manual=windowsUpdateJobsRoute({base,fixture,state,asset}),path='/api/devices/'+fixture.device.id+'/windows-update-jobs';
 return async route=>{
  const request=route.request(),url=new URL(request.url()),op=url.pathname===path+'/schedule'?'schedule':url.pathname===path+'/cancel-schedule'?'cancel-schedule':null;
  if(!op)return manual(route);
  const block=()=>{state.blocked.push('update-schedule-shape-or-binding');return route.abort('blockedbyclient');};
  if(url.origin!==base){state.external.push('external');return route.abort('blockedbyclient');}
  const raw=request.postData(),headers=request.headers();
  if(url.search||request.method()!=='POST'||typeof raw!=='string'||Buffer.byteLength(raw)>1024||headers['x-csrf-token']!==fixture.session.csrfToken||headers.origin!==base||headers['content-type']!=='application/json')return block();
  const value=fixture.scheduleMutation(op,raw);return value?route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(value)}):block();
 };
}

export async function exerciseWindowsUpdateSchedule({page,expect,base,fixture,locale,width,shot}){
 if(base!==windowsUpdateJobsOrigin)throw new Error('Invalid synthetic schedule origin');
 const de=locale==='de',panel=page.locator('.windows-update-jobs'),check=de?'Bereitschaft prüfen':'Check readiness',read=de?'Gespeicherten Status lesen':'Read saved status',receiptLabel=de?'Auftragsdetails':'Job details';
 const open=async()=>{await page.getByRole('tab',{name:de?'Inventar':'Inventory',exact:true}).click();await page.getByRole('tab',{name:'Updates',exact:true}).click();await expect(panel).toBeVisible();};
 const capture=async(kind,target=panel)=>{await target.evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);await shot(page,`synthetic-windows-update-schedule-${kind}-${width}-${locale}`,windowsUpdateScheduleDisclosure);};
 const noInstall=()=>{expect(fixture.updateCounts.approve).toBe(0);expect(fixture.scheduleCounts.immediateInstallWrites).toBe(0);expect(fixture.counts.approve).toBe(0);};
 const exactSaved=()=>{const saved=fixture.savedSchedule();expect(saved.job.id).toBe(fixture.savedID());expect(saved.job.selection).toEqual(fixture.selection);expect(saved.job.schedule).toEqual({version:'tracebolt.windows-selected-update-schedule.v1',digest:fixture.scheduleDigest,approvedAt:Date.parse(fixture.now)/1000,...fixture.scheduleWindow,permitIssuedAt:0,revoked:false});noInstall();};
 stage='document';await page.goto(base+'/#/devices/'+fixture.device.id);await page.getByLabel(/Language|Sprache/).selectOption(locale);await expect(page.locator('html')).toHaveAttribute('lang',locale);await open();
 stage='request';await panel.getByRole('combobox').selectOption(`${fixture.selection.updateId}:${fixture.selection.revision}`);await panel.getByRole('button',{name:check,exact:true}).click();await expect(panel.getByRole('status')).toContainText(de?'Bereitschaft ausstehend':'Readiness pending');noInstall();
 stage='readiness';await panel.getByRole('button',{name:read,exact:true}).click();await expect(panel.getByRole('button',{name:check,exact:true})).toBeVisible();await panel.getByRole('button',{name:check,exact:true}).click();
 stage='review';const review=panel.getByRole('group',{name:check,exact:true}),scheduleDetails=review.locator('details').filter({has:page.getByText(de?'Dieses Update planen':'Schedule this update',{exact:true})});
 await expect(review).toContainText(fixture.selection.updateId);await expect(scheduleDetails).not.toHaveAttribute('open');await scheduleDetails.locator('summary').first().click();
 const start=new Date(fixture.scheduleWindow.startAt*1000).toISOString().slice(0,16),end=new Date(fixture.scheduleWindow.endAt*1000).toISOString().slice(0,16);
 await scheduleDetails.getByLabel(de?'Beginn (UTC)':'Start (UTC)',{exact:true}).fill(start);await scheduleDetails.getByLabel(de?'Ende (UTC)':'End (UTC)',{exact:true}).fill(end);
 await expect(scheduleDetails.getByLabel(de?'Beginn (UTC)':'Start (UTC)',{exact:true})).toHaveValue(start);await expect(scheduleDetails.getByLabel(de?'Ende (UTC)':'End (UTC)',{exact:true})).toHaveValue(end);
 const ack=scheduleDetails.getByRole('checkbox',{name:de?/vorausschauend für dieses UTC/:/prospectively for this UTC/}),approve=scheduleDetails.getByRole('button',{name:de?'Geplantes Update einmal freigeben':'Approve scheduled update once',exact:true});
 await expect(ack).not.toBeChecked();await expect(approve).toBeDisabled();await expect(review.getByRole('button',{name:de?'Dieses Update einmal freigeben':'Approve this update once',exact:true})).toBeDisabled();await expect(scheduleDetails).toContainText(de?'auch bei Abbruch':'even if canceled');noInstall();await capture('review',scheduleDetails);await expect(ack).toBeInViewport();await expect(approve).toBeInViewport();
 stage='schedule';await ack.check();await approve.evaluate(button=>{button.click();button.click();});await expect(panel.getByRole('status')).toContainText(de?'Geplant; geeignete Abfrage':'Scheduled; waiting');expect(fixture.scheduleCounts.schedule).toBe(1);exactSaved();
 stage='pending';await panel.getByRole('button',{name:read,exact:true}).click();await expect(panel.getByRole('status')).toContainText(de?'Geplant; geeignete Abfrage':'Scheduled; waiting');exactSaved();
 const receipt=panel.getByRole('status').locator('details');await expect(receipt).not.toHaveAttribute('open');await receipt.getByText(receiptLabel,{exact:true}).click();await expect(receipt).toContainText(fixture.savedID());for(const at of Object.values(fixture.scheduleWindow))await expect(receipt).toContainText(new Date(at*1000).toISOString().replace('T',' ').replace('.000Z',' UTC'));await receipt.getByText(receiptLabel,{exact:true}).click();
 const cancel=panel.getByRole('button',{name:de?'Diese Planung abbrechen':'Cancel this schedule',exact:true});await expect(cancel).toBeEnabled();await expect(panel.getByRole('button',{name:de?'Dieses Update einmal freigeben':'Approve this update once',exact:true})).toHaveCount(0);await capture('pending');await expect(cancel).toBeInViewport();
 stage='cancel';await cancel.evaluate(button=>{button.click();button.click();});await expect(panel.getByRole('status')).toContainText(de?'Planung vor Abholung abgebrochen':'Schedule canceled before claim');expect(fixture.scheduleCounts.cancel).toBe(1);exactSaved();
 stage='reload';await page.reload();await open();await expect(panel.getByRole('status')).toContainText(de?'Planung vor Abholung abgebrochen':'Schedule canceled before claim');await expect(panel.getByRole('button',{name:de?'Diese Planung abbrechen':'Cancel this schedule',exact:true})).toHaveCount(0);await expect(panel.getByRole('status').locator('details')).not.toHaveAttribute('open');exactSaved();await capture('canceled');
 expect(fixture.updateCounts.request).toBe(1);expect(fixture.updateCounts.preview).toBe(1);expect(fixture.scheduleCounts).toEqual({schedule:1,cancel:1,immediateInstallWrites:0});
 stage='complete';return {request:fixture.updateCounts.request,preview:fixture.updateCounts.preview,...fixture.scheduleCounts,explicitUncheckedProspectiveApproval:true,exactSavedWindow:true,pendingReadback:true,cancelReadback:true,reloadReadback:true,duplicateClickGuard:true,nativeAcceptance:false};
}
export function requireWindowsUpdateScheduleEvidence(rows,sourceSha){
 const fail=()=>{throw new Error('Synthetic schedule UI evidence missing or mismatched');};if(!Array.isArray(rows)||rows.length!==12||!/^[a-f0-9]{40}$/.test(sourceSha??''))fail();
 for(const kind of ['review','pending','canceled'])for(const locale of ['en','de'])for(const width of [1440,390]){
  const matches=rows.filter(row=>row?.file===`synthetic-windows-update-schedule-${kind}-${width}-${locale}.png`);if(matches.length!==1)fail();const row=matches[0];
  if(row.sourceSha!==sourceSha||row.test!==windowsUpdateScheduleCaseName||row.locale!==locale||row.viewport?.width!==width||row.viewport?.height!==(width===390?844:1000)||row.publicSafe!==true||row.fullPage!==false||row.fixtureDisclosure!==windowsUpdateScheduleDisclosure)fail();
 }
 return {screens:12,nativeAcceptance:false};
}
