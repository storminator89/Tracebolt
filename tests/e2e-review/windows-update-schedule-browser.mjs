/** Inert prospective scheduling fixture. Imports start no browser, listener or host operation. */
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {createWindowsUpdateJobsFixture,windowsUpdateJobsRoute,windowsUpdateJobsOrigin} from './windows-update-jobs-browser.mjs';
const require=createRequire(new URL('../../web/package.json',import.meta.url));
const built=require('esbuild').buildSync({stdin:{contents:"export {validUpdateJobView,validUpdateJobHistory} from './windows-update-jobs-types';",resolveDir:fileURLToPath(new URL('../../web/src/',import.meta.url)),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {validUpdateJobView,validUpdateJobHistory}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
export const windowsUpdateScheduleCaseName='Synthetic Windows prospective schedule, exact UTC window and cancellation in the compiled UI';
export const windowsUpdateScheduleDisclosure='Entirely intercepted invented TLS-session, cached readiness and scheduling metadata in the compiled UI. Separate unchecked prospective consent, one fixed UTC window and cancel/readback exist only in an in-memory fixture. Zero immediate-install writes. No actual TLS authority, local grant, elevated executor, native WUA, real manager write, download, EULA acceptance, installation, reboot or exact-time guarantee. Source/browser evidence is not native acceptance.';
export const windowsBackgroundUpdateScheduleCaseName='Synthetic background Windows update service, separate UTC approval and cancellation in the compiled UI';
export const windowsBackgroundUpdateScheduleDisclosure=windowsUpdateScheduleDisclosure+' Fresh combined-background scheduling profile and signed shared-status metadata are synthetic; service availability is not checked live.';
const stages=new Set(['setup','document','request','readiness','review','schedule','pending','cancel','reload','complete']);let stage='setup';
export const windowsUpdateScheduleFailureStage=()=>stages.has(stage)?stage:'setup';

export function createWindowsUpdateScheduleFixture(profile='standalone'){
 if(!['standalone','background'].includes(profile))throw new Error('Invalid synthetic scheduling profile');
 const manual=createWindowsUpdateJobsFixture(),at=Date.parse(manual.now)/1000,window=Object.freeze({startAt:at+120,endAt:at+420});
 const counts={schedule:0,cancel:0,immediateInstallWrites:0},scheduleDigest='sha256:'+'b'.repeat(64);
 const background=profile==='background'?{backgroundExecutor:true,backgroundScheduling:true,coordinated:true,executorAvailability:'verified_recent',executorObservedAt:at,mutationCapturedAt:at,mutation:{active:true,blocked:false,phase:'idle',revision:'1',retained:0}}:{};
 let last=null,saved=null;
 const validate=value=>{
  if(!validUpdateJobView(value,manual.device.id,manual.session.actorId))throw new Error('Invalid synthetic schedule view');
  return structuredClone(value);
 };
 const publicView=()=>validate({...saved,available:saved.job.state==='schedule_canceled',reason:saved.job.state==='schedule_canceled'?'ready':'job_pending_or_intervention'});
 const fixture={...manual,device:{...manual.device,name:'SYNTHETIC · Selected cached update schedule'},session:{...manual.session,capabilities:['read','windows_update_install','windows_update_schedule']},scheduleCounts:counts,scheduleWindow:window,scheduleDigest,scheduleProfile:profile,
  updateView(){if(saved){manual.updateCounts.status++;return publicView();}last={...manual.updateView(),...background,schedulingAvailable:true};return validate(last);},
  updateMutation(op,raw){
   // Reusing manual readiness never admits its immediate-install approval route.
   if(op==='approve'){counts.immediateInstallWrites++;return null;}
   if(saved)return null;
   const value=manual.updateMutation(op,raw);if(!value)return null;last={...value,...background,schedulingAvailable:true};return validate(last);
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
 const background=fixture.scheduleProfile==='background',de=locale==='de',panel=page.locator('.windows-update-jobs'),jobStatus=panel.locator(':scope > div[role="status"]'),check=de?'Bereitschaft prüfen':'Check readiness',read=de?'Gespeicherten Status lesen':'Read saved status',receiptLabel=de?'Auftragsdetails':'Job details';
 const open=async()=>{await page.getByRole('tab',{name:de?'Inventar':'Inventory',exact:true}).click();await page.getByRole('tab',{name:'Updates',exact:true}).click();await expect(panel).toBeVisible();};
 const capture=async(kind,target=panel)=>{await target.evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);await shot(page,`synthetic-windows-${background?'background-update':'update'}-schedule-${kind}-${width}-${locale}`,background?windowsBackgroundUpdateScheduleDisclosure:windowsUpdateScheduleDisclosure);};
 const noInstall=()=>{expect(fixture.updateCounts.approve).toBe(0);expect(fixture.scheduleCounts.immediateInstallWrites).toBe(0);expect(fixture.counts.approve).toBe(0);};
 const exactSaved=()=>{const saved=fixture.savedSchedule();expect(saved.job.id).toBe(fixture.savedID());expect(saved.job.selection).toEqual(fixture.selection);expect(saved.job.schedule).toEqual({version:'tracebolt.windows-selected-update-schedule.v1',digest:fixture.scheduleDigest,approvedAt:Date.parse(fixture.now)/1000,...fixture.scheduleWindow,permitIssuedAt:0,revoked:false});noInstall();};
 stage='document';await page.goto(base+'/#/devices/'+fixture.device.id);await page.getByLabel(/Language|Sprache/).selectOption(locale);await expect(page.locator('html')).toHaveAttribute('lang',locale);await open();
 if(background){
  const executor=panel.locator('.windows-update-executor-status'),shared=panel.locator('.windows-mutation-status');
  await expect(executor).toContainText(de?'Update-Hintergrunddienst · Genehmigte UTC-Zeitfenster':'Background update service · Approved UTC windows');
  await expect(executor).toContainText(de?'Zuletzt bestätigt · Verfügbarkeit nicht live geprüft':'Recent confirmation · Availability not checked live');
  await expect(shared).toContainText(de?'Kein Besitzer gespeichert':'No owner saved');
  await expect(panel.getByText(de?'Nur manuelle Freigaben':'Manual approvals only',{exact:false})).toHaveCount(0);
  await capture('status');await expect(executor).toBeInViewport();await expect(shared).toBeInViewport();noInstall();
 }
 stage='request';await panel.getByRole('combobox').selectOption(`${fixture.selection.updateId}:${fixture.selection.revision}`);await panel.getByRole('button',{name:check,exact:true}).click();await expect(jobStatus).toContainText(de?'Bereitschaft ausstehend':'Readiness pending');noInstall();
 stage='readiness';await panel.getByRole('button',{name:read,exact:true}).click();await expect(panel.getByRole('button',{name:check,exact:true})).toBeVisible();await panel.getByRole('button',{name:check,exact:true}).click();
 stage='review';const review=panel.getByRole('group',{name:check,exact:true}),scheduleDetails=review.locator('details').filter({has:page.getByText(de?'Dieses Update planen':'Schedule this update',{exact:true})});
 await expect(review).toContainText(fixture.selection.updateId);await expect(scheduleDetails).not.toHaveAttribute('open');await scheduleDetails.locator('summary').first().click();
 const start=new Date(fixture.scheduleWindow.startAt*1000).toISOString().slice(0,16),end=new Date(fixture.scheduleWindow.endAt*1000).toISOString().slice(0,16);
 await scheduleDetails.getByLabel(de?'Beginn (UTC)':'Start (UTC)',{exact:true}).fill(start);await scheduleDetails.getByLabel(de?'Ende (UTC)':'End (UTC)',{exact:true}).fill(end);
 await expect(scheduleDetails.getByLabel(de?'Beginn (UTC)':'Start (UTC)',{exact:true})).toHaveValue(start);await expect(scheduleDetails.getByLabel(de?'Ende (UTC)':'End (UTC)',{exact:true})).toHaveValue(end);
 const ack=scheduleDetails.getByRole('checkbox',{name:de?/vorausschauend für dieses UTC/:/prospectively for this UTC/}),approve=scheduleDetails.getByRole('button',{name:de?'Geplantes Update einmal freigeben':'Approve scheduled update once',exact:true});
 if(background){
  const requirements=scheduleDetails.locator('details'),manual=review.getByRole('checkbox',{name:de?/Installation genau dieser Revision und mögliche/:/exact revision and its possible interruption/});
  await expect(requirements).not.toHaveAttribute('open');await requirements.locator('summary').click();
  await expect(requirements).toContainText(de?'separat aktivierte Update-Hintergrunddienst und der Beobachter':'separately activated background update service and observer');
  await expect(requirements).toContainText(de?'Das feste UTC-Zeitfenster begrenzt die Auslösung, nicht den Abschluss.':'The fixed UTC window limits dispatch, not completion.');
  await expect(requirements).toContainText(de?'Kein Download, keine Lizenzannahme, kein Neustart und kein Wiederholungsversuch':'No download, license acceptance, reboot or retry');
  await requirements.locator('summary').click();await expect(requirements).not.toHaveAttribute('open');
  await expect(manual).not.toBeChecked();await manual.check();await expect(ack).not.toBeChecked();await expect(approve).toBeDisabled();await manual.uncheck();
 }
 await expect(ack).not.toBeChecked();await expect(approve).toBeDisabled();await expect(review.getByRole('button',{name:de?'Dieses Update einmal freigeben':'Approve this update once',exact:true})).toBeDisabled();await expect(scheduleDetails).toContainText(de?'auch bei Abbruch':'even if canceled');noInstall();await capture('review',scheduleDetails);await expect(ack).toBeInViewport();await expect(approve).toBeInViewport();
 stage='schedule';await ack.check();await expect(review.getByRole('button',{name:de?'Dieses Update einmal freigeben':'Approve this update once',exact:true})).toBeDisabled();await approve.evaluate(button=>{button.click();button.click();});await expect(jobStatus).toContainText(de?'Geplant; geeignete Abfrage':'Scheduled; waiting');expect(fixture.scheduleCounts.schedule).toBe(1);exactSaved();
 stage='pending';await panel.getByRole('button',{name:read,exact:true}).click();await expect(jobStatus).toContainText(de?'Geplant; geeignete Abfrage':'Scheduled; waiting');exactSaved();
 const receipt=jobStatus.locator('details');await expect(receipt).not.toHaveAttribute('open');await receipt.getByText(receiptLabel,{exact:true}).click();await expect(receipt).toContainText(fixture.savedID());for(const at of Object.values(fixture.scheduleWindow))await expect(receipt).toContainText(new Date(at*1000).toISOString().replace('T',' ').replace('.000Z',' UTC'));await receipt.getByText(receiptLabel,{exact:true}).click();
 const cancel=panel.getByRole('button',{name:de?'Diese Planung abbrechen':'Cancel this schedule',exact:true});await expect(cancel).toBeEnabled();await expect(panel.getByRole('button',{name:de?'Dieses Update einmal freigeben':'Approve this update once',exact:true})).toHaveCount(0);if(background)await capture('pending',jobStatus);else await capture('pending');await expect(cancel).toBeInViewport();
 stage='cancel';await cancel.evaluate(button=>{button.click();button.click();});await expect(jobStatus).toContainText(de?'Planung vor Abholung abgebrochen':'Schedule canceled before claim');expect(fixture.scheduleCounts.cancel).toBe(1);exactSaved();
 stage='reload';await page.reload();await open();await expect(jobStatus).toContainText(de?'Planung vor Abholung abgebrochen':'Schedule canceled before claim');await expect(panel.getByRole('button',{name:de?'Diese Planung abbrechen':'Cancel this schedule',exact:true})).toHaveCount(0);await expect(jobStatus.locator('details')).not.toHaveAttribute('open');exactSaved();await capture('canceled');
 expect(fixture.updateCounts.request).toBe(1);expect(fixture.updateCounts.preview).toBe(1);expect(fixture.scheduleCounts).toEqual({schedule:1,cancel:1,immediateInstallWrites:0});
 stage='complete';return {request:fixture.updateCounts.request,preview:fixture.updateCounts.preview,...fixture.scheduleCounts,explicitUncheckedProspectiveApproval:true,exactSavedWindow:true,pendingReadback:true,cancelReadback:true,reloadReadback:true,duplicateClickGuard:true,...(background?{backgroundScheduling:true,compactBackgroundStatus:true,separateManualApproval:true}:{}),nativeAcceptance:false};
}
export function requireWindowsUpdateScheduleEvidence(rows,sourceSha){
 const fail=()=>{throw new Error('Synthetic schedule UI evidence missing or mismatched');};if(!Array.isArray(rows)||rows.length!==12||!/^[a-f0-9]{40}$/.test(sourceSha??''))fail();
 for(const kind of ['review','pending','canceled'])for(const locale of ['en','de'])for(const width of [1440,390]){
  const matches=rows.filter(row=>row?.file===`synthetic-windows-update-schedule-${kind}-${width}-${locale}.png`);if(matches.length!==1)fail();const row=matches[0];
  if(row.sourceSha!==sourceSha||row.test!==windowsUpdateScheduleCaseName||row.locale!==locale||row.viewport?.width!==width||row.viewport?.height!==(width===390?844:1000)||row.publicSafe!==true||row.fullPage!==false||row.fixtureDisclosure!==windowsUpdateScheduleDisclosure)fail();
 }
 return {screens:12,nativeAcceptance:false};
}

export function requireWindowsBackgroundUpdateScheduleEvidence(rows,sourceSha){
 const fail=()=>{throw new Error('Synthetic background schedule UI evidence missing or mismatched');};if(!Array.isArray(rows)||rows.length!==16||!/^[a-f0-9]{40}$/.test(sourceSha??''))fail();
 for(const kind of ['status','review','pending','canceled'])for(const locale of ['en','de'])for(const width of [1440,390]){
  const matches=rows.filter(row=>row?.file===`synthetic-windows-background-update-schedule-${kind}-${width}-${locale}.png`);if(matches.length!==1)fail();const row=matches[0];
  if(row.sourceSha!==sourceSha||row.test!==windowsBackgroundUpdateScheduleCaseName||row.locale!==locale||row.viewport?.width!==width||row.viewport?.height!==(width===390?844:1000)||row.publicSafe!==true||row.fullPage!==false||row.fixtureDisclosure!==windowsBackgroundUpdateScheduleDisclosure)fail();
 }
 return {screens:16,nativeAcceptance:false};
}

export const windowsFleetUpdateScheduleCaseName='Synthetic Windows fleet shared UTC window and independent per-device schedule summary';
export const windowsFleetUpdateScheduleDisclosure=windowsBackgroundUpdateScheduleDisclosure+' Temporary fleet window with separate per-device approval. The second device has an independently invented saved revoked schedule and receives GETs only; no real API request or mutation.';
export const windowsFleetUpdateScheduleScenes=Object.freeze(['shared-window-review','per-device-summary']);

/** Reuse exact first-device scheduling. The other device is read-only saved
 * evidence with separate ID/revision/digest, never an automatically approved peer. */
export function createWindowsFleetUpdateScheduleFixture(){
 const fixture=createWindowsUpdateScheduleFixture('background'),at=Date.parse(fixture.now)/1000;
 fixture.device.name='SYNTHETIC · Berlin WUA';fixture.secondDevice.name='SYNTHETIC · Hamburg WUA';
 const second={...fixture.updateView(),deviceId:fixture.secondDevice.id,available:false,reason:'job_pending_or_intervention',schedulingAvailable:false,schedulingRevoked:true,job:{id:fixture.secondSavedID,selection:fixture.secondSelection,state:'schedule_blocked',reason:'schedule_authority_revoked',preview:null,result:null,schedule:{version:'tracebolt.windows-selected-update-schedule.v1',digest:'sha256:'+'c'.repeat(64),approvedAt:at-60,...fixture.scheduleWindow,permitIssuedAt:0,revoked:true}}};
 if(!validUpdateJobView(second,fixture.secondDevice.id,fixture.session.actorId))throw new Error('Invalid synthetic fleet schedule view');
 const {preview,...job}=second.job,history={version:'tracebolt.windows-selected-update-history.v1',deviceId:second.deviceId,serverNow:at,available:false,reason:second.reason,remainingCapacity:31,jobs:[{...job,requestedAt:at-60,approvedAt:0,claimedAt:0}]};
 if(!validUpdateJobHistory(history,fixture.secondDevice.id,fixture.session.actorId))throw new Error('Invalid synthetic fleet schedule history');
 fixture.secondUpdateView=()=>{fixture.secondUpdateCounts.status++;return structuredClone(second);};
 fixture.secondUpdateHistory=()=>structuredClone(history);
 return fixture;
}

export async function exerciseWindowsFleetUpdateSchedule({page,expect,base,fixture,locale,width,shot}){
 if(base!==windowsUpdateJobsOrigin||fixture.scheduleProfile!=='background')throw new Error('Invalid synthetic fleet schedule profile');
 const de=locale==='de',title=de?'Windows-Updatearbeitsliste':'Windows update worklist',worklist=page.getByRole('region',{name:title,exact:true});
 const utc=at=>new Date(at*1000).toISOString().replace('T',' ').replace('.000Z',' UTC');
 const noPeerWrites=()=>{expect(fixture.secondPostAttempts).toEqual({request:0,preview:0,approve:0,other:0});expect(fixture.updateCounts.approve).toBe(0);expect(fixture.scheduleCounts.immediateInstallWrites).toBe(0);};
 const capture=async(kind,target)=>{await target.evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));expect(await worklist.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);await shot(page,`synthetic-windows-fleet-update-schedule-${kind}-${width}-${locale}`,windowsFleetUpdateScheduleDisclosure);};
 stage='document';await page.goto(base+'/#/devices');await page.getByLabel(/Language|Sprache/).selectOption(locale);await expect(page.locator('html')).toHaveAttribute('lang',locale);await worklist.getByRole('button',{name:title,exact:true}).click();
 const choices=worklist.getByRole('group',{name:de?'Geräte auswählen':'Select devices',exact:true});
 for(const device of [fixture.device,fixture.secondDevice]){const choice=choices.getByRole('checkbox',{name:new RegExp(device.name)});await expect(choice).not.toBeChecked();await choice.check();}
 const shared=worklist.getByRole('checkbox',{name:de?'Ein gemeinsames UTC-Zeitfenster verwenden':'Use one shared UTC window',exact:true}),freeze=worklist.getByRole('button',{name:de?'Geräteauswahl festhalten':'Freeze device selection',exact:true});
 await expect(shared).not.toBeChecked();await shared.check();await expect(freeze).toBeDisabled();
 await worklist.getByLabel(de?'Gemeinsamer Beginn (UTC)':'Shared start (UTC)',{exact:true}).fill(new Date(fixture.scheduleWindow.startAt*1000).toISOString().slice(0,16));
 await worklist.getByLabel(de?'Gemeinsames Ende (UTC)':'Shared end (UTC)',{exact:true}).fill(new Date(fixture.scheduleWindow.endAt*1000).toISOString().slice(0,16));
 await freeze.click();await expect(choices).toHaveCount(0);const fixed=worklist.locator('.windows-fleet-update-window-frozen');for(const at of Object.values(fixture.scheduleWindow))await expect(fixed).toContainText(utc(at));
 const rows=worklist.locator('.windows-fleet-update-list > li'),first=rows.filter({hasText:fixture.device.name}),second=rows.filter({hasText:fixture.secondDevice.name});
 const open=(row,device)=>row.getByRole('button',{name:(de?'Gerät öffnen: ':'Open device: ')+device.name,exact:true}),close=(row,device)=>row.getByRole('button',{name:(de?'Gerät schließen: ':'Close device: ')+device.name,exact:true});
 await expect(rows).toHaveCount(2);await expect(worklist.locator('.windows-update-jobs')).toHaveCount(0);expect(fixture.updateCounts.request).toBe(0);expect(fixture.secondUpdateCounts.status).toBe(0);noPeerWrites();
 await open(first,fixture.device).click();const panel=first.locator('.windows-update-jobs'),check=de?'Bereitschaft prüfen':'Check readiness',jobStatus=panel.locator(':scope > div[role="status"]');
 stage='request';await panel.getByRole('combobox').selectOption(`${fixture.selection.updateId}:${fixture.selection.revision}`);await panel.getByRole('button',{name:check,exact:true}).click();await expect(jobStatus).toContainText(de?'Bereitschaft ausstehend':'Readiness pending');
 stage='readiness';await panel.getByRole('button',{name:de?'Gespeicherten Status lesen':'Read saved status',exact:true}).click();await panel.getByRole('button',{name:check,exact:true}).click();
 stage='review';const review=panel.getByRole('group',{name:check,exact:true}),schedule=review.locator('details').filter({has:page.getByText(de?'Gemeinsames UTC-Zeitfenster':'Shared UTC window',{exact:true})});
 await expect(schedule).toHaveAttribute('open','');for(const at of Object.values(fixture.scheduleWindow))await expect(schedule).toContainText(utc(at));await expect(schedule.locator('input[type="datetime-local"]')).toHaveCount(0);
 const ack=schedule.getByRole('checkbox',{name:de?/vorausschauend für dieses UTC/:/prospectively for this UTC/}),approve=schedule.getByRole('button',{name:de?'Geplantes Update einmal freigeben':'Approve scheduled update once',exact:true});
 await expect(ack).not.toBeChecked();await expect(approve).toBeDisabled();await expect(panel.getByRole('button',{name:de?'Dieses Update einmal freigeben':'Approve this update once',exact:true})).toHaveCount(0);await expect(schedule.locator('details')).not.toHaveAttribute('open');expect(fixture.secondUpdateCounts.status).toBe(0);noPeerWrites();
 await capture('shared-window-review',schedule);await expect(ack).toBeInViewport({ratio:1});await expect(approve).toBeInViewport({ratio:1});
 stage='schedule';await ack.check();await approve.click();await expect(jobStatus).toContainText(de?'Geplant; geeignete Abfrage':'Scheduled; waiting');expect(fixture.scheduleCounts.schedule).toBe(1);expect(fixture.savedSchedule().job.schedule.startAt).toBe(fixture.scheduleWindow.startAt);expect(fixture.savedSchedule().job.schedule.endAt).toBe(fixture.scheduleWindow.endAt);expect(fixture.secondUpdateCounts.status).toBe(0);
 await expect(second.locator('.windows-fleet-update-outcome')).toHaveText(de?'Nicht begonnen':'Not started');
 // A deliberate open reads separate previously saved revoked evidence. Nothing
 // in the shared selection, first approval or first result advances this device.
 stage='pending';await open(second,fixture.secondDevice).click();await expect(first.locator('.windows-update-jobs')).toHaveCount(0);await expect(second.locator('.windows-update-jobs > div[role="status"]')).toContainText(de?'Planung blockiert':'Schedule blocked');await expect(second.locator('.windows-update-jobs').getByRole('checkbox')).toHaveCount(0);await close(second,fixture.secondDevice).click();
 await open(first,fixture.device).click();await expect(jobStatus).toContainText(de?'Geplant; geeignete Abfrage':'Scheduled; waiting');expect(fixture.updateReads.exact).toBeGreaterThan(0);await close(first,fixture.device).click();await expect(worklist.locator('.windows-update-jobs')).toHaveCount(0);
 const firstSummary=first.locator('.windows-fleet-update-row'),secondSummary=second.locator('.windows-fleet-update-row');await expect(firstSummary).toContainText(de?'Geplant; geeignete Abfrage':'Scheduled; waiting');await expect(secondSummary).toContainText(de?'Planung blockiert; Prüfung erforderlich':'Schedule blocked; review required');await expect(firstSummary).toContainText(fixture.selection.updateId);await expect(secondSummary).toContainText(fixture.secondSelection.updateId);for(const summary of [firstSummary,secondSummary])for(const at of Object.values(fixture.scheduleWindow))await expect(summary).toContainText(utc(at));
 await capture('per-device-summary',worklist.locator('.windows-fleet-update-list'));for(const summary of [firstSummary,secondSummary])await expect(summary).toBeInViewport({ratio:1});
 noPeerWrites();expect(fixture.scheduleCounts).toEqual({schedule:1,cancel:0,immediateInstallWrites:0});expect(fixture.updateCounts.request).toBe(1);expect(fixture.updateCounts.preview).toBe(1);expect(fixture.secondUpdateCounts).toEqual({request:0,preview:0,approve:0,status:1});
 stage='complete';return {sharedWindowExact:true,explicitUncheckedPerDeviceApproval:true,noAutomaticNextDevice:true,independentSavedStates:true,exactSavedReadback:true,syntheticScheduleRequests:1,secondDeviceMutationRequests:0,immediateInstallWrites:0,requestsToRealAPI:0,nativeAcceptance:false};
}

export function requireWindowsFleetUpdateScheduleEvidence(rows,sourceSha){
 const fail=()=>{throw new Error('Synthetic fleet shared-window UI evidence missing or mismatched');};if(!Array.isArray(rows)||rows.length!==8||!/^[a-f0-9]{40}$/.test(sourceSha??''))fail();
 for(const kind of windowsFleetUpdateScheduleScenes)for(const locale of ['en','de'])for(const width of [1440,390]){
  const matches=rows.filter(row=>row?.file===`synthetic-windows-fleet-update-schedule-${kind}-${width}-${locale}.png`);if(matches.length!==1)fail();const row=matches[0];
  if(row.sourceSha!==sourceSha||row.test!==windowsFleetUpdateScheduleCaseName||row.locale!==locale||row.viewport?.width!==width||row.viewport?.height!==(width===390?844:1000)||row.publicSafe!==true||row.fullPage!==false||row.fixtureDisclosure!==windowsFleetUpdateScheduleDisclosure)fail();
 }
 return {screens:8,nativeAcceptance:false};
}
