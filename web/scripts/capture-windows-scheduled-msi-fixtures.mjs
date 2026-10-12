/** Inert scheduled-MSI source fixture. --check starts no browser, listener or service.
 * Hosted capture accepts an already-authorized browser; never a local fallback. */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {mkdir,writeFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createWindowsReusableMSIFixture} from './capture-windows-reusable-msi-fixtures.mjs';
import {compileWindowsFleetMSIAssets,createWindowsFleetMSIRoute,createWindowsSavedMSIFixture,windowsFleetMSICases,windowsFleetMSIOrigin} from './capture-windows-fleet-msi-fixtures.mjs';
const require=createRequire(new URL('../package.json',import.meta.url));
const digest=s=>`sha256:${s.repeat(64)}`;
export const fleetScheduledMSIScenes=Object.freeze(['fleet-shared-window-unchecked','fleet-mixed-scheduled-unsent']);
export const scheduledMSIScenes=['approval-unchecked','scheduled','permit-issued','canceled','blocked',...fleetScheduledMSIScenes];
export const scheduledMSICaptureMatrix=Object.freeze(scheduledMSIScenes.flatMap(scene=>windowsFleetMSICases.map(testCase=>Object.freeze({scene,...testCase,file:`synthetic-windows-scheduled-msi-${scene}-${testCase.width}-${testCase.locale}.png`}))));
export const scheduledMSIDisclosure='Synthetic source fixture of one-device and exact fleet scheduled MSI with compiled production UI. The exact fleet schedule-preview POST reads only fixed invented data and is counted separately. Every actual mutation is blocked. No native installer, delivery, cleanup, endpoint grant, service activation or retry. Source checks capture no browser pixels; native acceptance remains separately approved and pending.';
async function contracts(){const {build}=require('esbuild');const result=await build({stdin:{contents:"export {validManagedView} from './windows-managed-msi-types'; export {managedScheduleRequest} from './windows-managed-msi-schedule-types'; export {validWorklistsView,validWorklistPreview,worklistAcknowledgements} from './windows-managed-msi-worklist-types';",resolveDir:fileURLToPath(new URL('../src/',import.meta.url)),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});return import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].text).toString('base64')}`)}
export async function createWindowsScheduledMSIFixture(scene,now){
 assert(scheduledMSIScenes.includes(scene));if(fleetScheduledMSIScenes.includes(scene))return createFleetScheduledMSIFixture(scene,now);const fixture=await createWindowsReusableMSIFixture('retirement-review',now),{views,seconds,session}=fixture,v=views[0],validation=await contracts();session.capabilities.push('windows_managed_msi_schedule');
 Object.assign(v,{state:'ready',result:null,canRetire:false,schedulingAvailable:true,leafExpiresAt:seconds+1800,expiresAt:seconds+60,readinessDigest:digest('e'),readiness:{selection:v.package,capturedAt:seconds,packageVerified:'yes',machineAbsent:'yes',installerBusy:'no',nativeAcceptance:'yes',packageReviewAccepted:'yes',maintenanceWindowEnd:seconds+600}});delete v.resultDigest;
 if(scene!=='approval-unchecked'){
  // Already-saved synthetic schedule. No POST, clock jump or actual installation.
  const approvedAt=seconds-180,startAt=seconds-60,endAt=seconds+240,q=validation.managedScheduleRequest(v,{startAt,endAt});
  v.schedule={version:'tracebolt.windows-managed-msi-schedule.v1',digest:digest('f'),requestDigest:'sha256:'+createHash('sha256').update('Tracebolt managed MSI schedule request v1\0'+JSON.stringify(q)).digest('hex'),actorId:session.actorId,approvedAt,startAt,endAt,readinessDigest:v.readinessDigest,state:scene==='permit-issued'?'permit_issued':scene,readinessIssuedAt:scene==='permit-issued'?seconds-50:0,permitIssuedAt:scene==='permit-issued'?seconds-40:0,outcomeAt:['canceled','blocked'].includes(scene)?seconds-20:0,canCancel:scene==='scheduled'};
  v.state=scene==='permit-issued'?'approved':'expired';v.expiresAt=seconds-120;
 }
 assert(validation.validManagedView(v,v.deviceId),`Scheduled scene ${scene}`);return fixture;
}
/** Two invented saved-worklist scenes; no POST modifies this fixture. */
async function createFleetScheduledMSIFixture(scene,now){
 const fixture=await createWindowsSavedMSIFixture('approval-unchecked',now),validation=await contracts(),{seconds,views,session,savedWorklist:w}=fixture;
 session.capabilities.push('windows_managed_msi_schedule');delete fixture.reviewedPreview;
 const startAt=Math.ceil((seconds+120)/60)*60,endAt=startAt+300;
 for(const view of views)Object.assign(view,{schedulingAvailable:true,leafExpiresAt:seconds+1800});
 const items=views.map(view=>({deviceId:view.deviceId,operation:'schedule',artifactId:w.artifactId,artifactRetiredCount:w.artifactRetiredCount,bindingDigest:view.bindingDigest,transferId:view.transferId,jobSequence:view.jobSequence,readinessDigest:view.readinessDigest,expiresAt:view.expiresAt,startAt,endAt}));
 if(scene==='fleet-shared-window-unchecked'){
  fixture.reviewedSchedulePreview={path:`/api/windows-managed-msi/worklists/${w.id}/schedule-preview`,body:JSON.stringify({revision:w.revision,startAt,endAt}),response:{worklistId:w.id,revision:w.revision,kind:'schedule',items,excluded:[{deviceId:fixture.devices[2].id,reason:'unavailable'}]}};
  assert(validation.validWorklistPreview(fixture.reviewedSchedulePreview.response,w,'schedule'));
 }else{
  const approvedAt=seconds-90,expiresAt=approvedAt+55;
  for(const [index,view] of views.entries()){view.state='expired';view.expiresAt=expiresAt;view.readiness.capturedAt=approvedAt;items[index].expiresAt=expiresAt;w.rows[index].state='expired'}
  const view=views[0],q=validation.managedScheduleRequest(view,{startAt,endAt});
  view.schedule={version:'tracebolt.windows-managed-msi-schedule.v1',digest:digest('f'),requestDigest:'sha256:'+createHash('sha256').update('Tracebolt managed MSI schedule request v1\0'+JSON.stringify(q)).digest('hex'),actorId:session.actorId,approvedAt,startAt,endAt,readinessDigest:view.readinessDigest,state:'scheduled',readinessIssuedAt:0,permitIssuedAt:0,outcomeAt:0,canCancel:true};
  w.batches=[{id:`batch_${'a'.repeat(32)}`,kind:'schedule',actorId:session.actorId,sessionDigest:digest('7'),sessionExpiresAt:Math.floor(Date.parse(session.expiresAt)/1000),createdAt:approvedAt,expiresAt,closedAt:approvedAt+1,closeReason:'stopped',confirmationDigest:digest('8'),acknowledgements:validation.worklistAcknowledgements('schedule'),items:items.map((request,index)=>({request,state:index===0?'scheduled':'not_dispatched',issuedAt:index===0?approvedAt:0,permitDigest:'',jobSequence:index===0?request.jobSequence:'0',...(index===0?{scheduleDigest:view.schedule.digest}:{})}))}];
 }
 fixture.sharedWindow={startAt,endAt};assert(validation.validWorklistsView(fixture.readWorklists()));for(const view of views)assert(validation.validManagedView(view,view.deviceId));return fixture;
}
/** Admit only the exact reviewed synthetic read; all mutations use the blocking route. */
export function createWindowsScheduledMSIRoute({fixture,compiled,state}){
 const base=createWindowsFleetMSIRoute({fixture,compiled,state});return async route=>{
  const request=route.request(),url=new URL(request.url()),preview=fixture.reviewedSchedulePreview;
  if(preview&&fixture.savedWorklist&&url.origin===windowsFleetMSIOrigin&&url.pathname===`/api/windows-managed-msi/worklists/${fixture.savedWorklist.id}/schedule-preview`&&url.pathname===preview.path&&!url.search&&request.method()==='POST'&&request.postData()===preview.body){
   assert(Array.isArray(state.previews));state.previews.push({method:'POST',path:preview.path,body:preview.body});return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(structuredClone(preview.response))});
  }
  return base(route);
 };
}
export async function checkWindowsScheduledMSIFixtures(){
 const validation=await contracts();assert.equal(scheduledMSICaptureMatrix.length,28);assert.equal(new Set(scheduledMSICaptureMatrix.map(row=>row.file)).size,28);
 for(const scene of fleetScheduledMSIScenes)for(const locale of ['en','de'])for(const width of [1440,390])assert(scheduledMSICaptureMatrix.some(row=>row.scene===scene&&row.locale===locale&&row.width===width&&row.height===(width===390?844:1100)));
 for(const scene of scheduledMSIScenes){
  const fixture=await createWindowsScheduledMSIFixture(scene,'2026-10-12T10:00:00.000Z'),v=fixture.views[0];assert.equal(validation.validManagedView({...v,schedulingAvailable:'yes'},v.deviceId),false);if(v.schedule)assert.equal(validation.validManagedView({...v,schedule:{...v.schedule,requestDigest:'unconfirmed'}},v.deviceId),false);
  const state={blocked:[],external:[],writes:[],previews:[]},route=createWindowsScheduledMSIRoute({fixture,compiled:{assets:new Map()},state});
  const call=async(suffix,method='GET',body=null)=>{let response;await route({request:()=>({url:()=>windowsFleetMSIOrigin+suffix,method:()=>method,postData:()=>body}),fulfill:value=>{response=value},abort:reason=>{response={aborted:reason}}});return response};
  for(const op of ['schedule','cancel-schedule'])assert.equal((await call(`/api/devices/${v.deviceId}/windows-managed-msi/${op}`,'POST','{}')).aborted,'blockedbyclient');assert.equal(state.writes.length,2);
  if(fixture.savedWorklist){
   const before=structuredClone(fixture.savedWorklist),base=`/api/windows-managed-msi/worklists/${fixture.savedWorklist.id}`,preview=fixture.reviewedSchedulePreview;
   assert(validation.validWorklistsView(JSON.parse((await call('/api/windows-managed-msi/worklists')).body)));
   if(preview){
    assert.deepEqual(JSON.parse((await call(preview.path,'POST',preview.body)).body),preview.response);assert.equal(state.previews.length,1);
    for(const raw of ['{}',JSON.stringify({...JSON.parse(preview.body),endAt:fixture.sharedWindow.endAt+60}),JSON.stringify({...JSON.parse(preview.body),acknowledged:true})])assert.equal((await call(preview.path,'POST',raw)).aborted,'blockedbyclient');
    for(const suffix of ['?unexpected=1','/'])assert.equal((await call(preview.path+suffix,'POST',preview.body)).aborted,'blockedbyclient');
    assert.equal(state.previews.length,1);assert.equal(preview.response.items.length,2);assert(preview.response.items.every(q=>q.startAt===fixture.sharedWindow.startAt&&q.endAt===fixture.sharedWindow.endAt));
   }else{assert.deepEqual(before.batches[0].items.map(item=>item.state),['scheduled','not_dispatched']);assert.equal(before.rows[0].state,'expired');assert.equal(before.rows[0].view.schedule.state,'scheduled');assert.equal(state.previews.length,0)}
   for(const operation of ['batches','close','archive'])assert.equal((await call(`${base}/${operation}`,'POST','{}')).aborted,'blockedbyclient');assert.deepEqual(fixture.savedWorklist,before);
  }
 }
 const compiled=await compileWindowsFleetMSIAssets();for(const file of ['web/src/windows-managed-msi-worklists.tsx','web/scripts/capture-windows-scheduled-msi-fixtures.mjs','web/scripts/run-windows-fleet-msi-ci.mjs'])assert(compiled.sourceInputs.some(input=>input.file===file));
 return {mode:'source-only',scenes:scheduledMSIScenes,cases:scheduledMSICaptureMatrix,fleetScenes:fleetScheduledMSIScenes,sourceDigest:compiled.sourceDigest,sourceInputs:compiled.sourceInputs,compiled:true,dtoAndRouteChecks:'passed',actualMutations:0,browserExecuted:false,screenshotsCaptured:0,nativeAcceptance:false,disclosure:scheduledMSIDisclosure};
}
export async function captureWindowsScheduledMSIFixtures({browser,expect,output}){
 assert(browser&&typeof browser.newContext==='function'&&typeof expect==='function');const compiled=await compileWindowsFleetMSIAssets(),captures=[];await mkdir(output,{recursive:true});
 for(const testCase of scheduledMSICaptureMatrix){
  const {scene,locale,width,height,file}=testCase,de=locale==='de',fixture=await createWindowsScheduledMSIFixture(scene),state={blocked:[],external:[],writes:[],previews:[],pageErrors:[]},context=await browser.newContext({viewport:{width,height},locale:de?'de-DE':'en-US',deviceScaleFactor:1,reducedMotion:'reduce',serviceWorkers:'block'});
  try{
   await context.route('**/*',createWindowsScheduledMSIRoute({fixture,compiled,state}));await context.addInitScript(value=>localStorage.setItem('tracebolt.locale',value),locale);const page=await context.newPage();page.on('pageerror',error=>state.pageErrors.push(error.message));await page.goto(`${windowsFleetMSIOrigin}/#/devices`);
   const title=de?'Windows-MSI-Arbeitsliste':'Windows MSI worklist',worklist=page.getByRole('region',{name:title,exact:true});await worklist.getByRole('button',{name:title,exact:true}).click();let focus,scroll;
   if(fleetScheduledMSIScenes.includes(scene)){
    focus=worklist.getByRole('region',{name:de?'Gespeicherte MSI-Arbeitslisten':'Saved MSI worklists',exact:true});await expect(focus).toBeVisible();scroll=focus;
    if(scene==='fleet-shared-window-unchecked'){
     const inputs=focus.locator('details.managed-msi-schedule');await inputs.locator(':scope>summary').click();const utc=seconds=>new Date(seconds*1000).toISOString().slice(0,16);
     await inputs.getByLabel(de?'Beginn (UTC)':'Start (UTC)').fill(utc(fixture.sharedWindow.startAt));await inputs.getByLabel(de?'Ende (UTC)':'End (UTC)').fill(utc(fixture.sharedWindow.endAt));await inputs.getByRole('button',{name:de?'Exakte Planungen prüfen':'Preview exact schedules'}).click();
     const review=focus.getByRole('region',{name:de?'Bereite Geräte planen':'Schedule ready devices',exact:true});await expect(review.getByRole('checkbox')).not.toBeChecked();await expect(review.getByRole('button',{name:de?'Exakte Anfragen bestätigen':'Confirm exact requests'})).toBeDisabled();await expect(review.locator('ol>li')).toHaveCount(2);await expect(review).toContainText(new Date(fixture.sharedWindow.startAt*1000).toISOString().slice(11,16));await expect(review).toContainText(new Date(fixture.sharedWindow.endAt*1000).toISOString().slice(11,16)+' UTC');await expect(review.locator(':scope>details')).not.toHaveAttribute('open','');await expect(review.getByText(fixture.devices[0].id,{exact:true})).not.toBeVisible();await expect(review).toContainText(de?'sie ist keine Installationsfreigabe':'it is not an installation permit');assert.equal(state.previews.length,1);scroll=review;
    }else{
     await expect(focus.getByRole('status')).toContainText(de?'1 Planungen genehmigt · 1 Nicht versendet':'1 Schedules approved · 1 Not dispatched');await expect(focus.getByText(de?'Installation geplant':'Installation scheduled',{exact:true})).toBeVisible();await expect(focus.getByText(de?'Prüfen: 2':'Attention: 2',{exact:true})).toBeVisible();await expect(focus.getByRole('checkbox')).toHaveCount(0);assert.equal(state.previews.length,0);
    }
   }else{
    const choices=worklist.getByRole('group',{name:de?'Geräte auswählen':'Select devices'});await choices.getByRole('checkbox').first().check();await worklist.getByRole('button',{name:de?'Geräteauswahl festhalten':'Freeze device selection'}).click();await worklist.getByRole('button',{name:`${de?'Gerät öffnen':'Open device'}: ${fixture.devices[0].name}`,exact:true}).click();focus=worklist.locator('.managed-msi-panel:not(.managed-msi-artifact)');const schedule=focus.locator('.managed-msi-schedule');scroll=schedule;
    if(scene==='approval-unchecked'){await schedule.locator(':scope>summary').click();await expect(schedule.getByRole('checkbox')).not.toBeChecked();await expect(schedule.getByRole('button',{name:de?'Geplante Installation einmal genehmigen':'Approve scheduled installation once'})).toBeDisabled();await expect(schedule.locator('details')).not.toHaveAttribute('open','')}
    else{await expect(schedule.getByRole('button',{name:de?'Diese Planung abbrechen':'Cancel this schedule'})).toHaveCount(scene==='scheduled'?1:0);await expect(focus.getByRole('button',{name:de?'Eine Installation genehmigen':'Approve one installation'})).toHaveCount(0)}
   }
   await page.evaluate(()=>document.fonts.ready);await scroll.evaluate(element=>element.scrollIntoView({block:'start',behavior:'instant'}));expect(await focus.evaluate(element=>element.scrollWidth<=element.clientWidth+1)).toBe(true);expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);await page.screenshot({path:path.join(output,file),animations:'disabled',fullPage:false});for(const key of ['writes','external','blocked','pageErrors'])assert.equal(state[key].length,0);
   captures.push({...testCase,sourceDigest:compiled.sourceDigest,synthetic:true,disclosure:scheduledMSIDisclosure,assertions:{fleet:fleetScheduledMSIScenes.includes(scene),confirmationUnchecked:scene==='fleet-shared-window-unchecked'||scene==='approval-unchecked',sharedWindowExact:scene==='fleet-shared-window-unchecked',mixedSavedOutcome:scene==='fleet-mixed-scheduled-unsent',previewReads:state.previews.length,actualMutationRequests:0}});
  }finally{await context.close()}
 }
 const result={captures,sourceDigest:compiled.sourceDigest,sourceInputs:compiled.sourceInputs,browserExecuted:true,nativeAcceptance:false,disclosure:scheduledMSIDisclosure};await writeFile(path.join(output,'windows-scheduled-msi-manifest.json'),JSON.stringify(result,null,2)+'\n');return result;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href){assert.deepEqual(process.argv.slice(2),['--check'],'Only source-only --check is supported directly');process.stdout.write(JSON.stringify(await checkWindowsScheduledMSIFixtures(),null,2)+'\n')}
