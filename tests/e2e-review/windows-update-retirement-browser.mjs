import {settlePausedDetailRoute} from './paused-detail-route.mjs';
/** Inert reusable-job UI fixture. No browser, server, manager or native WUA starts here. */
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {closeSync,lstatSync,openSync,readFileSync,readSync} from 'node:fs';
import path from 'node:path';
import {createWindowsUpdateJobsFixture,windowsUpdateJobsOrigin,windowsUpdateJobsRoute} from './windows-update-jobs-browser.mjs';
const require=createRequire(new URL('../../web/package.json',import.meta.url));
const built=require('esbuild').buildSync({stdin:{contents:"export {validUpdateJobView,validUpdateJobHistory} from './windows-update-jobs-types';",resolveDir:fileURLToPath(new URL('../../web/src/',import.meta.url)),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {validUpdateJobView,validUpdateJobHistory}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
export const windowsUpdateRetirementCaseName='Synthetic completed Windows update review and exact retirement reconciliation';
export const windowsUpdateRetirementDisclosure='Entirely intercepted invented reusable consent, signed-result digest and released-owner metadata in the compiled UI. One unchecked exact retirement writes to an in-memory fixture only. No actual TLS authority, host grant, native WUA, real manager write, installation or restart. Browser evidence is not native acceptance.';
// Producer, runner and external validator use this one compact scene contract.
export const windowsUpdateRetirementScenes=['review'];
export const windowsUpdateRetirementViewports=[{width:1440,height:1000},{width:390,height:844}];
let stage='setup';
export const windowsUpdateRetirementFailureStage=()=>stage;
export function createWindowsUpdateRetirementFixture(){
 const fixture=createWindowsUpdateJobsFixture(),at=Date.parse(fixture.now)/1000,id='update_'+'c'.repeat(32),envelopeDigest='sha256:'+'d'.repeat(64),resultDigest='sha256:'+'e'.repeat(64);
 const counts={retire:0,postAttempts:0,current:0,exact:0,history:0};let state='available';
 const view=()=>{
  const v={version:'tracebolt.windows-selected-update-job.v1',deviceId:fixture.device.id,serverNow:at,available:state==='retired',reason:state==='retired'?'ready':'job_pending_or_intervention',reusableJobs:true,backgroundExecutor:true,executorAvailability:'verified_recent',executorObservedAt:at,grantExpiresAt:at+1800,...(state==='retired'?{retiredFloor:'1'}:{}),coordinated:true,mutationCapturedAt:at,mutation:{active:true,blocked:false,phase:'idle',revision:'3',retained:1},job:{id,selection:fixture.selection,state:'complete',reason:'ready',preview:null,result:{jobId:id,envelopeDigest,attempted:true,outcome:'succeeded',operationResult:2,hresult:0,rebootRequired:'yes',completedAt:at-3},occurrence:'1',resultDigest,retirement:{state,...(state!=='available'?{requestedAt:at-2}:{}),...(state==='retired'?{claimedAt:at-1,retiredAt:at}:{})}}};
  if(!validUpdateJobView(v,fixture.device.id,fixture.session.actorId))throw Error('Invalid synthetic retirement view');return structuredClone(v);
 };
 const history=()=>{
  const v=view(),{preview:_,resultDigest:__,...job}=v.job;
  const h={version:'tracebolt.windows-selected-update-history.v1',deviceId:v.deviceId,serverNow:at,available:v.available,reason:v.reason,reusableJobs:true,grantExpiresAt:v.grantExpiresAt,...(v.retiredFloor?{retiredFloor:v.retiredFloor}:{}),remainingCapacity:state==='retired'?1:0,jobs:[{...job,requestedAt:at-10,approvedAt:at-8,claimedAt:at-6}]};
  if(!validUpdateJobHistory(h,v.deviceId,fixture.session.actorId))throw Error('Invalid synthetic retirement history');return structuredClone(h);
 };
 const body={jobId:id,occurrence:'1',envelopeDigest,resultDigest,acknowledged:true};
 return {...fixture,retirementCounts:counts,retirementID:id,retirementBody:body,retirementView:view,retirementHistory:history,
  retirementMutation(raw){counts.postAttempts++;if(state!=='available'||raw!==JSON.stringify(body))return null;state='pending';counts.retire++;return view();},
  confirmRetired(){if(state!=='pending'||counts.retire!==1)throw Error('Missing synthetic retirement');state='retired';},
 };
}
export function windowsUpdateRetirementRoute({base,fixture,state,asset}){
 if(base!==windowsUpdateJobsOrigin)throw Error('Invalid retirement fixture origin');
 const fallback=windowsUpdateJobsRoute({base,fixture,state,asset}),path='/api/devices/'+fixture.device.id+'/windows-update-jobs';
 return async route=>{
  const request=route.request(),url=new URL(request.url()),method=request.method(),raw=request.postData(),headers=request.headers();
  const block=()=>{state.blocked.push('retirement-shape-or-binding');return route.abort('blockedbyclient');};
  if(url.origin!==base){state.external.push('external');return route.abort('blockedbyclient');}
  if(!url.pathname.startsWith(path))return fallback(route);
  let value;
  if(url.pathname===path&&method==='GET'&&raw===null){
   if(url.search===''||url.search==='?jobId='+fixture.retirementID){fixture.retirementCounts[url.search?'exact':'current']++;value=fixture.retirementView();}
   else if(url.search==='?history=1'){fixture.retirementCounts.history++;value=fixture.retirementHistory();}
   else return block();
  }else if(url.pathname===path+'/retire'&&url.search===''&&method==='POST'&&typeof raw==='string'&&Buffer.byteLength(raw)<=1024&&headers.origin===base&&headers['x-csrf-token']===fixture.session.csrfToken&&headers['content-type']==='application/json')value=fixture.retirementMutation(raw);
  else return block();
  return value?route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(value)}):block();
 };
}
export async function exerciseWindowsUpdateRetirement({page,expect,base,fixture,locale,width,shot}){
 const de=locale==='de',panel=page.locator('.windows-update-jobs'),review=de?'Abgeschlossenen Auftrag prüfen':'Review completed job',close=de?'Abgeschlossenen Auftrag schließen':'Close completed job',read=de?'Gespeicherten Status lesen':'Read saved status';
 const open=async()=>{await page.getByRole('tab',{name:de?'Inventar':'Inventory',exact:true}).click();await page.getByRole('tab',{name:'Updates',exact:true}).click();await expect(panel).toBeVisible();};
 const result=de?'WUA hat Erfolg gemeldet':'WUA reported success',reboot=de?'Windows meldet einen erforderlichen Neustart.':'Windows reports that a restart is required.';
 stage='review';await page.goto(base+'/#/devices/'+fixture.device.id);await page.getByLabel(/Language|Sprache/).selectOption(locale);stage='detail-route-readiness';await settlePausedDetailRoute(page,expect,page.getByRole('tab',{name:locale==='de'?'Inventar':'Inventory',exact:true}));stage='review';await open();await expect(panel).toContainText(result);await expect(panel).toContainText(reboot);await expect(panel).toContainText(de?'Ursprüngliche Zustimmung läuft ab':'Original consent expires');await expect(panel).not.toContainText('/32');await expect(panel.getByRole('checkbox')).toHaveCount(0);
 await panel.getByRole('button',{name:review,exact:true}).click();const group=panel.getByRole('group',{name:review,exact:true}),button=group.getByRole('button',{name:close,exact:true});await expect(group.getByRole('checkbox')).not.toBeChecked();await expect(button).toBeDisabled();await expect(group.locator('details')).not.toHaveAttribute('open');await expect(group).toContainText(fixture.selection.updateId);
 // Keep the saved result/reboot and the exact unchecked review together in a
 // normal bounded viewport. No CSS injection, resizing or full-page capture.
 await panel.getByText(result,{exact:true}).evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));await expect(panel.getByText(result,{exact:true})).toBeInViewport();await expect(panel.getByText(reboot,{exact:true})).toBeInViewport();await expect(button).toBeInViewport();expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);
 await shot(page,`synthetic-windows-update-retirement-review-${width}-${locale}`,windowsUpdateRetirementDisclosure);
 stage='retire';await group.getByRole('checkbox').check();await button.evaluate(el=>{el.click();el.click();});await expect(panel).toContainText(de?'Abschließen ausstehend; nächster Auftrag blockiert.':'Closing pending; next job blocked.');expect(fixture.retirementCounts.retire).toBe(1);expect(fixture.retirementCounts.postAttempts).toBe(1);await expect(panel.getByRole('combobox')).toHaveCount(0);
 stage='reload';await page.reload();stage='reload-detail-route-readiness';await settlePausedDetailRoute(page,expect,page.getByRole('tab',{name:locale==='de'?'Inventar':'Inventory',exact:true}));stage='reload';await open();await expect(panel).toContainText(de?'Abschließen ausstehend; nächster Auftrag blockiert.':'Closing pending; next job blocked.');await expect(panel.getByRole('checkbox')).toHaveCount(0);await expect(panel).toContainText(result);await expect(panel).toContainText(reboot);expect(fixture.retirementCounts.postAttempts).toBe(1);
 stage='retired';fixture.confirmRetired();await panel.getByRole('button',{name:read,exact:true}).click();await expect(panel).toContainText(de?'Auftrag geschlossen; kein nächster Auftrag gestartet.':'Job closed; no next job started.');await expect(panel).toContainText(result);await expect(panel).toContainText(reboot);await expect(panel.getByRole('checkbox')).toHaveCount(0);
 await panel.getByText(de?'Gespeicherte Updateaufträge':'Saved update jobs',{exact:true}).click();await panel.getByRole('button',{name:de?'Gespeicherte Aufträge lesen':'Read saved jobs',exact:true}).click();await expect(panel).toContainText(de?'Verfügbarer Auftragsplatz: 1/1':'Available job slot: 1/1');await expect(panel).not.toContainText('/32');expect(fixture.retirementCounts.retire).toBe(1);expect(fixture.retirementCounts.postAttempts).toBe(1);expect(fixture.retirementCounts.exact).toBeGreaterThanOrEqual(3);await expect(panel.getByRole('checkbox')).toHaveCount(0);
 stage='complete';return {exactUncheckedReview:true,duplicateClickSuppressed:true,reloadGETOnly:true,retiredResultPreserved:true,rebootPreserved:true,noNextJobStarted:true,retireWrites:1,nativeAcceptance:false};
}
export function requireWindowsUpdateRetirementEvidence(rows,sourceSha){
 const fail=()=>{throw Error('Synthetic retirement evidence missing or mismatched');};if(!Array.isArray(rows)||rows.length!==4||!/^[a-f0-9]{40}$/.test(sourceSha??''))fail();
 for(const kind of windowsUpdateRetirementScenes)for(const locale of ['en','de'])for(const viewport of windowsUpdateRetirementViewports){const matches=rows.filter(row=>row?.file===`synthetic-windows-update-retirement-${kind}-${viewport.width}-${locale}.png`);if(matches.length!==1)fail();const row=matches[0];if(row.sourceSha!==sourceSha||row.test!==windowsUpdateRetirementCaseName||row.locale!==locale||row.viewport?.width!==viewport.width||row.viewport?.height!==viewport.height||row.publicSafe!==true||row.fullPage!==false||row.fixtureDisclosure!==windowsUpdateRetirementDisclosure)fail();}
 return {screens:4,nativeAcceptance:false};
}
export function requireWindowsUpdateRetirementDetails(details){
 if(!details||['exactUncheckedReview','duplicateClickSuppressed','reloadGETOnly','retiredResultPreserved','rebootPreserved','noNextJobStarted'].some(k=>details[k]!==true)||details.retireWrites!==1||details.nativeAcceptance!==false)throw Error('Synthetic retirement behavior missing or mismatched');
 return {retireWrites:1,nativeAcceptance:false};
}

/** Same canonical source contract validates both PR and full hosted evidence. */
export function validateWindowsUpdateRetirementReport(report,manifest,sourceSha){
 if(!report||report.sourceSha!==sourceSha||report.status!=='PASS'||report.browserAcceptance!==true||report.nativeAcceptance!==false||report.requestsToRealAPI!==0||report.runtimeErrorCount!==0||report.retirementScope!==windowsUpdateRetirementDisclosure||report.retirementStage!=='complete'||!Array.isArray(report.retirementVariants)||report.retirementVariants.length!==4||manifest?.sourceSha!==sourceSha||!Array.isArray(manifest.screenshots))throw Error('Incomplete retirement capture report');
 for(const locale of ['en','de'])for(const viewport of windowsUpdateRetirementViewports){const rows=report.retirementVariants.filter(row=>row?.locale===locale&&row.width===viewport.width);if(rows.length!==1)throw Error('Missing retirement variant');requireWindowsUpdateRetirementDetails(rows[0]);}
 const rows=manifest.screenshots.filter(row=>row?.test===windowsUpdateRetirementCaseName||row?.file?.startsWith('synthetic-windows-update-retirement-'));
 return requireWindowsUpdateRetirementEvidence(rows,sourceSha);
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  if(process.argv.length!==4||process.argv[2]!=='--check-evidence'||!/^[a-f0-9]{40}$/.test(process.argv[3]))throw Error('Invalid evidence check');
  const root=fileURLToPath(new URL('../../artifacts/review/',import.meta.url));
  const json=name=>{const file=path.join(root,name),stat=lstatSync(file);if(!stat.isFile()||stat.size>131072)throw Error('Invalid capture metadata');return JSON.parse(readFileSync(file,'utf8'));};
  const report=json('windows-service-actions-results.json'),manifest=json('windows-service-actions-manifest.json');validateWindowsUpdateRetirementReport(report,manifest,process.argv[3]);
  for(const scene of windowsUpdateRetirementScenes)for(const locale of ['en','de'])for(const viewport of windowsUpdateRetirementViewports){
   const file=path.join(root,`synthetic-windows-update-retirement-${scene}-${viewport.width}-${locale}.png`),stat=lstatSync(file);if(!stat.isFile()||stat.size<24||stat.size>8*1024*1024)throw Error('Invalid capture file');
   const fd=openSync(file,'r'),head=Buffer.alloc(24);try{if(readSync(fd,head,0,24,0)!==24||head.subarray(0,8).toString('hex')!=='89504e470d0a1a0a'||head.subarray(12,16).toString()!=='IHDR'||head.readUInt32BE(16)!==viewport.width||head.readUInt32BE(20)!==viewport.height)throw Error('Invalid capture dimensions');}finally{closeSync(fd);}
  }
  console.log('PASS: four exact-source retirement review captures and bounded reconciliation evidence; synthetic only.');
 }catch{console.error('FAIL: retirement capture evidence missing or mismatched; raw state withheld.');process.exitCode=1;}
}
