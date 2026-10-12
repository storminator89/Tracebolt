/** Inert coordinated-status fixtures. Importing launches no browser or host work. */
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {createWindowsManagedMSIFixture,windowsManagedMSIRoute,windowsManagedMSIOrigin} from './windows-managed-msi-browser.mjs';
const require=createRequire(new URL('../../web/package.json',import.meta.url));
const built=require('esbuild').buildSync({stdin:{contents:"export {validManagedView} from './windows-managed-msi-types'; export {validUpdateJobView,validUpdateJobHistory} from './windows-update-jobs-types'; export {validMutationStatus} from './windows-mutation-status-types';",resolveDir:fileURLToPath(new URL('../../web/src/',import.meta.url)),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {validManagedView,validUpdateJobView,validUpdateJobHistory,validMutationStatus}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
export const windowsMutationCoexistenceOrigin=windowsManagedMSIOrigin;
export const windowsMutationCoexistenceCaseName='Synthetic shared MSI and WUA blocking, exact recovery details and released status in both compiled views';
export const windowsMutationCoexistenceDisclosure='Entirely intercepted invented coordinated MSI/WUA status metadata. Both Software and Updates display the same saved shared owner, exact terminal-recovery details, then an externally supplied released snapshot while original domain results remain unchanged. Only read-only status and bounded inventory queries are exercised. No real API, package upload, grant, key, native installer, WUA, host mutation, remote unlock, recovery action, installation or reboot. Browser evidence is not durable-store or native acceptance.';
export const windowsMutationCoexistenceSurfaces=Object.freeze(['software','updates']);
export const windowsMutationCoexistencePhases=Object.freeze(['blocked','released']);
const stages=new Set(['setup','document','blocked','released','reload','complete']);let stage='setup';
export const windowsMutationCoexistenceFailureStage=()=>stages.has(stage)?stage:'setup';
const fail=()=>{throw new Error('Synthetic coordinated mutation evidence missing, unsafe or mismatched');};
const exact=(v,keys)=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));

export function createWindowsMutationCoexistenceFixture(owner='managed_msi'){
 if(!['managed_msi','cached_wua'].includes(owner))fail();
 const base=createWindowsManagedMSIFixture(),at=Date.parse(base.now)/1000,transfer='transfer_'+'9'.repeat(32),update='update_'+'8'.repeat(32);
 const counts={softwareReads:0,updateReads:0,historyReads:0,mutationWrites:0,secondTargetWrites:0},msiOwns=owner==='managed_msi';let phase='blocked';
 const managedResult=Object.freeze({returnCodeKnown:msiOwns,jobId:'software_'+transfer.slice(9),envelopeDigest:'sha256:'+'a'.repeat(64),attempted:msiOwns,outcome:msiOwns?'succeeded':'not_attempted',returnCode:0,registrationVerified:msiOwns?'yes':'unknown',completedAt:at});
 const updateResult=Object.freeze({jobId:update,envelopeDigest:'sha256:'+'b'.repeat(64),attempted:!msiOwns,outcome:msiOwns?'not_attempted':'succeeded',operationResult:msiOwns?0:2,hresult:0,rebootRequired:msiOwns?'unknown':'no',completedAt:at});
 const snapshot=()=>phase==='blocked'?{active:true,blocked:true,domain:owner,jobId:msiOwns?transfer:update,phase:'completion_recorded',recovery:'exact_terminal_receipt',revision:'7',retained:1}:{active:true,blocked:false,phase:'idle',revision:'9',retained:1};
 const fixture={...base,device:{...base.device,name:'SYNTHETIC · Paired MSI and cached Updates'},session:{...base.session,capabilities:['read','windows_managed_msi_deliver','windows_managed_msi_install','windows_update_install']},coexistenceCounts:counts,coexistenceOwner:owner,coexistenceJob:msiOwns?transfer:update,
  coexistencePhase:()=>phase,
  coexistenceSetPhase(next){if(phase!=='blocked'||next!=='released')fail();phase=next;},
  coexistenceSaved(surface){return view(surface);},
  managedSaved(){return view('software');},
  managedView(){counts.softwareReads++;return view('software');},
  updateView(){counts.updateReads++;return view('updates');},
  savedID(){return update;},
  updateHistory(){counts.historyReads++;const v=view('updates'),history={version:'tracebolt.windows-selected-update-history.v1',deviceId:fixture.device.id,serverNow:at,available:false,reason:'job_pending_or_intervention',remainingCapacity:31,jobs:[{id:update,selection:fixture.selection,state:'complete',reason:'ready',result:v.job.result,requestedAt:at-30,approvedAt:at-20,claimedAt:at-10}]};if(!validUpdateJobHistory(history,fixture.device.id,fixture.session.actorId))fail();return structuredClone(history);},
 };
 function view(surface){
  const shared={coordinated:true,mutation:snapshot(),mutationCapturedAt:at};if(!validMutationStatus(shared.mutation))fail();
  if(surface==='software'){
   const value={...shared,version:'tracebolt.windows-managed-msi.v1',deviceId:fixture.device.id,serverNow:at,state:'complete',package:fixture.managedSelection,nativeAcceptanceDigest:fixture.managedNativeDigest,transferId:transfer,readinessDigest:'',expiresAt:at+60,readiness:null,result:managedResult,uploadOffset:fixture.managedSelection.size,uploadPendingDigest:'',canReview:false};
   if(!validManagedView(value,fixture.device.id))fail();return structuredClone(value);
  }
  if(surface==='updates'){
   const value={...shared,version:'tracebolt.windows-selected-update-job.v1',deviceId:fixture.device.id,serverNow:at,available:false,reason:'job_pending_or_intervention',job:{id:update,selection:fixture.selection,state:'complete',reason:'ready',preview:null,result:updateResult}};
   if(!validUpdateJobView(value,fixture.device.id,fixture.session.actorId))fail();return structuredClone(value);
  }
  fail();
 }
 view('software');view('updates');return fixture;
}

export function windowsMutationCoexistenceRoute({base,fixture,state,asset}){
 if(base!==windowsMutationCoexistenceOrigin)fail();
 const fallback=windowsManagedMSIRoute({base,fixture,state,asset}),prefix='/api/devices/'+fixture.device.id,managed=prefix+'/windows-managed-msi',updates=prefix+'/windows-update-jobs';
 return async route=>{
  const req=route.request(),url=new URL(req.url()),method=req.method(),raw=req.postData(),headers=req.headers();
  const block=()=>{state.blocked.push('coordinated-read-only-binding');return route.abort('blockedbyclient');};
  if(url.origin!==base){state.external.push('external');return route.abort('blockedbyclient');}
  if(method!=='GET'&&![prefix+'/windows-full-software/query',prefix+'/windows-full-processes/query'].includes(url.pathname)){
   fixture.coexistenceCounts.mutationWrites++;if(url.pathname.startsWith('/api/devices/'+fixture.secondDevice.id+'/'))fixture.coexistenceCounts.secondTargetWrites++;return block();
  }
  if(url.pathname.includes('/windows-managed-msi')||url.pathname.includes('/windows-update-jobs')){
   if(method!=='GET'||raw!==null||['content-encoding','range','content-range','content-disposition','forwarded','proxy-authorization'].some(k=>Object.hasOwn(headers,k))||Object.keys(headers).some(k=>k.startsWith('x-forwarded-')))return block();
   const reply=value=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(value)});
   if(url.pathname===managed&&url.search==='')return reply(fixture.managedView());
   if(url.pathname===updates&&url.search==='')return reply(fixture.updateView());
   if(url.pathname===updates&&url.search==='?jobId='+fixture.savedID())return reply(fixture.updateView());
   if(url.pathname===updates&&url.search==='?history=1')return reply(fixture.updateHistory());
   return block();
  }
  return fallback(route);
 };
}

export async function exerciseWindowsMutationCoexistence({page,expect,base,fixture,locale,width,shot}){
 const de=locale==='de',read=de?'Gespeicherten Status lesen':'Read saved status',recovery=de?'Wiederherstellung prüfen':'Review recovery';
 const originals={software:fixture.coexistenceSaved('software').result,updates:fixture.coexistenceSaved('updates').job.result};
 const open=async surface=>{
  await page.getByRole('tab',{name:de?'Inventar':'Inventory',exact:true}).click();
  await page.getByRole('tab',{name:surface==='software'?'Software':'Updates',exact:true}).click();
  if(surface==='software'){const button=page.getByRole('button',{name:de?'MSI hochladen & verteilen':'Upload & deliver MSI',exact:true});if(await button.getAttribute('aria-expanded')!=='true')await button.click();}
  const panel=page.locator(surface==='software'?'.managed-msi-panel':'.windows-update-jobs');await expect(panel).toBeVisible();
  await expect(panel.getByRole('button',{name:read,exact:true})).toBeEnabled();
  return panel;
 };
 const verify=async(surface,phase,capture)=>{
  const panel=await open(surface);await panel.getByRole('button',{name:read,exact:true}).click();
  await expect(panel.getByRole('button',{name:read,exact:true})).toBeEnabled();
  const shared=panel.locator('.windows-mutation-status'),summary=shared.getByRole('status');
  await expect(shared).toHaveCount(1);await expect(summary).toBeVisible();
  await expect(panel.getByRole('checkbox')).toHaveCount(0);await expect(panel.getByRole('combobox')).toHaveCount(0);
  await expect(shared.getByRole('button')).toHaveCount(0);
  if(phase==='blocked'){
   await expect(summary).toContainText(de?'Blockiert durch':'Blocked by');await expect(summary).toContainText(fixture.coexistenceOwner==='managed_msi'?'MSI':de?'Windows-Update':'Windows Update');
   await expect(summary).not.toContainText(fixture.coexistenceJob);
   const details=shared.locator('details');await expect(details).toHaveCount(1);await expect(details).not.toHaveAttribute('open');
   await details.getByText(recovery,{exact:true}).click();await expect(details).toContainText(fixture.coexistenceJob);await expect(details).toContainText(de?'gespeicherte Abschlussnachweis':'saved completion receipt');
   await details.getByText(recovery,{exact:true}).click();await expect(details).not.toHaveAttribute('open');
  }else{await expect(summary).toContainText(de?'Kein Besitzer gespeichert':'No owner saved');await expect(shared.locator('details')).toHaveCount(0);}
  expect(fixture.coexistenceSaved('software').result).toEqual(originals.software);expect(fixture.coexistenceSaved('updates').job.result).toEqual(originals.updates);
  await shared.evaluate(el=>el.scrollIntoView({block:'center',inline:'nearest',behavior:'instant'}));
  expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);
  await expect(summary).toBeInViewport({ratio:1});expect(await summary.evaluate(el=>el.getBoundingClientRect().height)).toBeLessThanOrEqual(96);
  if(capture)await shot(page,`synthetic-windows-mutation-coexistence-${surface}-${phase}-${width}-${locale}`,windowsMutationCoexistenceDisclosure);
 };
 stage='document';await page.goto(base+'/#/devices/'+fixture.device.id);await page.getByLabel(/Language|Sprache/).selectOption(locale);await expect(page.locator('html')).toHaveAttribute('lang',locale);
 stage='blocked';for(const surface of windowsMutationCoexistenceSurfaces)await verify(surface,'blocked',true);
 // A new saved snapshot is supplied externally by this inert fixture. The UI
 // never sends an unlock, completion, recovery, approval or native request.
 fixture.coexistenceSetPhase('released');stage='released';for(const surface of windowsMutationCoexistenceSurfaces)await verify(surface,'released',true);
 stage='reload';await page.reload();for(const surface of windowsMutationCoexistenceSurfaces)await verify(surface,'released',false);
 expect(fixture.coexistenceCounts.mutationWrites).toBe(0);expect(fixture.coexistenceCounts.secondTargetWrites).toBe(0);
 expect(fixture.managedAttempts).toEqual({reserve:0,upload:0,complete:0,deliver:0,review:0,approve:0});expect(fixture.updateCounts.approve).toBe(0);expect(fixture.softwareCounts.approve).toBe(0);
 stage='complete';return {softwareMounted:true,updatesMounted:true,blockedSharedOwner:true,exactRecoveryReadback:true,compactSummary:true,releasedReadback:true,originalOutcomesRetained:true,reloadReadback:true,readOnly:true,softwareReads:fixture.coexistenceCounts.softwareReads,updateReads:fixture.coexistenceCounts.updateReads,mutationWrites:0,secondTargetWrites:0,realAPIRequests:0,nativeAcceptance:false};
}

export function requireWindowsMutationCoexistenceDetails(d){
 const truths=['softwareMounted','updatesMounted','blockedSharedOwner','exactRecoveryReadback','compactSummary','releasedReadback','originalOutcomesRetained','reloadReadback','readOnly'],zeros=['mutationWrites','secondTargetWrites','realAPIRequests'];
 if(!exact(d,[...truths,'softwareReads','updateReads',...zeros,'nativeAcceptance'])||truths.some(k=>d[k]!==true)||zeros.some(k=>d[k]!==0)||!Number.isSafeInteger(d.softwareReads)||d.softwareReads<2||!Number.isSafeInteger(d.updateReads)||d.updateReads<2||d.nativeAcceptance!==false)fail();
 return {readOnly:true,nativeAcceptance:false};
}
export function requireWindowsMutationCoexistenceEvidence(rows,sourceSha){
 if(!Array.isArray(rows)||rows.length!==16||!/^[a-f0-9]{40}$/.test(sourceSha??''))fail();
 for(const surface of windowsMutationCoexistenceSurfaces)for(const phase of windowsMutationCoexistencePhases)for(const locale of ['en','de'])for(const width of [1440,390]){
  const matches=rows.filter(row=>row?.file===`synthetic-windows-mutation-coexistence-${surface}-${phase}-${width}-${locale}.png`);if(matches.length!==1)fail();const row=matches[0];
  if(!exact(row,['file','sourceSha','test','locale','viewport','publicSafe','fullPage','fixtureDisclosure','sha256'])||row.sourceSha!==sourceSha||row.test!==windowsMutationCoexistenceCaseName||row.locale!==locale||!exact(row.viewport,['width','height'])||row.viewport.width!==width||row.viewport.height!==(width===390?844:1000)||row.publicSafe!==true||row.fullPage!==false||row.fixtureDisclosure!==windowsMutationCoexistenceDisclosure||!/^[a-f0-9]{64}$/.test(row.sha256??''))fail();
 }
 return {screens:16,readOnly:true,nativeAcceptance:false};
}
export function requireWindowsMutationCoexistenceReport(report,manifest,sourceSha){
 if(!exact(report,['sourceSha','createdAt','name','status','stage','scope','variants','runtimeErrorCount','requestsToRealAPI','browserAcceptance','durableStoreAcceptance','nativeAcceptance','secretsExported','realTelemetryExported'])||report.sourceSha!==sourceSha||typeof report.createdAt!=='string'||!Number.isFinite(Date.parse(report.createdAt))||report.name!==windowsMutationCoexistenceCaseName||report.status!=='PASS'||report.stage!=='complete'||report.scope!==windowsMutationCoexistenceDisclosure||!Array.isArray(report.variants)||report.variants.length!==4||report.runtimeErrorCount!==0||report.requestsToRealAPI!==0||report.browserAcceptance!==true||report.durableStoreAcceptance!==false||report.nativeAcceptance!==false||report.secretsExported!==false||report.realTelemetryExported!==false)fail();
 for(const locale of ['en','de'])for(const width of [1440,390]){const found=report.variants.filter(v=>v?.locale===locale&&v?.width===width);if(found.length!==1)fail();const {locale:l,width:w,...details}=found[0];requireWindowsMutationCoexistenceDetails(details);}
 if(!exact(manifest,['sourceSha','screenshots'])||manifest.sourceSha!==sourceSha)fail();requireWindowsMutationCoexistenceEvidence(manifest.screenshots,sourceSha);return {variants:4,screens:16,readOnly:true,nativeAcceptance:false};
}
