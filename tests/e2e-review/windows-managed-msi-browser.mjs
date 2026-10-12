/** Inert managed-MSI fixture; imports start no browser, listener or host action. */
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {createWindowsSoftwareJobsFixture,windowsSoftwareJobsRoute,windowsSoftwareJobsOrigin} from './windows-software-jobs-browser.mjs';
const require=createRequire(new URL('../../web/package.json',import.meta.url));
const built=require('esbuild').buildSync({stdin:{contents:"export {validManagedView} from './windows-managed-msi-types';",resolveDir:fileURLToPath(new URL('../../web/src/',import.meta.url)),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {validManagedView}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
const digest=bytes=>'sha256:'+createHash('sha256').update(bytes).digest('hex');
export const windowsManagedMSIOrigin=windowsSoftwareJobsOrigin;
export const windowsManagedMSICaseName='Synthetic central MSI bounded upload, separate delivery, unchecked exact approval and durable outcome';
export const windowsManagedMSIDisclosure='Entirely intercepted invented TLS-session and managed-MSI metadata. The browser hashes and sends three bounded chunks of inert synthetic bytes only into an in-memory fixture. Upload, protected import, signed readiness and durable outcome are simulated; separate unchecked delivery, package/terms/maintenance review and one install approval are exercised. No actual package, TLS authority, host grant, key, manager upload, elevated service, Windows Installer call, terms acceptance, installation or reboot. Hashes are not safety evidence. Browser evidence is not native package acceptance.';
export const windowsManagedMSICaptureKinds=Object.freeze(['uploaded','imported','ready','outcome']);
const stages=new Set(['setup','document','upload','deliver','imported','review','ready','approve','outcome','reload','complete']);let stage='setup';
export const windowsManagedMSIFailureStage=()=>stages.has(stage)?stage:'setup';
export function createWindowsManagedMSIFixture(){
 const base=createWindowsSoftwareJobsFixture(),at=Date.parse(base.now)/1000,bytes=Buffer.alloc(65536+512);
 // Merely inert bytes, never a structurally valid or executable MSI.
 bytes.set([0xd0,0xcf,0x11,0xe0,0xa1,0xb1,0x1a,0xe1]);
 const selection=Object.freeze({...base.softwareSelection,sha256:digest(bytes),size:bytes.length,name:'SYNTHETIC · Centrally delivered MSI',reviewReference:'Synthetic central review, fixture only'}),native=digest('synthetic native acceptance'),readinessDigest=digest('synthetic signed readiness'),permitDigest=digest('synthetic signed install permit');
 const counts={reserve:0,upload:0,complete:0,deliver:0,review:0,approve:0,status:0,unexpectedWrites:0,secondTargetWrites:0},attempts={reserve:0,upload:0,complete:0,deliver:0,review:0,approve:0};
 let phase='empty',offset=0,transferId='',readiness=null;
 const fixture={...base,device:{...base.device,name:'SYNTHETIC · Central MSI device'},session:{...base.session,capabilities:['read','windows_managed_msi_deliver','windows_managed_msi_install']},managedSelection:selection,managedNativeDigest:native,managedReadinessDigest:readinessDigest,managedPermitDigest:permitDigest,managedCounts:counts,managedAttempts:attempts,
  managedBytes(){return Buffer.from(bytes);},managedReview(){return {package:selection,nativeAcceptanceDigest:native};},managedSaved(){return view();},
  managedView(){counts.status++;if(phase==='delivery_pending')phase='imported';else if(phase==='readiness_pending'){phase='ready';readiness={selection,capturedAt:at,packageVerified:'yes',machineAbsent:'yes',installerBusy:'no',nativeAcceptance:'yes',packageReviewAccepted:'yes',maintenanceWindowEnd:at+600};}else if(phase==='approved')phase='complete';return view();},
  managedMutation(op,raw){let input;try{input=JSON.parse(raw);}catch{return null;}
   if(op==='reserve'&&phase==='empty'&&raw===JSON.stringify(fixture.managedReview())){phase='upload_incomplete';counts.reserve++;return view();}
   if(op==='upload'&&phase==='upload_incomplete'&&offset<bytes.length){const part=bytes.subarray(offset,Math.min(offset+32768,bytes.length)),expected={packageDigest:selection.sha256,index:offset/32768,digest:digest(part),data:part.toString('base64')};if(raw!==JSON.stringify(expected))return null;offset+=part.length;counts.upload++;return view();}
   if(op==='complete'&&phase==='upload_incomplete'&&offset===bytes.length&&raw==='{}'){phase='uploaded';counts.complete++;return view();}
   if(op==='deliver'&&phase==='uploaded'&&/^transfer_[a-f0-9]{32}$/.test(input?.transferId)&&raw===JSON.stringify({transferId:input.transferId,acknowledged:true})){transferId=input.transferId;phase='delivery_pending';counts.deliver++;return view();}
   if(op==='review'&&phase==='imported'&&raw===JSON.stringify({packageReviewAccepted:true,termsAccepted:true,maintenanceAcknowledged:true})){phase='readiness_pending';counts.review++;return view();}
   if(op==='approve'&&phase==='ready'&&raw===JSON.stringify({readinessDigest,acknowledged:true})){phase='approved';counts.approve++;return view();}
   return null;
  },
 };
 function view(){const value={version:'tracebolt.windows-managed-msi.v1',deviceId:fixture.device.id,serverNow:at,state:phase,package:phase==='empty'?null:selection,nativeAcceptanceDigest:phase==='empty'?'':native,transferId,readinessDigest:readiness?readinessDigest:'',expiresAt:transferId?(counts.review?at+60:at+600):0,readiness,result:phase==='complete'?{returnCodeKnown:true,jobId:'software_'+transferId.slice(9),envelopeDigest:permitDigest,attempted:true,outcome:'restart_required',returnCode:3010,registrationVerified:'unknown',completedAt:at}:null,uploadOffset:offset,uploadPendingDigest:'',canReview:phase==='imported'};if(!validManagedView(value,fixture.device.id))throw new Error('Invalid synthetic managed MSI view');return structuredClone(value);}
 return fixture;
}
export function windowsManagedMSIRoute({base,fixture,state,asset}){
 const fallback=windowsSoftwareJobsRoute({base,fixture,state,asset}),prefix='/api/devices/'+fixture.device.id,path=prefix+'/windows-managed-msi';
 return async route=>{
  const req=route.request(),url=new URL(req.url()),method=req.method(),raw=req.postData(),headers=req.headers();
  const block=()=>{state.blocked.push('managed-msi-shape-or-binding');return route.abort('blockedbyclient');};
  if(url.origin!==base){state.external.push('external');return route.abort('blockedbyclient');}
  if(url.pathname.includes('/windows-managed-msi')){
   if(url.pathname!==path&&!url.pathname.startsWith(path+'/')){if(method!=='GET')fixture.managedCounts.secondTargetWrites++;return block();}
   const reply=value=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(value)});
   if(url.pathname===path&&method==='GET'&&raw===null&&url.search==='')return reply(fixture.managedView());
   const op=url.pathname.slice(path.length+1),known=Object.hasOwn(fixture.managedAttempts,op);
   if(method!=='GET'){if(known)fixture.managedAttempts[op]++;else fixture.managedCounts.unexpectedWrites++;}
   if(!known||url.search||url.pathname!==path+'/'+op||method!=='POST'||typeof raw!=='string'||Buffer.byteLength(raw)>65536||headers['x-csrf-token']!==fixture.session.csrfToken||headers.origin!==base||headers['content-type']!=='application/json'||['content-encoding','range','content-range','content-disposition','forwarded','proxy-authorization'].some(k=>Object.hasOwn(headers,k))||Object.keys(headers).some(k=>k.startsWith('x-forwarded-')))return block();
   const value=fixture.managedMutation(op,raw);return value?reply(value):block();
  }
  if(method!=='GET'&&![prefix+'/windows-full-software/query',prefix+'/windows-full-processes/query'].includes(url.pathname)){
   if(url.pathname.startsWith('/api/devices/'+fixture.secondDevice.id+'/'))fixture.managedCounts.secondTargetWrites++;else fixture.managedCounts.unexpectedWrites++;
   return block();
  }
  return fallback(route);
 };
}
export async function exerciseWindowsManagedMSI({page,expect,base,fixture,locale,width,shot}){
 const de=locale==='de',panel=page.locator('.managed-msi-panel'),read=de?'Gespeicherten Status lesen':'Read saved status';
 const open=async()=>{await page.getByRole('tab',{name:de?'Inventar':'Inventory',exact:true}).click();await page.getByRole('tab',{name:'Software',exact:true}).click();await page.getByRole('button',{name:de?'MSI hochladen & verteilen':'Upload & deliver MSI',exact:true}).click();await expect(panel).toBeVisible();};
 // Semantic disclosure lookup, only after the exact selected package has arrived.
 const evidence=async()=>{await expect(panel.getByText(fixture.managedSelection.name,{exact:true})).toBeVisible();await expect(panel).toHaveAttribute('aria-busy','false');const label=de?'Hashes & Prüfnachweise':'Hashes & review evidence',summary=panel.getByText(label,{exact:true}),details=panel.locator('details').filter({has:page.getByText(label,{exact:true})});await expect(details).toHaveCount(1);await expect(details).not.toHaveAttribute('open');await summary.click();for(const text of [fixture.managedSelection.sha256,fixture.managedSelection.productCode,fixture.managedSelection.packageCode,fixture.managedSelection.termsReviewDigest,fixture.managedSelection.reviewReference,fixture.managedNativeDigest])await expect(details).toContainText(text);await summary.click();await expect(details).not.toHaveAttribute('open');await expect(panel).toContainText(fixture.device.id);};
 const capture=async kind=>{await expect(panel).toHaveAttribute('aria-busy','false');await panel.evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);await expect(panel.getByRole('status')).toBeInViewport({ratio:1});if(kind==='ready'){await expect(panel.getByRole('checkbox')).toBeInViewport({ratio:1});await expect(panel.getByRole('button',{name:de?'Eine Installation genehmigen':'Approve one installation',exact:true})).toBeInViewport({ratio:1});}await shot(page,`synthetic-windows-managed-msi-${kind}-${width}-${locale}`,windowsManagedMSIDisclosure);};
 stage='document';await page.goto(base+'/#/devices/'+fixture.device.id);await page.getByLabel(/Language|Sprache/).selectOption(locale);await expect(page.locator('html')).toHaveAttribute('lang',locale);await open();await expect(panel).toHaveAttribute('aria-busy','false');await expect(panel.getByRole('status')).toContainText(de?'Kein Paket hochgeladen':'No package uploaded');
 stage='upload';const upload=panel.getByRole('button',{name:de?'Exaktes Paket hochladen':'Upload exact package',exact:true});await expect(upload).toBeDisabled();await panel.getByLabel(de?'Exakte x64-Geräte-MSI':'Exact x64 machine MSI',{exact:true}).setInputFiles({name:'synthetic-inert.msi',mimeType:'application/octet-stream',buffer:fixture.managedBytes()});await panel.getByLabel(de?'Paketprüfung als JSON':'Package review JSON',{exact:true}).setInputFiles({name:'synthetic-review.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(fixture.managedReview()))});await expect(upload).toBeEnabled();await upload.click();await expect(panel.getByRole('status')).toContainText(de?'Paket hochgeladen; Verteilung nicht genehmigt':'Package uploaded; delivery not approved');expect(fixture.managedCounts.upload).toBe(3);expect(fixture.managedCounts.deliver).toBe(0);expect(fixture.managedCounts.review).toBe(0);expect(fixture.managedCounts.approve).toBe(0);await evidence();const deliver=panel.getByRole('button',{name:de?'An dieses Gerät verteilen':'Deliver to this device',exact:true});await expect(panel.getByRole('checkbox')).not.toBeChecked();await expect(deliver).toBeDisabled();await capture('uploaded');
 stage='deliver';await panel.getByRole('checkbox').check();await deliver.click();await expect(panel.getByRole('status')).toContainText(de?'Verteilung ausstehend':'Delivery pending');await expect(panel.getByRole('checkbox')).toHaveCount(0);expect(fixture.managedCounts.approve).toBe(0);
 stage='imported';await panel.getByRole('button',{name:read,exact:true}).click();await expect(panel.getByRole('status')).toContainText(de?'Exaktes Paket in geschützten Bestand übernommen':'Exact package imported in protected custody');await evidence();const checks=panel.getByRole('checkbox'),review=panel.getByRole('button',{name:de?'Installation prüfen':'Review installation',exact:true});await expect(checks).toHaveCount(3);for(let i=0;i<3;i++)await expect(checks.nth(i)).not.toBeChecked();await expect(review).toBeDisabled();await expect(panel).toContainText('LocalSystem');await expect(panel).toContainText(de?'Computerkonto':'machine-account');await capture('imported');
 stage='review';for(let i=0;i<2;i++){await checks.nth(i).check();await expect(review).toBeDisabled();}await checks.nth(2).check();await review.click();await expect(panel.getByRole('status')).toContainText(de?'Bereitschaft ausstehend':'Readiness pending');await expect(panel.getByRole('checkbox')).toHaveCount(0);expect(fixture.managedCounts.approve).toBe(0);
 stage='ready';await panel.getByRole('button',{name:read,exact:true}).click();await expect(panel.getByRole('status')).toContainText(de?'Bereit für exakte Genehmigung':'Ready for exact approval');await evidence();const approve=panel.getByRole('button',{name:de?'Eine Installation genehmigen':'Approve one installation',exact:true});await expect(panel.getByRole('checkbox')).not.toBeChecked();await expect(approve).toBeDisabled();await capture('ready');
 stage='approve';await panel.getByRole('checkbox').check();await approve.evaluate(button=>{button.click();button.click();});await expect(panel.getByRole('status')).toContainText(de?'Genehmigt; einmalige Abholung ausstehend':'Approved; one-time claim pending');await expect(panel.getByRole('checkbox')).toHaveCount(0);expect(fixture.managedCounts.approve).toBe(1);
 stage='outcome';await panel.getByRole('button',{name:read,exact:true}).click();await expect(panel).toContainText(de?'3010: Neustart erforderlich':'3010: Restart required');await expect(panel).toContainText((de?'Nativer Rückgabecode':'Native return code')+': 3010');await expect(panel).toContainText(de?'Exakte Geräteregistrierung: Unbekannt':'Exact machine registration: Unknown');
 stage='reload';await page.reload();await open();await evidence();await expect(panel).toContainText(de?'3010: Neustart erforderlich':'3010: Restart required');await expect(panel.getByRole('checkbox')).toHaveCount(0);await capture('outcome');
 expect(fixture.managedAttempts).toEqual({reserve:1,upload:3,complete:1,deliver:1,review:1,approve:1});expect(fixture.managedCounts.unexpectedWrites).toBe(0);expect(fixture.managedCounts.secondTargetWrites).toBe(0);expect(fixture.softwareCounts.approve).toBe(0);expect(fixture.updateCounts.approve).toBe(0);expect(fixture.counts.approve).toBe(0);
 const saved=fixture.managedSaved();expect(saved.package).toEqual(fixture.managedSelection);expect(saved.deviceId).toBe(fixture.device.id);expect(saved.result.returnCode).toBe(3010);expect(saved.result.registrationVerified).toBe('unknown');expect(saved.result.outcome).toBe('restart_required');
 stage='complete';return {reserve:1,upload:3,complete:1,deliver:1,review:1,approve:1,boundedChunks:true,separateStages:true,uncheckedDelivery:true,threeUncheckedReviewAcknowledgements:true,uncheckedInstall:true,initialDisabledApproval:true,exactPackageHashReadback:true,exactDeviceReadback:true,numericReturnCode:true,independentRegistrationTruth:true,reloadReadback:true,duplicateClickGuard:true,unexpectedWrites:0,secondTargetWrites:0,nativeAcceptance:false};
}
export function requireWindowsManagedMSIEvidence(rows,sourceSha){
 const fail=()=>{throw new Error('Synthetic managed MSI UI evidence missing or mismatched');};if(!Array.isArray(rows)||rows.length!==16||!/^[a-f0-9]{40}$/.test(sourceSha??''))fail();
 for(const kind of windowsManagedMSICaptureKinds)for(const locale of ['en','de'])for(const width of [1440,390]){const matches=rows.filter(row=>row?.file===`synthetic-windows-managed-msi-${kind}-${width}-${locale}.png`);if(matches.length!==1)fail();const row=matches[0];if(row.sourceSha!==sourceSha||row.test!==windowsManagedMSICaseName||row.locale!==locale||row.viewport?.width!==width||row.viewport?.height!==(width===390?844:1000)||row.publicSafe!==true||row.fullPage!==false||row.fixtureDisclosure!==windowsManagedMSIDisclosure)fail();}
 return {screens:16,nativeAcceptance:false};
}
export function requireWindowsManagedMSIDetails(d){
 if(!d||['reserve','complete','deliver','review','approve'].some(k=>d[k]!==1)||d.upload!==3||['boundedChunks','separateStages','uncheckedDelivery','threeUncheckedReviewAcknowledgements','uncheckedInstall','initialDisabledApproval','exactPackageHashReadback','exactDeviceReadback','numericReturnCode','independentRegistrationTruth','reloadReadback','duplicateClickGuard'].some(k=>d[k]!==true)||d.unexpectedWrites!==0||d.secondTargetWrites!==0||d.nativeAcceptance!==false)throw new Error('Incomplete synthetic managed MSI behavior evidence');
 return {unexpectedWrites:0,secondTargetWrites:0,nativeAcceptance:false};
}
