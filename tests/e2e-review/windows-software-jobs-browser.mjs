/** Inert prepared-MSI fixture. Importing starts no browser, listener or host action. */
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {createWindowsUpdateJobsFixture,windowsUpdateJobsRoute,windowsUpdateJobsOrigin} from './windows-update-jobs-browser.mjs';
import {windowsFullSoftwareFixtureQuery,windowsFullSoftwareAbsentPage} from './windows-full-software-browser.mjs';
const require=createRequire(new URL('../../web/package.json',import.meta.url));
const built=require('esbuild').buildSync({stdin:{contents:"export {validSoftwareJobView} from './windows-software-jobs-types';",resolveDir:fileURLToPath(new URL('../../web/src/',import.meta.url)),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {validSoftwareJobView}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
export const windowsSoftwareJobsOrigin=windowsUpdateJobsOrigin;
export const windowsSoftwareJobsCaseName='Synthetic prepared MSI exact review, unchecked approval and saved outcome in the compiled Software UI';
export const windowsSoftwareJobsDisclosure='Entirely intercepted invented TLS-session, prepared MSI metadata, readiness and saved outcome in an in-memory fixture. One explicit simulated approval only; zero unexpected install or second-target writes. Hashes identify synthetic reviewed bytes, not benign or offline behavior. No actual TLS authority, host grant, key, elevated executor, Windows Installer call, real manager write, package staging, installation, network access by an MSI or reboot. Browser evidence is not native package acceptance.';
const stages=new Set(['setup','document','request','readiness','review','approve','result','reload','complete']);let stage='setup';
export const windowsSoftwareJobsFailureStage=()=>stages.has(stage)?stage:'setup';
export function createWindowsSoftwareJobsFixture(){
 const base=createWindowsUpdateJobsFixture(),at=Date.parse(base.now)/1000;
 const selection=Object.freeze({sha256:'sha256:'+'a'.repeat(64),size:1048576,productCode:'{11111111-2222-3333-4444-555555555555}',packageCode:'{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}',version:'1.2.3',architecture:'amd64',name:'SYNTHETIC · Prepared MSI',termsReviewDigest:'sha256:'+'b'.repeat(64),reviewReference:'Synthetic reviewed terms, fixture only'}),digest='sha256:'+'c'.repeat(64);
 const counts={request:0,preview:0,approve:0,status:0,unexpectedInstallWrites:0,secondTargetWrites:0},attempts={request:0,preview:0,approve:0};let phase='ready',id=null,preview=null;
 const fixture={...base,device:{...base.device,name:'SYNTHETIC · Prepared MSI device'},session:{...base.session,capabilities:['read','windows_software_install']},softwareSelection:selection,softwareDigest:digest,softwareCounts:counts,softwareAttempts:attempts,
  softwareView(){counts.status++;if(phase==='requested')phase='preview';else if(phase==='approved')phase='complete';return view();},
  softwareMutation(op,raw){let input;try{input=JSON.parse(raw);}catch{return null;}
   if(op==='request'&&phase==='ready'&&/^software_[a-f0-9]{32}$/.test(input?.requestId)&&raw===JSON.stringify({requestId:input.requestId,package:selection})){
    id=input.requestId;preview={id,actorId:base.session.actorId,binding:{managerId:'manager_'+'1'.repeat(32),deviceId:base.device.id,incarnationDigest:'sha256:'+'2'.repeat(64),executorId:'executor_'+'4'.repeat(32),executorKeyId:'sha256:'+'5'.repeat(64),grantId:'grant_'+'6'.repeat(32),keyId:'sha256:'+'8'.repeat(64)},readiness:{selection,capturedAt:at,packageVerified:'yes',machineAbsent:'yes',installerBusy:'no',nativeAcceptance:'yes',packageReviewAccepted:'yes',maintenanceWindowEnd:at+600},createdAt:at,expiresAt:at+60,digest};phase='requested';counts.request++;return view();
   }
   if(op==='preview'&&phase==='preview'&&counts.preview===0&&raw===JSON.stringify({requestId:id})){counts.preview++;return view();}
   if(op==='approve'&&phase==='preview'&&counts.preview===1&&raw===JSON.stringify({previewId:id,previewDigest:digest,acknowledged:true})){phase='approved';counts.approve++;return view();}
   return null;
  },softwareSavedID(){return id;},softwareSaved(){return view();},
 };
 function view(){const value={version:'tracebolt.windows-prepared-msi-job.v1',deviceId:base.device.id,serverNow:at,package:selection,available:phase==='ready',reason:phase==='ready'?'ready':counts.approve?'capacity_exhausted':'job_pending_or_intervention',job:phase==='ready'?null:{id,selection,state:phase,reason:phase==='requested'?'readiness_pending':'ready',preview:phase==='preview'?preview:null,result:phase==='complete'?{jobId:id,envelopeDigest:'sha256:'+'d'.repeat(64),attempted:true,outcome:'succeeded',returnCodeKnown:true,returnCode:0,registrationVerified:'yes',completedAt:at}:null}};if(!validSoftwareJobView(value,base.device.id,base.session.actorId))throw new Error('Invalid synthetic software view');return structuredClone(value);}
 return fixture;
}
export function windowsSoftwareJobsRoute({base,fixture,state,asset}){
 const fallback=windowsUpdateJobsRoute({base,fixture,state,asset}),prefix='/api/devices/'+fixture.device.id,path=prefix+'/windows-software-jobs';
 return async route=>{
  const req=route.request(),url=new URL(req.url()),method=req.method(),raw=req.postData(),headers=req.headers();
  const block=()=>{state.blocked.push('software-job-shape-or-binding');return route.abort('blockedbyclient');};
  if(url.origin!==base){state.external.push('external');return route.abort('blockedbyclient');}
  const reply=value=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(value)});
  if(url.pathname.includes('/windows-software-jobs')){
   if(url.pathname!==path&&!url.pathname.startsWith(path+'/')){if(method!=='GET')fixture.softwareCounts.secondTargetWrites++;return block();}
   if(url.pathname===path&&method==='GET'&&raw===null&&(url.search===''||fixture.softwareSavedID()&&url.search==='?jobId='+fixture.softwareSavedID()))return reply(fixture.softwareView());
   const op=url.pathname.slice(path.length+1);
   if(method!=='GET'){if(['request','preview','approve'].includes(op))fixture.softwareAttempts[op]++;else fixture.softwareCounts.unexpectedInstallWrites++;}
   if(url.search||url.pathname!==path+'/'+op||!['request','preview','approve'].includes(op)||method!=='POST'||typeof raw!=='string'||Buffer.byteLength(raw)>2048||headers['x-csrf-token']!==fixture.session.csrfToken||headers.origin!==base||headers['content-type']!=='application/json')return block();
   const value=fixture.softwareMutation(op,raw);return value?reply(value):block();
  }
  if(url.pathname===prefix+'/windows-full-software/query'){
   const query=windowsFullSoftwareFixtureQuery({pathname:url.pathname,search:url.search,method,headers,raw},prefix);
   if(!query||headers['x-csrf-token']!==fixture.session.csrfToken||headers.origin!==base||headers['content-type']!=='application/json')return block();
   return reply(windowsFullSoftwareAbsentPage(fixture.device.id,query,fixture.now));
  }
  if(method!=='GET'&&url.pathname!==prefix+'/windows-full-processes/query'){
   if(url.pathname.startsWith('/api/devices/'+fixture.secondDevice.id+'/'))fixture.softwareCounts.secondTargetWrites++;else fixture.softwareCounts.unexpectedInstallWrites++;
   return block();
  }
  return fallback(route);
 };
}
export async function exerciseWindowsSoftwareJobs({page,expect,base,fixture,locale,width,shot}){
 const de=locale==='de',panel=page.locator('.windows-software-job-review'),title=de?'Vorbereitete MSI installieren':'Install prepared MSI',read=de?'Gespeicherten Status lesen':'Read saved status';
 const open=async()=>{await page.getByRole('tab',{name:de?'Inventar':'Inventory',exact:true}).click();await page.getByRole('tab',{name:'Software',exact:true}).click();await page.getByRole('button',{name:title,exact:true}).click();await expect(panel).toBeVisible();};
 const evidence=async()=>{const details=panel.locator('details').first();await expect(details).not.toHaveAttribute('open');await details.locator('summary').click();for(const text of [fixture.softwareSelection.sha256,fixture.softwareSelection.productCode,fixture.softwareSelection.packageCode,fixture.softwareSelection.termsReviewDigest,fixture.softwareSelection.reviewReference])await expect(details).toContainText(text);await details.locator('summary').click();await expect(details).not.toHaveAttribute('open');await expect(panel).toContainText(fixture.device.id);await expect(panel).toContainText(fixture.softwareSelection.name);await expect(panel).toContainText(fixture.softwareSelection.version);};
 const capture=async kind=>{await panel.evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);await expect(panel.getByText(fixture.softwareSelection.name,{exact:true})).toBeInViewport({ratio:1});await expect(panel.getByText(new RegExp(fixture.device.id))).toBeInViewport({ratio:1});await shot(page,`synthetic-windows-software-jobs-${kind}-${width}-${locale}`,windowsSoftwareJobsDisclosure);};
 stage='document';await page.goto(base+'/#/devices/'+fixture.device.id);await page.getByLabel(/Language|Sprache/).selectOption(locale);await expect(page.locator('html')).toHaveAttribute('lang',locale);await open();await evidence();
 stage='request';await panel.getByRole('button',{name:de?'Bereitschaft prüfen':'Check readiness',exact:true}).click();await expect(panel.getByRole('status')).toContainText(de?'Bereitschaft ausstehend':'Readiness pending');await expect(panel.getByRole('checkbox')).toHaveCount(0);expect(fixture.softwareCounts.approve).toBe(0);
 stage='readiness';await panel.getByRole('button',{name:read,exact:true}).click();await panel.getByRole('button',{name:de?'Exaktes Paket prüfen':'Review exact package',exact:true}).click();
 stage='review';const checks=panel.getByRole('checkbox'),approve=panel.getByRole('button',{name:de?'Dieses Paket einmal freigeben':'Approve this package once',exact:true});await expect(checks).toHaveCount(2);for(let i=0;i<2;i++)await expect(checks.nth(i)).not.toBeChecked();await expect(approve).toBeDisabled();await evidence();await capture('review');for(let i=0;i<2;i++)await expect(panel.locator('label').nth(i)).toBeInViewport({ratio:1});await expect(approve).toBeInViewport({ratio:1});
 stage='approve';await checks.nth(0).check();await expect(approve).toBeDisabled();await checks.nth(1).check();await approve.evaluate(button=>{button.click();button.click();});await expect(panel.getByRole('status')).toContainText(de?'Freigegeben; einmalige Abholung ausstehend':'Approved; awaiting one-time claim');await expect(panel.getByRole('checkbox')).toHaveCount(0);expect(fixture.softwareCounts.approve).toBe(1);
 stage='result';await panel.getByRole('button',{name:read,exact:true}).click();await expect(panel).toContainText(de?'Installiert; exakte Geräteregistrierung geprüft':'Installed; exact machine registration verified');await expect(panel).toContainText((de?'Nativer Rückgabecode':'Native return code')+': 0');await expect(panel).toContainText(de?'Exakte Geräteregistrierung: Geprüft':'Exact machine registration: Verified');
 stage='reload';await page.reload();await open();await evidence();await expect(panel).toContainText(de?'Installiert; exakte Geräteregistrierung geprüft':'Installed; exact machine registration verified');await expect(panel.getByRole('checkbox')).toHaveCount(0);await capture('result');
 expect(fixture.softwareAttempts).toEqual({request:1,preview:1,approve:1});expect(fixture.softwareCounts.unexpectedInstallWrites).toBe(0);expect(fixture.softwareCounts.secondTargetWrites).toBe(0);expect(fixture.updateCounts.approve).toBe(0);expect(fixture.counts.approve).toBe(0);
 const saved=fixture.softwareSaved();expect(saved.deviceId).toBe(fixture.device.id);expect(saved.package).toEqual(fixture.softwareSelection);expect(saved.job.result).toEqual({jobId:fixture.softwareSavedID(),envelopeDigest:'sha256:'+'d'.repeat(64),attempted:true,outcome:'succeeded',returnCodeKnown:true,returnCode:0,registrationVerified:'yes',completedAt:Date.parse(fixture.now)/1000});
 stage='complete';return {request:1,preview:1,approve:1,twoUncheckedAcknowledgements:true,initialDisabledApproval:true,exactPackageHashReadback:true,exactDeviceReadback:true,savedOutcomeReadback:true,numericReturnCode:true,independentRegistrationTruth:true,reloadReadback:true,duplicateClickGuard:true,unexpectedInstallWrites:0,secondTargetWrites:0,nativeAcceptance:false};
}
export function requireWindowsSoftwareJobsEvidence(rows,sourceSha){
 const fail=()=>{throw new Error('Synthetic prepared MSI UI evidence missing or mismatched');};if(!Array.isArray(rows)||rows.length!==8||!/^[a-f0-9]{40}$/.test(sourceSha??''))fail();
 for(const kind of ['review','result'])for(const locale of ['en','de'])for(const width of [1440,390]){const matches=rows.filter(row=>row?.file===`synthetic-windows-software-jobs-${kind}-${width}-${locale}.png`);if(matches.length!==1)fail();const row=matches[0];if(row.sourceSha!==sourceSha||row.test!==windowsSoftwareJobsCaseName||row.locale!==locale||row.viewport?.width!==width||row.viewport?.height!==(width===390?844:1000)||row.publicSafe!==true||row.fullPage!==false||row.fixtureDisclosure!==windowsSoftwareJobsDisclosure)fail();}
 return {screens:8,nativeAcceptance:false};
}
export function requireWindowsSoftwareJobsDetails(d){
 if(!d||['request','preview','approve'].some(k=>d[k]!==1)||['twoUncheckedAcknowledgements','initialDisabledApproval','exactPackageHashReadback','exactDeviceReadback','savedOutcomeReadback','numericReturnCode','independentRegistrationTruth','reloadReadback','duplicateClickGuard'].some(k=>d[k]!==true)||d.unexpectedInstallWrites!==0||d.secondTargetWrites!==0||d.nativeAcceptance!==false)throw new Error('Incomplete synthetic prepared MSI behavior evidence');
 return {unexpectedInstallWrites:0,secondTargetWrites:0,nativeAcceptance:false};
}
