import {settlePausedDetailRoute} from './paused-detail-route.mjs';
/** Inert selected-download fixtures. Importing never starts a browser, listener or native provider. */
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {closeSync,lstatSync,openSync,readFileSync,readSync} from 'node:fs';
import path from 'node:path';
import {createWindowsUpdateJobsFixture,windowsUpdateJobsOrigin,windowsUpdateJobsRoute} from './windows-update-jobs-browser.mjs';
const require=createRequire(new URL('../../web/package.json',import.meta.url));
const built=require('esbuild').buildSync({stdin:{contents:"export {validUpdateJobView} from './windows-update-jobs-types';",resolveDir:fileURLToPath(new URL('../../web/src/',import.meta.url)),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {validUpdateJobView}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
export const windowsUpdateDownloadCaseName='Synthetic selected Windows download review and cached-only result';
export const windowsUpdateDownloadDisclosure='Entirely intercepted invented fresh manual-download and installation-scheduling profile, metadata origins, estimates and WUA result in the compiled UI. Download-only operator permissions do not authorize installation or scheduling. One explicit unchecked download approval writes only to an in-memory fixture. No real network download, online scan, EULA acceptance, host grant, native WUA, installation, reboot or real manager write. Source/browser evidence is not native acceptance.';
export const windowsUpdateDownloadScenes=['coexistence','review','result'];
export const windowsUpdateDownloadViewports=[{width:1440,height:1000},{width:390,height:844}];
let stage='setup';
export const windowsUpdateDownloadFailureStage=()=>stage;
export function createWindowsUpdateDownloadFixture({coexistence=true}={}){
 if(typeof coexistence!=='boolean')throw Error('Invalid synthetic profile');
 const fixture=createWindowsUpdateJobsFixture(),at=Date.parse(fixture.now)/1000,digest='sha256:'+'9'.repeat(64),counts={request:0,preview:0,approve:0,status:0,postAttempts:0};
 fixture.session.capabilities=['read','windows_update_download'];fixture.device.name='SYNTHETIC · Selected Windows download';fixture.inventory.updates.rows[0].downloaded=false;
 let phase='ready',id=null,preview=null;
 const view=()=>{
  const value={version:'tracebolt.windows-selected-update-job.v1',deviceId:fixture.device.id,serverNow:at,available:false,reason:phase==='ready'||phase==='preview'?'ready':'job_pending_or_intervention',downloadEnabled:true,...(coexistence?{backgroundScheduling:true,schedulingAvailable:false}:{}),downloadAvailable:phase==='ready'||phase==='preview',reusableJobs:true,grantExpiresAt:at+1800,coordinated:true,backgroundExecutor:true,executorAvailability:'verified_recent',executorObservedAt:at,mutationCapturedAt:at,mutation:{active:true,blocked:false,phase:'idle',revision:'1',retained:0},job:phase==='ready'?null:{purpose:'download',id,selection:fixture.selection,state:phase,reason:phase==='requested'?'readiness_pending':'ready',preview:phase==='preview'?preview:null,result:phase==='complete'?{purpose:'download',jobId:id,envelopeDigest:'sha256:'+'a'.repeat(64),attempted:true,nativeReturned:true,cleanupSucceeded:true,aggregateResultKnown:true,aggregateHresultKnown:true,updateResultKnown:true,updateHresultKnown:true,aggregateOperationResult:2,downloadedAfter:'yes',outcome:'succeeded',operationResult:2,hresult:0,rebootRequired:'unknown',completedAt:at}:null,...(['approved','complete'].includes(phase)?{occurrence:'1'}:{}),...(phase==='complete'?{resultDigest:'sha256:'+'b'.repeat(64),retirement:{state:'available'}}:{})}};
  if(!validUpdateJobView(value,fixture.device.id,fixture.session.actorId))throw Error('Invalid synthetic download view');return structuredClone(value);
 };
 return {...fixture,downloadCoexistence:coexistence,downloadCounts:counts,downloadView:view,downloadID:()=>id,
  downloadRead(){counts.status++;if(phase==='requested')phase='preview';else if(phase==='approved')phase='complete';return view();},
  downloadMutation(op,raw){counts.postAttempts++;let input;try{input=JSON.parse(raw)}catch{return null}
   if(op==='request-download'&&phase==='ready'&&/^update_[a-f0-9]{32}$/.test(input?.requestId)&&raw===JSON.stringify({requestId:input.requestId,...fixture.selection})){
    id=input.requestId;preview={id,actorId:fixture.session.actorId,binding:{managerId:'manager_'+'1'.repeat(32),deviceId:fixture.device.id,incarnationDigest:'sha256:'+'2'.repeat(64),executorId:'executor_'+'4'.repeat(32),executorKeyId:'sha256:'+'5'.repeat(64),grantId:'grant_'+'6'.repeat(32),keyId:'sha256:'+'8'.repeat(64)},readiness:{purpose:'download',downloadMetadataKnown:true,downloadOrigins:'https://updates.example.invalid',downloadMinBytes:1048576,downloadMaxBytes:2097152,downloadSource:'default',selection:fixture.selection,capturedAt:at,software:'yes',installed:'no',hidden:'no',downloaded:'no',eulaAccepted:'yes',canRequestUserInput:'unknown',canRequireSource:'unknown',requiresNetwork:'unknown',bundledCount:0,installerBusy:'unknown',rebootRequiredBefore:'unknown',rebootBehavior:'unknown',offlineVerified:'yes'},createdAt:at,expiresAt:at+60,digest};phase='requested';counts.request++;return view();
   }
   if(op==='preview-download'&&phase==='preview'&&counts.preview===0&&raw===JSON.stringify({requestId:id})){counts.preview++;return view();}
   if(op==='approve-download'&&phase==='preview'&&counts.preview===1&&raw===JSON.stringify({previewId:id,previewDigest:digest,acknowledged:true})){phase='approved';counts.approve++;return view();}
   return null;
  }
 };
}
export function windowsUpdateDownloadRoute({base,fixture,state,asset}){
 if(base!==windowsUpdateJobsOrigin)throw Error('Invalid synthetic download origin');
 const fallback=windowsUpdateJobsRoute({base,fixture,state,asset}),path='/api/devices/'+fixture.device.id+'/windows-update-jobs';
 return async route=>{
  const request=route.request(),url=new URL(request.url()),method=request.method(),raw=request.postData(),headers=request.headers();
  const block=()=>{state.blocked.push('download-shape-or-binding');return route.abort('blockedbyclient');};
  if(url.origin!==base){state.external.push('external');return route.abort('blockedbyclient');}
  if(!url.pathname.startsWith(path))return fallback(route);
  let value;
  if(url.pathname===path&&method==='GET'&&raw===null&&(url.search===''||fixture.downloadID()&&url.search==='?jobId='+fixture.downloadID()))value=fixture.downloadRead();
  else {
   const op=url.pathname.slice(path.length+1);
   if(!['request-download','preview-download','approve-download'].includes(op)||url.pathname!==path+'/'+op||url.search!==''||method!=='POST'||typeof raw!=='string'||Buffer.byteLength(raw)>1024||headers.origin!==base||headers['x-csrf-token']!==fixture.session.csrfToken||headers['content-type']!=='application/json')return block();
   value=fixture.downloadMutation(op,raw);
  }
  return value?route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(value)}):block();
 };
}
export async function exerciseWindowsUpdateDownload({page,expect,base,fixture,locale,width,shot}){
 const de=locale==='de',panel=page.locator('.windows-update-jobs'),reviewLabel=de?'Download prüfen':'Review download',approveLabel=de?'Download einmal freigeben':'Approve download once',read=de?'Gespeicherten Status lesen':'Read saved status';
 const open=async()=>{await page.getByRole('tab',{name:de?'Inventar':'Inventory',exact:true}).click();await page.getByRole('tab',{name:'Updates',exact:true}).click();await expect(panel).toBeVisible();};
 const capture=async(kind,focus)=>{await focus.evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);await shot(page,`synthetic-windows-update-download-${kind}-${width}-${locale}`,windowsUpdateDownloadDisclosure);};
 stage='document';await page.goto(base+'/#/devices/'+fixture.device.id);await page.getByLabel(/Language|Sprache/).selectOption(locale);stage='detail-route-readiness';await settlePausedDetailRoute(page,expect,page.getByRole('tab',{name:locale==='de'?'Inventar':'Inventory',exact:true}));stage='document';await open();
 if(!fixture.downloadCoexistence)throw Error('Capture requires the fresh coexistence fixture');
 await expect(panel).toContainText(de?'Downloads bleiben manuell':'Downloads stay manual');await expect(panel).toContainText(de?'Genehmigte UTC-Zeitfenster':'Approved UTC windows');await expect(panel.getByRole('button',{name:de?'Bereitschaft prüfen':'Check readiness',exact:true})).toHaveCount(0);await expect(panel.getByText(de?'Planungsberechtigung widerrufen':'Revoke scheduling',{exact:true})).toHaveCount(0);await panel.getByRole('combobox').selectOption(`${fixture.selection.updateId}:${fixture.selection.revision}`);await expect(panel.getByRole('button',{name:reviewLabel,exact:true})).toBeVisible();await capture('coexistence',panel);
 stage='request';await panel.getByRole('combobox').selectOption(`${fixture.selection.updateId}:${fixture.selection.revision}`);await panel.getByRole('button',{name:reviewLabel,exact:true}).click();await expect(panel).toContainText(de?'Bereitschaft ausstehend':'Readiness pending');await expect(panel.getByRole('checkbox')).toHaveCount(0);
 stage='readiness';await panel.getByRole('button',{name:read,exact:true}).click();await panel.getByRole('button',{name:reviewLabel,exact:true}).click();
 stage='review';const group=panel.getByRole('group',{name:de?'Bereitschaft prüfen':'Check readiness',exact:true}),ack=group.getByRole('checkbox'),approve=group.getByRole('button',{name:approveLabel,exact:true});await expect(ack).not.toBeChecked();await expect(approve).toBeDisabled();await expect(group).toContainText(de?'keine feste Datenobergrenze':'no hard byte quota');await expect(group).toContainText(de?'separate frische Installationsprüfung':'separate fresh installation review');await expect(panel.getByRole('button',{name:de?'Dieses Update einmal freigeben':'Approve this update once',exact:true})).toHaveCount(0);await expect(panel.getByText(de?'Dieses Update planen':'Schedule this update',{exact:true})).toHaveCount(0);await expect(panel.locator('input[type="datetime-local"]')).toHaveCount(0);
 const identity=group.getByText(`${fixture.selection.updateId} · Revision ${fixture.selection.revision}`,{exact:true}),readiness=group.getByText(de?'Bereitschaftsdetails':'Readiness details',{exact:true}),origins=group.getByText(de?'Metadaten-Ursprünge':'Metadata origins',{exact:true});
 await expect(group.getByText(fixture.inventory.updates.rows[0].title,{exact:true})).toBeVisible();await expect(identity).toBeHidden();
 await expect(group.getByText(de?/Ursprünge begrenzen die Ziele nicht/:/origins do not restrict destinations/)).toBeVisible();await expect(group.getByText(de?/Downloads können Cache-Inhalte hinterlassen/:/downloads may leave cached content/)).toBeVisible();
 await readiness.click();await expect(identity).toBeVisible();await readiness.click();await origins.click();await expect(group.getByText('https://updates.example.invalid',{exact:true})).toBeVisible();await expect(group.getByText(de?/einschließlich konfigurierter Proxys, BITS/:/including configured proxies, BITS/)).toBeVisible();await origins.click();await expect(identity).toBeHidden();await expect(ack).not.toBeChecked();expect(fixture.downloadCounts).toMatchObject({request:1,preview:1,approve:0,postAttempts:2});
 await capture('review',panel.locator('.windows-update-download-review'));await expect(ack).toBeInViewport();await expect(approve).toBeInViewport();
 stage='approve';await ack.check();await approve.evaluate(el=>{el.click();el.click()});await expect(panel).toContainText(de?'Freigegeben; einmalige Abholung ausstehend':'Approved; awaiting one-time claim');expect(fixture.downloadCounts.approve).toBe(1);
 stage='result';await panel.getByRole('button',{name:read,exact:true}).click();const result=panel.getByText(de?'Download erfolgreich; Inhalt im Cache':'Download succeeded; content cached',{exact:true});await expect(result).toBeVisible();await panel.getByText(de?'WUA-Downloadnachweis':'WUA download evidence',{exact:true}).click();await expect(panel).toContainText('2 / 0x00000000');await capture('result',result);await expect(panel.getByRole('checkbox')).toHaveCount(0);
 stage='reload';await page.reload();stage='reload-detail-route-readiness';await settlePausedDetailRoute(page,expect,page.getByRole('tab',{name:locale==='de'?'Inventar':'Inventory',exact:true}));stage='reload';await open();await expect(panel).toContainText(de?'Download erfolgreich; Inhalt im Cache':'Download succeeded; content cached');await expect(panel.getByRole('checkbox')).toHaveCount(0);expect(fixture.downloadCounts).toMatchObject({request:1,preview:1,approve:1,postAttempts:3});
 stage='complete';return {manualDownloadWithInstallationScheduling:true,noDownloadSchedule:true,downloadOnly:true,exactUncheckedReview:true,duplicateClickSuppressed:true,reloadGETOnly:true,cachedNotInstalled:true,approvedWrites:1,noAutomaticInstall:true,nativeAcceptance:false};
}
export function requireWindowsUpdateDownloadDetails(details){
 if(!details||['manualDownloadWithInstallationScheduling','noDownloadSchedule','downloadOnly','exactUncheckedReview','duplicateClickSuppressed','reloadGETOnly','cachedNotInstalled','noAutomaticInstall'].some(k=>details[k]!==true)||details.approvedWrites!==1||details.nativeAcceptance!==false)throw Error('Incomplete synthetic download behavior');
}
export function requireWindowsUpdateDownloadEvidence(rows,sourceSha){
 if(!Array.isArray(rows)||rows.length!==windowsUpdateDownloadScenes.length*2*windowsUpdateDownloadViewports.length||!/^[a-f0-9]{40}$/.test(sourceSha??''))throw Error('Incomplete synthetic download captures');
 for(const scene of windowsUpdateDownloadScenes)for(const locale of ['en','de'])for(const viewport of windowsUpdateDownloadViewports){const matches=rows.filter(row=>row?.file===`synthetic-windows-update-download-${scene}-${viewport.width}-${locale}.png`);if(matches.length!==1)throw Error('Missing synthetic download capture');const row=matches[0];if(row.sourceSha!==sourceSha||row.test!==windowsUpdateDownloadCaseName||row.fixtureDisclosure!==windowsUpdateDownloadDisclosure||row.locale!==locale||row.viewport?.width!==viewport.width||row.viewport?.height!==viewport.height||row.publicSafe!==true||row.fullPage!==false)throw Error('Invalid synthetic download capture');}
 return {screens:windowsUpdateDownloadScenes.length*2*windowsUpdateDownloadViewports.length,nativeAcceptance:false};
}

export function validateWindowsUpdateDownloadReport(report,manifest,sourceSha){
 if(!report||report.sourceSha!==sourceSha||report.status!=='PASS'||report.browserAcceptance!==true||report.nativeAcceptance!==false||report.requestsToRealAPI!==0||report.runtimeErrorCount!==0||report.downloadScope!==windowsUpdateDownloadDisclosure||report.downloadStage!=='complete'||!Array.isArray(report.downloadVariants)||report.downloadVariants.length!==4||manifest?.sourceSha!==sourceSha||!Array.isArray(manifest.screenshots))throw Error('Incomplete download capture report');
 for(const locale of ['en','de'])for(const viewport of windowsUpdateDownloadViewports){const rows=report.downloadVariants.filter(row=>row?.locale===locale&&row.width===viewport.width);if(rows.length!==1)throw Error('Missing download variant');requireWindowsUpdateDownloadDetails(rows[0]);}
 return requireWindowsUpdateDownloadEvidence(manifest.screenshots.filter(row=>row?.test===windowsUpdateDownloadCaseName||row?.file?.startsWith('synthetic-windows-update-download-')),sourceSha);
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  if(process.argv.length!==4||process.argv[2]!=='--check-evidence'||!/^[a-f0-9]{40}$/.test(process.argv[3]))throw Error('Invalid evidence check');
  const root=fileURLToPath(new URL('../../artifacts/review/',import.meta.url)),json=name=>{const file=path.join(root,name),stat=lstatSync(file);if(!stat.isFile()||stat.size>131072)throw Error('Invalid capture metadata');return JSON.parse(readFileSync(file,'utf8'));};
  validateWindowsUpdateDownloadReport(json('windows-service-actions-results.json'),json('windows-service-actions-manifest.json'),process.argv[3]);
  for(const scene of windowsUpdateDownloadScenes)for(const locale of ['en','de'])for(const viewport of windowsUpdateDownloadViewports){
   const file=path.join(root,`synthetic-windows-update-download-${scene}-${viewport.width}-${locale}.png`),stat=lstatSync(file);if(!stat.isFile()||stat.size<24||stat.size>8*1024*1024)throw Error('Invalid capture file');
   const fd=openSync(file,'r'),head=Buffer.alloc(24);try{if(readSync(fd,head,0,24,0)!==24||head.subarray(0,8).toString('hex')!=='89504e470d0a1a0a'||head.subarray(12,16).toString()!=='IHDR'||head.readUInt32BE(16)!==viewport.width||head.readUInt32BE(20)!==viewport.height)throw Error('Invalid capture dimensions');}finally{closeSync(fd);}
  }
  console.log('PASS: twelve exact-source manual-download coexistence/review/result captures and bounded behavior evidence; synthetic only.');
 }catch{console.error('FAIL: download capture evidence missing or mismatched; raw state withheld.');process.exitCode=1;}
}
