/** Five bounded catalogue/review scenes. Direct --check compiles source only.
 * Hosted callers supply an already-authorized browser; this module launches none.
 * Invented GET DTOs only, no manager, native operations, bytes or accepted writes. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { compileWindowsFleetMSIAssets, createWindowsFleetMSIRoute, createWindowsSavedMSIFixture, windowsFleetMSICases, windowsFleetMSIOrigin } from './capture-windows-fleet-msi-fixtures.mjs';

const require=createRequire(new URL('../package.json',import.meta.url)),clone=value=>structuredClone(value);
// One domain-owned source contract supplies producer and Python gate expectations.
const sceneBytes=await readFile(new URL('./windows-msi-catalogue-scenes.json',import.meta.url));
assert(sceneBytes.length>0&&sceneBytes.length<=8192);
const sceneManifest=JSON.parse(sceneBytes.toString('utf8'));
assert.equal(sceneBytes.toString('utf8'),JSON.stringify(sceneManifest,null,2)+'\n');
assert.deepEqual(Object.keys(sceneManifest).sort(),['scenes','schemaVersion','viewports']);
assert.equal(sceneManifest.schemaVersion,1);
assert(Array.isArray(sceneManifest.scenes)&&sceneManifest.scenes.length>0&&sceneManifest.scenes.length<=8);
assert(sceneManifest.scenes.every(scene=>typeof scene==='string'&&/^[a-z][a-z0-9-]{0,63}$/.test(scene)));
assert.equal(new Set(sceneManifest.scenes).size,sceneManifest.scenes.length);
assert.deepEqual(sceneManifest.viewports,windowsFleetMSICases);
export const msiCatalogueSceneManifestSHA256=createHash('sha256').update(sceneBytes).digest('hex');
export const msiCatalogueScenes=Object.freeze([...sceneManifest.scenes]);
const msiCatalogueViewports=Object.freeze(sceneManifest.viewports.map(testCase=>Object.freeze({...testCase})));
export const msiCatalogueDisclosure='Synthetic compiled-UI manager multi-package MSI catalogue fixture. All DTOs are invented and every request is intercepted. Only exact GETs are admitted; all writes and external requests are blocked. No real login, MSI bytes, reservation, upload, delivery, installation, retirement, host grant, native acceptance or release.';
export const msiCatalogueCaptureMatrix=Object.freeze(msiCatalogueScenes.flatMap(scene=>msiCatalogueViewports.map(testCase=>Object.freeze({scene,...testCase,file:`synthetic-windows-msi-catalogue-${scene}-${testCase.width}-${testCase.locale}.png`}))));
let validation;
async function contracts(){validation??=(async()=>{const {build}=require('esbuild');const result=await build({stdin:{contents:"export {validManagedCatalogue} from './windows-managed-msi-catalogue-types';export {validManagedArtifact,validManagedView,validReusableManagedReview} from './windows-managed-msi-types';export {validWorklistsView} from './windows-managed-msi-worklist-types';",resolveDir:fileURLToPath(new URL('../src/',import.meta.url)),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});return import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].text).toString('base64')}`)})();return validation}
function entry(template,occurrence,name,size=1048576){
 const value={...clone(template),package:{...clone(template.package),name,size},retiredCount:String(occurrence),recent:[],uploadOffset:size,state:'uploaded',canRetire:false,retirementBlocked:'awaiting_device_retirement'};
 const identity={package:value.package,nativeAcceptanceDigest:value.nativeAcceptanceDigest,publisherStatus:value.publisherStatus,publisherEvidenceDigest:value.publisherEvidenceDigest};value.artifactId=`sha256:${createHash('sha256').update('Tracebolt reusable MSI artifact v3\0').update(JSON.stringify(identity)).digest('hex')}`;return value;
}
function worklist(template,artifact,id){
 const value={...clone(template),id:`worklist_${id.repeat(32)}`,name:`SYNTHETIC · ${artifact.package.name}`,artifactId:artifact.artifactId,artifactRetiredCount:artifact.retiredCount,package:clone(artifact.package)};
 for(const row of value.rows)if(row.view){Object.assign(row.view,{artifactId:artifact.artifactId,artifactRetiredCount:artifact.retiredCount,package:clone(artifact.package),uploadOffset:artifact.package.size});if(row.view.readiness)row.view.readiness.selection=clone(artifact.package)}return value;
}
export async function createWindowsMSICatalogueFixture(scene,now){
 assert(msiCatalogueScenes.includes(scene));const fixture=await createWindowsSavedMSIFixture(scene==='retained-outcome-after-reuse'?'retired-outcomes':'compact-summary',now),{seconds}=fixture;
 let entries,worklists;
 if(scene.startsWith('guided-review-')){entries=[entry(fixture.artifact,1,'Retained package')];worklists=[]}
 else if(scene==='catalogue-storage-limit'){entries=['A','B','C','D'].map((label,i)=>entry(fixture.artifact,i+1,`Package ${label}`,32*1048576));worklists=[]}
 else if(scene==='selected-package-worklist'){
  entries=[entry(fixture.artifact,1,'Package A'),entry(fixture.artifact,2,'Package B')];worklists=entries.map((artifact,i)=>worklist(fixture.savedWorklist,artifact,String(i+1)));
  for(const [i,w] of worklists.entries())for(const [index,row] of w.rows.entries())if(row.available&&index!==i)w.rows[index]={deviceId:row.deviceId,available:false,state:'unavailable',...(row.view?.result?{historicalResult:clone(row.view.result)}:{})};
 }else{
  const retired=entry(fixture.artifact,1,'Archived package A'),archived=worklist(fixture.savedWorklist,retired,'1');archived.archivedAt=seconds-1;archived.rows=archived.rows.map(row=>({deviceId:row.deviceId,available:false,state:'unavailable',...(row.view?.result?{historicalResult:clone(row.view.result)}:row.historicalOutcome?{historicalOutcome:row.historicalOutcome}:{})}));
  entries=[entry(fixture.artifact,4,'Replacement package D')];worklists=[archived];
 }
 fixture.catalogue={version:'tracebolt.windows-managed-msi-catalogue.v1',enabled:true,serverNow:seconds,revision:'7',maxEntries:4,maxRetainedPayloadBytes:134217728,reservedBytes:entries.reduce((sum,e)=>sum+e.package.size,0),entries};fixture.catalogueWorklists={version:'tracebolt.windows-managed-msi-worklists.v2',enabled:true,serverNow:seconds,worklists};fixture.selectedOccurrence=entries[0].retiredCount;delete fixture.reviewedPreview;
 const v=await contracts();assert(v.validManagedCatalogue(fixture.catalogue));assert(v.validWorklistsView(fixture.catalogueWorklists));for(const e of entries){assert(v.validManagedArtifact(e,true));assert(!v.validManagedArtifact(e),'Catalogue occurrence must not be interpreted as singleton history')}for(const w of worklists)for(const row of w.rows)if(row.view)assert(v.validManagedView(row.view,row.deviceId));return fixture;
}
export function createWindowsMSICatalogueRoute({fixture,compiled,state}){
 const base=createWindowsFleetMSIRoute({fixture,compiled,state});return async route=>{
  const request=route.request(),url=new URL(request.url()),method=request.method(),raw=request.postData();
  if(url.origin!==windowsFleetMSIOrigin||method!=='GET'||raw!==null)return base(route);
  const reply=value=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(clone(value))});
  if(url.pathname==='/api/windows-managed-msi/catalogue'&&!url.search)return reply(fixture.catalogue);
  if(url.pathname==='/api/windows-managed-msi/worklists'&&!url.search)return reply(fixture.catalogueWorklists);
  if(url.pathname==='/api/windows-managed-msi/artifact'||/^\/api\/devices\/agent_[a-f0-9]{32}\/windows-managed-msi$/.test(url.pathname)){
   const occurrence=url.searchParams.get('artifactRetiredCount'),artifact=fixture.catalogue.entries.find(e=>e.retiredCount===occurrence);
   if(!artifact||url.search!==`?artifactRetiredCount=${occurrence}`){state.blocked.push('unselected-occurrence');return route.abort('blockedbyclient')}
   if(url.pathname==='/api/windows-managed-msi/artifact')return reply(artifact);
   const device=url.pathname.split('/')[3],view=fixture.catalogueWorklists.worklists.find(w=>w.artifactRetiredCount===occurrence)?.rows.find(row=>row.deviceId===device)?.view;
   if(view)return reply(view);state.blocked.push('unavailable-device');return route.abort('blockedbyclient');
  }
  if(url.pathname.startsWith('/api/windows-managed-msi/')){state.blocked.push('unexpected-managed-route');return route.abort('blockedbyclient')}
  return base(route);
 };
}
export async function checkWindowsMSICatalogueFixtures(){
 const v=await contracts();assert.equal(msiCatalogueCaptureMatrix.length,msiCatalogueScenes.length*msiCatalogueViewports.length);assert.equal(new Set(msiCatalogueCaptureMatrix.map(c=>c.file)).size,msiCatalogueCaptureMatrix.length);
 for(const scene of msiCatalogueScenes){const fixture=await createWindowsMSICatalogueFixture(scene,'2026-10-12T10:00:00.000Z'),state={blocked:[],external:[],writes:[]},route=createWindowsMSICatalogueRoute({fixture,compiled:{assets:new Map()},state});
  const call=async(suffix,method='GET',body=null)=>{let response;await route({request:()=>({url:()=>windowsFleetMSIOrigin+suffix,method:()=>method,postData:()=>body}),fulfill:value=>{response=value},abort:reason=>{response={aborted:reason}}});return response};
  assert(v.validManagedCatalogue(JSON.parse((await call('/api/windows-managed-msi/catalogue')).body)));assert(v.validWorklistsView(JSON.parse((await call('/api/windows-managed-msi/worklists')).body)));assert.equal((await call(`/api/windows-managed-msi/artifact?artifactRetiredCount=${fixture.selectedOccurrence}`)).status,200);assert.equal((await call('/api/windows-managed-msi/artifact?artifactRetiredCount=999')).aborted,'blockedbyclient');assert.equal((await call('/api/windows-managed-msi/artifact')).aborted,'blockedbyclient');assert.equal((await call('/api/windows-managed-msi/catalogue/reserve','POST','{}')).aborted,'blockedbyclient');assert.equal(state.writes.length,1);
  if(scene.startsWith('guided-review-'))assert(v.validReusableManagedReview({package:fixture.artifact.package,nativeAcceptanceDigest:fixture.artifact.nativeAcceptanceDigest,publisherStatus:fixture.artifact.publisherStatus,publisherEvidenceDigest:fixture.artifact.publisherEvidenceDigest}));
  if(scene==='catalogue-storage-limit')assert.equal(fixture.catalogue.reservedBytes,134217728);
  if(scene==='selected-package-worklist'){assert.equal(fixture.catalogueWorklists.worklists[0].rows.filter(r=>r.available).length,1);assert(v.validManagedView(JSON.parse((await call(`/api/devices/${fixture.devices[0].id}/windows-managed-msi?artifactRetiredCount=1`)).body),fixture.devices[0].id));assert.equal((await call(`/api/devices/${fixture.devices[1].id}/windows-managed-msi?artifactRetiredCount=1`)).aborted,'blockedbyclient')}
  if(scene==='retained-outcome-after-reuse'){assert(!fixture.catalogue.entries.some(e=>e.retiredCount==='1'));const rows=fixture.catalogueWorklists.worklists[0].rows;assert.equal(rows[0].historicalResult.returnCode,1603);assert.equal(rows[1].historicalResult.returnCode,3010);assert.equal(rows[1].historicalResult.registrationVerified,'yes')}
 }
 const compiled=await compileWindowsFleetMSIAssets();assert(compiled.sourceInputs.some(input=>input.file==='web/src/windows-managed-msi-catalogue.tsx'));assert(compiled.sourceInputs.some(input=>input.file==='web/src/windows-managed-msi-review.tsx'));return {mode:'source-only',scenes:msiCatalogueScenes,cases:msiCatalogueCaptureMatrix,sourceDigest:compiled.sourceDigest,compiled:true,dtoAndRouteChecks:'passed',browserExecuted:false,screenshotsCaptured:0,nativeAcceptance:false,disclosure:msiCatalogueDisclosure};
}
export async function captureWindowsMSICatalogueFixtures({browser,expect,output}){
 assert(browser&&typeof browser.newContext==='function'&&typeof expect==='function');const compiled=await compileWindowsFleetMSIAssets(),captures=[];await mkdir(output,{recursive:true});
 for(const testCase of msiCatalogueCaptureMatrix){const {scene,locale,width,height,file}=testCase,de=locale==='de',fixture=await createWindowsMSICatalogueFixture(scene),state={blocked:[],external:[],writes:[],pageErrors:[]},context=await browser.newContext({viewport:{width,height},locale:de?'de-DE':'en-US',deviceScaleFactor:1,reducedMotion:'reduce',serviceWorkers:'block'});
  try{await context.route('**/*',createWindowsMSICatalogueRoute({fixture,compiled,state}));await context.addInitScript(value=>localStorage.setItem('tracebolt.locale',value),locale);const page=await context.newPage();page.on('pageerror',error=>state.pageErrors.push(error.message));await page.goto(`${windowsFleetMSIOrigin}/#/devices`);const title=de?'Windows-MSI-Arbeitsliste':'Windows MSI worklist',panel=page.getByRole('region',{name:title,exact:true});await panel.getByRole('button',{name:title,exact:true}).click();const catalogue=panel.getByRole('region',{name:de?'Gespeicherte MSI-Pakete':'Retained MSI packages',exact:true});await expect(catalogue).toBeVisible();let focus=catalogue;
   if(scene.startsWith('guided-review-')){
    const form=catalogue.locator('.managed-msi-review-form'),bytes=Buffer.alloc(1024),ready=scene==='guided-review-ready';focus=form;
    await form.getByLabel(de?'MSI-Datei':'MSI file',{exact:true}).setInputFiles({name:'SYNTHETIC-inert.msi',mimeType:'application/octet-stream',buffer:bytes});
    await expect(form.getByLabel(de?'Paketname':'Package name',{exact:true})).toBeEnabled();
    await form.getByLabel(de?'Paketname':'Package name',{exact:true}).fill('SYNTHETIC · Example app');await form.getByLabel(de?'MSI-Version':'MSI version',{exact:true}).fill('1.2.3');
    const advanced=form.locator('.managed-msi-review-advanced');await expect(advanced).not.toHaveAttribute('open','');await expect(form.getByText(de?'Erweitert: Prüf-JSON importieren':'Advanced: import review JSON',{exact:true})).toBeVisible();
    if(ready){await advanced.locator(':scope>summary').click();const p=fixture.artifact.package;
     for(const [label,value] of [['ProductCode',p.productCode],['PackageCode',p.packageCode],[de?'Prüfverweis':'Review reference',p.reviewReference],[de?'SHA-256 der Bedingungsprüfung':'Terms-review SHA-256',p.termsReviewDigest],[de?'SHA-256 der nativen Abnahme':'Native-acceptance SHA-256',fixture.artifact.nativeAcceptanceDigest],[de?'SHA-256 des Herausgebernachweises':'Publisher-evidence SHA-256',fixture.artifact.publisherEvidenceDigest]])await form.getByLabel(label,{exact:true}).fill(value);
     // Nested select options are label text; match each select's exact accessible name.
     await form.getByRole('combobox',{name:de?'Geprüfter Pakettyp':'Reviewed package type',exact:true}).selectOption('amd64');await form.getByRole('combobox',{name:de?'Herausgeberprüfung':'Publisher review',exact:true}).selectOption('unverified');await advanced.locator(':scope>summary').click();
     await expect(catalogue.getByRole('button',{name:de?'Geprüftes Paket reservieren':'Reserve reviewed package',exact:true})).toBeEnabled();
    }else{await expect(form.locator('.managed-msi-review-guidance')).toContainText(de?'8 Identitäts-/Nachweisfelder':'8 identity/evidence fields');await expect(catalogue.getByRole('button',{name:de?'Geprüftes Paket reservieren':'Reserve reviewed package',exact:true})).toBeDisabled()}
    await expect(form.getByRole('checkbox')).toHaveCount(0);
   }
   else if(scene==='catalogue-storage-limit'){await expect(catalogue.getByRole('progressbar')).toHaveAttribute('value','134217728');await expect(catalogue.locator('.managed-msi-catalogue-list>li')).toHaveCount(4);await expect(catalogue.getByRole('button',{name:de?'Geprüftes Paket reservieren':'Reserve reviewed package',exact:true})).toBeDisabled();await expect(panel.getByRole('region',{name:de?'Gespeicherte MSI-Arbeitslisten':'Saved MSI worklists',exact:true})).toHaveCount(0)}
   else{const selected=fixture.catalogue.entries[0];await catalogue.getByRole('button',{name:`${de?'Paket auswählen':'Select package'}: ${selected.package.name} ${selected.package.version} · ${selected.retiredCount}`,exact:true}).click();const saved=panel.getByRole('region',{name:de?'Gespeicherte MSI-Arbeitslisten':'Saved MSI worklists',exact:true});await expect(saved).toBeVisible();focus=saved;
    if(scene==='selected-package-worklist'){await expect(saved.getByText('SYNTHETIC · Package A',{exact:true})).toBeVisible();await expect(saved.getByText('SYNTHETIC · Package B',{exact:true})).toHaveCount(0);await expect(saved.getByRole('button',{name:`${de?'Gerät öffnen':'Open device'}: ${fixture.devices[0].name}`,exact:true})).toBeEnabled();await expect(saved.getByRole('button',{name:`${de?'Gerät öffnen':'Open device'}: ${fixture.devices[1].name}`,exact:true})).toBeDisabled();await expect(saved.getByRole('checkbox')).toHaveCount(0)}
    else{const history=saved.locator('.managed-msi-archived-packages');await history.locator(':scope>summary').click();await history.locator(':scope>details>summary').click();await expect(history.getByText(de?'Installation fehlgeschlagen; Versuch verbraucht':'Installation failed; attempt consumed',{exact:true})).toBeVisible();await expect(history.getByText(de?'3010: Neustart erforderlich':'3010: Restart required',{exact:true})).toBeVisible();await expect(history.getByText(de?'Rückgabecode: 3010 · Exakte Registrierung: Geprüft':'Return code: 3010 · Exact registration: Verified',{exact:true})).toBeVisible();await expect(history.getByRole('button')).toHaveCount(0);await expect(history.getByRole('checkbox')).toHaveCount(0);for(const checkbox of await saved.getByRole('checkbox').all())await expect(checkbox).not.toBeChecked();focus=history}
   }
   await page.evaluate(()=>document.fonts.ready);await focus.evaluate(element=>element.scrollIntoView({block:'start',behavior:'instant'}));expect(await panel.evaluate(element=>element.scrollWidth<=element.clientWidth+1)).toBe(true);expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);await page.screenshot({path:path.join(output,file),animations:'disabled',fullPage:false});for(const kind of ['blocked','external','writes','pageErrors'])assert.equal(state[kind].length,0);captures.push({...testCase,sourceDigest:compiled.sourceDigest,synthetic:true,disclosure:msiCatalogueDisclosure});
  }finally{await context.close()}
 }
 const result={captures,sourceDigest:compiled.sourceDigest,sourceInputs:compiled.sourceInputs,browserExecuted:true,nativeAcceptance:false,disclosure:msiCatalogueDisclosure};await writeFile(path.join(output,'windows-msi-catalogue-manifest.json'),JSON.stringify(result,null,2)+'\n');return result;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href){assert.deepEqual(process.argv.slice(2),['--check'],'Only source-only --check is supported directly');process.stdout.write(JSON.stringify(await checkWindowsMSICatalogueFixtures(),null,2)+'\n')}
