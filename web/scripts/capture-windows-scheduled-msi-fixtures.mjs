/** Inert scheduled-MSI source fixture. --check starts no browser, listener or service.
 * Hosted capture accepts an already-authorized browser; never a local fallback. */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {mkdir,writeFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createWindowsReusableMSIFixture} from './capture-windows-reusable-msi-fixtures.mjs';
import {compileWindowsFleetMSIAssets,createWindowsFleetMSIRoute,windowsFleetMSICases,windowsFleetMSIOrigin} from './capture-windows-fleet-msi-fixtures.mjs';
const require=createRequire(new URL('../package.json',import.meta.url));
const digest=s=>`sha256:${s.repeat(64)}`;
export const scheduledMSIScenes=['approval-unchecked','scheduled','permit-issued','canceled','blocked'];
export const scheduledMSIDisclosure='Synthetic source fixture of one-device scheduled MSI and compiled production UI. Every mutation is blocked. No native installer, delivery, cleanup, endpoint grant, service activation or retry. Source checks capture no browser pixels; native acceptance remains separately approved and pending.';
async function contracts(){const {build}=require('esbuild');const result=await build({stdin:{contents:"export {validManagedView} from './windows-managed-msi-types'; export {managedScheduleRequest} from './windows-managed-msi-schedule-types';",resolveDir:fileURLToPath(new URL('../src/',import.meta.url)),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});return import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].text).toString('base64')}`)}
export async function createWindowsScheduledMSIFixture(scene,now){
 assert(scheduledMSIScenes.includes(scene));const fixture=await createWindowsReusableMSIFixture('retirement-review',now),{views,seconds,session}=fixture,v=views[0],validation=await contracts();session.capabilities.push('windows_managed_msi_schedule');
 Object.assign(v,{state:'ready',result:null,canRetire:false,schedulingAvailable:true,leafExpiresAt:seconds+1800,expiresAt:seconds+60,readinessDigest:digest('e'),readiness:{selection:v.package,capturedAt:seconds,packageVerified:'yes',machineAbsent:'yes',installerBusy:'no',nativeAcceptance:'yes',packageReviewAccepted:'yes',maintenanceWindowEnd:seconds+600}});delete v.resultDigest;
 if(scene!=='approval-unchecked'){
  // Already-saved synthetic schedule. No POST, clock jump or actual installation.
  const approvedAt=seconds-180,startAt=seconds-60,endAt=seconds+240,q=validation.managedScheduleRequest(v,{startAt,endAt});
  v.schedule={version:'tracebolt.windows-managed-msi-schedule.v1',digest:digest('f'),requestDigest:'sha256:'+createHash('sha256').update('Tracebolt managed MSI schedule request v1\0'+JSON.stringify(q)).digest('hex'),actorId:session.actorId,approvedAt,startAt,endAt,readinessDigest:v.readinessDigest,state:scene==='permit-issued'?'permit_issued':scene,readinessIssuedAt:scene==='permit-issued'?seconds-50:0,permitIssuedAt:scene==='permit-issued'?seconds-40:0,outcomeAt:['canceled','blocked'].includes(scene)?seconds-20:0,canCancel:scene==='scheduled'};
  v.state=scene==='permit-issued'?'approved':'expired';v.expiresAt=seconds-120;
 }
 assert(validation.validManagedView(v,v.deviceId),`Scheduled scene ${scene}`);return fixture;
}
export async function checkWindowsScheduledMSIFixtures(){
 const validation=await contracts();for(const scene of scheduledMSIScenes){const fixture=await createWindowsScheduledMSIFixture(scene,'2026-10-12T10:00:00.000Z'),v=fixture.views[0];assert.equal(validation.validManagedView({...v,schedulingAvailable:'yes'},v.deviceId),false);if(v.schedule)assert.equal(validation.validManagedView({...v,schedule:{...v.schedule,requestDigest:'unconfirmed'}},v.deviceId),false);const state={blocked:[],external:[],writes:[]},route=createWindowsFleetMSIRoute({fixture,compiled:{assets:new Map()},state});for(const op of ['schedule','cancel-schedule']){let blocked=false;await route({request:()=>({url:()=>`${windowsFleetMSIOrigin}/api/devices/${v.deviceId}/windows-managed-msi/${op}`,method:()=>'POST',postData:()=>'{}'}),abort:()=>{blocked=true},fulfill:()=>{}});assert(blocked)}assert.equal(state.writes.length,2)}
 const compiled=await compileWindowsFleetMSIAssets();return {mode:'source-only',scenes:scheduledMSIScenes,cases:windowsFleetMSICases,sourceDigest:compiled.sourceDigest,compiled:true,browserExecuted:false,screenshotsCaptured:0,nativeAcceptance:false,disclosure:scheduledMSIDisclosure};
}
export async function captureWindowsScheduledMSIFixtures({browser,expect,output}){
 assert(browser&&typeof browser.newContext==='function'&&typeof expect==='function');const compiled=await compileWindowsFleetMSIAssets(),captures=[];await mkdir(output,{recursive:true});
 for(const scene of scheduledMSIScenes)for(const testCase of windowsFleetMSICases){
  const {locale,width,height}=testCase,de=locale==='de',fixture=await createWindowsScheduledMSIFixture(scene),state={blocked:[],external:[],writes:[],pageErrors:[]},context=await browser.newContext({viewport:{width,height},locale:de?'de-DE':'en-US',deviceScaleFactor:1,reducedMotion:'reduce',serviceWorkers:'block'});
  try{await context.route('**/*',createWindowsFleetMSIRoute({fixture,compiled,state}));await context.addInitScript(value=>localStorage.setItem('tracebolt.locale',value),locale);const page=await context.newPage();page.on('pageerror',error=>state.pageErrors.push(error.message));await page.goto(`${windowsFleetMSIOrigin}/#/devices`);const title=de?'Windows-MSI-Arbeitsliste':'Windows MSI worklist',worklist=page.getByRole('region',{name:title,exact:true});await worklist.getByRole('button',{name:title,exact:true}).click();const choices=worklist.getByRole('group',{name:de?'Geräte auswählen':'Select devices'});await choices.getByRole('checkbox').first().check();await worklist.getByRole('button',{name:de?'Geräteauswahl festhalten':'Freeze device selection'}).click();await worklist.getByRole('button',{name:`${de?'Gerät öffnen':'Open device'}: ${fixture.devices[0].name}`,exact:true}).click();const focus=worklist.locator('.managed-msi-panel:not(.managed-msi-artifact)'),schedule=focus.locator('.managed-msi-schedule');
   if(scene==='approval-unchecked'){await schedule.locator(':scope > summary').click();await expect(schedule.getByRole('checkbox')).not.toBeChecked();await expect(schedule.getByRole('button',{name:de?'Geplante Installation einmal genehmigen':'Approve scheduled installation once'})).toBeDisabled();await expect(schedule.locator('details')).not.toHaveAttribute('open','')}
   else{await expect(schedule.getByRole('button',{name:de?'Diese Planung abbrechen':'Cancel this schedule'})).toHaveCount(scene==='scheduled'?1:0);await expect(focus.getByRole('button',{name:de?'Eine Installation genehmigen':'Approve one installation'})).toHaveCount(0)}
   await page.evaluate(()=>document.fonts.ready);await schedule.evaluate(element=>element.scrollIntoView({block:'start',behavior:'instant'}));expect(await focus.evaluate(element=>element.scrollWidth<=element.clientWidth+1)).toBe(true);expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);const file=`synthetic-windows-scheduled-msi-${scene}-${width}-${locale}.png`;await page.screenshot({path:path.join(output,file),animations:'disabled',fullPage:false});assert.equal(state.writes.length,0);assert.equal(state.external.length,0);assert.equal(state.blocked.length,0);assert.equal(state.pageErrors.length,0);captures.push({file,scene,...testCase,sourceDigest:compiled.sourceDigest,synthetic:true,disclosure:scheduledMSIDisclosure});
  }finally{await context.close()}
 }
 const result={captures,sourceDigest:compiled.sourceDigest,browserExecuted:true,nativeAcceptance:false,disclosure:scheduledMSIDisclosure};await writeFile(path.join(output,'windows-scheduled-msi-manifest.json'),JSON.stringify(result,null,2)+'\n');return result;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href){assert.deepEqual(process.argv.slice(2),['--check'],'Only source-only --check is supported directly');process.stdout.write(JSON.stringify(await checkWindowsScheduledMSIFixtures(),null,2)+'\n')}
