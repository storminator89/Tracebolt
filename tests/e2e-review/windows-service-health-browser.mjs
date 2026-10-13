/** Invented selected-service policy GETs only. No browser launch, policy POST,
 * native service read/action, local grant, AI request or deployment. */
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {build}=require('esbuild');
const built=await build({stdin:{contents:"export {windowsServiceHealthView,windowsServiceHealthIncident} from './windows-service-health-fixture'; export {validWindowsServiceHealthView} from './windows-service-health-types'; export {windowsServiceHealthCopy} from './windows-service-health-copy'; export {completeServicePickerCopy} from './windows-service-health-complete-copy'; export {windowsNow,windowsDeviceId} from './windows-inventory-fixture';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {windowsServiceHealthView,windowsServiceHealthIncident,validWindowsServiceHealthView,windowsServiceHealthCopy,completeServicePickerCopy,windowsNow,windowsDeviceId}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
export const windowsServiceHealthDisclosure='Invented default-off selected Windows service policy with a bounded reported-name chooser and original state observations in the compiled UI. Running is a reported SCM state, not application health. Policy phases are injected through read-only fixtures; no policy save, native Windows read, service start/restart, new grant, AI call, notification or deployment.';
export const windowsServiceHealthStageNames=Object.freeze(['services-disabled','services-pending','services-attention','services-unknown','services-recovered','services-policy-changed']);
export const windowsServiceHealthFixturePath=(pathname,prefix)=>pathname===prefix+'/windows-services';
function shifted(value,now){if(Array.isArray(value))return value.map(row=>shifted(row,now));if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([key,row])=>[key,shifted(row,now)]));return typeof value==='string'&&/^2026-\d\d-\d\dT/.test(value)?new Date(Date.parse(value)+Date.parse(now)-Date.parse(windowsNow)).toISOString():value;}
export function windowsServiceHealthBrowserFixture(serverNow,origin=serverNow,phase='services-disabled'){
 if(!windowsServiceHealthStageNames.includes(phase))throw new Error('Invalid invented service phase');
 const state=phase==='services-pending'?'pending':['services-attention','services-unknown'].includes(phase)?'attention':phase==='services-recovered'?'running':'disabled';
 const value=shifted(windowsServiceHealthView(state),origin);value.serverNow=serverNow;
 if(phase==='services-unknown'||state!=='disabled'&&Date.parse(serverNow)-Date.parse(value.checks[0].observation.collectedAt)>120000){value.status='unknown';for(const check of value.checks){check.status='unknown';check.observation=null;}}
 if(value.inventory&&Date.parse(serverNow)-Date.parse(value.inventory.collectedAt)>120000)value.inventory=null;
 if(phase==='services-policy-changed'){value.policy.revision=2;value.incidents=[shifted(windowsServiceHealthIncident('policy-changed'),origin)];value.incidents[0].resolvedAt=serverNow;}
 if(!validWindowsServiceHealthView(value,windowsDeviceId))throw new Error('Invalid invented service-health fixture');return value;
}
/** Preserve independent policy revisions and original evidence across sibling reads. */
export function createWindowsServiceHealthFixtureState(){
 let phase='services-disabled',origin=null,closedAt=null;
 return {
  setPhase(next,at){if(!windowsServiceHealthStageNames.includes(next))return false;if(!Number.isFinite(Date.parse(at)))throw new Error('Invalid invented service phase time');if(windowsServiceHealthStageNames.indexOf(next)<windowsServiceHealthStageNames.indexOf(phase))throw new Error('Invented service policy rollback');if(origin===null)origin=at;phase=next;if(next==='services-policy-changed')closedAt??=at;return true;},
  view(at){const value=windowsServiceHealthBrowserFixture(at,origin??at,phase);if(closedAt&&phase==='services-policy-changed')value.incidents[0].resolvedAt=closedAt;return value;},
 };
}
/** This walkthrough retains the v1 policy source, including its disabled state.
 * The new default complete view may probe status but cannot convert that ledger. */
export async function windowsServiceHealthCompleteLegacyRead({route,base,prefix}){
 const request=route.request(),url=new URL(request.url());
 if(prefix!=='/api/devices/'+windowsDeviceId||url.origin!==base||url.pathname!==prefix+'/windows-services/complete'||url.search||request.method()!=='GET'||request.postData()!==null)throw new Error('Unexpected synthetic complete service status request');
 return route.fulfill({status:409,contentType:'application/json',body:JSON.stringify({error:{code:'windows_service_source_conflict',message:'This policy uses another explicit source version.'}})});
}
export async function exerciseWindowsServiceHealth({page,expect,locale,width,shot,setPhase,mark}){
 const de=locale==='de',c=windowsServiceHealthCopy[locale];
 mark('services-source');await page.getByRole('combobox',{name:completeServicePickerCopy[locale].sourceLabel,exact:true}).selectOption('preview');
 const panel=page.locator('.windows-service-health'),refresh=panel.getByRole('button',{name:c.refresh,exact:true});
 const metadata=page.getByRole('button',{name:de?'Gerätedaten aktualisieren':'Refresh device metadata',exact:true});
 const read=async phase=>{mark(phase);setPhase(phase);await metadata.click();await expect(metadata).toBeEnabled();await refresh.click();await expect(refresh).toBeEnabled();};
 const capture=async label=>{expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);await panel.scrollIntoViewIfNeeded();await shot(page,`synthetic-windows-service-health-${label}-${width}-${locale}`,windowsServiceHealthDisclosure);};
 await read('services-disabled');await expect(panel.getByText(c.disabled,{exact:true})).toBeVisible();
 const settings=panel.getByText(c.settings,{exact:true});await expect(settings.locator('..')).not.toHaveAttribute('open','');await settings.click();
 const enabled=panel.getByRole('checkbox',{name:c.enable,exact:true}),save=panel.getByRole('button',{name:c.save,exact:true});
 await expect(enabled).not.toBeChecked();await expect(save).toBeDisabled();await enabled.check();await expect(save).toBeDisabled();
 await panel.getByRole('searchbox',{name:c.search,exact:true}).fill('background');const choice=panel.getByRole('checkbox',{name:/Fixture Background Service/});await choice.check();await expect(save).toBeEnabled();
 // A passive metadata/policy refresh preserves only the unsaved draft.
 await metadata.click();await expect(metadata).toBeEnabled();await expect(enabled).toBeChecked();await expect(panel.getByRole('button',{name:`${c.remove}: FixtureService`,exact:true})).toBeVisible();await expect(save).toBeEnabled();
 await panel.getByRole('button',{name:c.cancel,exact:true}).click();await expect(enabled).not.toBeChecked();await expect(save).toBeDisabled();await capture('disabled');
 await read('services-pending');await expect(enabled).toBeChecked();await expect(panel.locator('.windows-capacity-assessment').getByText(c.pending,{exact:true})).toBeVisible();await expect(save).toBeDisabled();await settings.click();await capture('pending');
 await read('services-attention');await expect(panel.locator('.windows-capacity-assessment').getByText(c.attention,{exact:true})).toBeVisible();await expect(panel.getByText('wservice_0000000000000001',{exact:true})).toBeVisible();const original=await panel.locator('.windows-service-checks time').first().getAttribute('datetime');await refresh.click();await expect(panel.locator('.windows-service-checks time').first()).toHaveAttribute('datetime',original);await capture('attention');
 await read('services-unknown');await expect(panel.locator('.windows-capacity-assessment').getByText(c.unknown,{exact:true})).toBeVisible();await expect(panel.getByText(c.open,{exact:true})).toBeVisible();await expect(panel.locator('.windows-service-checks time')).toHaveCount(0);await capture('unknown');
 await read('services-recovered');await expect(panel.getByText(c.running,{exact:true})).toBeVisible();await expect(panel.getByText(c.recovered,{exact:true})).toBeVisible();await capture('recovered');
 await read('services-policy-changed');await expect(panel.getByText(c.changed,{exact:true})).toBeVisible();await expect(panel.getByText(c.recovered,{exact:true})).toHaveCount(0);await expect(panel.getByText(c.recovery,{exact:true})).toHaveCount(0);await capture('policy-changed');
}
