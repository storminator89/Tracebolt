/** Invented capacity-policy GETs in the existing hosted case only.
 * No browser launch, policy POST, host read, grant or deployment. */
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {build}=require('esbuild');
const built=await build({stdin:{contents:"export {windowsCapacityView,windowsCapacityIncident} from './windows-capacity-fixture'; export {validWindowsCapacityView} from './windows-capacity-types'; export {windowsNow,windowsDeviceId} from './windows-inventory-fixture';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {windowsCapacityView,windowsCapacityIncident,validWindowsCapacityView,windowsNow,windowsDeviceId}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
export const windowsCapacityDisclosure='Invented quota-aware system-volume policy, observations and incidents in the compiled UI with real loopback fixture login. Enabled policy is injected by read-only fixtures; no policy save, native Windows read, installed-service acceptance, notification, AI call or deployment.';
export const windowsCapacityStageNames=Object.freeze(['capacity-disabled','capacity-enabled','capacity-pressure','capacity-unknown','capacity-closed']);
function shifted(value,now){if(Array.isArray(value))return value.map(row=>shifted(row,now));if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([key,row])=>[key,shifted(row,now)]));return typeof value==='string'&&/^2026-\d\d-\d\dT/.test(value)?new Date(Date.parse(value)+Date.parse(now)-Date.parse(windowsNow)).toISOString():value;}
export function windowsCapacityBrowserFixture(serverNow,origin=serverNow,phase='capacity-disabled'){
 const state=phase==='capacity-enabled'?'pending':['capacity-pressure','capacity-unknown'].includes(phase)?'pressure':'disabled';
 const value=shifted(windowsCapacityView(state),origin);value.serverNow=serverNow;
 if(phase==='capacity-unknown'||state!=='disabled'&&Date.parse(serverNow)-Date.parse(value.observation.collectedAt)>120000){value.status='unknown';value.observation=null;}
 if(phase==='capacity-closed'){value.policy.revision=2;value.incidents=[shifted(windowsCapacityIncident('policy-changed'),origin)];value.incidents[0].resolvedAt=serverNow;}
 if(!validWindowsCapacityView(value,windowsDeviceId))throw new Error('Invalid invented capacity fixture');return value;
}
export async function exerciseWindowsCapacity({page,expect,locale,width,shot,setPhase,mark}){
 const de=locale==='de',panel=page.locator('.windows-capacity[data-metric="disk"]'),refresh=panel.getByRole('button',{name:de?'Kapazitätsrichtlinie aktualisieren':'Refresh capacity policy',exact:true});
 const metadata=page.getByRole('button',{name:de?'Gerätedaten aktualisieren':'Refresh device metadata',exact:true});
 const read=async phase=>{mark(phase);setPhase(phase);await metadata.click();await expect(metadata).toBeEnabled();await refresh.click();await expect(refresh).toBeEnabled();};
 const capture=async label=>{expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);await panel.scrollIntoViewIfNeeded();await shot(page,`synthetic-windows-capacity-${label}-${width}-${locale}`,windowsCapacityDisclosure);};
 await read('capacity-disabled');await expect(panel.getByText(de?'Richtlinie deaktiviert':'Policy disabled',{exact:true})).toBeVisible();
 const settings=panel.getByText(de?'Kapazitätsrichtlinie & Grenzen':'Capacity policy settings & limits',{exact:true});await expect(settings.locator('..')).not.toHaveAttribute('open','');await settings.click();
 const enabled=panel.getByRole('checkbox',{name:de?'Kapazitätsrichtlinie des Systemvolumes aktivieren':'Enable system-volume capacity policy',exact:true}),save=panel.getByRole('button',{name:de?'Kapazitätsrichtlinie speichern':'Save capacity policy',exact:true});
 await expect(enabled).not.toBeChecked();await expect(save).toBeDisabled();await enabled.check();await expect(save).toBeEnabled();
 // Exercise deliberate editing and discard only. All policy writes stay blocked.
 await panel.getByRole('button',{name:de?'Änderungen verwerfen':'Discard changes',exact:true}).click();await expect(enabled).not.toBeChecked();await expect(save).toBeDisabled();await capture('disabled');
 await read('capacity-enabled');await expect(enabled).toBeChecked();await expect(panel.getByText(de?'Kapazitätsschwelle erreicht · Bestätigung ausstehend':'Capacity threshold reached · confirmation pending',{exact:true})).toBeVisible();await expect(save).toBeDisabled();
 await settings.click();await capture('enabled');
 await read('capacity-pressure');await expect(panel.getByText(de?'Kapazitätsengpass · Vorfall offen':'Capacity pressure · incident open',{exact:true})).toBeVisible();await expect(panel.getByText('wcapacity_0000000000000001',{exact:true})).toBeVisible();
 const original=await panel.locator('.windows-capacity-times').nth(1).locator('time').first().getAttribute('datetime');await refresh.click();await expect(panel.locator('.windows-capacity-times').nth(1).locator('time').first()).toHaveAttribute('datetime',original);await capture('pressure');
 await read('capacity-unknown');await expect(panel.getByText(de?'Unbekannt':'Unknown',{exact:true})).toBeVisible();await expect(panel.getByText(de?'Offen':'Open',{exact:true})).toBeVisible();await expect(panel.getByText('wcapacity_0000000000000001',{exact:true})).toBeVisible();await capture('unknown');
 await read('capacity-closed');await expect(panel.getByText(de?'Wegen Richtlinienänderung geschlossen':'Closed because policy changed',{exact:true})).toBeVisible();await expect(panel.getByText(de?'Innerhalb der Richtlinie erholt':'Recovered within policy',{exact:true})).toHaveCount(0);await capture('closed');
}
