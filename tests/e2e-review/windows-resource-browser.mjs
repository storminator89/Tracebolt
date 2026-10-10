/** Invented CPU/RAM policy GETs in the existing hosted case only.
 * No browser launch, policy POST, native read, grant or deployment. */
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {build}=require('esbuild');
const built=await build({stdin:{contents:"export {windowsResourceView} from './windows-resource-fixture'; export {validWindowsResourceView} from './windows-capacity-types'; export {windowsNow,windowsDeviceId} from './windows-inventory-fixture';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {windowsResourceView,validWindowsResourceView,windowsNow,windowsDeviceId}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
export const windowsResourceDisclosure='Invented independent CPU/RAM policies, observations and incidents in the compiled UI with real loopback fixture login. CPU uses the existing GetSystemTimes observed processor group, not an all-group aggregate. RAM is physical RAM not immediately available: 100 × (ullTotalPhys − ullAvailPhys) / ullTotalPhys from GlobalMemoryStatusEx. Enabled policies are injected by read-only fixtures; no policy save, native Windows read, local grant, installed-service acceptance, notification, AI call or deployment.';
export const windowsResourceStageNames=Object.freeze(['cpu','memory'].flatMap(metric=>['disabled','pending','pressure','unknown','policy-changed'].map(state=>`${metric}-${state}`)));
function shifted(value,now){if(Array.isArray(value))return value.map(row=>shifted(row,now));if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([key,row])=>[key,shifted(row,now)]));return typeof value==='string'&&/^2026-\d\d-\d\dT/.test(value)?new Date(Date.parse(value)+Date.parse(now)-Date.parse(windowsNow)).toISOString():value;}
/** Exact allowlist; policy suffixes, aliases, trailing slashes and encoded paths never match. */
export function windowsResourceFixtureMetric(pathname,prefix){
 if(pathname===prefix+'/windows-resource/cpu')return 'cpu';
 if(pathname===prefix+'/windows-resource/memory')return 'memory';
 return null;
}
export function windowsResourceBrowserFixture(metric,serverNow,origin=serverNow,phase=`${metric}-disabled`){
 if(!['cpu','memory'].includes(metric))throw new Error('Invalid invented resource metric');
 const state=phase===`${metric}-pending`?'pending':[`${metric}-pressure`,`${metric}-unknown`].includes(phase)?'pressure':'disabled';
 const value=shifted(windowsResourceView(metric,state),origin);value.serverNow=serverNow;
 if(phase===`${metric}-unknown`||state!=='disabled'&&Date.parse(serverNow)-Date.parse(value.observation.collectedAt)>120000){value.status='unknown';value.observation=null;}
 if(phase===`${metric}-policy-changed`){
  value.policy.revision=2;value.incidents=shifted(windowsResourceView(metric,'pressure').incidents,origin);
  value.incidents[0].resolvedAt=serverNow;value.incidents[0].closedReason='policy-changed';value.incidents[0].recoveryObservation=null;
 }
 if(!validWindowsResourceView(value,windowsDeviceId,metric))throw new Error('Invalid invented resource fixture');return value;
}
const labels={
 cpu:{en:{heading:'CPU percentage policy',refresh:'Refresh CPU policy',settings:'CPU policy settings & limits',enable:'Enable CPU percentage policy',save:'Save CPU policy',pending:'CPU threshold reached · confirmation pending',pressure:'CPU pressure · incident open'},de:{heading:'CPU-Prozentrichtlinie',refresh:'CPU-Richtlinie aktualisieren',settings:'CPU-Richtlinie & Grenzen',enable:'CPU-Prozentrichtlinie aktivieren',save:'CPU-Richtlinie speichern',pending:'CPU-Schwelle erreicht · Bestätigung ausstehend',pressure:'CPU-Engpass · Vorfall offen'}},
 memory:{en:{heading:'Physical RAM percentage policy',refresh:'Refresh RAM policy',settings:'RAM policy settings & limits',enable:'Enable physical RAM percentage policy',save:'Save RAM policy',pending:'RAM threshold reached · confirmation pending',pressure:'RAM pressure · incident open'},de:{heading:'Prozentrichtlinie für physischen RAM',refresh:'RAM-Richtlinie aktualisieren',settings:'RAM-Richtlinie & Grenzen',enable:'Prozentrichtlinie für physischen RAM aktivieren',save:'RAM-Richtlinie speichern',pending:'RAM-Schwelle erreicht · Bestätigung ausstehend',pressure:'RAM-Engpass · Vorfall offen'}},
};
export async function exerciseWindowsResources({page,expect,locale,width,shot,setPhase,mark}){
 const de=locale==='de',metadata=page.getByRole('button',{name:de?'Gerätedaten aktualisieren':'Refresh device metadata',exact:true});
 const panelFor=metric=>page.locator(`.windows-capacity[data-metric="${metric}"]`),disabled=de?'Richtlinie deaktiviert':'Policy disabled';
 for(const metric of ['cpu','memory']){
  const copy=labels[metric][locale],panel=panelFor(metric),refresh=panel.getByRole('button',{name:copy.refresh,exact:true});
  const read=async state=>{const phase=`${metric}-${state}`;mark(phase);setPhase(phase);await metadata.click();await expect(metadata).toBeEnabled();await refresh.click();await expect(refresh).toBeEnabled();};
  const capture=async state=>{expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);await panel.scrollIntoViewIfNeeded();await shot(page,`synthetic-windows-${metric}-policy-${state}-${width}-${locale}`,windowsResourceDisclosure);};
  // An injected CPU phase cannot enable RAM or disk, and vice versa.
  const assertIndependent=async()=>{for(const sibling of ['disk','cpu','memory'].filter(other=>other!==metric)){
   const siblingPanel=panelFor(sibling),name=sibling==='disk'?(de?'Kapazitätsrichtlinie aktualisieren':'Refresh capacity policy'):labels[sibling][locale].refresh;
   const siblingRefresh=siblingPanel.getByRole('button',{name,exact:true});await siblingRefresh.click();await expect(siblingRefresh).toBeEnabled();await expect(siblingPanel.getByText(disabled,{exact:true})).toBeVisible();
  }};
  await read('disabled');await expect(panel.getByRole('heading',{name:copy.heading,exact:true})).toBeVisible();await expect(panel.getByText(disabled,{exact:true})).toBeVisible();await assertIndependent();
  const settings=panel.getByText(copy.settings,{exact:true});await expect(settings.locator('..')).not.toHaveAttribute('open','');await settings.click();
  const enabled=panel.getByRole('checkbox',{name:copy.enable,exact:true}),save=panel.getByRole('button',{name:copy.save,exact:true});
  await expect(enabled).not.toBeChecked();await expect(save).toBeDisabled();await enabled.check();await expect(save).toBeEnabled();
  // Deliberate editing is discarded; no policy write is ever submitted.
  await panel.getByRole('button',{name:de?'Änderungen verwerfen':'Discard changes',exact:true}).click();await expect(enabled).not.toBeChecked();await expect(save).toBeDisabled();await capture('disabled');
  await read('pending');await expect(enabled).toBeChecked();await expect(panel.getByText(copy.pending,{exact:true})).toBeVisible();await expect(save).toBeDisabled();await assertIndependent();await settings.click();await capture('pending');
  await read('pressure');await expect(panel.getByText(copy.pressure,{exact:true})).toBeVisible();await assertIndependent();
  const original=await panel.locator('.windows-capacity-times').nth(1).locator('time').first().getAttribute('datetime');await refresh.click();await expect(panel.locator('.windows-capacity-times').nth(1).locator('time').first()).toHaveAttribute('datetime',original);await capture('pressure');
  await read('unknown');await expect(panel.getByText(de?'Unbekannt':'Unknown',{exact:true})).toBeVisible();await expect(panel.getByText(de?'Offen':'Open',{exact:true})).toBeVisible();await capture('unknown');
  await read('policy-changed');await expect(panel.getByText(de?'Wegen Richtlinienänderung geschlossen':'Closed because policy changed',{exact:true})).toBeVisible();await expect(panel.getByText(de?'Innerhalb der Richtlinie erholt':'Recovered within policy',{exact:true})).toHaveCount(0);await capture('policy-changed');
 }
}
