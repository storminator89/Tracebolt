/** Invented hardware source labels in the compiled production Device UI.
 * No native read, local grant, asset identity assertion or power action. */
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {build}=require('esbuild');
const bundle=await build({stdin:{contents:"export {windowsHardwareContextView} from './windows-hardware-context-fixture'; export {validWindowsInventoryView} from './windows-inventory-types';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {windowsHardwareContextView,validWindowsInventoryView}=await import('data:text/javascript;base64,'+Buffer.from(bundle.outputFiles[0].text).toString('base64'));
export const windowsHardwareContextDisclosure='Invented hardware, source-labeled BIOS/chassis serials and power metadata in the private production Device UI. UI-only fixture evidence; no native Windows read, local consent, hardware or power action, verified unique identity or AI export.';
function unavailable(source,quality='unavailable'){
 source.quality=quality;source.reason=quality==='denied'?'windows_hardware_context_access_denied':'windows_hardware_context_budget_exhausted';
 if(source.source==='GetSystemPowerStatus')Object.assign(source,{acLineStatus:'unknown',batteryPresence:'unknown',charging:'unknown',batteryPercent:null,estimatedSeconds:null});
 else for(const value of Object.values(source))if(value&&typeof value==='object')Object.assign(value,{value:null,quality});
}
export function windowsHardwareContextBrowserFixture({serverNow,capturedAt,phase='observed',retainedCapturedAt}){
 const view=windowsHardwareContextView(),s=view.hardwareContext;
 view.serverNow=view.receivedAt=serverNow;view.snapshot.collectedAt=s.collectedAt=capturedAt;
 const age=Date.parse(serverNow)-Date.parse(capturedAt);view.status=age<0||age>120000?'stale':'fresh';
 if(phase==='retained'){
  const previous=structuredClone(s);previous.collectedAt=retainedCapturedAt;previous.generationId=`sample_${'b'.repeat(32)}`;
  view.sequence=2;view.snapshot.generationId=s.generationId=`sample_${'c'.repeat(32)}`;
  for(const key of ['system','firmware','chassis','power'])unavailable(s[key]);
  if(Date.parse(serverNow)-Date.parse(retainedCapturedAt)<86400000)view.retainedContext={hardwareContext:previous};
  else if(!Number.isFinite(Date.parse(retainedCapturedAt)))throw new Error('Invalid synthetic retained hardware capture');
 }
 if(phase==='absent-battery')Object.assign(s.power,{batteryPresence:'absent',charging:'unknown',batteryPercent:null});
 if(phase==='unknown-battery')Object.assign(s.power,{quality:'partial',reason:'windows_hardware_context_partial_result',batteryPresence:'unknown',charging:'unknown',batteryPercent:null});
 if(phase==='denied-bios')unavailable(s.firmware,'denied');
 if(phase==='denied-chassis')unavailable(s.chassis,'denied');
 if(phase==='legacy')delete view.hardwareContext;
 if(['revoked','unavailable-view'].includes(phase)){view.status=phase==='revoked'?'revoked':'unavailable';view.snapshot=null;delete view.hardwareContext;}
 if(age>=86400000){view.status='unavailable';view.snapshot=null;delete view.hardwareContext;delete view.retainedContext;}
 if(!validWindowsInventoryView(view,view.deviceId))throw new Error('Invalid synthetic Windows hardware context fixture');
 return view;
}
/** Use the authenticated runner page, route seam and virtual clock unchanged. */
export async function exerciseWindowsHardwareContext({page,expect,locale,width,shot}){
 const de=locale==='de',tab=de?'Gerät':'Device',panel=page.locator('.windows-hardware-context'),details=panel.locator('.windows-hardware-details');
 await page.getByRole('tab',{name:tab,exact:true}).click();await expect(panel).toBeVisible();
 await expect(panel.locator('.windows-hardware-system')).toContainText('Fixture Devices');await expect(panel.locator('.windows-hardware-system')).toContainText('Example Laptop 14');
 await expect(panel.locator('.windows-hardware-chassis')).toContainText('FIXTURE-CHASSIS-0042');await expect(panel.locator('.windows-hardware-chassis')).toContainText('Win32_SystemEnclosure');
 await expect(panel.locator('.windows-hardware-firmware')).toContainText('2026-08-15');await expect(panel.locator('.windows-hardware-firmware')).toContainText('F.42');
 await expect(panel.locator('.windows-hardware-power')).toContainText('74%');await expect(panel.locator('.windows-hardware-power')).toContainText(de?'Verbunden':'Connected');
 await expect(details).not.toHaveAttribute('open');await expect(details.getByText(de?'BIOS-Seriennummer (Win32_BIOS)':'BIOS serial (Win32_BIOS)',{exact:true})).toBeHidden();
 for(const group of await panel.locator('.windows-hardware-group').all())expect(await group.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
 await panel.evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));
 await shot(page,`synthetic-windows-hardware-summary-${width}-${locale}`,windowsHardwareContextDisclosure);
 await details.locator('> summary').click();await expect(details).toHaveAttribute('open','');await expect(details).toContainText(de?'Zugriff verweigert':'Access denied');await expect(details).toContainText(de?'keine geprüfte Systemseriennummer':'not a verified system serial');await expect(details).toContainText('GetSystemPowerStatus');
 await expect(panel.locator('a,img,iframe,form,input,button')).toHaveCount(0);await details.evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));
 await shot(page,`synthetic-windows-hardware-details-${width}-${locale}`,windowsHardwareContextDisclosure);
 await page.getByRole('tab',{name:'Hostname',exact:true}).click();await expect(panel).toHaveCount(0);await page.getByRole('tab',{name:tab,exact:true}).click();await expect(details).not.toHaveAttribute('open');
}
export async function exerciseWindowsHardwareState({page,expect,locale,phase}){
 const de=locale==='de',panel=page.locator('.windows-hardware-context');
 await page.getByRole('tab',{name:de?'Gerät':'Device',exact:true}).click();await expect(panel).toBeVisible();
 if(phase==='absent-battery')await expect(panel.locator('.windows-hardware-power')).toContainText(de?'Kein Akku gemeldet':'No battery reported');
 if(phase==='unknown-battery'){await expect(panel.locator('.windows-hardware-power')).not.toContainText(de?'Kein Akku gemeldet':'No battery reported');await expect(panel.locator('.windows-hardware-power')).toContainText(de?'Unbekannt':'Unknown');}
 if(phase==='denied-bios'){await expect(panel.locator('.windows-hardware-firmware')).toContainText(de?'Zugriff verweigert':'Access denied');await expect(panel.locator('.windows-hardware-chassis')).toContainText('FIXTURE-CHASSIS-0042');}
 if(phase==='denied-chassis'){await expect(panel.locator('.windows-hardware-chassis')).toContainText(de?'Zugriff verweigert':'Access denied');await expect(panel.locator('.windows-hardware-firmware')).toContainText('F.42');}
 await expect(panel.locator('.windows-hardware-system')).toContainText('Example Laptop 14');
}
export async function exerciseWindowsHardwareRetainedContext({page,expect,locale,width,shot,capturedAt,retainedCapturedAt}){
 const de=locale==='de',panels=page.locator('.windows-hardware-context'),latest=panels.first(),previous=page.locator('details.windows-inventory-bounds').filter({has:page.locator('.windows-hardware-context')}),old=previous.locator('.windows-hardware-context');
 await page.getByRole('tab',{name:de?'Gerät':'Device',exact:true}).click();await expect(panels).toHaveCount(2);await expect(previous).not.toHaveAttribute('open');await expect(old).toBeHidden();
 await expect(latest.locator('.windows-hardware-quality')).toHaveText(Array(4).fill(de?'Nicht verfügbar':'Unavailable'));await expect(latest).not.toContainText('Example Laptop 14');await expect(latest.locator('time')).toHaveAttribute('datetime',capturedAt);
 await latest.evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));await shot(page,`synthetic-windows-hardware-current-failure-${width}-${locale}`,windowsHardwareContextDisclosure);
 await previous.locator('> summary').click();await expect(old).toBeVisible();await expect(previous.locator('> .windows-inventory-caution')).toContainText(de?'ursprüngliche Erfassungszeit':'original capture time');
 await expect(old.locator('time')).toHaveAttribute('datetime',retainedCapturedAt);await expect(old).toContainText('FIXTURE-CHASSIS-0042');await expect(old.locator('> .windows-inventory-caution')).toContainText(de?'Veraltete Beobachtung':'Stale observation');await expect(old.locator('.windows-hardware-details')).not.toHaveAttribute('open');
 await old.locator('.windows-inventory-section-header').evaluate(el=>el.scrollIntoView({block:'center',inline:'nearest',behavior:'instant'}));await shot(page,`synthetic-windows-hardware-retained-details-${width}-${locale}`,windowsHardwareContextDisclosure);
 await page.getByRole('tab',{name:'Hostname',exact:true}).click();await expect(panels).toHaveCount(0);await page.getByRole('tab',{name:de?'Gerät':'Device',exact:true}).click();await expect(previous).not.toHaveAttribute('open');
}
export function requireWindowsHardwareContextEvidence(screenshots,sourceSha,testName){
 const fail=()=>{throw new Error('Windows hardware context completion evidence missing or inconsistent');};
 if(!Array.isArray(screenshots)||!(typeof sourceSha==='string'&&/^[a-f0-9]{40}$/.test(sourceSha))||typeof testName!=='string'||!testName)fail();
 const captured=screenshots.filter(item=>typeof item?.file==='string'&&/^synthetic-windows-hardware-/.test(item.file));if(captured.length!==16)fail();
 for(const kind of ['summary','details','current-failure','retained-details'])for(const locale of ['en','de'])for(const width of [1440,390]){
  const matches=captured.filter(item=>item.file===`synthetic-windows-hardware-${kind}-${width}-${locale}.png`);if(matches.length!==1)fail();
  const item=matches[0];if(item.sourceSha!==sourceSha||item.test!==testName||item.locale!==locale||item.viewport?.width!==width||item.viewport?.height!==(width===390?844:1000)||item.publicSafe!==true||item.fullPage!==false||item.fixtureDisclosure!==windowsHardwareContextDisclosure)fail();
 }
 return {hardwareSummary:4,hardwareDetails:4,hardwareCurrentFailure:4,hardwareRetainedDetails:4};
}
