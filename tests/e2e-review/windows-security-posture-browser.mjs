/** Synthetic private security observations in the compiled production UI.
 * No native read, local grant, scan, policy change or external request. */
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {build}=require('esbuild');
const bundle=await build({stdin:{contents:"export {windowsSecurityPostureView} from './windows-security-posture-fixture'; export {validWindowsInventoryView} from './windows-inventory-types';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {windowsSecurityPostureView,validWindowsInventoryView}=await import('data:text/javascript;base64,'+Buffer.from(bundle.outputFiles[0].text).toString('base64'));
export const windowsSecurityPostureDisclosure='Invented Defender and local firewall configuration in the private production Security UI. UI-only fixture evidence; no native Windows read, consent, scan, security change, protection verdict or AI export.';
/** Caller supplies all times. Reads never refresh the original capture. */
export function windowsSecurityPostureBrowserFixture({serverNow,capturedAt,phase='observed'}){
 const view=windowsSecurityPostureView(),s=view.securityPosture;
 view.serverNow=view.receivedAt=serverNow;view.snapshot.collectedAt=s.collectedAt=capturedAt;s.generationId=view.snapshot.generationId;
 const age=Date.parse(serverNow)-Date.parse(capturedAt);view.status=age<0||age>120000?'stale':'fresh';
 if(['passive','edr-block','unknown'].includes(phase)){s.defender.mode=phase;s.defender.antivirusEnabled=s.defender.realTimeProtectionEnabled='off';if(phase==='unknown')Object.assign(s.defender,{quality:'partial',reason:'windows_security_posture_partial_result'});}
 if(phase==='partial')Object.assign(s.defender,{quality:'partial',reason:'windows_security_posture_invalid_metadata',signatureAgeDays:null});
 if(['denied','unavailable'].includes(phase))Object.assign(s.defender,{quality:phase,reason:phase==='denied'?'windows_security_posture_access_denied':'windows_security_posture_unavailable',mode:'unknown',serviceEnabled:'unknown',antivirusEnabled:'unknown',realTimeProtectionEnabled:'unknown',signatureVersion:null,signatureAgeDays:null});
 if(phase==='legacy')delete view.securityPosture;
 if(['revoked','unavailable-view'].includes(phase)){view.status=phase==='revoked'?'revoked':'unavailable';view.snapshot=null;delete view.securityPosture;}
 if(age>=86400000){view.status='unavailable';view.snapshot=null;delete view.securityPosture;}
 if(!validWindowsInventoryView(view,view.deviceId))throw new Error('Invalid synthetic Windows security fixture');
 return view;
}
/** Requires the shared authenticated fixture page, without starting a browser. */
export async function exerciseWindowsSecurityPosture({page,expect,locale,width,shot}){
 const de=locale==='de',panel=page.locator('.windows-security-posture'),defender=panel.getByRole('region',{name:'Microsoft Defender',exact:true}),firewall=panel.getByRole('region',{name:de?'Windows-Firewall':'Windows Firewall',exact:true}),details=panel.locator('.windows-security-details');
 await page.getByRole('tab',{name:de?'Sicherheit':'Security',exact:true}).click();
 await expect(panel).toBeVisible();await expect(defender.locator('.windows-security-mode')).toHaveText(de?'Normalmodus':'Normal mode');
 await expect(defender.locator('.windows-security-quality')).toHaveText(de?'Beobachtet':'Observed');await expect(firewall.locator('.windows-security-quality')).toHaveText(de?'Teilweise':'Partial');
 await expect(details).toHaveCount(2);for(const item of await details.all())await expect(item).not.toHaveAttribute('open');
 const explanation=firewall.getByText(de?'Einige Werte für Windows-Firewall konnten nicht ermittelt werden (Unbekannt). Status der Quelle auf dem Gerät prüfen.':'Some Windows Firewall values could not be determined (Unknown). Check the source status on the device.',{exact:true});
 await expect(explanation).toHaveCount(1);await expect(explanation).toBeVisible();
 await expect(defender.getByText('1.437.1234.0',{exact:true})).toBeHidden();
 await expect(defender).toContainText(de?'Andere Antivirusprodukte werden nicht geprüft.':'Other antivirus products are not assessed.');
 await expect(firewall).toContainText(de?'Wirksame Richtlinien und Netzwerkerreichbarkeit werden nicht geprüft.':'Effective policy and network connectivity are not checked.');
 await expect(panel).not.toContainText(/unprotected|compliant|compliance|ungeschützt|konform/i);
 await defender.evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));
 expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
 await shot(page,`synthetic-windows-security-defender-${width}-${locale}`,windowsSecurityPostureDisclosure);
 const table=firewall.locator('table');await expect(table.locator('tbody tr')).toHaveCount(3);
 const labels=de?['Profil','Aktives Profil','Konfigurierte Firewall']:['Profile','Active profile','Configured firewall'];
 for(const label of labels){
  if(width===1440)await expect(table.getByRole('columnheader',{name:label,exact:true})).toBeVisible();
  else {const cell=table.locator('tbody tr').first().locator(`td[data-label="${label}"]`);await expect(cell).toBeVisible();expect(await cell.evaluate(el=>getComputedStyle(el,'::before').content)).toBe(JSON.stringify(label));}
 }
 await expect(table.locator('tbody tr').last().locator('td')).toHaveText(de?['Öffentlich','Unbekannt','Unbekannt']:['Public','Unknown','Unknown']);
 await firewall.evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));
 expect(await table.evaluate(el=>{const r=el.getBoundingClientRect(),p=el.closest('.windows-security-card').getBoundingClientRect();return r.left>=p.left-1&&r.right<=p.right+1&&el.scrollWidth<=el.clientWidth+1;})).toBe(true);
 await shot(page,`synthetic-windows-security-firewall-${width}-${locale}`,windowsSecurityPostureDisclosure);
 await details.first().locator('> summary').click();await expect(defender.getByText('1.437.1234.0',{exact:true})).toBeVisible();await expect(defender).toContainText(de?'1 Tag':'1 day');
 await details.last().locator('> summary').click();await expect(explanation).toHaveCount(1);await expect(explanation).toBeVisible();await expect(details.last()).not.toContainText(de?'Einige Werte für':'Some Windows Firewall values');
 await expect(panel.locator('a,img,iframe,form,input,button')).toHaveCount(0);
 await defender.evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));
 await shot(page,`synthetic-windows-security-details-${width}-${locale}`,windowsSecurityPostureDisclosure);
 await page.getByRole('tab',{name:'Hostname',exact:true}).click();await page.getByRole('tab',{name:de?'Sicherheit':'Security',exact:true}).click();for(const item of await details.all())await expect(item).not.toHaveAttribute('open');
}
/** Records count only after the runner captures actual browser screenshots. */
export function requireWindowsSecurityPostureEvidence(screenshots,sourceSha,testName){
 const fail=()=>{throw new Error('Windows security completion evidence missing or inconsistent');};
 if(!Array.isArray(screenshots)||!(typeof sourceSha==='string'&&/^[a-f0-9]{40}$/.test(sourceSha))||typeof testName!=='string'||!testName)fail();
 const captured=screenshots.filter(item=>typeof item?.file==='string'&&/^synthetic-windows-security-/.test(item.file));if(captured.length!==12)fail();
 for(const kind of ['defender','firewall','details'])for(const locale of ['en','de'])for(const width of [1440,390]){
  const matches=captured.filter(item=>item.file===`synthetic-windows-security-${kind}-${width}-${locale}.png`);if(matches.length!==1)fail();
  const item=matches[0];if(item.sourceSha!==sourceSha||item.test!==testName||item.locale!==locale||item.viewport?.width!==width||item.viewport?.height!==(width===390?844:1000)||item.publicSafe!==true||item.fullPage!==false||item.fixtureDisclosure!==windowsSecurityPostureDisclosure)fail();
 }
 return {securityDefender:4,securityFirewall:4,securityDetails:4};
}
