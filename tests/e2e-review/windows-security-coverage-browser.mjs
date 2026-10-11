/** Inert synthetic Security Center/TPM fixtures in the private production UI.
 * No Windows host read, grant, security change or provider request. */
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {build}=require('esbuild');
const bundle=await build({stdin:{contents:"export {windowsSecurityCoverageView} from './windows-security-coverage-fixture'; export {windowsSecurityPosture} from './windows-security-posture-fixture'; export {validWindowsInventoryView} from './windows-inventory-types';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {windowsSecurityCoverageView,windowsSecurityPosture,validWindowsInventoryView}=await import('data:text/javascript;base64,'+Buffer.from(bundle.outputFiles[0].text).toString('base64'));
export const windowsSecurityCoverageDisclosure='Invented antivirus registrations and TPM presence/version in the private production Security UI. UI-only fixture evidence; no native Windows read, local grant, protection or readiness verdict, BitLocker collection, remediation or AI export.';
const emptyAV=reason=>({quality:reason==='windows_security_coverage_access_denied'?'denied':'unavailable',reason,reportedCount:null,rows:[],truncated:false});
const emptyTPM=reason=>({quality:reason==='windows_security_coverage_access_denied'?'denied':'unavailable',reason,presence:'unknown',version:'unknown'});
/** Explicit source times never advance when the fixture is reread. */
export function windowsSecurityCoverageBrowserFixture({serverNow,capturedAt,phase='observed',retainedCapturedAt}){
 const view=windowsSecurityCoverageView(),s=view.securityCoverage;view.securityPosture=windowsSecurityPosture();
 view.serverNow=view.receivedAt=serverNow;view.snapshot.collectedAt=s.collectedAt=view.securityPosture.collectedAt=capturedAt;
 const age=Date.parse(serverNow)-Date.parse(capturedAt);view.status=age<0||age>120000?'stale':'fresh';
 if(phase==='empty')Object.assign(s.antivirus,{reportedCount:0,rows:[]});
 if(phase==='not-found')Object.assign(s.tpm,{presence:'not-found',version:'unknown'});
 if(phase==='unsupported-antivirus')s.antivirus=emptyAV('windows_security_coverage_unsupported_platform');
 if(phase==='denied-tpm')s.tpm=emptyTPM('windows_security_coverage_access_denied');
 if(phase==='partial')Object.assign(s.tpm,{quality:'partial',reason:'windows_security_coverage_invalid_metadata',version:'unknown'});
 if(phase==='bounded')Object.assign(s.antivirus,{quality:'partial',reason:'windows_security_coverage_bounds',reportedCount:40,truncated:true});
 if(phase==='unknown-only'){s.antivirus={quality:'partial',reason:'windows_security_coverage_partial_result',reportedCount:1,rows:[{index:0,name:null,state:'unknown',signatureStatus:'unknown'}],truncated:false};s.tpm=emptyTPM('windows_security_coverage_unavailable');}
 if(phase==='retained'){
  if(typeof retainedCapturedAt!=='string'||!Number.isFinite(Date.parse(retainedCapturedAt))||Date.parse(retainedCapturedAt)>=Date.parse(capturedAt))throw new Error('Invalid synthetic retained Windows coverage capture');
  const old=structuredClone(s);old.collectedAt=retainedCapturedAt;old.generationId=`sample_${'b'.repeat(32)}`;
  s.antivirus=emptyAV('windows_security_coverage_budget_exhausted');s.tpm=emptyTPM('windows_security_coverage_budget_exhausted');
  if(Date.parse(serverNow)-Date.parse(retainedCapturedAt)<86400000)view.retainedContext={securityCoverage:old};
 }
 if(phase==='legacy')delete view.securityCoverage;
 if(['revoked','unavailable-view'].includes(phase)||age>=86400000){view.status=phase==='revoked'?'revoked':'unavailable';view.snapshot=null;delete view.securityCoverage;delete view.securityPosture;delete view.retainedContext;}
 if(!validWindowsInventoryView(view,view.deviceId))throw new Error('Invalid synthetic Windows security coverage fixture');
 return view;
}
export async function exerciseWindowsSecurityCoverage({page,expect,locale,width,shot}){
 const de=locale==='de',panel=page.locator('.windows-security-coverage'),av=panel.getByRole('region',{name:de?'Antivirusregistrierung':'Antivirus registration',exact:true}),tpm=panel.getByRole('region',{name:'TPM',exact:true}),details=panel.locator('.windows-coverage-details');
 await page.getByRole('tab',{name:de?'Sicherheit':'Security',exact:true}).click();await expect(panel).toBeVisible();
 await expect(page.locator('.windows-security-posture')).toBeVisible();await expect(av.getByText('Example Antivirus',{exact:true})).toBeVisible();await expect(av).toContainText(de?'Pausiert':'Snoozed');await expect(av).toContainText(de?'Veraltet':'Out of date');await expect(tpm.getByText('2.0',{exact:true})).toBeVisible();
 await expect(panel).toContainText(de?'In diesem Profil nicht erfasst.':'Not collected under this profile.');await expect(panel).not.toContainText(/healthy|compliant|unprotected|konform|ungeschützt/i);
 await expect(details).toHaveCount(2);for(const item of await details.all())await expect(item).not.toHaveAttribute('open');
 await expect(av.getByText(de?/Registrierung und gemeldeter Status/:/Registration and reported status/)).toBeHidden();await expect(tpm.getByText(de?/Vorhandensein und Version/:/Presence and version/)).toBeHidden();
 const table=av.locator('table'),labels=de?['Produkt','Gemeldeter Status','Signaturstatus']:['Product','Reported state','Signature status'];
 for(const label of labels){if(width===1440)await expect(table.getByRole('columnheader',{name:label,exact:true})).toBeVisible();else{const cell=table.locator('tbody tr').first().locator(`td[data-label="${label}"]`);await expect(cell).toBeVisible();expect(await cell.evaluate(el=>getComputedStyle(el,'::before').content)).toBe(JSON.stringify(label));}}
 await panel.evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
 await shot(page,`synthetic-windows-coverage-summary-${width}-${locale}`,windowsSecurityCoverageDisclosure);
 for(const item of await details.all())await item.locator('> summary').click();await expect(av.getByText(/IWSCProductList/)).toBeVisible();await expect(tpm.getByText(/Tbsi_GetDeviceInfo/)).toBeVisible();await expect(av.getByText(de?/Registrierung und gemeldeter Status/:/Registration and reported status/)).toBeVisible();await expect(tpm.getByText(de?/Vorhandensein und Version/:/Presence and version/)).toBeVisible();await expect(panel.locator('a,button,form,input,img,iframe')).toHaveCount(0);
 await shot(page,`synthetic-windows-coverage-details-${width}-${locale}`,windowsSecurityCoverageDisclosure);
 await page.getByRole('tab',{name:'Hostname',exact:true}).click();await page.getByRole('tab',{name:de?'Sicherheit':'Security',exact:true}).click();for(const item of await details.all())await expect(item).not.toHaveAttribute('open');
}
export async function exerciseWindowsSecurityCoverageState({page,expect,locale,phase}){
 const de=locale==='de',panel=page.locator('.windows-security-coverage');await expect(panel).toBeVisible();
 if(phase==='unsupported-antivirus'){await expect(panel.getByText(de?/auf dieser Plattform nicht unterstützt/:/unsupported on this platform/)).toBeVisible();await expect(panel.getByText('Example Antivirus',{exact:true})).toHaveCount(0);await expect(panel.getByText('2.0',{exact:true})).toBeVisible();}
 if(phase==='denied-tpm'){await expect(panel.getByText(de?'Zugriff verweigert':'Access denied',{exact:true})).toBeVisible();await expect(panel.getByText('Example Antivirus',{exact:true})).toBeVisible();await expect(panel.getByText(de?'Kein unterstütztes TPM gefunden':'No supported TPM found',{exact:true})).toHaveCount(0);}
 if(phase==='not-found'){await expect(panel.getByText(de?'Kein unterstütztes TPM gefunden':'No supported TPM found',{exact:true})).toBeVisible();await expect(panel.getByText(de?/dies belegt keine fehlende Hardware/:/does not establish hardware absence/)).toBeHidden();}
 if(phase==='empty'){await expect(panel.getByText(de?'Diese Quelle meldet keine Produkte.':'No products reported by this source.',{exact:true})).toBeVisible();await expect(panel.getByText(de?'Dies belegt nicht, dass Antivirussoftware fehlt.':'This does not establish that antivirus software is absent.',{exact:true})).toBeHidden();}
 if(phase==='bounded')await expect(panel.getByText(de?/Einige gemeldete Produkte fehlen/:/Some reported products are omitted/)).toBeVisible();
}
export async function exerciseWindowsSecurityCoverageRetained({page,expect,locale,width,shot,capturedAt,retainedCapturedAt}){
 const de=locale==='de',current=page.locator('.windows-security-coverage').first(),previous=page.locator('.windows-inventory-bounds').filter({has:page.locator('.windows-security-coverage')});
 await expect(current).toBeVisible();await expect(current.getByText(de?/Zeitlimit beim Lesen/:/source read timed out/)).toHaveCount(2);await expect(current.locator('time')).toHaveAttribute('datetime',capturedAt);await expect(previous).not.toHaveAttribute('open');
 await current.evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));await shot(page,`synthetic-windows-coverage-current-failure-${width}-${locale}`,windowsSecurityCoverageDisclosure);
 await previous.locator('> summary').click();await expect(previous.getByText('Example Antivirus',{exact:true})).toBeVisible();await expect(previous.locator('time')).toHaveAttribute('datetime',retainedCapturedAt);await expect(previous).toContainText(de?'ursprüngliche Erfassungszeit':'original capture time');
 for(const item of await previous.locator('.windows-coverage-details').all())await item.locator('> summary').click();await previous.evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));await shot(page,`synthetic-windows-coverage-retained-details-${width}-${locale}`,windowsSecurityCoverageDisclosure);
}
/** Only actual source-bound screenshot records satisfy browser completion. */
export function requireWindowsSecurityCoverageEvidence(screenshots,sourceSha,testName){
 const fail=()=>{throw new Error('Windows security coverage completion evidence missing or inconsistent');};
 if(!Array.isArray(screenshots)||!(typeof sourceSha==='string'&&/^[a-f0-9]{40}$/.test(sourceSha))||typeof testName!=='string'||!testName)fail();
 const captured=screenshots.filter(item=>typeof item?.file==='string'&&/^synthetic-windows-coverage-/.test(item.file));if(captured.length!==16)fail();
 for(const kind of ['summary','details','current-failure','retained-details'])for(const locale of ['en','de'])for(const width of [1440,390]){
  const matches=captured.filter(item=>item.file===`synthetic-windows-coverage-${kind}-${width}-${locale}.png`);if(matches.length!==1)fail();const item=matches[0];
  if(item.sourceSha!==sourceSha||item.test!==testName||item.locale!==locale||item.viewport?.width!==width||item.viewport?.height!==(width===390?844:1000)||item.publicSafe!==true||item.fullPage!==false||item.fixtureDisclosure!==windowsSecurityCoverageDisclosure)fail();
 }
 return {coverageSummary:4,coverageDetails:4,coverageCurrentFailure:4,coverageRetainedDetails:4};
}
