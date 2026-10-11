/** Invented drive mappings and MSFT_PhysicalDisk provider fields in the compiled
 * private Storage UI. No native read, local grant or physical-health assertion. */
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {build}=require('esbuild');
const bundle=await build({stdin:{contents:"export {windowsStorageContextView, unavailableWindowsStorageGroup} from './windows-storage-context-fixture'; export {validWindowsInventoryView} from './windows-inventory-types';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {windowsStorageContextView,unavailableWindowsStorageGroup,validWindowsInventoryView}=await import('data:text/javascript;base64,'+Buffer.from(bundle.outputFiles[0].text).toString('base64'));
export const windowsStorageContextDisclosure='Invented drive letters, exact volume GUID mappings and MSFT_PhysicalDisk provider health/status in the private production Storage UI. UI-only fixture evidence; no native Windows read, local consent, SMART, whole-device health proof, inferred volume-to-physical-disk join, storage action or AI export.';
export function windowsStorageContextBrowserFixture({serverNow,capturedAt,phase='observed',retainedCapturedAt}){
 const view=windowsStorageContextView(),s=view.storageContext;
 view.serverNow=view.receivedAt=serverNow;view.snapshot.collectedAt=s.collectedAt=capturedAt;view.volumes.collectedAt=new Date(Date.parse(capturedAt)+2000).toISOString();
 const age=Date.parse(serverNow)-Date.parse(capturedAt);view.status=age<0||age>120000?'stale':'fresh';
 if(phase==='retained'){
  const previous=structuredClone(s);previous.collectedAt=retainedCapturedAt;previous.generationId=`sample_${'b'.repeat(32)}`;
  view.sequence=2;view.snapshot.generationId=s.generationId=view.volumes.generationId=`sample_${'c'.repeat(32)}`;
  s.drives=unavailableWindowsStorageGroup();s.disks=unavailableWindowsStorageGroup();
  if(Date.parse(serverNow)-Date.parse(retainedCapturedAt)<86400000)view.retainedContext={storageContext:previous};
  else if(!Number.isFinite(Date.parse(retainedCapturedAt)))throw new Error('Invalid synthetic retained storage capture');
 }
 if(phase==='denied-drives')s.drives=unavailableWindowsStorageGroup('denied');
 if(phase==='unsupported-disks')s.disks=unavailableWindowsStorageGroup('unavailable','windows_storage_context_unsupported_platform');
 if(phase==='unknown'){for(const row of s.disks.rows)Object.assign(row,{healthStatus:null,busType:null,mediaType:null,sizeBytes:null,operationalStatus:[]});}
 if(phase==='future-codes')Object.assign(s.disks.rows[0],{healthStatus:65535,busType:65535,mediaType:65535,operationalStatus:[0,65535]});
 if(phase==='virtual-raid'){s.disks.rows[0].busType=8;s.disks.rows[1].busType=15;}
 if(phase==='bounded')Object.assign(s.disks,{observedCount:64,countExact:false,complete:false,truncated:true,quality:'partial',reason:'windows_storage_context_bounds'});
 if(phase==='empty')for(const key of ['drives','disks'])Object.assign(s[key],{rows:[],observedCount:0,quality:'observed',reason:''});
 if(phase==='legacy')delete view.storageContext;
 if(['revoked','unavailable-view'].includes(phase)){view.status=phase==='revoked'?'revoked':'unavailable';view.snapshot=null;delete view.storageContext;delete view.volumes;}
 if(age>=86400000){view.status='unavailable';view.snapshot=null;delete view.storageContext;delete view.volumes;delete view.retainedContext;}
 if(!validWindowsInventoryView(view,view.deviceId))throw new Error('Invalid synthetic Windows storage context fixture');
 return view;
}
/** Uses the authenticated runner's page, route seam and virtual clock unchanged. */
export async function exerciseWindowsStorageContext({page,expect,locale,width,shot}){
 const de=locale==='de',tab=de?'Speicher':'Storage',panel=page.locator('.windows-storage-context'),details=panel.locator('.windows-storage-details');
 await page.getByRole('tab',{name:tab,exact:true}).click();await expect(panel).toBeVisible();
 await expect(panel.locator('.windows-storage-drives')).toContainText('C:');await expect(panel.locator('.windows-storage-drives')).toContainText(de?'Zugriff verweigert':'Access denied');
 await expect(panel.locator('.windows-storage-drives')).toContainText(de?'Auflistung vollständig':'Enumeration complete');await expect(panel.locator('.windows-storage-disks')).toContainText('Fixture NVMe');await expect(panel.locator('.windows-storage-health').first()).toContainText(de?'Fehlerfrei (0)':'Healthy (0)');
 await expect(panel.locator('.windows-storage-health').last()).toContainText(de?'Unbekannt':'Unknown');await expect(panel.locator('.windows-storage-disks')).toContainText('Storage Spaces (16)');
 const capacity=page.getByRole('region',{name:de?'Speicher':'Storage',exact:true});expect(await panel.locator('time').getAttribute('datetime')).not.toBe(await capacity.locator('time').getAttribute('datetime'));await expect(capacity.locator('table')).not.toContainText('C:');await expect(page.getByLabel(`9007199254740993 ${de?'Bytes':'bytes'}`,{exact:true})).toBeVisible();await expect(page.getByLabel(`18446744073709551615 ${de?'Bytes':'bytes'}`,{exact:true})).toBeVisible();
 await expect(details).not.toHaveAttribute('open');await expect(details.getByText('provider-local-04',{exact:true})).toBeHidden();
 for(const group of await panel.locator('.windows-storage-group').all())expect(await group.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
 await panel.evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));await shot(page,`synthetic-windows-storage-context-summary-${width}-${locale}`,windowsStorageContextDisclosure);
 await details.locator('> summary').click();await expect(details).toHaveAttribute('open','');await expect(details.getByText('provider-local-04',{exact:true})).toBeVisible();await expect(details.getByText('32768',{exact:true})).toBeVisible();
 await expect(details).toContainText(de?'keine Datenträgernummer':'not an OS disk number');await expect(details).toContainText(de?'keine Zuordnung von Volumes':'No volume-to-physical-disk mapping');await expect(panel).toContainText('SMART');
 await expect(panel.locator('a,img,iframe,form,input,button')).toHaveCount(0);await details.evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));await shot(page,`synthetic-windows-storage-context-details-${width}-${locale}`,windowsStorageContextDisclosure);
 await page.getByRole('tab',{name:'Hostname',exact:true}).click();await expect(panel).toHaveCount(0);await page.getByRole('tab',{name:tab,exact:true}).click();await expect(details).not.toHaveAttribute('open');
}
export async function exerciseWindowsStorageState({page,expect,locale,phase}){
 const de=locale==='de',panel=page.locator('.windows-storage-context');await page.getByRole('tab',{name:de?'Speicher':'Storage',exact:true}).click();await expect(panel).toBeVisible();
 if(phase==='denied-drives'){await expect(panel.locator('.windows-storage-drives')).toContainText(de?'Zugriff verweigert':'Access denied');await expect(panel.locator('.windows-storage-disks')).toContainText('Fixture NVMe');}
 if(phase==='unsupported-disks'){await expect(panel.locator('.windows-storage-disks')).toContainText(de?'Quelle nicht unterstützt.':'Source unsupported.');await expect(panel.locator('.windows-storage-drives')).toContainText('C:');}
 if(phase==='unknown'){await expect(panel.locator('.windows-storage-health').first()).toContainText(de?'Unbekannt':'Unknown');await expect(panel.locator('.windows-storage-health').first()).not.toContainText('(0)');}
 if(phase==='future-codes')await expect(panel.locator('.windows-storage-health').first()).toContainText('Code (65535)');
 if(phase==='virtual-raid'){await expect(panel.locator('.windows-storage-disks')).toContainText('RAID (8)');await expect(panel.locator('.windows-storage-disks')).toContainText(de?'Dateibasiert virtuell (15)':'File-backed virtual (15)');}
 if(phase==='bounded'){await expect(panel.locator('.windows-storage-disks')).toContainText(de?'mindestens 64':'at least 64');await expect(panel.locator('.windows-storage-disks')).toContainText(de?'Zeilen durch':'Rows omitted');}
 if(phase==='empty'){await expect(panel.locator('.windows-storage-drives')).toContainText(de?'Keine lokalen Laufwerksbuchstaben':'No local drive letters');await expect(panel.locator('.windows-storage-disks')).toContainText(de?'Keine Provider-Datenträger':'No provider disks');}
 await expect(page.getByLabel(`9007199254740993 ${de?'Bytes':'bytes'}`,{exact:true})).toBeVisible();
}
export async function exerciseWindowsStorageRetainedContext({page,expect,locale,width,shot,capturedAt,retainedCapturedAt}){
 const de=locale==='de',panels=page.locator('.windows-storage-context'),latest=panels.first(),previous=page.locator('details.windows-inventory-bounds').filter({has:page.locator('.windows-storage-context')}),old=previous.locator('.windows-storage-context');
 await page.getByRole('tab',{name:de?'Speicher':'Storage',exact:true}).click();await expect(panels).toHaveCount(2);await expect(previous).not.toHaveAttribute('open');await expect(old).toBeHidden();
 await expect(latest.locator('.windows-storage-heading>span')).toHaveText(Array(2).fill(de?'Nicht verfügbar':'Unavailable'));await expect(latest).not.toContainText('Fixture NVMe');await expect(latest.locator('time')).toHaveAttribute('datetime',capturedAt);
 await latest.evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));await shot(page,`synthetic-windows-storage-context-current-failure-${width}-${locale}`,windowsStorageContextDisclosure);
 await previous.locator('> summary').click();await expect(old).toBeVisible();await expect(previous.locator('> .windows-inventory-caution')).toContainText(de?'ursprüngliche Erfassungszeit':'original capture time');await expect(old.locator('time')).toHaveAttribute('datetime',retainedCapturedAt);await expect(old).toContainText('Fixture NVMe');await expect(old.locator('> .windows-inventory-caution').first()).toContainText(de?'Veralteter Speicherkontext':'Stale storage context');await expect(old.locator('.windows-storage-details')).not.toHaveAttribute('open');
 await old.locator('.windows-inventory-section-header').evaluate(el=>el.scrollIntoView({block:'center',inline:'nearest',behavior:'instant'}));await shot(page,`synthetic-windows-storage-context-retained-details-${width}-${locale}`,windowsStorageContextDisclosure);
 await page.getByRole('tab',{name:'Hostname',exact:true}).click();await expect(panels).toHaveCount(0);await page.getByRole('tab',{name:de?'Speicher':'Storage',exact:true}).click();await expect(previous).not.toHaveAttribute('open');
}
export function requireWindowsStorageContextEvidence(screenshots,sourceSha,testName){
 const fail=()=>{throw new Error('Windows storage context completion evidence missing or inconsistent');};
 if(!Array.isArray(screenshots)||!(typeof sourceSha==='string'&&/^[a-f0-9]{40}$/.test(sourceSha))||typeof testName!=='string'||!testName)fail();
 const captured=screenshots.filter(item=>typeof item?.file==='string'&&/^synthetic-windows-storage-context-/.test(item.file));if(captured.length!==16)fail();
 for(const kind of ['summary','details','current-failure','retained-details'])for(const locale of ['en','de'])for(const width of [1440,390]){
  const matches=captured.filter(item=>item.file===`synthetic-windows-storage-context-${kind}-${width}-${locale}.png`);if(matches.length!==1)fail();
  const item=matches[0];if(item.sourceSha!==sourceSha||item.test!==testName||item.locale!==locale||item.viewport?.width!==width||item.viewport?.height!==(width===390?844:1000)||item.publicSafe!==true||item.fullPage!==false||item.fixtureDisclosure!==windowsStorageContextDisclosure)fail();
 }
 return {storageSummary:4,storageDetails:4,storageCurrentFailure:4,storageRetainedDetails:4};
}
