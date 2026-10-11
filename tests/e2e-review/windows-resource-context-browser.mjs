/** Invented CPU and memory source metadata in the production Device UI.
 * Fixture-only: no native read, local grant, memory action or health claim. */
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {build}=require('esbuild');
const bundle=await build({stdin:{contents:"export {windowsResourceContextView,unavailableWindowsResourceContext} from './windows-resource-context-fixture'; export {validWindowsInventoryView} from './windows-inventory-types';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {windowsResourceContextView,unavailableWindowsResourceContext,validWindowsInventoryView}=await import('data:text/javascript;base64,'+Buffer.from(bundle.outputFiles[0].text).toString('base64'));
export const windowsResourceContextDisclosure='Invented CPU model/counts, installed and OS-usable RAM, committed-memory and aggregate pagefile context in the private production Device UI. UI-only fixture evidence; no native Windows read, local consent, socket-topology, pressure or health assertion, memory action or AI export.';
export function windowsResourceContextBrowserFixture({serverNow,capturedAt,phase='observed',retainedCapturedAt}){
 const view=windowsResourceContextView(),s=view.resourceContext;
 view.serverNow=view.receivedAt=serverNow;view.snapshot.collectedAt=s.collectedAt=capturedAt;
 const age=Date.parse(serverNow)-Date.parse(capturedAt);view.status=age<0||age>120000?'stale':'fresh';
 if(phase==='retained'){
  const previous=structuredClone(s);previous.collectedAt=retainedCapturedAt;previous.generationId=`sample_${'c'.repeat(32)}`;
  view.sequence=2;view.snapshot.generationId=s.generationId=`sample_${'d'.repeat(32)}`;
  const unavailable=unavailableWindowsResourceContext();for(const key of ['processors','installedMemory','memory','pagefiles'])s[key]=unavailable[key];
  if(Date.parse(serverNow)-Date.parse(retainedCapturedAt)<86400000)view.retainedContext={resourceContext:previous};
  else if(!Number.isFinite(Date.parse(retainedCapturedAt)))throw new Error('Invalid synthetic retained resource capture');
 }
 if(phase==='no-pagefiles')Object.assign(s.pagefiles,{count:0,totalBytes:'0',totalInUseBytes:'0'});
 if(phase==='denied-installed')Object.assign(s.installedMemory,{quality:'denied',reason:'windows_resource_context_access_denied',installedBytes:null});
 if(phase==='unavailable-memory')s.memory=unavailableWindowsResourceContext().memory;
 if(phase==='partial-cpu'){s.processors.rows[0].cores={value:null,quality:'unavailable'};Object.assign(s.processors,{quality:'partial',reason:'windows_resource_context_partial_result',totalCores:null,totalLogicalProcessors:null});}
 if(phase==='large-bytes')Object.assign(s.pagefiles,{totalBytes:'18446744073709551615',totalInUseBytes:'9007199254740993'});
 if(phase==='legacy')delete view.resourceContext;
 if(['revoked','unavailable-view'].includes(phase)){view.status=phase==='revoked'?'revoked':'unavailable';view.snapshot=null;delete view.resourceContext;}
 if(age>=86400000){view.status='unavailable';view.snapshot=null;delete view.resourceContext;delete view.retainedContext;}
 if(!validWindowsInventoryView(view,view.deviceId))throw new Error('Invalid synthetic Windows resource context fixture');
 return view;
}
export async function exerciseWindowsResourceContext({page,expect,locale,width,shot}){
 const de=locale==='de',panel=page.locator('.windows-resource-context'),details=panel.locator('.windows-resource-details');
 await page.getByRole('tab',{name:de?'Gerät':'Device',exact:true}).click();await expect(panel).toBeVisible();
 await expect(panel.locator('.windows-resource-groups')).toContainText('Fixture CPU 12-Core');await expect(panel.locator('.windows-resource-groups')).toContainText(de?'32,0 GiB':'32.0 GiB');await expect(panel.locator('.windows-resource-groups')).toContainText(de?'31,0 GiB':'31.0 GiB');await expect(panel.locator('.windows-resource-groups')).toContainText(de?'28,0 GiB':'28.0 GiB');
 await expect(details).not.toHaveAttribute('open');await expect(details.getByText(de?'34359738368 Bytes':'34359738368 bytes',{exact:true})).toBeHidden();
 for(const group of await panel.locator('.windows-resource-groups>section').all())expect(await group.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
 await panel.evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));await shot(page,`synthetic-windows-resource-context-summary-${width}-${locale}`,windowsResourceContextDisclosure);
 await details.locator('> summary').click();await expect(details).toHaveAttribute('open','');await expect(details).toContainText('34359738368');await expect(details).toContainText('K32GetPerformanceInfo');await expect(details).toContainText(de?'keine physische Sockeltopologie':'do not establish physical socket topology');await expect(details).toContainText('windows-resource-context-v1');
 await expect(panel.locator('a,img,iframe,form,input,button,[role="progressbar"]')).toHaveCount(0);await details.evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));await shot(page,`synthetic-windows-resource-context-details-${width}-${locale}`,windowsResourceContextDisclosure);
 await page.getByRole('tab',{name:'Hostname',exact:true}).click();await expect(panel).toHaveCount(0);await page.getByRole('tab',{name:de?'Gerät':'Device',exact:true}).click();await expect(details).not.toHaveAttribute('open');
}
export async function exerciseWindowsResourceContextState({page,expect,locale,phase}){
 const de=locale==='de',panel=page.locator('.windows-resource-context');await page.getByRole('tab',{name:de?'Gerät':'Device',exact:true}).click();await expect(panel).toBeVisible();
 if(phase==='no-pagefiles')await expect(panel.getByRole('region',{name:de?'Auslagerungsdateien':'Pagefiles',exact:true})).toContainText(de?'Keine Auslagerungsdateien gemeldet':'No pagefiles reported');
 if(phase==='denied-installed'){await expect(panel.getByRole('region',{name:de?'Physischer Arbeitsspeicher':'Physical memory',exact:true})).toContainText(de?'Zugriff verweigert':'Access denied');await expect(panel.locator('.windows-resource-groups')).toContainText(de?'31,0 GiB':'31.0 GiB');}
 if(phase==='unavailable-memory'){await expect(panel.getByRole('region',{name:de?'Zugesicherter Speicher':'Committed memory',exact:true})).toContainText(de?'Nicht verfügbar':'Unavailable');await expect(panel.locator('.windows-resource-groups')).toContainText(de?'32,0 GiB':'32.0 GiB');}
 if(phase==='partial-cpu'){await expect(panel.getByRole('region',{name:'CPU',exact:true})).toContainText(de?'Teilweise':'Partial');await expect(panel.getByRole('region',{name:'CPU',exact:true})).toContainText(de?'Unbekannt':'Unknown');}
 if(phase==='large-bytes'){const details=panel.locator('.windows-resource-details');await details.locator('> summary').click();await expect(details).toContainText('18446744073709551615');await expect(details).toContainText('9007199254740993');}
 await expect(panel.locator('.windows-resource-groups')).toContainText('Fixture CPU 12-Core');
}
export async function exerciseWindowsResourceRetainedContext({page,expect,locale,width,shot,capturedAt,retainedCapturedAt}){
 const de=locale==='de',panels=page.locator('.windows-resource-context'),latest=panels.first(),previous=page.locator('details.windows-inventory-bounds').filter({has:page.locator('.windows-resource-context')}),old=previous.locator('.windows-resource-context');
 await page.getByRole('tab',{name:de?'Gerät':'Device',exact:true}).click();await expect(panels).toHaveCount(2);await expect(previous).not.toHaveAttribute('open');await expect(old).toBeHidden();
 await expect(latest).toContainText(de?'Nicht verfügbar':'Unavailable');await expect(latest).not.toContainText('Fixture CPU 12-Core');await expect(latest.locator('time')).toHaveAttribute('datetime',capturedAt);
 await latest.evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));await shot(page,`synthetic-windows-resource-context-current-failure-${width}-${locale}`,windowsResourceContextDisclosure);
 await previous.locator('> summary').click();await expect(old).toBeVisible();await expect(previous.locator('> .windows-inventory-caution')).toContainText(de?'ursprüngliche Erfassungszeit':'original capture time');
 await expect(old.locator('time')).toHaveAttribute('datetime',retainedCapturedAt);await expect(old).toContainText('Fixture CPU 12-Core');await expect(old.locator('> .windows-inventory-caution')).toContainText(de?'Veraltete Beobachtung':'Stale observation');await expect(old.locator('.windows-resource-details')).not.toHaveAttribute('open');
 await old.locator('.windows-inventory-section-header').evaluate(el=>el.scrollIntoView({block:'center',inline:'nearest',behavior:'instant'}));await shot(page,`synthetic-windows-resource-context-retained-details-${width}-${locale}`,windowsResourceContextDisclosure);
 await page.getByRole('tab',{name:'Hostname',exact:true}).click();await expect(panels).toHaveCount(0);await page.getByRole('tab',{name:de?'Gerät':'Device',exact:true}).click();await expect(previous).not.toHaveAttribute('open');
}
export function requireWindowsResourceContextEvidence(screenshots,sourceSha,testName){
 const fail=()=>{throw new Error('Windows resource context completion evidence missing or inconsistent');};
 if(!Array.isArray(screenshots)||!(typeof sourceSha==='string'&&/^[a-f0-9]{40}$/.test(sourceSha))||typeof testName!=='string'||!testName)fail();
 const captured=screenshots.filter(item=>typeof item?.file==='string'&&/^synthetic-windows-resource-context-/.test(item.file));if(captured.length!==16)fail();
 for(const kind of ['summary','details','current-failure','retained-details'])for(const locale of ['en','de'])for(const width of [1440,390]){
  const matches=captured.filter(item=>item.file===`synthetic-windows-resource-context-${kind}-${width}-${locale}.png`);if(matches.length!==1)fail();
  const item=matches[0];if(item.sourceSha!==sourceSha||item.test!==testName||item.locale!==locale||item.viewport?.width!==width||item.viewport?.height!==(width===390?844:1000)||item.publicSafe!==true||item.fullPage!==false||item.fixtureDisclosure!==windowsResourceContextDisclosure)fail();
 }
 return {resourceSummary:4,resourceDetails:4,resourceCurrentFailure:4,resourceRetainedDetails:4};
}
