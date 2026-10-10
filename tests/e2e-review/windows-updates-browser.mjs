/** Assertion helper for the existing authenticated synthetic loopback
 * runner. This file launches no browser, changes no shared allowlist and reads
 * no host. Importing or source-testing it is not a hosted-browser pass. */
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {build}=require('esbuild');
const bundle=await build({stdin:{contents:"export {windowsUpdatesView} from './windows-updates-fixture'; export {validWindowsInventoryView} from './windows-inventory-types';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {windowsUpdatesView,validWindowsInventoryView}=await import('data:text/javascript;base64,'+Buffer.from(bundle.outputFiles[0].text).toString('base64'));
export const windowsUpdatesFixtureDisclosure='Invented cached Windows Update metadata in the production UI. UI-only fixture evidence; no native WUA read, endpoint consent, online scan, download, installation, reboot or AI call.';
/** The caller supplies all times. Repeated reads never renew original capture. */
export function windowsUpdatesBrowserFixture({serverNow,capturedAt,phase='bounded',count=61}){
 const view=windowsUpdatesView(count);
 view.serverNow=serverNow;view.receivedAt=serverNow;view.snapshot.collectedAt=view.updates.collectedAt=capturedAt;
 const age=Date.parse(serverNow)-Date.parse(capturedAt);
 view.status=age<0||age>120000?'stale':'fresh';
 if(phase==='bounded')Object.assign(view.updates,{observedCount:1000,truncated:true});
 if(phase==='empty')Object.assign(view.updates,{rows:[],observedCount:0,truncated:false});
 if(phase==='partial')Object.assign(view.updates,{quality:'partial',reason:'windows_updates_partial_result',countExact:false,observedCount:1000,truncated:true});
 if(phase==='partial-empty')Object.assign(view.updates,{quality:'partial',reason:'windows_updates_partial_result',countExact:false,rows:[],observedCount:0,truncated:false});
 if(['denied','unavailable'].includes(phase))Object.assign(view.updates,{quality:phase,reason:phase==='denied'?'windows_updates_access_denied':'windows_updates_offline_not_verified',countExact:false,rows:[],observedCount:0,truncated:false});
 if(phase==='legacy')delete view.updates;
 if(age>=86400000){view.status='unavailable';view.snapshot=null;delete view.updates;}
 if(!validWindowsInventoryView(view,view.deviceId))throw new Error('Invalid synthetic cached update fixture');
 return view;
}
/** Requires a caller-owned authenticated fixture page already showing Updates.
 * No source fixture runs this function without a hosted browser. */
export async function exerciseWindowsUpdates({page,expect,locale,width,shot}){
 const de=locale==='de',panel=page.locator('.windows-updates');
 await page.getByRole('tab',{name:'Updates',exact:true}).click();
 const table=panel.getByRole('table'),rows=table.locator('tbody tr');
 const search=panel.getByRole('searchbox',{name:de?'Erfasste Updates filtern':'Filter captured updates'}),sort=panel.getByRole('combobox',{name:de?'Erfasste Updates sortieren':'Sort captured updates'});
 await expect(panel).toContainText(de?'Die Aktualität des Caches ist unbekannt':'Cache freshness is unknown');
 await expect(panel).toContainText(de?'61 erfasst · 1000 Cache-Ergebnisse beobachtet':'61 captured · 1000 cached results observed');
 await expect(rows).toHaveCount(25);
 const labels=de?['Titel','KB-Artikel','Hersteller-Schweregrad','Bereits heruntergeladen','Update-ID / Revision']:['Title','KB articles','Vendor severity','Already downloaded','Update ID / revision'];
 for(const label of labels){
  if(width>600)await expect(table.getByRole('columnheader',{name:label,exact:true})).toBeVisible();
  else {const cell=rows.first().locator(`td[data-label="${label}"]`);await expect(cell).toBeVisible();expect(await cell.evaluate(el=>getComputedStyle(el,'::before').content)).toBe(JSON.stringify(label));}
 }
 const next=panel.getByRole('button',{name:de?'Nächste Seite':'Next page'}),previous=panel.getByRole('button',{name:de?'Vorherige Seite':'Previous page'});
 await expect(previous).toBeDisabled();await next.click();await next.click();await expect(rows).toHaveCount(11);await expect(next).toBeDisabled();
 await search.fill('KB1000060');await expect(rows).toHaveCount(1);await expect(rows.first()).toContainText('Synthetic cached update 061');await expect(previous).toBeDisabled();
 await search.fill('');await sort.selectOption('severity-desc');await expect(rows.first()).toContainText(de?'Kritisch':'Critical');await expect(table.locator('th[aria-sort]')).toHaveAttribute('aria-sort','descending');
 await sort.selectOption('downloaded-asc');await expect(rows.first().locator('td').nth(3)).toHaveText(de?'Nein':'No');
 await expect(panel.locator('a, img, iframe, form')).toHaveCount(0);
 expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
 await panel.locator('.windows-inventory-table-controls').scrollIntoViewIfNeeded();if(shot)await shot(page,`synthetic-windows-updates-${width}-${locale}`,windowsUpdatesFixtureDisclosure);
 if(width<=600){await rows.first().scrollIntoViewIfNeeded();if(shot)await shot(page,`synthetic-windows-updates-row-${width}-${locale}`,windowsUpdatesFixtureDisclosure);}
 await search.fill('private filter');await page.getByRole('tab',{name:'Hostname',exact:true}).click();await page.getByRole('tab',{name:'Updates',exact:true}).click();await expect(search).toHaveValue('');await expect(sort).toHaveValue('title-asc');
}
