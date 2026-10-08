/** Additive invented header-sample coverage in the existing hosted Windows case.
 * No browser launch, route, native source, mutation or permission setup here. */
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {build}=require('esbuild');
const built=await build({stdin:{contents:"export {windowsEventsFixture} from './windows-events-fixture';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {windowsEventsFixture}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
export function windowsLogsFixture(view,now,phase,phaseAt=now){
 if(!['logs','logs-expiring'].includes(phase))return view;
 view.events=windowsEventsFixture();view.events.generationId=view.snapshot.generationId;
 const captureClock=phase==='logs-expiring'?phaseAt:now;
 view.events.collectedAt=new Date(Date.parse(captureClock)-(phase==='logs-expiring'?86400000-5000:2000)).toISOString();
 // The existing event wire contract omits expired headers; a repeat cannot
 // mint a new capture time or renew the original private-row lifetime.
 if(Date.parse(now)-Date.parse(view.events.collectedAt)>=86400000)delete view.events;
 return view;
}
export async function remountWindowsLogsDevice(page,expect,base,deviceId){
 await page.goto(`${base}/#/devices`);
 await expect(page.locator('.device-page')).toHaveCount(0);
 await expect(page.locator('.device-table')).toBeVisible();
 await page.goto(`${base}/#/devices/${deviceId}`);
}
export async function windowsLogsBrowserCase({page,expect,base,deviceId,locale,width,shot,disclosure,setPhase,advance}){
 const de=locale==='de',logsTab=page.getByRole('tab',{name:'Logs',exact:true});
 await page.getByRole('button',{name:de?'Ereignisköpfe in Logs öffnen':'Open event headers in Logs',exact:true}).click();
 await expect(logsTab).toBeFocused();await expect(logsTab).toHaveAttribute('aria-selected','true');
 const panel=page.locator('.windows-logs'),refresh=panel.getByRole('button',{name:de?'Stichprobe aktualisieren':'Refresh sample',exact:true}),provider=panel.getByLabel('Provider',{exact:true}),next=panel.getByRole('button',{name:de?'Weiter':'Next',exact:true}),table=panel.getByRole('table');
 setPhase('logs');await refresh.click();await expect(panel).toContainText(de?'Seite 1 von 3 · 24 passende Köpfe':'Page 1 of 3 · 24 matching headers');
 await expect(panel.locator('.windows-logs-boundary')).toContainText(de?'keine älteren Ereignisse':'do not retrieve older events');
 await expect(table.locator('tbody tr')).toHaveCount(10);await expect(table.locator('tbody tr').first()).toContainText('18446744073709551615');
 await next.click();await expect(panel).toContainText(de?'Seite 2 von 3':'Page 2 of 3');await next.focus();
 // A real resource poll under the existing frozen fixture clock must not drop
 // page-control focus, change the local page or trigger a source continuation.
 const capture=panel.locator('.windows-inventory-count time'),beforeCapture=await capture.getAttribute('datetime');
 const poll=page.waitForResponse(response=>response.request().method()==='GET'&&new URL(response.url()).pathname===`/api/devices/${deviceId}/windows-inventory`&&response.ok());
 await advance(15000);await poll;await expect(refresh).toBeEnabled();await expect(capture).not.toHaveAttribute('datetime',beforeCapture);
 await expect(panel).toContainText(de?'Seite 2 von 3':'Page 2 of 3');await expect(next).toBeFocused();
 await provider.fill('provider a');await panel.getByLabel(de?'Kanal':'Channel',{exact:true}).selectOption('System');await panel.getByLabel(de?'Stufe':'Level',{exact:true}).selectOption('2');await panel.getByLabel(de?'Ereignis-ID':'Event ID',{exact:true}).fill('102');
 await expect(table.locator('tbody tr')).toHaveCount(1);await expect(table.locator('tbody tr')).toContainText('102');
 await panel.getByLabel(de?'Ereignis-ID':'Event ID',{exact:true}).fill('2');await expect(table).toHaveCount(0);await expect(panel).toContainText(de?'Keine Köpfe dieser Stichprobe passen':'No headers in this sample match');
 await panel.getByRole('button',{name:de?'Filter zurücksetzen':'Reset filters',exact:true}).click();await expect(table.locator('tbody tr')).toHaveCount(10);
 expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
 const label=de?'Datensatz-ID':'Record ID';
 if(width===1440)await expect(table.getByRole('columnheader',{name:label,exact:true})).toBeVisible();
 else {const cell=table.locator('tbody tr').first().locator(`td[data-label="${label}"]`);await cell.scrollIntoViewIfNeeded();await expect(cell).toBeVisible();const before=await cell.evaluate(el=>{const s=getComputedStyle(el,'::before');return {content:s.content,display:s.display,visibility:s.visibility};});expect(before.content).toBe(JSON.stringify(label));expect(before.display).not.toBe('none');expect(before.visibility).toBe('visible');}
 await table.locator('tbody tr').first().scrollIntoViewIfNeeded();await shot(page,`synthetic-windows-logs-${width}-${locale}`,disclosure);
 setPhase('logs-expiring');await remountWindowsLogsDevice(page,expect,base,deviceId);await logsTab.click();await expect(table).toBeVisible();await provider.fill('Fixture Provider A');
 await advance(6000);await expect(table).toHaveCount(0);await expect(provider).toHaveValue('');await expect(panel).toContainText(de?'Ereignisstichprobe abgelaufen':'Event sample expired');await shot(page,`synthetic-windows-logs-expired-${width}-${locale}`,disclosure);
 setPhase('fresh');
}
