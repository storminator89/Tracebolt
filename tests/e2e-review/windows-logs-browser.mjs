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
// Closed source-only diagnostic labels. Never derive a stage from UI, network,
// error or fixture values. The parent reporter already redacts raw failures.
export const windowsLogsStageNames=Object.freeze([
 'logs-expiry-leave',
 'logs-expiry-unmounted',
 'logs-expiry-fleet',
 'logs-expiry-return',
 'logs-shortcut-click',
 'logs-tab-focus',
 'logs-tab-selected',
 'logs-refresh-click',
 'logs-first-page',
 'logs-sample-boundary',
 'logs-first-rows',
 'logs-record-id',
 'logs-next-click',
 'logs-second-page',
 'logs-next-focus',
 'logs-capture-before',
 'logs-poll-arm',
 'logs-poll-clock',
 'logs-poll-response',
 'logs-poll-ready',
 'logs-poll-capture',
 'logs-poll-page',
 'logs-poll-focus',
 'logs-filter-provider',
 'logs-filter-channel',
 'logs-filter-level',
 'logs-filter-id',
 'logs-filter-count',
 'logs-filter-match',
 'logs-filter-no-match-id',
 'logs-filter-no-match-count',
 'logs-filter-no-match-state',
 'logs-filter-reset-click',
 'logs-filter-reset-rows',
 'logs-layout-width',
 'logs-layout-heading',
 'logs-layout-mobile-scroll',
 'logs-layout-mobile-visible',
 'logs-layout-mobile-style',
 'logs-screenshot-scroll',
 'logs-screenshot',
 'logs-expiry-remount',
 'logs-expiry-tab',
 'logs-expiry-table',
 'logs-expiry-filter',
 'logs-expiry-clock',
 'logs-expiry-no-rows',
 'logs-expiry-no-filter',
 'logs-expiry-state',
 'logs-expiry-screenshot'
]);
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
export async function remountWindowsLogsDevice(page,expect,base,deviceId,mark=()=>{}){
 mark('logs-expiry-leave');await page.goto(`${base}/#/devices`);
 mark('logs-expiry-unmounted');await expect(page.locator('.device-page')).toHaveCount(0);
 mark('logs-expiry-fleet');await expect(page.locator('.device-table')).toBeVisible();
 mark('logs-expiry-return');await page.goto(`${base}/#/devices/${deviceId}`);
}
export async function windowsLogsBrowserCase({page,expect,base,deviceId,locale,width,shot,disclosure,setPhase,advance,mark=()=>{}}){
 const de=locale==='de',logsTab=page.getByRole('tab',{name:'Logs',exact:true});
 mark('logs-shortcut-click');await page.getByRole('button',{name:de?'Ereignisköpfe in Logs öffnen':'Open event headers in Logs',exact:true}).click();
 mark('logs-tab-focus');await expect(logsTab).toBeFocused();
 mark('logs-tab-selected');await expect(logsTab).toHaveAttribute('aria-selected','true');
 const panel=page.locator('.windows-logs'),refresh=panel.getByRole('button',{name:de?'Stichprobe aktualisieren':'Refresh sample',exact:true}),provider=panel.getByLabel('Provider',{exact:true}),next=panel.getByRole('button',{name:de?'Weiter':'Next',exact:true}),table=panel.getByRole('table');
 setPhase('logs');mark('logs-refresh-click');await refresh.click();
 mark('logs-first-page');await expect(panel).toContainText(de?'Seite 1 von 3 · 24 passende Köpfe':'Page 1 of 3 · 24 matching headers');
 mark('logs-sample-boundary');await expect(panel.locator('.windows-logs-boundary')).toContainText(de?'keine älteren Ereignisse':'do not retrieve older events');
 mark('logs-first-rows');await expect(table.locator('tbody tr')).toHaveCount(10);
 mark('logs-record-id');await expect(table.locator('tbody tr').first()).toContainText('18446744073709551615');
 mark('logs-next-click');await next.click();
 mark('logs-second-page');await expect(panel).toContainText(de?'Seite 2 von 3':'Page 2 of 3');
 mark('logs-next-focus');await next.focus();
 // A real resource poll under the existing frozen fixture clock must not drop
 // page-control focus, change the local page or trigger a source continuation.
 const capture=panel.locator('.windows-inventory-count time');
 mark('logs-capture-before');const beforeCapture=await capture.getAttribute('datetime');
 mark('logs-poll-arm');const poll=page.waitForResponse(response=>response.request().method()==='GET'&&new URL(response.url()).pathname===`/api/devices/${deviceId}/windows-inventory`&&response.ok());
 mark('logs-poll-clock');await advance(15000);
 mark('logs-poll-response');await poll;
 mark('logs-poll-ready');await expect(refresh).toBeEnabled();
 mark('logs-poll-capture');await expect(capture).not.toHaveAttribute('datetime',beforeCapture);
 mark('logs-poll-page');await expect(panel).toContainText(de?'Seite 2 von 3':'Page 2 of 3');
 mark('logs-poll-focus');await expect(next).toBeFocused();
 mark('logs-filter-provider');await provider.fill('provider a');
 mark('logs-filter-channel');await panel.getByLabel(de?'Kanal':'Channel',{exact:true}).selectOption('System');
 mark('logs-filter-level');await panel.getByLabel(de?'Stufe':'Level',{exact:true}).selectOption('2');
 mark('logs-filter-id');await panel.getByLabel(de?'Ereignis-ID':'Event ID',{exact:true}).fill('102');
 mark('logs-filter-count');await expect(table.locator('tbody tr')).toHaveCount(1);
 mark('logs-filter-match');await expect(table.locator('tbody tr')).toContainText('102');
 mark('logs-filter-no-match-id');await panel.getByLabel(de?'Ereignis-ID':'Event ID',{exact:true}).fill('2');
 mark('logs-filter-no-match-count');await expect(table).toHaveCount(0);
 mark('logs-filter-no-match-state');await expect(panel).toContainText(de?'Keine Köpfe dieser Stichprobe passen':'No headers in this sample match');
 mark('logs-filter-reset-click');await panel.getByRole('button',{name:de?'Filter zurücksetzen':'Reset filters',exact:true}).click();
 mark('logs-filter-reset-rows');await expect(table.locator('tbody tr')).toHaveCount(10);
 mark('logs-layout-width');expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
 const label=de?'Datensatz-ID':'Record ID';
 if(width===1440){mark('logs-layout-heading');await expect(table.getByRole('columnheader',{name:label,exact:true})).toBeVisible();}
 else {const cell=table.locator('tbody tr').first().locator(`td[data-label="${label}"]`);
  mark('logs-layout-mobile-scroll');await cell.scrollIntoViewIfNeeded();
  mark('logs-layout-mobile-visible');await expect(cell).toBeVisible();
  mark('logs-layout-mobile-style');const before=await cell.evaluate(el=>{const s=getComputedStyle(el,'::before');return {content:s.content,display:s.display,visibility:s.visibility};});expect(before.content).toBe(JSON.stringify(label));expect(before.display).not.toBe('none');expect(before.visibility).toBe('visible');}
 mark('logs-screenshot-scroll');await table.locator('tbody tr').first().scrollIntoViewIfNeeded();
 mark('logs-screenshot');await shot(page,`synthetic-windows-logs-${width}-${locale}`,disclosure);
 setPhase('logs-expiring');mark('logs-expiry-remount');await remountWindowsLogsDevice(page,expect,base,deviceId,mark);
 mark('logs-expiry-tab');await logsTab.click();
 mark('logs-expiry-table');await expect(table).toBeVisible();
 mark('logs-expiry-filter');await provider.fill('Fixture Provider A');
 mark('logs-expiry-clock');await advance(6000);
 mark('logs-expiry-no-rows');await expect(table).toHaveCount(0);
 mark('logs-expiry-no-filter');await expect(provider).toHaveValue('');
 mark('logs-expiry-state');await expect(panel).toContainText(de?'Ereignisstichprobe abgelaufen':'Event sample expired');
 mark('logs-expiry-screenshot');await shot(page,`synthetic-windows-logs-expired-${width}-${locale}`,disclosure);
 setPhase('fresh');
}
