/** Invented private session/join metadata in the compiled production UI.
 * No native read, local grant, session/account action or directory query. */
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {build}=require('esbuild');
const bundle=await build({stdin:{contents:"export {windowsSessionContextView} from './windows-session-context-fixture'; export {validWindowsInventoryView} from './windows-inventory-types';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {windowsSessionContextView,validWindowsInventoryView}=await import('data:text/javascript;base64,'+Buffer.from(bundle.outputFiles[0].text).toString('base64'));
export const windowsSessionContextDisclosure='Invented caller-visible session and local join metadata in the private production Users / Sessions UI. UI-only fixture evidence; no native Windows read, local consent, account/session action, directory query or AI export.';
export function windowsSessionContextBrowserFixture({serverNow,capturedAt,phase='observed'}){
 const view=windowsSessionContextView(),s=view.sessionContext;
 view.serverNow=view.receivedAt=serverNow;view.snapshot.collectedAt=s.collectedAt=capturedAt;s.generationId=view.snapshot.generationId;
 const age=Date.parse(serverNow)-Date.parse(capturedAt);view.status=age<0||age>120000?'stale':'fresh';
 if(['denied','unavailable'].includes(phase))Object.assign(s.sessions,{quality:phase,reason:phase==='denied'?'windows_session_context_access_denied':'windows_session_context_unavailable',observedCount:null,retainedCount:0,truncatedCount:null,rows:[]});
 if(phase==='legacy')delete view.sessionContext;
 if(['revoked','unavailable-view'].includes(phase)){view.status=phase==='revoked'?'revoked':'unavailable';view.snapshot=null;delete view.sessionContext;}
 if(age>=86400000){view.status='unavailable';view.snapshot=null;delete view.sessionContext;}
 if(!validWindowsInventoryView(view,view.deviceId))throw new Error('Invalid synthetic Windows session context fixture');
 return view;
}
/** Uses the existing authenticated page; creates no browser, request or clock. */
export async function exerciseWindowsSessionContext({page,expect,locale,width,shot}){
 const de=locale==='de',tab=de?'Benutzer / Sitzungen':'Users / Sessions',panel=page.locator('.windows-session-context'),details=panel.locator('.windows-session-details'),membership=panel.locator('.windows-session-membership'),table=panel.locator('table');
 await page.getByRole('tab',{name:tab,exact:true}).click();await expect(panel).toBeVisible();
 await expect(membership).toContainText(de?'Arbeitsgruppe':'Workgroup');await expect(membership).toContainText('FIXTURE-WORKGROUP');
 await expect(table.locator('tbody tr')).toHaveCount(3);await expect(table.locator('tbody tr').nth(1)).toContainText('fixture-alex');
 await expect(table.locator('tbody tr').last()).toContainText(de?'Zugriff verweigert':'Access denied');await expect(table.locator('tbody tr').last()).toContainText(de?'Nicht verfügbar':'Unavailable');await expect(table.locator('tbody tr').last()).toContainText('RDP');
 await expect(details).not.toHaveAttribute('open');
 const labels=de?['Sitzungs-ID','Benutzer','Domäne','Zustand','Protokoll']:['Session ID','User','Domain','State','Protocol'];
 for(const label of labels){
  if(width===1440)await expect(table.getByRole('columnheader',{name:label,exact:true})).toBeVisible();
  else {const cell=table.locator('tbody tr').first().locator(`td[data-label="${label}"]`);await expect(cell).toBeVisible();expect(await cell.evaluate(el=>getComputedStyle(el,'::before').content)).toBe(JSON.stringify(label));}
 }
 expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
 await membership.evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));
 await shot(page,`synthetic-windows-sessions-summary-${width}-${locale}`,windowsSessionContextDisclosure);
 await details.locator('> summary').click();await expect(details).toHaveAttribute('open','');
 await expect(details).toContainText(de?'Sichtbare Sitzungen':'Caller-visible count');await expect(details).toContainText('32');
 await expect(panel.locator('a,img,iframe,form,input,button')).toHaveCount(0);
 await details.evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));
 await shot(page,`synthetic-windows-sessions-details-${width}-${locale}`,windowsSessionContextDisclosure);
 await page.getByRole('tab',{name:'Hostname',exact:true}).click();await expect(page.locator('.windows-session-context')).toHaveCount(0);
 await page.getByRole('tab',{name:tab,exact:true}).click();await expect(details).not.toHaveAttribute('open');
}
/** Completion accepts only actual source-bound records from the shared runner. */
export function requireWindowsSessionContextEvidence(screenshots,sourceSha,testName){
 const fail=()=>{throw new Error('Windows session context completion evidence missing or inconsistent');};
 if(!Array.isArray(screenshots)||!(typeof sourceSha==='string'&&/^[a-f0-9]{40}$/.test(sourceSha))||typeof testName!=='string'||!testName)fail();
 const captured=screenshots.filter(item=>typeof item?.file==='string'&&/^synthetic-windows-sessions-/.test(item.file));if(captured.length!==8)fail();
 for(const kind of ['summary','details'])for(const locale of ['en','de'])for(const width of [1440,390]){
  const matches=captured.filter(item=>item.file===`synthetic-windows-sessions-${kind}-${width}-${locale}.png`);if(matches.length!==1)fail();
  const item=matches[0];if(item.sourceSha!==sourceSha||item.test!==testName||item.locale!==locale||item.viewport?.width!==width||item.viewport?.height!==(width===390?844:1000)||item.publicSafe!==true||item.fullPage!==false||item.fixtureDisclosure!==windowsSessionContextDisclosure)fail();
 }
 return {sessionSummary:4,sessionDetails:4};
}
