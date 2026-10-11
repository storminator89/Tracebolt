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
export function windowsSessionContextBrowserFixture({serverNow,capturedAt,phase='observed',retainedCapturedAt}){
 const view=windowsSessionContextView(),s=view.sessionContext;
 view.serverNow=view.receivedAt=serverNow;view.snapshot.collectedAt=s.collectedAt=capturedAt;s.generationId=view.snapshot.generationId;
 const age=Date.parse(serverNow)-Date.parse(capturedAt);view.status=age<0||age>120000?'stale':'fresh';
 if(phase==='retained'){
  // A separate invented generation, under the unchanged exact local grant.
  // Repeated replies advance server time only, never either original capture.
  const previous=structuredClone(s);previous.collectedAt=retainedCapturedAt;previous.generationId=`sample_${'b'.repeat(32)}`;
  view.sequence=2;view.snapshot.generationId=s.generationId=`sample_${'c'.repeat(32)}`;
  s.sessions={quality:'unavailable',reason:'windows_session_context_budget_exhausted',observedCount:null,retainedCount:0,truncatedCount:null,rows:[]};
  s.join={quality:'unavailable',reason:'windows_session_context_budget_exhausted',status:'unknown',name:null};
  if(Date.parse(serverNow)-Date.parse(retainedCapturedAt)<86400000)view.retainedContext={sessionContext:previous};
  else if(!Number.isFinite(Date.parse(retainedCapturedAt)))throw new Error('Invalid synthetic retained session capture');
 }
 if(['denied','unavailable'].includes(phase))Object.assign(s.sessions,{quality:phase,reason:phase==='denied'?'windows_session_context_access_denied':'windows_session_context_unavailable',observedCount:null,retainedCount:0,truncatedCount:null,rows:[]});
 if(phase==='legacy')delete view.sessionContext;
 if(['revoked','unavailable-view'].includes(phase)){view.status=phase==='revoked'?'revoked':'unavailable';view.snapshot=null;delete view.sessionContext;}
 if(age>=86400000){view.status='unavailable';view.snapshot=null;delete view.sessionContext;delete view.retainedContext;}
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
/** Same authenticated page and inventory response; no new request seam or clock. */
export async function exerciseWindowsSessionRetainedContext({page,expect,locale,width,shot,capturedAt,retainedCapturedAt}){
 const de=locale==='de',tab=de?'Benutzer / Sitzungen':'Users / Sessions',panels=page.locator('.windows-session-context'),latest=panels.first(),previous=page.locator('details.windows-inventory-bounds').filter({has:page.locator('.windows-session-context')}),old=previous.locator('.windows-session-context');
 await page.getByRole('tab',{name:tab,exact:true}).click();await expect(panels).toHaveCount(2);await expect(latest).toBeVisible();
 await expect(previous.locator('> summary')).toHaveText(de?'Vorherige Erfassung anzeigen':'Show previous capture');
 await expect(previous).not.toHaveAttribute('open');await expect(old).toBeHidden();await expect(previous.getByText('fixture-alex',{exact:true})).toBeHidden();
 const unavailable=de?'Nicht verfügbar':'Unavailable',failure=latest.locator('.windows-inventory-empty'),currentTime=latest.locator('time'),oldTime=old.locator('time');
 await expect(latest.locator('.windows-session-quality')).toHaveText([unavailable,unavailable]);
 await expect(failure).toHaveText(de?'Sitzungsdaten sind nicht verfügbar. Eine leere Sitzungsliste ist damit nicht belegt.':'Session visibility is unavailable. An empty session list cannot be established.');
 await expect(latest.locator('table')).toHaveCount(0);await expect(latest).not.toContainText('fixture-alex');await expect(currentTime).toHaveAttribute('datetime',capturedAt);
 const dates=await page.evaluate(({locale,capturedAt,retainedCapturedAt})=>{const format=new Intl.DateTimeFormat(locale==='de'?'de-DE':'en-GB',{dateStyle:'medium',timeStyle:'medium'});return [capturedAt,retainedCapturedAt].map(value=>format.format(new Date(value)));},{locale,capturedAt,retainedCapturedAt});
 await expect(currentTime).toHaveText(dates[0]);expect(dates[0]).not.toBe(dates[1]);
 const source=latest.locator('.windows-session-details');await expect(source).not.toHaveAttribute('open');await source.locator('> summary').click();await expect(source).toHaveAttribute('open','');
 await expect(source.locator('.windows-inventory-caution')).toHaveText([de?'Zeitlimit der Quelle erreicht.':'Source collection time limit reached.',de?'Zeitlimit der Quelle erreicht.':'Source collection time limit reached.']);
 await expect(source.locator('.windows-inventory-caution').first()).toBeVisible();
 await source.locator('> summary').click();await expect(source).not.toHaveAttribute('open');
 // Capture the compact current result separately, while the previous capture
 // is still collapsed. Center it away from the app/test banner; never resize UI.
 await latest.scrollIntoViewIfNeeded();await latest.evaluate(el=>el.scrollIntoView({block:'center',inline:'nearest',behavior:'instant'}));
 for(const item of [currentTime,failure,latest.locator('.windows-session-heading .windows-session-quality')])await expect(item).toBeInViewport({ratio:1});
 await expect(previous).not.toHaveAttribute('open');
 await shot(page,`synthetic-windows-sessions-current-failure-${width}-${locale}`,windowsSessionContextDisclosure);
 await previous.locator('> summary').click();await expect(previous).toHaveAttribute('open','');await expect(old).toBeVisible();
 const caution=previous.locator('> .windows-inventory-caution');
 await expect(caution).toHaveText(de?'Der letzte Versuch hat diese frühere Beobachtung nicht ersetzt. Sie behält ihre ursprüngliche Erfassungszeit und belegt keinen aktuellen Zustand.':'The latest attempt did not replace this earlier observation. It keeps its original capture time and does not establish current state.');
 await expect(oldTime).toHaveAttribute('datetime',retainedCapturedAt);expect(Date.parse(retainedCapturedAt)).toBeLessThan(Date.parse(capturedAt));
 await expect(currentTime).toHaveText(dates[0]);await expect(oldTime).toHaveText(dates[1]);
 await expect(old.locator('> .windows-inventory-caution')).toHaveText(de?'Veraltete Beobachtung; Werte gelten für die ursprüngliche Erfassung.':'Stale observation; values describe the original capture.');
 await expect(old.locator('.windows-session-membership')).toContainText('FIXTURE-WORKGROUP');await expect(old.locator('tbody tr')).toHaveCount(3);await expect(old.getByText('fixture-alex',{exact:true})).toBeVisible();
 await expect(old.locator('.windows-session-details')).not.toHaveAttribute('open');await expect(latest.locator('.windows-session-quality')).toHaveText([unavailable,unavailable]);
 await expect(panels.locator('a,img,iframe,form,input,button')).toHaveCount(0);
 expect(await previous.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
 // This second viewport shows the older date and its caution, not an artificial
 // simultaneous view of both full sections. The current failure remains in DOM.
 const oldHeader=old.locator('.windows-inventory-section-header');await oldHeader.scrollIntoViewIfNeeded();await oldHeader.evaluate(el=>el.scrollIntoView({block:'center',inline:'nearest',behavior:'instant'}));
 for(const item of [previous.locator('> summary'),caution,oldTime,old.locator('> .windows-inventory-caution')])await expect(item).toBeInViewport({ratio:1});
 await shot(page,`synthetic-windows-sessions-retained-details-${width}-${locale}`,windowsSessionContextDisclosure);
 await page.getByRole('tab',{name:'Hostname',exact:true}).click();await expect(panels).toHaveCount(0);
 await page.getByRole('tab',{name:tab,exact:true}).click();await expect(previous).not.toHaveAttribute('open');await expect(old).toBeHidden();await expect(latest.locator('.windows-session-quality')).toHaveText([unavailable,unavailable]);
}
/** Completion accepts only actual source-bound records from the shared runner. */
export function requireWindowsSessionContextEvidence(screenshots,sourceSha,testName){
 const fail=()=>{throw new Error('Windows session context completion evidence missing or inconsistent');};
 if(!Array.isArray(screenshots)||!(typeof sourceSha==='string'&&/^[a-f0-9]{40}$/.test(sourceSha))||typeof testName!=='string'||!testName)fail();
 const captured=screenshots.filter(item=>typeof item?.file==='string'&&/^synthetic-windows-sessions-/.test(item.file));if(captured.length!==16)fail();
 for(const kind of ['summary','details','current-failure','retained-details'])for(const locale of ['en','de'])for(const width of [1440,390]){
  const matches=captured.filter(item=>item.file===`synthetic-windows-sessions-${kind}-${width}-${locale}.png`);if(matches.length!==1)fail();
  const item=matches[0];if(item.sourceSha!==sourceSha||item.test!==testName||item.locale!==locale||item.viewport?.width!==width||item.viewport?.height!==(width===390?844:1000)||item.publicSafe!==true||item.fullPage!==false||item.fixtureDisclosure!==windowsSessionContextDisclosure)fail();
 }
 return {sessionSummary:4,sessionDetails:4,sessionCurrentFailure:4,sessionRetainedDetails:4};
}
