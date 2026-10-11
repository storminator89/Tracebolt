/** Synthetic read-only patch context in the existing compiled Updates UI.
 * No native source, grant, installation, reboot, external call or clock advance. */
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {build}=require('esbuild');
const bundle=await build({stdin:{contents:"export {windowsPatchContext} from './windows-patch-context-fixture';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {windowsPatchContext}=await import('data:text/javascript;base64,'+Buffer.from(bundle.outputFiles[0].text).toString('base64'));
export const windowsPatchContextDisclosure='Invented OS, reboot indicators and retained Windows Update history in the production UI. UI-only fixture evidence; no native Windows read, consent, online scan, installation, reboot or AI export.';
export function addWindowsPatchContextFixture(view,phase='bounded'){
 if(!view.snapshot||phase==='legacy')return view;
 const context=windowsPatchContext(),capture=view.snapshot.collectedAt;
 context.generationId=view.snapshot.generationId;context.collectedAt=capture;
 context.history.rows.forEach((row,index)=>{row.occurredAt=new Date(Date.parse(capture)-(index+1)*86400000).toISOString();});
 if(phase==='empty')Object.assign(context.history,{rows:[],totalCount:0,truncated:false});
 if(['partial','partial-empty'].includes(phase))Object.assign(context.history,{quality:'partial',reason:'windows_patch_context_partial_result',countExact:false,...(phase==='partial-empty'?{rows:[],totalCount:0,truncated:false}:{})});
 if(['denied','unavailable'].includes(phase))Object.assign(context.history,{quality:phase,reason:phase==='denied'?'windows_patch_context_access_denied':'windows_patch_context_unavailable',countExact:false,rows:[],totalCount:0,truncated:false});
 view.patchContext=context;return view;
}
export async function exerciseWindowsPatchContext({page,expect,locale,width,shot}){
 const de=locale==='de',panel=page.locator('.windows-patch-context'),details=panel.locator('.windows-patch-details'),table=panel.locator('.windows-patch-history-table');
 await expect(panel).toBeVisible();await expect(panel.locator('.windows-patch-os')).toHaveText(`Windows 11 Pro · ${de?'Version':'Release'} 24H2 · Build 26100.1000`);
 await expect(panel.locator('.windows-patch-reboot')).toHaveText(`${de?'Neustartindikatoren: Ausstehend':'Reboot indicators: Pending'}`);
 await expect(details).not.toHaveAttribute('open');await expect(table).toBeHidden();await expect(details.locator('> summary')).toContainText(de?'2 angezeigt · 8 gespeicherte Ereignisse':'2 shown · 8 retained events');
 await panel.locator('.windows-inventory-section-header').evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));
 expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
 await shot(page,`synthetic-windows-patch-context-${width}-${locale}`,windowsPatchContextDisclosure);
 await details.locator('> summary').click();await expect(table).toBeVisible();await expect(table.locator('tbody tr')).toHaveCount(2);
 await expect(panel.locator('.windows-patch-sources dd')).toHaveText(de?['Ausstehend','Keine gemeldet','Nicht verfügbar']:['Pending','None reported','Unavailable']);
 await expect(panel).toContainText(de?'kein aktueller Installationsbestand':'not current installed inventory');
 const labels=de?['Update','Aufgezeichnet am','Vorgang','Ergebnis']:['Update','Recorded at','Operation','Result'];
 for(const label of labels){
  if(width===1440)await expect(table.getByRole('columnheader',{name:label,exact:true})).toBeVisible();
  else {const cell=table.locator('tbody tr').first().locator(`td[data-label="${label}"]`);await expect(cell).toBeVisible();expect(await cell.evaluate(el=>getComputedStyle(el,'::before').content)).toBe(JSON.stringify(label));}
 }
 await expect(table).toContainText(de?'Deinstallation':'Uninstallation');await expect(table).toContainText('HRESULT: 80240022');await expect(table).toContainText(de?'Titel gekürzt':'Title shortened');
 await expect(panel.locator('a,img,iframe,form,input,button')).toHaveCount(0);
 expect(await table.evaluate(el=>{const r=el.getBoundingClientRect(),p=el.closest('[role="tabpanel"]').getBoundingClientRect();return r.left>=p.left-1&&r.right<=p.right+1&&el.scrollWidth<=el.clientWidth+1;})).toBe(true);
 if(width===390)await table.locator('tbody tr').first().scrollIntoViewIfNeeded();
 else await details.locator('> summary').scrollIntoViewIfNeeded();
 await expect(table.locator('tbody tr').first()).toBeInViewport({ratio:1});
 await shot(page,`synthetic-windows-patch-history-${width}-${locale}`,windowsPatchContextDisclosure);
 await details.locator('> summary').click();await expect(table).toBeHidden();
}
/** Screenshot records are appended only after actual browser capture succeeds. */
export function requireWindowsPatchContextEvidence(screenshots,sourceSha,testName){
 const fail=()=>{throw new Error('Windows patch context completion evidence missing or inconsistent');};
 if(!Array.isArray(screenshots)||!(sourceSha===null||typeof sourceSha==='string'&&/^[a-f0-9]{40}$/.test(sourceSha))||typeof testName!=='string'||!testName)fail();
 const captured=screenshots.filter(item=>typeof item?.file==='string'&&/^synthetic-windows-patch-(context|history)-/.test(item.file));
 if(captured.length!==8)fail();
 for(const kind of ['context','history'])for(const locale of ['en','de'])for(const width of [1440,390]){
  const matches=captured.filter(item=>item.file===`synthetic-windows-patch-${kind}-${width}-${locale}.png`);if(matches.length!==1)fail();
  const item=matches[0];if(item.sourceSha!==sourceSha||item.test!==testName||item.locale!==locale||item.viewport?.width!==width||item.viewport?.height!==(width===390?844:1000)||item.publicSafe!==true||item.fullPage!==false||typeof item.fixtureDisclosure!=='string'||!item.fixtureDisclosure.trim())fail();
 }
 return {patchContext:4,patchHistory:4};
}
