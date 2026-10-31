/** Synthetic selected-content overlay for the existing Windows browser case.
 * No endpoint/native read, grant, browser launch or external destination. */
import assert from 'node:assert/strict';
import {settlePausedDetailRoute} from './paused-detail-route.mjs';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..'),require=createRequire(path.join(root,'web/package.json'));
const built=await require('esbuild').build({stdin:{contents:"export * from './windows-event-content-fixture'; export {validEventContentView,validEventContentResult} from './windows-event-content-types';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {eventContentView,eventContentRecord,eventContentAccepted,eventContentResult,validEventContentView,validEventContentResult}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
export const windowsEventContentDisclosure='Invented selected Windows messages through the production UI and real session/CSRF reads. UI-only fixture evidence; no native event read, local grant, host changes, AI call or external request.';
export const windowsEventContentStages=Object.freeze(['content-open','content-select','content-review','content-create','content-poll','content-result','content-literal','content-search','content-layout','content-screenshot','content-cancel']);
export function createWindowsEventContentFixture(){
 let record=null,ready=false,creates=0,queries=0,cancels=0,hideCreatedResponse=false;
 return {
  counts:()=>({creates,queries,cancels}),reset(){record=null;ready=false;hideCreatedResponse=false;},loseCreatedResponse(){hideCreatedResponse=true;},releaseCreatedResponse(){hideCreatedResponse=false;},settleCanceled(){assert.ok(record);record={...record,state:'canceled',canceledAt:record.description.createdAt};},complete(){assert.ok(record);ready=true;},
  response({action,body,serverNow,sessionExpiresAt,headers,enabled}){
   const view=eventContentView(serverNow);view.sessionExpiresAt=sessionExpiresAt;view.capability.reportedAt=serverNow;view.capability.expiresAt=new Date(Date.parse(serverNow)+300000).toISOString();
   if(!enabled){view.localStatus='disabled';view.capability.enabled=false;delete view.headers;record=null;ready=false;}
   else {assert.ok(headers);view.headers={generationId:headers.generationId,snapshotDigest:'sha256:'+'3'.repeat(64),collectedAt:headers.collectedAt,expiresAt:new Date(Date.parse(headers.collectedAt)+86400000).toISOString()};}
   if(record){view.request=record;view.expectedFloor=record.description.identity.sequence;view.contentStatus=record.state==='accepted'?'available':record.state;}
   if(action==='create'){
    assert.equal(enabled,true);assert.equal(record,null);assert.deepEqual(Object.keys(body).sort(),['acknowledgeContent','acknowledgePlaintext','expectedFloor','expectedHeaderGenerationId','expectedHeaderSnapshotDigest','selections']);assert.equal(body.acknowledgeContent,true);assert.equal(body.acknowledgePlaintext,true);assert.equal(body.expectedFloor,'0');assert.equal(body.expectedHeaderGenerationId,view.headers.generationId);assert.equal(body.expectedHeaderSnapshotDigest,view.headers.snapshotDigest);
    assert.ok(Array.isArray(body.selections)&&body.selections.length>0&&body.selections.length<=16);const seen=new Set(),events=body.selections.map(selection=>{assert.deepEqual(Object.keys(selection).sort(),['channel','recordId']);assert.equal(typeof selection.recordId,'string');const key=selection.channel+':'+selection.recordId;assert.equal(seen.has(key),false);seen.add(key);const channel=headers.channels.find(c=>c.channel===selection.channel),row=channel?.rows.find(r=>r.recordId===selection.recordId);assert.ok(row);return {...row,channel:channel.channel};});
    record=eventContentRecord(events,view);view.request=record;view.expectedFloor=record.description.identity.sequence;view.contentStatus='pending';creates++;
   } else if(action==='cancel'){
    assert.equal(enabled,true);assert.ok(record);assert.deepEqual(Object.keys(body),['identity']);assert.deepEqual(body.identity,record.description.identity);record={...record,state:'canceled',canceledAt:serverNow};view.request=record;view.contentStatus='canceled';cancels++;
   } else if(action==='query'){
    assert.equal(enabled,true);assert.equal(record?.state,'accepted');assert.deepEqual(Object.keys(body),['identity']);assert.deepEqual(body.identity,record.description.identity);const result=eventContentResult(record);
    if(result.report.events.length>1){Object.assign(result.report,{quality:'partial',complete:false});Object.assign(result.report.events[1],{message:'',quality:'unavailable',complete:false,reason:'windows_event_content_publisher_unavailable'});}
    // The request/receipt keeps its original 15-minute lifetime. Disclosure is
    // separately bounded by this real authenticated session, as in the manager.
    result.expiresAt=new Date(Math.min(Date.parse(result.expiresAt),Date.parse(sessionExpiresAt))).toISOString();
    assert.equal(validEventContentResult(result,record,sessionExpiresAt),true);queries++;return result;
   } else {assert.equal(action,'');assert.equal(body,null);if(ready&&record?.state==='pending'){record=eventContentAccepted(record);view.request=record;view.contentStatus='available';}}
   // Commit privately but hide its response/status until explicitly released.
   // No network failure or additional diagnostic exemption is needed.
   if(hideCreatedResponse&&action==='create')return {};
   if(hideCreatedResponse&&action===''){view.request=null;view.expectedFloor='0';view.contentStatus='unavailable';}
   assert.equal(validEventContentView(view,view.deviceId,sessionExpiresAt),true);return view;
  }
 };
}
export async function exerciseWindowsEventContent({page,expect,locale,width,shot,setPhase,advance,fixture,mark=()=>{}}){
 const de=locale==='de',logs=page.locator('.windows-logs'),panel=page.locator('.windows-event-content');fixture.reset();setPhase('event-content');
 mark('content-open');await logs.getByRole('button',{name:de?'Stichprobe aktualisieren':'Refresh sample',exact:true}).click();await expect(logs.getByRole('table')).toBeVisible();await panel.getByRole('button',{name:de?'Inhaltsstatus prüfen':'Check content status',exact:true}).click();
 const first=logs.getByRole('checkbox',{name:(de?'Auswählen':'Select')+' Application 18446744073709551615',exact:true}),second=logs.getByRole('checkbox',{name:(de?'Auswählen':'Select')+' System 18446744073709551615',exact:true});
 mark('content-select');await expect(first).toBeEnabled();const before=fixture.counts();await first.check();await second.check();expect(fixture.counts()).toEqual(before);
 mark('content-review');await panel.getByRole('button',{name:de?'Auswahl prüfen':'Review selection',exact:true}).click();const review=panel.getByRole('group',{name:de?'Genau diese Auswahl bestätigen':'Confirm this exact selection',exact:true}),create=review.getByRole('button',{name:de?'Einmalig Nachrichten anfordern':'Request messages once',exact:true});await expect(review.locator('li')).toHaveCount(2);await expect(create).toBeDisabled();await review.getByRole('checkbox').nth(0).check();await expect(create).toBeDisabled();await review.getByRole('checkbox').nth(1).check();
 mark('content-create');await create.focus();await page.keyboard.press('Enter');await expect(panel).toContainText(de?'Wartet auf Endpunkt':'Waiting for endpoint');expect(fixture.counts().creates).toBe(before.creates+1);fixture.complete();
 mark('content-poll');await advance(3000);mark('content-result');await expect(panel.locator('.windows-event-message')).toBeVisible();await expect(panel).toContainText(de?'Teilweise verfügbar':'Partially available');await expect(panel).toContainText(de?'Publisher-Ressourcen sind nicht verfügbar.':'Publisher resources are unavailable.');expect(fixture.counts().queries).toBe(before.queries+1);
 mark('content-literal');await expect(panel.locator('.windows-event-message')).toContainText('<img src=x onerror=alert(1)>');await expect(panel.locator('img,a,iframe')).toHaveCount(0);
 mark('content-search');const search=panel.getByRole('searchbox');const captured=fixture.counts();await search.fill('no synthetic match');await expect(panel.locator('.windows-event-message')).toHaveCount(0);await search.fill('');await expect(panel.locator('.windows-event-message')).toBeVisible();expect(fixture.counts()).toEqual(captured);
 mark('content-layout');expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);expect(await panel.locator('.windows-event-message').evaluate(el=>getComputedStyle(el).whiteSpace)).toBe('pre-wrap');
 mark('content-screenshot');await panel.locator('.windows-event-message').scrollIntoViewIfNeeded();await shot(page,`synthetic-windows-selected-messages-${width}-${locale}`,windowsEventContentDisclosure);
 mark('content-cancel');await panel.getByRole('button',{name:de?'Abbrechen und Inhalte verwerfen':'Cancel and discard content',exact:true}).click();await expect(panel.locator('.windows-event-message')).toHaveCount(0);await expect(panel).toContainText(de?'Anfragestatus: Abgebrochen':'Request status: Canceled');expect(fixture.counts().cancels).toBe(before.cancels+1);
 const base=new URL(page.url()).origin,deviceId=eventContentView().deviceId;
 const leave=async()=>{await page.goto(`${base}/#/devices`);await expect(panel).toHaveCount(0);};
 const returnToLogs=async()=>{await page.goto(`${base}/#/devices/${deviceId}`);const tab=page.getByRole('tab',{name:'Logs',exact:true});await settlePausedDetailRoute(page,expect,tab);await tab.click();await expect(logs.getByRole('table')).toBeVisible();};
 await leave();fixture.reset();fixture.loseCreatedResponse();await returnToLogs();await expect(first).toBeEnabled();await first.check();await panel.getByRole('button',{name:de?'Auswahl prüfen':'Review selection',exact:true}).click();await review.getByRole('checkbox').nth(0).check();await review.getByRole('checkbox').nth(1).check();await create.click();
 await expect(panel).toContainText(de?'Das Ergebnis der Anfrage ist ungewiss.':'The request outcome is uncertain.');await expect(panel.getByRole('button',{name:de?'Auswahl prüfen':'Review selection',exact:true})).toBeDisabled();await expect.poll(()=>fixture.counts().creates).toBe(before.creates+2);
 await leave();await returnToLogs();await expect(panel.locator('.windows-event-message')).toHaveCount(0);await expect(first).not.toBeChecked();await expect(review).toHaveCount(0);await expect(panel.getByRole('button',{name:de?'Auswahl prüfen':'Review selection',exact:true})).toBeDisabled();
 await expect(panel).toContainText(de?'Das Ergebnis der Anfrage ist ungewiss.':'The request outcome is uncertain.');await expect(panel.getByRole('button',{name:de?'Inhaltsstatus prüfen':'Check content status',exact:true})).toBeEnabled();fixture.settleCanceled();fixture.releaseCreatedResponse();await panel.getByRole('button',{name:de?'Inhaltsstatus prüfen':'Check content status',exact:true}).click();await expect(panel).toContainText(de?'Anfragestatus:':'Request status:');await expect(panel.locator('.windows-event-message')).toHaveCount(0);expect(fixture.counts().queries).toBe(before.queries+1);expect(fixture.counts().creates).toBe(before.creates+2);
 await expect(panel).toContainText(de?'Anfragestatus: Abgebrochen':'Request status: Canceled');expect(fixture.counts().queries).toBe(before.queries+1);setPhase('fresh');
}
