/** Hosted production-UI fixture gate. Importing starts no browser/server. */
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..'),require=createRequire(path.join(root,'web/package.json'));
const built=await require('esbuild').build({stdin:{contents:"export * from './windows-event-history-fixture'; export {validEventHistoryView,validEventHistoryResult,validHistorySearch} from './windows-event-history-types'; export {windowsDevice,windowsView,windowsDeviceId} from './windows-inventory-fixture';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {historyView,historyRecord,historyAccepted,historyResult,validEventHistoryView,validEventHistoryResult,validHistorySearch,windowsDevice,windowsView,windowsDeviceId}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
export const windowsEventHistoryCaseName='Private bounded Windows event history and selected-message followup';
export const windowsEventHistoryDisclosure='Production UI and real loopback login/CSRF with intercepted invented event headers/messages. Hosted browser fixture evidence only; no native event read, host grant, service action, external request, AI or export.';
let stage='setup';
const stages=new Set(['setup','login','search','paging','messages','layout','cancel','complete']);
export const windowsEventHistoryFailureStage=()=>stages.has(stage)?stage:'setup';
export async function windowsEventHistoryBrowserCase({page,expect,base,login,shot}){
 stage='login';await login(page);
 const prefix='/api/devices/'+windowsDeviceId,external=[],unexpected=[];let record=null,result=null,creates=0,messages=0,queries=0;
 const fulfill=(route,value,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(value)});
 await page.route('**/*',async route=>{
  const req=route.request(),url=new URL(req.url());if(url.origin!==base){external.push('external');return route.abort('blockedbyclient');}
  if(url.pathname.startsWith(prefix+'/windows-event-history')){
   const response=await page.request.get(base+'/api/auth/session',{maxRedirects:0,timeout:5000});let session;try{assert.equal(response.status(),200);session=await response.json();}finally{await response.dispose();}
   const now=session.serverNow,view=historyView(now,session.expiresAt),action=url.pathname.slice((prefix+'/windows-event-history').length);
   if(url.search||action&&!['/create','/messages','/query','/cancel'].includes(action)||req.method()!==(action?'POST':'GET')){unexpected.push('shape');return route.abort('blockedbyclient');}
   let body=null;if(action){assert.equal(req.headers()['x-csrf-token'],session.csrfToken);body=JSON.parse(req.postData());}
   if(record){view.request=record;view.expectedFloor=record.description.identity.sequence;view.contentStatus=record.state==='accepted'?'available':record.state;}
   if(action==='/create'){
    assert.deepEqual(Object.keys(body).sort(),['acknowledgeHistory','acknowledgePlaintext','expectedFloor','search']);assert.equal(body.acknowledgeHistory,true);assert.equal(body.acknowledgePlaintext,true);assert.equal(body.expectedFloor,view.expectedFloor);assert.ok(validHistorySearch(body.search,now));assert.ok(!record||record.state==='canceled');
    record=historyAccepted(historyRecord(view,body.search),now);result=historyResult(record);creates++;
   }else if(action==='/messages'){
    assert.deepEqual(Object.keys(body).sort(),['acknowledgeContent','acknowledgePlaintext','expectedFloor','receipt','selections']);assert.equal(body.acknowledgeContent,true);assert.equal(body.acknowledgePlaintext,true);assert.equal(body.expectedFloor,view.expectedFloor);assert.deepEqual(body.receipt,record.receipt);assert.ok(record.description.query.search);assert.ok(body.selections.length>0&&body.selections.length<=16);
    const rows=body.selections.map(s=>{assert.deepEqual(Object.keys(s).sort(),['channel','recordId']);const row=result.report.events.find(r=>r.event.channel===s.channel&&r.event.recordId===s.recordId);assert.ok(row);return row.event;});
    const prior=record;record=historyAccepted(historyRecord(view,undefined,prior,rows),now);assert.equal(record.description.expiresAt,prior.description.expiresAt);result=historyResult(record);messages++;
   }else if(action==='/query'){
    assert.deepEqual(body,{identity:record.description.identity});assert.equal(record.state,'accepted');const pageResult={...result,expiresAt:new Date(Math.min(Date.parse(result.expiresAt),Date.parse(session.expiresAt))).toISOString()};assert.ok(validEventHistoryResult(pageResult,record,session.expiresAt));queries++;return fulfill(route,pageResult);
   }else if(action==='/cancel'){
    if(JSON.stringify(body.identity)!==JSON.stringify(record?.description.identity))return fulfill(route,{error:{code:'windows_history_conflict'}},409);
    record={...record,state:'canceled',canceledAt:now};result=null;
   }
   if(record){view.request=record;view.expectedFloor=record.description.identity.sequence;view.contentStatus=record.state==='accepted'?'available':record.state;}
   assert.ok(validEventHistoryView(view,windowsDeviceId,session.expiresAt));return fulfill(route,view);
  }
  if(url.pathname===prefix){const d=windowsDevice();d.agentCertificate.expiresAt='2027-02-15T08:00:00Z';return fulfill(route,d);}
  if(url.pathname===prefix+'/windows-inventory'){const v=windowsView(),now=new Date().toISOString();v.serverNow=now;v.receivedAt=now;v.snapshot.collectedAt=now;return fulfill(route,v);}
  if(url.pathname.startsWith(prefix+'/'))return fulfill(route,{error:{code:'synthetic_unavailable'}},404);
  if(req.method()!=='GET'&&!['/api/auth/login','/api/auth/logout'].includes(url.pathname)){unexpected.push('write');return route.abort('blockedbyclient');}
  return route.continue();
 });
 const panel=page.locator('.windows-event-history');
 for(const locale of ['en','de'])for(const width of [1440,390]){
  const de=locale==='de';await page.setViewportSize({width,height:width===390?844:1000});await page.getByLabel(/Language|Sprache/).selectOption(locale);await page.goto(base+'/#/devices');record=null;result=null;await page.goto(base+'/#/devices/'+windowsDeviceId);await page.getByRole('tab',{name:'Logs',exact:true}).click();
  stage='search';const before=creates;await expect(panel.getByLabel(de?'Diesen Zeitraum für meine private Sitzung lesen.':'Read this time window for my private session.',{exact:true})).toBeEnabled();await panel.getByLabel(de?'Diesen Zeitraum für meine private Sitzung lesen.':'Read this time window for my private session.',{exact:true}).check();await panel.getByLabel(de?'HTTP überträgt Ereignisse und Nachrichten unverschlüsselt.':'HTTP sends headers and messages in plaintext.',{exact:true}).check();await panel.getByRole('button',{name:de?'Einmal suchen':'Search once',exact:true}).click();await expect(panel.locator('tbody>tr')).toHaveCount(10);expect(creates).toBe(before+1);
  stage='paging';const captured=queries;await panel.getByRole('button',{name:de?'Weiter':'Next',exact:true}).click();await panel.getByRole('searchbox').fill('Synthetic Provider 1');await expect(panel.locator('tbody>tr')).toHaveCount(10);await panel.getByRole('searchbox').fill('');expect(queries).toBe(captured);expect(creates).toBe(before+1);
  stage='layout';expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);await panel.evaluate(el=>el.scrollIntoView({block:'start',behavior:'instant'}));await shot(page,`synthetic-windows-event-history-search-${width}-${locale}`,windowsEventHistoryDisclosure);
  stage='messages';await panel.getByRole('checkbox',{name:(de?'Auswählen':'Select')+' Application 18446744073709551615',exact:true}).check();await panel.getByLabel(de?'Nachrichten können Zugangsdaten, persönliche Daten und andere Geheimnisse enthalten.':'Messages may contain credentials, personal data and other secrets.',{exact:true}).check();await panel.getByLabel(de?'Unverschlüsselte HTTP-Nachrichten erlauben.':'Allow plaintext HTTP messages.',{exact:true}).check();const beforeMessages=messages;await panel.getByRole('button',{name:de?'1 Nachrichten lesen':'Read 1 messages',exact:true}).click();await expect(panel.locator('.history-messages details')).toHaveCount(1);expect(messages).toBe(beforeMessages+1);await panel.locator('.history-messages summary').click();await expect(panel.locator('pre')).toContainText('<img src=x onerror=alert(1)>');await expect(panel.locator('img,iframe,a')).toHaveCount(0);expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);await panel.locator('.history-messages').scrollIntoViewIfNeeded();await shot(page,`synthetic-windows-event-history-messages-${width}-${locale}`,windowsEventHistoryDisclosure);
  stage='cancel';await panel.getByRole('button',{name:de?'Schließen / neue Suche':'Close / new search',exact:true}).click();await expect(panel.locator('pre')).toHaveCount(0);await expect(panel).toContainText(de?'Anfrage beendet.':'Request ended.');
 }
 expect(external).toEqual([]);expect(unexpected).toEqual([]);stage='complete';return{screens:8,nativeAcceptance:false,liveStoreAcceptance:false};
}
export function requireWindowsEventHistoryEvidence(rows,sourceSha){
 assert.match(sourceSha??'',/^[a-f0-9]{40}$/);assert.equal(rows.length,8);
 for(const kind of ['search','messages'])for(const locale of ['en','de'])for(const width of [1440,390]){
  const matches=rows.filter(row=>row.file===`synthetic-windows-event-history-${kind}-${width}-${locale}.png`);assert.equal(matches.length,1);const row=matches[0];assert.equal(row.sourceSha,sourceSha);assert.equal(row.test,windowsEventHistoryCaseName);assert.equal(row.locale,locale);assert.equal(row.viewport?.width,width);assert.equal(row.viewport?.height,width===390?844:1000);assert.equal(row.fullPage,false);assert.equal(row.publicSafe,true);assert.equal(row.fixtureDisclosure,windowsEventHistoryDisclosure);
 }
 return{search:4,messages:4};
}
