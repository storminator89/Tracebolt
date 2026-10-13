/** Inert retained-history fixture. Importing never launches a server/browser. */
import fs from 'node:fs';
import {createWindowsServiceActionsFixture,windowsServiceActionsRoute,windowsServiceActionsDisclosure} from './windows-service-actions-browser.mjs';
const golden=JSON.parse(fs.readFileSync(new URL('../fixtures/windows-service-action-history.json',import.meta.url),'utf8'));
export const windowsServiceActionHistoryCaseName='Synthetic retained Windows action history and exact receipt reads in the compiled UI';
let stage='setup';
export const windowsServiceActionHistoryFailureStage=()=>stage;
export function createWindowsServiceActionHistoryFixture(){
 const fixture=createWindowsServiceActionsFixture(golden.history.serverNow),counts={list:0,detail:0},latest=golden.details[0];
 return {...fixture,historyCounts:counts,history:structuredClone(golden.history),details:structuredClone(golden.details),
  view(){fixture.counts.status++;return {schemaVersion:'tracebolt.windows-service-action-view.v1',deviceId:golden.deviceId,serverNow:golden.history.serverNow,configured:true,available:false,reason:'stale',target:golden.history.binding.target,preview:null,job:structuredClone(latest.job)};},
  previewAction(){return null;},approveAction(){return null;},
 };
}
export function windowsServiceActionHistoryRoute({base,fixture,state}){
 const existing=windowsServiceActionsRoute({base,fixture,state}),path='/api/devices/'+fixture.device.id+'/windows-service-actions/history';
 return async route=>{
  const request=route.request(),url=new URL(request.url());
  if(url.origin!==base||!url.pathname.startsWith(path))return existing(route);
  if(request.method()!=='GET'||request.postData()!==null||url.search){state.blocked.push('history-shape');return route.abort('blockedbyclient');}
  let value;
  if(url.pathname===path){fixture.historyCounts.list++;value=fixture.history;}
  else {value=fixture.details.find(d=>url.pathname===path+'/'+d.job.identity.jobId);if(value)fixture.historyCounts.detail++;}
  if(!value){state.blocked.push('history-identity');return route.abort('blockedbyclient');}
  return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(value)});
 };
}
export async function exerciseWindowsServiceActionHistory({page,expect,base,fixture,locale,width,shot}){
 const de=locale==='de',title=de?'Gespeicherte Aktionshistorie':'Saved action history',read=de?'Beleg lesen':'Read receipt';
 stage='document';await page.goto(base+'/#/devices/'+fixture.device.id);await page.getByLabel(/Language|Sprache/).selectOption(locale);
 await page.getByRole('tab',{name:de?'Inventar':'Inventory',exact:true}).click();await page.getByRole('tab',{name:de?'Dienste':'Services',exact:true}).click();
 const history=page.locator('.windows-service-action-history'),toggle=history.getByRole('button',{name:title,exact:true});
 await expect(toggle).toHaveAttribute('aria-expanded','false');expect(fixture.historyCounts).toEqual({list:0,detail:0});
 stage='open-list';await toggle.click();await expect(history.locator('li')).toHaveCount(3);await expect(history.locator('.windows-service-action-history-receipt')).toHaveCount(0);
 stage='read-first';await history.getByRole('button',{name:read+' #1',exact:true}).click();const receipt=history.locator('.windows-service-action-history-receipt');
 await expect(receipt).toContainText(fixture.details[2].job.identity.jobId);await expect(receipt.locator('time').first()).toHaveAttribute('datetime',fixture.details[2].job.approvedAt);await expect(receipt).toContainText(de?'keinen Abschlusszeitpunkt':'no completion timestamp');
 stage='collapse';await toggle.click();await expect(history.locator('li')).toHaveCount(0);await toggle.click();await expect(history.locator('li')).toHaveCount(3);await expect(receipt).toHaveCount(0);
 stage='read-latest';await history.getByRole('button',{name:read+' #3',exact:true}).click();await expect(receipt).toContainText(fixture.details[0].job.identity.jobId);
 stage='capture';await history.evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));expect(await history.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);await expect(toggle).toBeInViewport();await expect(receipt.locator('time').first()).toBeInViewport();
 await shot(page,`synthetic-windows-service-action-history-${width}-${locale}`,windowsServiceActionsDisclosure);
 stage='guards';expect(fixture.historyCounts).toEqual({list:2,detail:2});expect(fixture.counts.preview).toBe(0);expect(fixture.counts.approve).toBe(0);
 stage='complete';return {list:2,detail:2,closeClearsReceipt:true,originalTimestamps:true,mutationRequests:0,nativeAcceptance:false};
}
export function requireWindowsServiceActionHistoryEvidence(screenshots,sourceSha){
 const fail=()=>{throw new Error('Windows action history evidence missing or inconsistent');};
 if(!Array.isArray(screenshots)||screenshots.length!==4||!/^[a-f0-9]{40}$/.test(sourceSha??''))fail();
 for(const locale of ['en','de'])for(const width of [1440,390]){
  const matches=screenshots.filter(item=>item?.file===`synthetic-windows-service-action-history-${width}-${locale}.png`);if(matches.length!==1)fail();const item=matches[0];
  if(item.sourceSha!==sourceSha||item.test!==windowsServiceActionHistoryCaseName||item.locale!==locale||item.viewport?.width!==width||item.viewport?.height!==(width===390?844:1000)||item.publicSafe!==true||item.fullPage!==false||item.fixtureDisclosure!==windowsServiceActionsDisclosure)fail();
 }
 return {screens:4,nativeAcceptance:false};
}
