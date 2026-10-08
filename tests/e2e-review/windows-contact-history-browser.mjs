/** Additive invented accepted-contact coverage inside the existing hosted case.
 * No browser launch, host read, mutation, permission or fixture server setup. */
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {build}=require('esbuild');
const built=await build({stdin:{contents:"export {windowsContactView} from './windows-contact-fixture'; export {validWindowsContactView} from './windows-contact-types'; export {windowsNow,windowsDeviceId} from './windows-inventory-fixture';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {windowsContactView,validWindowsContactView,windowsNow,windowsDeviceId}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
export const windowsContactHistoryDisclosure='Invented manager-accepted report and incident records in the compiled UI with real loopback fixture login. Source-only test; no native Windows read, installed-service acceptance, notification, provider call or deployment.';
export const windowsContactHistoryStageNames=Object.freeze(['contact-overdue','contact-repeated','contact-unknown','contact-denied','contact-recovered']);
function shifted(value,now){if(Array.isArray(value))return value.map(row=>shifted(row,now));if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([key,row])=>[key,shifted(row,now)]));return typeof value==='string'&&/^2026-\d\d-\d\dT/.test(value)?new Date(Date.parse(value)+Date.parse(now)-Date.parse(windowsNow)).toISOString():value;}
export function windowsContactBrowserFixture(serverNow,origin=serverNow,phase='contact-overdue'){
 const incidentPhase=phase.startsWith('contact-'),value=shifted(windowsContactView(incidentPhase?'overdue':'recent'),origin);value.serverNow=serverNow;
 if(!incidentPhase){value.lastAcceptedAt=new Date(Date.parse(origin)-1000).toISOString();value.incidents=[];}
 if(Date.parse(serverNow)-Date.parse(value.evaluatedAt)>120000)value.status='unknown';
 if(phase==='contact-recovered'){
  const recoveryAcceptedAt=new Date(Date.parse(serverNow)-60000).toISOString();
  Object.assign(value.incidents[0],{resolvedAt:serverNow,recoveryAcceptedAt,recoverySequence:4,closedReason:'reports-resumed'});
  Object.assign(value,{status:'recent',evaluatedAt:serverNow,lastAcceptedAt:new Date(Date.parse(serverNow)-1000).toISOString(),sequence:5});
 }
 if(!validWindowsContactView(value,windowsDeviceId))throw new Error('Invalid invented contact fixture');return value;
}
export async function exerciseWindowsContactHistory({page,expect,locale,width,shot,setPhase,mark,advance}){
 const de=locale==='de',panel=page.locator('.windows-contact'),refresh=panel.getByRole('button',{name:de?'Meldungsverlauf aktualisieren':'Refresh contact history',exact:true});
 const metadata=page.getByRole('button',{name:de?'Gerätedaten aktualisieren':'Refresh device metadata',exact:true});
 const read=async()=>{await metadata.click();await expect(metadata).toBeEnabled();await refresh.click();await expect(refresh).toBeEnabled();};
 mark('contact-overdue');setPhase('contact-overdue');await read();
 await expect(panel.getByText(de?'Meldung überfällig · Vorfall offen':'Report overdue · incident open',{exact:true})).toBeVisible();
 const receipt=await panel.locator('.windows-contact-times').first().locator('time').first().getAttribute('datetime');
 mark('contact-repeated');await refresh.click();await expect(panel.locator('.windows-contact-times').first().locator('time').first()).toHaveAttribute('datetime',receipt);
 expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);await panel.scrollIntoViewIfNeeded();
 await shot(page,`synthetic-windows-contact-open-${width}-${locale}`,windowsContactHistoryDisclosure);
 mark('contact-unknown');await advance(121000);await read();
 await expect(panel.getByText(de?'Unbekannt':'Unknown',{exact:true})).toBeVisible();await expect(panel.getByText('wcontact_0000000000000001',{exact:true})).toBeVisible();
 await expect(panel.locator('.windows-contact-times').first().locator('time').first()).toHaveAttribute('datetime',receipt);
 await shot(page,`synthetic-windows-contact-unknown-${width}-${locale}`,windowsContactHistoryDisclosure);
 mark('contact-denied');setPhase('contact-denied');await refresh.click();await expect(panel.getByText('wcontact_0000000000000001',{exact:true})).toHaveCount(0);
 await expect(panel.getByText(de?'Unbekannt':'Unknown',{exact:true})).toBeVisible();
 mark('contact-recovered');setPhase('contact-recovered');await read();
 await expect(panel.getByText(de?'Aktuelle Meldung':'Recent report',{exact:true})).toBeVisible();await expect(panel.getByText(de?'Erholt':'Recovered',{exact:true})).toBeVisible();
 await expect(panel.getByText('wcontact_0000000000000001',{exact:true})).toBeVisible();
 await shot(page,`synthetic-windows-contact-recovered-${width}-${locale}`,windowsContactHistoryDisclosure);
}
