/** Inert production-UI fixture helper. Importing starts no browser or server. */
import assert from 'node:assert/strict';
import {fleetGroupsCaseName,fleetGroupsDisclosure,fleetGroupsCaptureMatrix,fleetGroupsCaptureName} from './fleet-groups-evidence.mjs';
export {fleetGroupsCaseName,fleetGroupsDisclosure,fleetGroupsCaptureMatrix,fleetGroupsCaptureName,fleetGroupsScenes,requireFleetGroupsEvidence} from './fleet-groups-evidence.mjs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..'),require=createRequire(path.join(root,'web/package.json'));
const built=await require('esbuild').build({stdin:{contents:"export {windowsCapacityDevice,windowsCapacityView} from './windows-capacity-fixture'; export {windowsResourceView} from './windows-resource-fixture'; export {validFleetGroupsView} from './fleet-groups-types'; export {validWindowsPercentageView} from './windows-capacity-types'; export {validGroupMonitoringView} from './fleet-group-monitoring-types';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {windowsCapacityDevice,windowsCapacityView,windowsResourceView,validFleetGroupsView,validWindowsPercentageView,validGroupMonitoringView}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
export const fleetGroupIds={first:`agent_${'7'.repeat(32)}`,second:`agent_${'2'.repeat(32)}`,linux:`agent_${'3'.repeat(32)}`,group:`group_${'4'.repeat(32)}`,created:`group_${'5'.repeat(32)}`};
let stage='setup',failures=0,pending=0;
export const fleetGroupsRouteState=()=>({failures,pending});
export const fleetGroupsFailureStage=()=>new Set(['setup','login','groups','review','apply','conflict','uncertain','uncertain-review','uncertain-apply','uncertain-result','uncertain-remaining','uncertain-count','uncertain-close','stop','layout','inheritance','complete']).has(stage)?stage:'setup';
export function guardFleetGroupsRoute(route,handler){pending++;return Promise.resolve().then(()=>handler(route)).catch(async()=>{failures++;try{await route.abort('failed');}catch{/* Teardown already ended the request. */}}).finally(()=>{pending--;});}
export function fleetGroupsBrowserFixture(serverNow,expiresAt){
 const source=windowsCapacityDevice(),devices=[{id:fleetGroupIds.first,name:'Synthetic Desk One',platform:'windows'},{id:fleetGroupIds.second,name:'Synthetic Desk Two',platform:'windows'},{id:fleetGroupIds.linux,name:'Synthetic Linux',platform:'linux'}];
 const view={schemaVersion:'tracebolt.fleet-groups.v1',serverNow,groups:[{id:fleetGroupIds.group,name:'Synthetic Office',revision:2,memberIds:devices.map(d=>d.id),unavailableMembers:1}],devices};assert.ok(validFleetGroupsView(view));
 const metadata=devices.map(d=>({...source,...d,os:d.platform==='windows'?'Windows fixture':'Linux fixture',status:'unknown',agentCertificate:{source:'guided-enrollment',expiresAt,checkedAt:serverNow}}));
 return{view,metadata};
}
export function fleetGroupsPolicyFixture(serverNow,expiresAt,id,metric,policy){
 const value={...(metric==='disk'?windowsCapacityView(policy.enabled?'unknown':'disabled'):windowsResourceView(metric,policy.enabled?'unknown':'disabled')),deviceId:id,serverNow,certificateExpiresAt:expiresAt,policy:{...policy},evaluatedAt:null,observation:null,incidents:[]};assert.ok(validWindowsPercentageView(value,id,metric));return value;
}
export function fleetGroupsMonitoringFixture(serverNow,expiresAt,groupRevision=2){
 const devices=fleetGroupsBrowserFixture(serverNow,expiresAt).view.devices.filter(d=>d.platform==='windows');
 const targets=devices.flatMap(d=>['disk','cpu','memory'].map(metric=>({deviceId:d.id,name:d.name,metric,assignmentRevision:0,policy:{enabled:false,thresholdPercent:90,revision:0},desired:null,status:'manual',owned:false,certificateExpiresAt:expiresAt})));
 Object.assign(targets[0],{status:'pending',owned:true,assignmentRevision:2,desired:{enabled:true,thresholdPercent:90}});
 Object.assign(targets[2],{status:'inherited',owned:true,assignmentRevision:4,policy:{enabled:true,thresholdPercent:85,revision:7},desired:{enabled:true,thresholdPercent:85}});
 Object.assign(targets[4],{status:'manual-override',assignmentRevision:3,policy:{enabled:true,thresholdPercent:87,revision:5},desired:{enabled:true,thresholdPercent:91}});
 const view={schemaVersion:'tracebolt.fleet-group-monitoring.v1',serverNow,groupId:fleetGroupIds.group,groupRevision,revision:7,definitions:[{metric:'disk',enabled:true,thresholdPercent:90},{metric:'memory',enabled:true,thresholdPercent:85}],targets,unavailableAssignments:1};assert.ok(validGroupMonitoringView(view,fleetGroupIds.group));return view;
}
export async function fleetGroupsBrowserCase({page,expect,base,login,shot}){
 stage='login';failures=0;pending=0;await login(page);
 let groupRows=[],policies=new Map(),policyPosts=0,groupPosts=0,monitoring=null,monitoringPosts=0,mode='normal',release=null,held=false;
 const external=[],unexpected=[],ids=fleetGroupIds;
 const getSession=async()=>{const response=await page.request.get(base+'/api/auth/session',{maxRedirects:0,timeout:5000});try{assert.equal(response.status(),200);const session=await response.json();assert.equal(session.authenticated,true);assert.equal(session.loginMode,'shared');return session;}finally{await response.dispose();}};
 const fulfill=(route,value,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(value)});
 const handle=async route=>{
  const req=route.request(),url=new URL(req.url());if(url.origin!==base){external.push('external');return route.abort('blockedbyclient');}
  if(url.pathname==='/api/overview'){
   assert.equal(req.method(),'GET');assert.equal(url.search,'');const response=await route.fetch({maxRedirects:0,timeout:5000});let value;try{assert.equal(response.status(),200);value=await response.json();}finally{await response.dispose();}
   const session=await getSession(),fixture=fleetGroupsBrowserFixture(session.serverNow,session.expiresAt);return fulfill(route,{...value,devices:fixture.metadata,stats:{...value.stats,totalDevices:3,healthyDevices:0,attentionDevices:0},generatedAt:session.serverNow});
  }
  if(url.pathname==='/api/fleet/groups'||url.pathname===`/api/fleet/groups/${ids.group}`||url.pathname===`/api/fleet/groups/${ids.created}`||url.pathname===`/api/fleet/groups/${ids.created}/delete`){
   assert.equal(url.search,'');assert.ok(['GET','POST'].includes(req.method()));const session=await getSession(),fixture=fleetGroupsBrowserFixture(session.serverNow,session.expiresAt);
   if(req.method()==='POST'){
    assert.equal(req.headers()['x-csrf-token'],session.csrfToken);const body=JSON.parse(req.postData());groupPosts++;
    if(url.pathname==='/api/fleet/groups'){assert.deepEqual(Object.keys(body).sort(),['expectedRevision','memberIds','name']);assert.equal(body.expectedRevision,0);assert.deepEqual(body.memberIds,[ids.first]);assert.equal(body.name,'Synthetic Temporary');groupRows.push({id:ids.created,name:body.name,revision:1,memberIds:[...body.memberIds],unavailableMembers:0});}
    else if(url.pathname.endsWith('/delete')){assert.deepEqual(body,{expectedRevision:1});groupRows=groupRows.filter(g=>g.id!==ids.created);}
    else{assert.deepEqual(Object.keys(body).sort(),['expectedRevision','memberIds','name','removeUnavailableMembers']);const group=groupRows.find(g=>g.id===ids.group);assert.equal(body.expectedRevision,group.revision);assert.equal(body.removeUnavailableMembers,false);assert.deepEqual(body.memberIds,[ids.first,ids.second,ids.linux]);group.name=body.name;group.revision++;assert.equal(group.unavailableMembers,1);}
   }
   const one=req.method()==='GET'&&url.pathname!=='/api/fleet/groups';const view={...fixture.view,groups:one?groupRows.filter(g=>url.pathname.endsWith(g.id)):groupRows};assert.ok(validFleetGroupsView(view));return fulfill(route,view);
  }
  if(url.pathname===`/api/fleet/groups/${ids.group}/monitoring`){
   assert.equal(url.search,'');assert.ok(['GET','POST'].includes(req.method()));const session=await getSession();
   monitoring??=fleetGroupsMonitoringFixture(session.serverNow,session.expiresAt,groupRows.find(g=>g.id===ids.group).revision);
   monitoring.serverNow=session.serverNow;for(const target of monitoring.targets)target.certificateExpiresAt=session.expiresAt;
   if(req.method()==='POST'){
    assert.equal(req.headers()['x-csrf-token'],session.csrfToken);const body=JSON.parse(req.postData());assert.deepEqual(Object.keys(body).sort(),['assignments','consent','definitions','expectedGroupRevision','expectedRevision']);assert.equal(body.expectedGroupRevision,monitoring.groupRevision);assert.equal(body.expectedRevision,monitoring.revision);
    const stopping=body.definitions.length===0;assert.equal(body.consent,!stopping);assert.deepEqual(body.definitions,stopping?[]:[{metric:'cpu',enabled:true,thresholdPercent:91}]);
    const target=monitoring.targets.find(t=>t.deviceId===ids.first&&t.metric===(stopping?'memory':'cpu'));assert.deepEqual(body.assignments,[{deviceId:ids.first,metric:target.metric,expectedRevision:target.assignmentRevision,expectedPolicyRevision:target.policy.revision,inherit:!stopping}]);monitoringPosts++;
    if(!stopping){monitoring.revision++;monitoring.definitions.push(...body.definitions);}target.assignmentRevision++;target.owned=!stopping;target.status=stopping?'stopped':'pending';target.desired=stopping?null:{enabled:true,thresholdPercent:91};
   }
   assert.ok(validGroupMonitoringView(monitoring,ids.group));return fulfill(route,monitoring);
  }
  const deviceMatch=/^\/api\/devices\/(agent_[a-f0-9]{32})(?:\/(windows-capacity|windows-resource\/(cpu|memory))(\/policy)?)?$/.exec(url.pathname);
  if(deviceMatch&&[ids.first,ids.second].includes(deviceMatch[1])){
   assert.equal(url.search,'');const id=deviceMatch[1],session=await getSession();
   if(!deviceMatch[2]){assert.equal(req.method(),'GET');return fulfill(route,fleetGroupsBrowserFixture(session.serverNow,session.expiresAt).metadata.find(d=>d.id===id));}
   const metric=deviceMatch[3]??'disk',key=id+':'+metric,policy=policies.get(key)??{enabled:false,thresholdPercent:90,revision:0};
   if(deviceMatch[4]){
    assert.equal(req.method(),'POST');assert.equal(req.headers()['x-csrf-token'],session.csrfToken);const body=JSON.parse(req.postData());assert.deepEqual(Object.keys(body).sort(),['enabled','expectedRevision','thresholdPercent']);assert.equal(body.expectedRevision,policy.revision);assert.equal(body.enabled,true);assert.equal(body.thresholdPercent,90);policyPosts++;
    if(mode==='conflict')return fulfill(route,{error:{code:'conflict'}},409);
    if(mode==='hold'){held=true;const reason=await new Promise(resolve=>{release=()=>resolve('explicit-stop');});held=false;assert.equal(reason,'explicit-stop');try{return await route.abort('failed');}catch(error){if(req.failure()?.errorText!=='net::ERR_ABORTED')throw error;return;}}
    policies.set(key,{enabled:body.enabled,thresholdPercent:body.thresholdPercent,revision:policy.revision+1});
    if(mode==='uncertain')return route.abort('failed');
   }else assert.equal(req.method(),'GET');
   return fulfill(route,fleetGroupsPolicyFixture(session.serverNow,session.expiresAt,id,metric,policies.get(key)??policy));
  }
  const allowedRead=['/api/auth/session','/api/session','/api/enrollment','/api/windows/enrollment','/api/fleet/identities'];
  if(req.method()==='GET'&&!url.pathname.startsWith('/api/'))return route.continue();
  if(req.method()==='GET'&&allowedRead.includes(url.pathname)&&!url.search)return route.continue();
  unexpected.push('unexpected-route');return route.abort('blockedbyclient');
 };
 await page.route('**/*',route=>guardFleetGroupsRoute(route,handle));
 const verifyPolicyLayout=async()=>{
  const layout=await page.getByRole('dialog').getByRole('table').evaluate(table=>{
   const wrap=table.parentElement,bounds=wrap.getBoundingClientRect();
   return{overflow:wrap.scrollWidth-wrap.clientWidth,cells:[...table.querySelectorAll('tbody td')].map(cell=>{const rect=cell.getBoundingClientRect();return{left:rect.left-bounds.left,right:bounds.right-rect.right,overflow:cell.scrollWidth-cell.clientWidth};})};
  });
  expect(layout.overflow).toBeLessThanOrEqual(1);expect(layout.cells.length).toBeGreaterThan(0);
  for(const cell of layout.cells){expect(cell.left).toBeGreaterThanOrEqual(-1);expect(cell.right).toBeGreaterThanOrEqual(-1);expect(cell.overflow).toBeLessThanOrEqual(1);}
 };
 for(const locale of ['en','de'])for(const width of [1440,390]){
  const de=locale==='de';await page.setViewportSize({width,height:width===390?844:1000});await page.getByRole('combobox',{name:/Language|Sprache/}).selectOption(locale);const session=await getSession();groupRows=fleetGroupsBrowserFixture(session.serverNow,session.expiresAt).view.groups;policies=new Map([[ids.second+':cpu',{enabled:true,thresholdPercent:90,revision:1}]]);mode='normal';monitoring=null;await page.reload();await expect(page.locator('.app-shell')).toBeVisible();
  stage='groups';await page.getByRole('button',{name:de?'Flottengruppen':'Fleet groups',exact:true}).click();const manage=page.getByRole('button',{name:de?'Gruppen verwalten':'Manage groups',exact:true});await expect(manage).toBeEnabled();
  await manage.click();await page.getByRole('button',{name:de?'Gruppe erstellen':'Create group',exact:true}).click();await page.getByRole('textbox',{name:de?'Gruppenname':'Group name'}).fill('Synthetic Temporary');await page.getByRole('checkbox',{name:`Synthetic Desk One Windows · ${ids.first}`,exact:true}).check();const beforeCreate=groupPosts;await page.getByRole('button',{name:de?'Gruppenänderungen prüfen':'Review group changes',exact:true}).click();expect(groupPosts).toBe(beforeCreate);await page.getByRole('button',{name:de?'Geprüfte Gruppe speichern':'Save reviewed group',exact:true}).click();await expect(page.getByRole('dialog')).toHaveCount(0);expect(groupPosts).toBe(beforeCreate+1);
  await manage.click();await page.getByRole('button',{name:'Synthetic Temporary',exact:true}).click();await page.getByRole('button',{name:de?'Gruppe löschen':'Delete group',exact:true}).click();expect(groupPosts).toBe(beforeCreate+1);await page.getByRole('button',{name:de?'Löschen der Gruppe bestätigen':'Confirm group deletion',exact:true}).click();await expect(page.getByRole('dialog')).toHaveCount(0);expect(groupPosts).toBe(beforeCreate+2);
  await manage.click();await page.getByRole('button',{name:'Synthetic Office',exact:true}).click();await expect(page.getByRole('checkbox',{name:de?'Nicht verfügbare Mitglieder entfernen (1)':'Remove unavailable members (1)',exact:true})).not.toBeChecked();stage='layout';expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);await shot(page,fleetGroupsCaptureName('groups',width,locale),fleetGroupsDisclosure);
  await page.getByRole('textbox',{name:de?'Gruppenname':'Group name'}).fill('Synthetic Office reviewed');await page.getByRole('button',{name:de?'Gruppenänderungen prüfen':'Review group changes',exact:true}).click();await expect(page.getByText(de?'Nicht verfügbare Mitglieder bleiben erhalten. (1)':'Unavailable members will be retained. (1)',{exact:true})).toBeVisible();await page.getByRole('button',{name:de?'Geprüfte Gruppe speichern':'Save reviewed group',exact:true}).click();await expect(page.getByRole('dialog')).toHaveCount(0);
  await page.getByRole('combobox',{name:de?'Flottengruppen':'Fleet groups',exact:true}).selectOption(ids.group);
  const prepare=async (metrics,captureDraft=false)=>{
   await page.getByRole('button',{name:de?'Monitoring-Richtlinien anwenden':'Apply monitoring policies',exact:true}).click();
   const labels=de?{disk:'Kapazität des Systemvolumes',cpu:'CPU-Prozentwert',memory:'Physischer RAM-Prozentwert'}:{disk:'System-volume capacity',cpu:'CPU percentage',memory:'Physical RAM percentage'};
   for(const label of Object.values(labels)){await expect(page.getByRole('checkbox',{name:(de?'Einbeziehen ':'Include ')+label,exact:true})).not.toBeChecked();await expect(page.getByRole('checkbox',{name:(de?'Diese Richtlinie aktivieren':'Enable this policy')+' · '+label,exact:true})).not.toBeChecked();}
   for(const metric of Array.isArray(metrics)?metrics:[metrics]){await page.getByRole('checkbox',{name:(de?'Einbeziehen ':'Include ')+labels[metric],exact:true}).check();await page.getByRole('checkbox',{name:(de?'Diese Richtlinie aktivieren':'Enable this policy')+' · '+labels[metric],exact:true}).check();}
   for(const [name,id]of[['Synthetic Desk One',ids.first],['Synthetic Desk Two',ids.second]])await page.getByRole('checkbox',{name:name+' '+id,exact:true}).check();
   if(captureDraft){expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);await shot(page,fleetGroupsCaptureName('draft',width,locale),fleetGroupsDisclosure);}
   await page.getByRole('button',{name:de?'Exakte Änderungen prüfen':'Review exact changes',exact:true}).click();await expect(page.getByRole('button',{name:de?'Geprüfte Richtlinien anwenden':'Apply reviewed policies',exact:true})).toBeEnabled();
  };
  const apply=()=>page.getByRole('button',{name:de?'Geprüfte Richtlinien anwenden':'Apply reviewed policies',exact:true}).click(),close=()=>page.getByRole('dialog').getByRole('button',{name:de?'Abbrechen':'Cancel',exact:true}).click();
  stage='review';const before=policyPosts;await prepare(['cpu','memory'],true);expect(policyPosts).toBe(before);await expect(page.getByRole('dialog').getByRole('table')).toContainText(ids.first);await expect(page.getByRole('dialog').getByRole('table')).toContainText(ids.second);await expect(page.getByRole('dialog').getByRole('table')).not.toContainText(ids.linux);expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);await verifyPolicyLayout();await shot(page,fleetGroupsCaptureName('review',width,locale),fleetGroupsDisclosure);
  stage='apply';await apply();await expect(page.getByText(de?'Geändert · bestätigte Antwort':'Changed · confirmed response',{exact:true})).toHaveCount(3);await expect(page.getByText(de?'Entspricht bereits · nicht geschrieben':'Currently matching · no write',{exact:true})).toBeVisible();expect(policyPosts).toBe(before+3);await verifyPolicyLayout();await shot(page,fleetGroupsCaptureName('results',width,locale),fleetGroupsDisclosure);await close();
  stage='inheritance';const inheritanceTitle=de?'Gruppen-Monitoring':'Group monitoring',panel=page.getByRole('region',{name:inheritanceTitle,exact:true});const inheritanceBefore=monitoringPosts;
  await page.getByRole('button',{name:inheritanceTitle,exact:true}).click();await expect(panel).toBeVisible();
  for(const label of de?['Kapazität des Systemvolumes','CPU-Prozentwert','Physischer RAM-Prozentwert']:['System-volume capacity','CPU percentage','Physical RAM percentage'])await expect(panel.getByRole('checkbox',{name:(de?'Einbeziehen ':'Include ')+label,exact:true})).not.toBeChecked();
  for(const [name,id]of[['Synthetic Desk One',ids.first],['Synthetic Desk Two',ids.second]])await expect(panel.getByRole('checkbox',{name:name+' '+id,exact:true})).not.toBeChecked();
  const consent=panel.getByRole('checkbox',{name:de?'Diese geprüften Richtlinien für diese exakten Mitglieder bis zum Stoppen oder manuellen Überschreiben synchron halten.':'Keep these reviewed policies in sync for these exact members until stopped or manually overridden.',exact:true});await expect(consent).not.toBeChecked();expect(monitoringPosts).toBe(inheritanceBefore);expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);await panel.getByRole('heading',{level:3}).scrollIntoViewIfNeeded();await shot(page,fleetGroupsCaptureName('inheritance-unchecked',width,locale),fleetGroupsDisclosure);
  await panel.getByRole('checkbox',{name:de?'Einbeziehen CPU-Prozentwert':'Include CPU percentage',exact:true}).check();await panel.getByRole('checkbox',{name:de?'Richtlinie aktivieren · CPU-Prozentwert':'Enable policy · CPU percentage',exact:true}).check();await panel.getByRole('spinbutton',{name:de?'Schwellenwert (%) · CPU-Prozentwert':'Threshold (%) · CPU percentage',exact:true}).fill('91');await panel.getByRole('checkbox',{name:'Synthetic Desk One '+ids.first,exact:true}).check();await consent.check();await panel.getByRole('button',{name:de?'Vererbung prüfen':'Review inheritance',exact:true}).click();
  await expect(panel.getByRole('button',{name:de?'Geprüfte Vererbung speichern':'Save reviewed inheritance',exact:true})).toBeEnabled();await expect(panel).toContainText(ids.first);await expect(panel).not.toContainText(ids.second);await expect(panel.locator('.fleet-inheritance-details')).not.toHaveAttribute('open','');await panel.locator('.fleet-inheritance-details > summary').click();await expect(panel.getByText(ids.first,{exact:true})).toBeVisible();await panel.locator('.fleet-inheritance-details > summary').click();expect(monitoringPosts).toBe(inheritanceBefore);expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);await shot(page,fleetGroupsCaptureName('inheritance-review',width,locale),fleetGroupsDisclosure);
  await panel.getByRole('button',{name:de?'Geprüfte Vererbung speichern':'Save reviewed inheritance',exact:true}).click();await expect(panel.getByText(de?'Vererbung gespeichert. Die Synchronisierung kann noch ausstehen.':'Inheritance saved. Synchronization may still be pending.',{exact:true})).toBeVisible();expect(monitoringPosts).toBe(inheritanceBefore+1);await panel.locator('.fleet-inheritance-status > summary').click();await expect(panel.getByText(de?'CPU-Prozentwert · Manuell überschrieben':'CPU percentage · Manual override',{exact:true})).toBeVisible();expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);await panel.locator('.fleet-inheritance-status').scrollIntoViewIfNeeded();await shot(page,fleetGroupsCaptureName('inheritance-status',width,locale),fleetGroupsDisclosure);
  await panel.getByRole('button',{name:de?'Neu prüfen':'Start new review',exact:true}).click();await expect(panel.getByRole('button',{name:de?'Vererbung prüfen':'Review inheritance',exact:true})).toBeVisible();await panel.locator('.fleet-inheritance-status > summary').click();const stop=panel.getByRole('button',{name:de?'Vererbung stoppen · Synthetic Desk One · Physischer RAM-Prozentwert':'Stop inheriting · Synthetic Desk One · Physical RAM percentage',exact:true});await expect(stop).toBeEnabled();await stop.click();await expect(panel.getByRole('button',{name:de?'Geprüfte Vererbung stoppen':'Stop reviewed inheritance',exact:true})).toBeEnabled();await expect(panel).toContainText(de?'Die letzte Geräte-Richtlinie bleibt bestehen.':'The last device policy stays in place.');expect(monitoringPosts).toBe(inheritanceBefore+1);expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);await shot(page,fleetGroupsCaptureName('inheritance-stop',width,locale),fleetGroupsDisclosure);
  const previousPolicy={...monitoring.targets.find(t=>t.deviceId===ids.first&&t.metric==='memory').policy};await panel.getByRole('button',{name:de?'Geprüfte Vererbung stoppen':'Stop reviewed inheritance',exact:true}).click();await expect(panel.getByText(de?'Vererbung gestoppt. Die letzte Geräte-Richtlinie bleibt bestehen.':'Inheritance stopped. The last device policy stays in place.',{exact:true})).toBeVisible();expect(monitoringPosts).toBe(inheritanceBefore+2);expect(monitoring.targets.find(t=>t.deviceId===ids.first&&t.metric==='memory').policy).toEqual(previousPolicy);await panel.getByRole('button',{name:de?'Vererbung schließen':'Close inheritance',exact:true}).click();await expect(panel).toHaveCount(0);
  // Failure outcomes use the same production dialog and exact routes; never loosen routing.
  if(locale==='en'&&width===1440){
   stage='conflict';mode='conflict';await prepare('disk');const previous=policyPosts;await apply();await expect(page.getByText('Conflict · review again',{exact:true})).toBeVisible();await expect(page.getByText('Not attempted',{exact:true})).toBeVisible();expect(policyPosts).toBe(previous+1);await close();
   stage='uncertain-review';mode='uncertain';policies.delete(ids.first+':memory');policies.delete(ids.second+':memory');await prepare('memory');const uncertainBefore=policyPosts;
   stage='uncertain-apply';await apply();
   // The readback disclaimer is a child of the outcome cell. An exact text
   // locator for the status alone stops matching once reconciliation completes.
   stage='uncertain-result';const uncertainOutcome=page.getByRole('dialog').getByRole('row').filter({hasText:ids.first}).getByRole('cell').last();
   await expect(uncertainOutcome).toBeVisible();await expect(uncertainOutcome).toHaveText('Physical RAM percentageUnconfirmed · write may have happenedCurrent policy matches, but this does not prove our write succeeded.');
   stage='uncertain-remaining';await expect(page.getByText('Not attempted',{exact:true})).toBeVisible();
   stage='uncertain-count';expect(policyPosts).toBe(uncertainBefore+1);
   stage='uncertain-close';await close();
   stage='stop';mode='hold';await prepare('disk');const stoppedBefore=policyPosts;await apply();await expect.poll(()=>held).toBe(true);await page.getByRole('button',{name:'Stop remaining writes',exact:true}).click();assert.ok(release);release();release=null;await expect(page.getByText('Unconfirmed · write may have happened',{exact:true})).toBeVisible();await expect(page.getByText('Not attempted',{exact:true})).toBeVisible();expect(policyPosts).toBe(stoppedBefore+1);await close();mode='normal';
  }
 }
 await expect.poll(()=>fleetGroupsRouteState().pending).toBe(0);expect(external).toEqual([]);expect(unexpected).toEqual([]);expect(failures).toBe(0);stage='complete';return{screens:fleetGroupsCaptureMatrix.length,groupWrites:groupPosts,policyWrites:policyPosts,monitoringWrites:monitoringPosts,nativeAcceptance:false,liveStoreAcceptance:false};
}
