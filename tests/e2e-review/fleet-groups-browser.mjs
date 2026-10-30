/** Inert production-UI fixture helper. Importing starts no browser or server. */
import assert from 'node:assert/strict';
import {fleetGroupsCaseName,fleetGroupsDisclosure,fleetGroupsCaptureMatrix,fleetGroupsCaptureName} from './fleet-groups-evidence.mjs';
export {fleetGroupsCaseName,fleetGroupsDisclosure,fleetGroupsCaptureMatrix,fleetGroupsCaptureName,fleetGroupsScenes,requireFleetGroupsEvidence} from './fleet-groups-evidence.mjs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..'),require=createRequire(path.join(root,'web/package.json'));
const built=await require('esbuild').build({stdin:{contents:"export {windowsCapacityDevice,windowsCapacityView} from './windows-capacity-fixture'; export {windowsResourceView} from './windows-resource-fixture'; export {validFleetGroupsView} from './fleet-groups-types'; export {validWindowsPercentageView} from './windows-capacity-types'; export {validGroupMonitoringView} from './fleet-group-monitoring-types'; export {validGroupMaintenanceView} from './fleet-group-maintenance-workflow'; export {validGroupServiceChecksView,validGroupServiceChoiceView} from './fleet-group-service-checks-workflow'; export {windowsServiceHealthInventory} from './windows-service-health-fixture';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {windowsCapacityDevice,windowsCapacityView,windowsResourceView,validFleetGroupsView,validWindowsPercentageView,validGroupMonitoringView,validGroupMaintenanceView,validGroupServiceChecksView,validGroupServiceChoiceView,windowsServiceHealthInventory}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
export const fleetGroupIds={first:`agent_${'7'.repeat(32)}`,second:`agent_${'2'.repeat(32)}`,linux:`agent_${'3'.repeat(32)}`,group:`group_${'4'.repeat(32)}`,created:`group_${'5'.repeat(32)}`};
let stage='setup',failures=0,pending=0;
export const fleetGroupsRouteState=()=>({failures,pending});
export const fleetGroupsFailureStage=()=>new Set(['setup','login','groups','review','apply','conflict','uncertain','uncertain-review','uncertain-apply','uncertain-result','uncertain-remaining','uncertain-count','uncertain-close','stop','layout','inheritance','maintenance','maintenance-end','service-checks','complete']).has(stage)?stage:'setup';
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
export function fleetGroupsMaintenanceFixture(serverNow,groupRevision=2,groupName='Synthetic Office'){
 const devices=fleetGroupsBrowserFixture(serverNow,new Date(Date.parse(serverNow)+3600000).toISOString()).view.devices.filter(d=>d.platform==='windows').sort((a,b)=>a.id.localeCompare(b.id));
 const view={schemaVersion:'tracebolt.fleet-group-maintenance.v1',serverNow,authorityExpiresAt:new Date(Date.parse(serverNow)+120000).toISOString().replace(/\.000Z$/,'Z').replace(/(\.\d*?[1-9])0+Z$/,'$1Z'),groupId:fleetGroupIds.group,groupName,groupRevision,excludedLinuxMembers:1,unavailableMembers:1,members:devices.map((d,i)=>({deviceId:d.id,name:d.name,targets:['all','contact','cpu','disk','memory','service'].map((domain,j)=>({key:(i*6+j+1).toString(16).padStart(64,'0'),deviceId:d.id,domain,revision:0,changedAt:null,windows:[]}))}))};assert.ok(validGroupMaintenanceView(view,fleetGroupIds.group));return view;
}
/** Invented mixed-domain windows; an all-domain window never overlaps another
 * active domain on the same device. Historical originals remain visible only
 * in metadata, never offered as new early-end selections. */
export function fleetGroupsMaintenanceEndFixture(serverNow,groupRevision=2,groupName='Synthetic Office'){
 const view=fleetGroupsMaintenanceFixture(serverNow,groupRevision,groupName);
 const at=offset=>new Date(Date.parse(serverNow)+offset).toISOString().replace(/\.000Z$/,'Z').replace(/(\.\d*?[1-9])0+Z$/,'$1Z');
 for(const [index,member]of view.members.entries())for(const [domainIndex,target]of member.targets.entries()){
  if(index===0?target.domain!=='all':target.domain==='all')continue;
  const id=3+domainIndex*2;
  Object.assign(target,{revision:id,changedAt:at(-60000),windows:[{id,startedAt:at(-60000),endsAt:at(1800000+domainIndex*60000),endedAt:null,intent:'planned-work'},{id:id-2,startedAt:at(-240000),endsAt:at(600000),endedAt:at(-120000),intent:'investigation'}]});
 }
 // Non-active latest windows also must not appear in the selection list.
 const ended=view.members[0].targets[1],expired=view.members[0].targets[2];
 Object.assign(ended,{revision:2,changedAt:at(-120000),windows:[{id:1,startedAt:at(-240000),endsAt:at(600000),endedAt:at(-120000),intent:'other'}]});
 Object.assign(expired,{revision:1,changedAt:at(-240000),windows:[{id:1,startedAt:at(-240000),endsAt:at(-120000),endedAt:null,intent:'other'}]});
 assert.ok(validGroupMaintenanceView(view,fleetGroupIds.group));return view;
}
/** Pure fixture transition only. Reject any widening of the exact end request. */
export function fleetGroupsMaintenanceEndWrite(original,body,serverNow){
 assert.deepEqual(Object.keys(body).sort(),['groupRevision','key','revision','windowId']);assert.equal(body.groupRevision,original.groupRevision);
 const view=structuredClone(original),target=view.members.flatMap(member=>member.targets).find(target=>target.key===body.key),window=target?.windows[0];
 assert.ok(target&&window);assert.equal(body.revision,target.revision);assert.equal(body.windowId,window.id);assert.equal(window.endedAt,null);assert.ok(Date.parse(window.endsAt)>Date.parse(serverNow));
 window.endedAt=serverNow;target.revision++;target.changedAt=serverNow;view.serverNow=serverNow;
 assert.ok(validGroupMaintenanceView(view,view.groupId));return view;
}
/** Run against the existing production dialog and canonical screenshot sink.
 * The source/DOM tests use the same selectors without claiming rendered pixels. */
export async function exerciseFleetGroupsMaintenanceEnd({page,expect,width,locale,fixture,shot,verifyLayout,state}){
 const de=locale==='de',labels=de?{all:'Alle Windows-Prüfungen',contact:'Kontakt',cpu:'CPU-Prozentwert',disk:'Kapazität des Systemvolumes',memory:'Physischer RAM-Prozentwert',service:'Prüfungen ausgewählter Dienste'}:{all:'All Windows checks',contact:'Contact',cpu:'CPU percentage',disk:'System-volume capacity',memory:'Physical RAM percentage',service:'Selected-service checks'};
 const dialog=page.getByRole('dialog',{name:de?'Gruppenwartung beenden':'End group maintenance',exact:true}),review=dialog.getByRole('button',{name:de?'Vorzeitige Enden prüfen':'Review early ends',exact:true}),before=state().posts;
 const active=fixture.members.flatMap(member=>member.targets.filter(target=>target.windows[0]?.endedAt===null&&Date.parse(target.windows[0].endsAt)>Date.parse(fixture.serverNow)).map(target=>({name:member.name,deviceId:member.deviceId,target}))),selected=active.slice(0,3);
 const checkboxName=row=>`${row.name} ${row.deviceId} ${labels[row.target.domain]} ${row.target.windows[0].id}`;
 const capture=async scene=>{if(fleetGroupsCaptureMatrix.some(row=>row.scene===scene&&row.width===width&&row.locale===locale)){expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);await shot(page,fleetGroupsCaptureName(scene,width,locale),fleetGroupsDisclosure);}};
 await expect(review).toBeDisabled();await expect(dialog.getByRole('checkbox')).toHaveCount(active.length);
 for(const row of active)await expect(dialog.getByRole('checkbox',{name:checkboxName(row),exact:true})).not.toBeChecked();
 await expect(dialog).toContainText((de?'Ausgeschlossene Linux-Mitglieder':'Excluded Linux members')+': 1');await expect(dialog).toContainText((de?'Nicht verfügbare Mitglieder':'Unavailable members')+': 1');expect(state().posts).toBe(before);await capture('maintenance-end-unchecked');
 for(const row of selected)await dialog.getByRole('checkbox',{name:checkboxName(row),exact:true}).check();await review.click();
 const table=dialog.getByRole('table',{name:de?'Vorzeitige Enden prüfen':'Review early ends',exact:true}),apply=dialog.getByRole('button',{name:de?'Geprüfte Fenster beenden':'End reviewed windows',exact:true}),consent=dialog.getByRole('checkbox',{name:de?'Nur diese exakten aktiven Fenster jetzt beenden. Jedes ursprüngliche Ende bleibt im Verlauf.':'End only these exact active windows now. Keep each original end in history.',exact:true});
 await expect(table.getByRole('row')).toHaveCount(4);await expect(table.getByRole('columnheader')).toHaveText(de?['Gerät / exakte ID','Umfang','Ursprüngliches Ende','Wartungsversion']:['Device / exact ID','Scope','Original end','Maintenance revision']);await expect(apply).toBeDisabled();await expect(consent).not.toBeChecked();expect(state().posts).toBe(before);
 const details=dialog.locator('details');await expect(details).not.toHaveAttribute('open','');await details.locator('summary').click();
 for(const [index,row]of selected.entries()){await expect(details).toContainText(row.target.key);await expect(details).toContainText(row.target.windows[0].endsAt);await expect(details).toContainText((de?'Fenster-ID':'Window ID')+': '+row.target.windows[0].id+' · '+(de?'Wartungsversion':'Maintenance revision')+': '+row.target.revision);await expect(table.locator('tbody time').nth(index)).toHaveAttribute('datetime',row.target.windows[0].endsAt);}
 await details.locator('summary').click();await expect(details).not.toHaveAttribute('open','');await verifyLayout();await capture('maintenance-end-review');
 await consent.check();await apply.click();
 const results=dialog.getByRole('table',{name:de?'Wartungsergebnisse je Fenster':'Per-window maintenance results',exact:true});await expect(results.getByRole('row')).toHaveCount(4);await expect(results.getByRole('columnheader')).toHaveText(de?['Gerät / exakte ID','Umfang','Ursprüngliches Ende','Wartungsversion','Ergebnis']:['Device / exact ID','Scope','Original end','Maintenance revision','Outcome']);
 for(const [index,row]of selected.entries()){const result=results.getByRole('row').nth(index+1);await expect(result).toContainText(row.deviceId);await expect(result).toContainText(labels[row.target.domain]);await expect(result.locator('time')).toHaveAttribute('datetime',row.target.windows[0].endsAt);await expect(result.getByRole('cell').last()).toContainText(index===0?(de?'Beendet · bestätigte Antwort':'Ended · confirmed response'):index===1?(de?'Gesperrt / Konflikt':'Blocked / conflict'):(de?'Nicht versucht':'Not attempted'));}
 expect(state().posts).toBe(before+2);expect(state().bodies).toEqual(selected.slice(0,2).map(row=>({groupRevision:fixture.groupRevision,key:row.target.key,revision:row.target.revision,windowId:row.target.windows[0].id})));
 for(const member of fixture.members)for(const target of member.targets){const current=state().view.members.flatMap(row=>row.targets).find(row=>row.key===target.key);if(target.key===selected[0].target.key){expect(current.revision).toBe(target.revision+1);expect(current.windows[0].endedAt===null).toBe(false);expect({...current.windows[0],endedAt:null}).toEqual(target.windows[0]);expect(current.windows.slice(1)).toEqual(target.windows.slice(1));}else expect(current).toEqual(target);}
 await expect(apply).toHaveCount(0);await verifyLayout();await capture('maintenance-end-results');await dialog.getByRole('button',{name:de?'Wartung schließen':'Close maintenance',exact:true}).click();
}
/** Mounted organizational panels may read their empty synthetic catalogues.
 * This grants neither customer writes nor assignment/enrollment operations. */
export function fleetGroupsOrganizationalRead(method,pathname,search,body,serverNow){
 if(method!=='GET'||search!==''||body!==null)return null;
 if(pathname==='/api/customers')return{schemaVersion:'tracebolt.customers.v1',customers:[]};
 if(pathname==='/api/customer-windows-assignments')return{schemaVersion:'tracebolt.customer-windows-assignments.v1',serverNow,validUntil:new Date(Date.parse(serverNow)+30000).toISOString(),customers:[],devices:[],unavailableAssignments:0};
 return null;
}
export async function fleetGroupsBrowserCase({page,expect,base,login,shot}){
 stage='login';failures=0;pending=0;await login(page);
 let groupRows=[],policies=new Map(),policyPosts=0,groupPosts=0,monitoring=null,monitoringPosts=0,maintenance=null,maintenancePosts=0,maintenanceBodies=[],maintenanceEndPosts=0,maintenanceEndBodies=[],maintenanceEndExpected=[],mode='normal',release=null,held=false;
 const external=[],unexpected=[],ids=fleetGroupIds;
 const getSession=async()=>{const response=await page.request.get(base+'/api/auth/session',{maxRedirects:0,timeout:5000});try{assert.equal(response.status(),200);const session=await response.json();assert.equal(session.authenticated,true);assert.equal(session.loginMode,'shared');return session;}finally{await response.dispose();}};
 const fulfill=(route,value,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(value)});
 const handle=async route=>{
  const req=route.request(),url=new URL(req.url());if(url.origin!==base){external.push('external');return route.abort('blockedbyclient');}
  if(['/api/customers','/api/customer-windows-assignments'].includes(url.pathname)){
   const session=await getSession(),view=fleetGroupsOrganizationalRead(req.method(),url.pathname,url.search,req.postData(),session.serverNow);
   if(view)return fulfill(route,view);
   unexpected.push('unexpected-organizational-route');return route.abort('blockedbyclient');
  }
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
  if(url.pathname===`/api/fleet/groups/${ids.group}/maintenance`||url.pathname===`/api/fleet/groups/${ids.group}/maintenance/start`||url.pathname===`/api/fleet/groups/${ids.group}/maintenance/end`){
   assert.equal(url.search,'');const starting=url.pathname.endsWith('/start'),ending=url.pathname.endsWith('/end');assert.equal(req.method(),starting||ending?'POST':'GET');const session=await getSession(),group=groupRows.find(g=>g.id===ids.group);
   maintenance??=fleetGroupsMaintenanceFixture(session.serverNow,group.revision,group.name);maintenance.serverNow=session.serverNow;
   if(starting){
    assert.equal(req.headers()['x-csrf-token'],session.csrfToken);const body=JSON.parse(req.postData());assert.deepEqual(Object.keys(body).sort(),['endsAt','groupRevision','intent','key','revision']);assert.equal(body.groupRevision,group.revision);assert.equal(body.intent,'planned-work');assert.equal(body.revision,0);const target=maintenance.members.flatMap(m=>m.targets).find(t=>t.key===body.key);assert.ok(target);assert.equal(target.domain,'all');maintenancePosts++;maintenanceBodies.push(body);
    if(maintenanceBodies.length===2){assert.equal(body.endsAt,maintenanceBodies[0].endsAt);return fulfill(route,{error:{code:'windows_maintenance_conflict'}},409);}
    assert.equal(maintenanceBodies.length,1);target.revision++;target.changedAt=session.serverNow;target.windows=[{id:target.revision,startedAt:session.serverNow,endsAt:body.endsAt,endedAt:null,intent:body.intent}];
   }
   if(ending){
    assert.equal(req.headers()['x-csrf-token'],session.csrfToken);const body=JSON.parse(req.postData());assert.equal(body.groupRevision,group.revision);assert.deepEqual(body,maintenanceEndExpected[maintenanceEndBodies.length]);
    const next=fleetGroupsMaintenanceEndWrite(maintenance,body,session.serverNow);maintenanceEndPosts++;maintenanceEndBodies.push(body);
    if(maintenanceEndBodies.length===2)return fulfill(route,{error:{code:'windows_maintenance_conflict'}},409);
    assert.equal(maintenanceEndBodies.length,1);maintenance=next;
   }
   assert.ok(validGroupMaintenanceView(maintenance,ids.group));return fulfill(route,maintenance);
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
  const de=locale==='de';await page.setViewportSize({width,height:width===390?844:1000});await page.getByRole('combobox',{name:/Language|Sprache/}).selectOption(locale);const session=await getSession();groupRows=fleetGroupsBrowserFixture(session.serverNow,session.expiresAt).view.groups;policies=new Map([[ids.second+':cpu',{enabled:true,thresholdPercent:90,revision:1}]]);mode='normal';monitoring=null;maintenance=null;maintenanceBodies=[];maintenanceEndBodies=[];maintenanceEndExpected=[];await page.reload();await expect(page.locator('.app-shell')).toBeVisible();
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
  stage='maintenance';const maintenanceBefore=maintenancePosts;
  await page.getByRole('button',{name:de?'Gruppenwartung starten':'Start group maintenance',exact:true}).click();
  const maintenanceDialog=page.getByRole('dialog'),maintenanceReview=maintenanceDialog.getByRole('button',{name:de?'Gruppenwartung prüfen':'Review group maintenance',exact:true});await expect(maintenanceReview).toBeDisabled();
  for(const [name,id]of[['Synthetic Desk One',ids.first],['Synthetic Desk Two',ids.second]])await expect(maintenanceDialog.getByRole('checkbox',{name:name+' '+id,exact:true})).not.toBeChecked();
  await expect(maintenanceDialog).toContainText((de?'Ausgeschlossene Linux-Mitglieder':'Excluded Linux members')+': 1');await expect(maintenanceDialog).toContainText((de?'Nicht verfügbare Mitglieder':'Unavailable members')+': 1');
  const maintenanceShot=async scene=>{if(fleetGroupsCaptureMatrix.some(row=>row.scene===scene&&row.width===width&&row.locale===locale)){expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);await shot(page,fleetGroupsCaptureName(scene,width,locale),fleetGroupsDisclosure);}};
  await maintenanceShot('maintenance-unchecked');
  for(const [name,id]of[['Synthetic Desk One',ids.first],['Synthetic Desk Two',ids.second]])await maintenanceDialog.getByRole('checkbox',{name:name+' '+id,exact:true}).check();
  await maintenanceDialog.getByRole('combobox',{name:de?'Absicht des Operators':'Operator intent',exact:true}).selectOption('planned-work');await maintenanceReview.click();
  const maintenanceApply=maintenanceDialog.getByRole('button',{name:de?'Geprüfte Wartung starten':'Start reviewed maintenance',exact:true}),maintenanceConsent=maintenanceDialog.getByRole('checkbox',{name:de?'Diesen exakten Wartungsumfang für diese gewählten Mitglieder bis zum oben angezeigten festen Ende starten.':'Start this exact maintenance scope for these selected members until the fixed end shown above.',exact:true});
  await expect(maintenanceApply).toBeDisabled();await expect(maintenanceConsent).not.toBeChecked();expect(maintenancePosts).toBe(maintenanceBefore);await verifyPolicyLayout();await maintenanceShot('maintenance-review');
  await maintenanceConsent.check();await maintenanceApply.click();const maintenanceResult=maintenanceDialog.getByRole('table',{name:de?'Wartungsergebnisse je Gerät':'Per-device maintenance results',exact:true});await expect(maintenanceResult).toContainText(de?'Gestartet · bestätigte Antwort':'Started · confirmed response');await expect(maintenanceResult).toContainText(de?'Gesperrt / Konflikt':'Blocked / conflict');expect(maintenancePosts).toBe(maintenanceBefore+2);expect(maintenanceBodies[0].endsAt).toBe(maintenanceBodies[1].endsAt);await verifyPolicyLayout();await maintenanceShot('maintenance-results');await maintenanceDialog.getByRole('button',{name:de?'Wartung schließen':'Close maintenance',exact:true}).click();
  stage='maintenance-end';const endSession=await getSession(),endGroup=groupRows.find(group=>group.id===ids.group);maintenance=fleetGroupsMaintenanceEndFixture(endSession.serverNow,endGroup.revision,endGroup.name);const endFixture=structuredClone(maintenance);
  maintenanceEndExpected=endFixture.members.flatMap(member=>member.targets.filter(target=>target.windows[0]?.endedAt===null&&Date.parse(target.windows[0].endsAt)>Date.parse(endFixture.serverNow))).slice(0,3).map(target=>({groupRevision:endFixture.groupRevision,key:target.key,revision:target.revision,windowId:target.windows[0].id}));
  await page.getByRole('button',{name:de?'Gruppenwartung beenden':'End group maintenance',exact:true}).click();
  await exerciseFleetGroupsMaintenanceEnd({page,expect,width,locale,fixture:endFixture,shot,verifyLayout:verifyPolicyLayout,state:()=>({posts:maintenanceEndPosts,bodies:maintenanceEndBodies,view:maintenance})});
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
 const serviceChecksCases=[];
 // Changed views use a separate fully intercepted App startup. No API falls
 // through to the disposable manager during these synthetic service checks.
 for(const [locale,width]of [['en',1440],['de',390]]){
  stage='service-checks';const fixture=fleetGroupsServiceChecksFixture(await getSession());
  await expect.poll(()=>fleetGroupsRouteState().pending).toBe(0);await page.unroute('**/*');
  const serviceHandle=fleetGroupsServiceChecksRoute({base,fixture,external,unexpected});
  await page.route('**/*',route=>guardFleetGroupsRoute(route,serviceHandle));
  await page.setViewportSize({width,height:width===390?844:1000});await page.reload();await expect(page.locator('.app-shell')).toBeVisible();
  await page.getByRole('combobox',{name:/Language|Sprache/}).selectOption(locale);await expect(page.locator('html')).toHaveAttribute('lang',locale);
  await exerciseFleetGroupsServiceChecks({page,expect,fixture,locale,width,shot,verifyLayout:verifyPolicyLayout});
  serviceChecksCases.push({locale,width,policyWrites:fixture.writes.length,reviewApprovalInitiallyUnchecked:true,partialResults:['changed','conflict','not-attempted']});
 }
 await expect.poll(()=>fleetGroupsRouteState().pending).toBe(0);expect(external).toEqual([]);expect(unexpected).toEqual([]);expect(failures).toBe(0);stage='complete';return{screens:fleetGroupsCaptureMatrix.length,groupWrites:groupPosts,policyWrites:policyPosts,monitoringWrites:monitoringPosts,maintenanceWrites:maintenancePosts,maintenanceEndWrites:maintenanceEndPosts,serviceChecksCases,nativeAcceptance:false,liveStoreAcceptance:false};
}

/** Synthetic bounded, already-consented preview. Source and authority times are
 * fixed once; fixture GETs never refresh the source or extend its first lease. */
export function fleetGroupsServiceChecksFixture(source){
 assert.equal(source.mode,'lan');assert.equal(source.authenticated,true);assert.equal(source.loginMode,'shared');assert.equal(source.actorId,null);assert.deepEqual(source.capabilities,['read']);assert.ok(Date.parse(source.expiresAt)>Date.parse(source.serverNow));
 const session=structuredClone(source),{serverNow}=session,at=offset=>new Date(Date.parse(serverNow)+offset).toISOString().replace(/\.000Z$/,'Z');
 const base=fleetGroupsBrowserFixture(serverNow,session.expiresAt),third={id:`agent_${'9'.repeat(32)}`,name:'Synthetic Desk Three',platform:'windows'};
 const devices=[...base.view.devices,third],group={...base.view.groups[0],memberIds:devices.map(d=>d.id)};
 const view={schemaVersion:'tracebolt.fleet-group-service-checks.v1',serverNow,authorityExpiresAt:new Date(Math.min(Date.parse(session.expiresAt),Date.parse(serverNow)+110000)).toISOString().replace(/\.000Z$/,'Z'),groupId:group.id,groupName:group.name,groupRevision:group.revision,excludedLinuxMembers:1,unavailableMembers:1,members:devices.filter(d=>d.platform==='windows').sort((a,b)=>a.id.localeCompare(b.id)).map((d,i)=>({key:(i+1).toString(16).padStart(64,'0'),deviceId:d.id,name:d.name,policy:{enabled:false,services:[],revision:i*2}}))};
 assert.ok(validGroupServiceChecksView(view,group.id));
 const {authorityExpiresAt,groupId,groupName,groupRevision}=view;
 const choices=new Map(view.members.map(member=>{
  const inventory={...windowsServiceHealthInventory(),collectedAt:at(-10000),receivedAt:at(-9000),quality:'partial',complete:false,truncated:true,countExact:false,observedCount:128};
  const choice={schemaVersion:'tracebolt.fleet-group-service-choice.v1',serverNow,authorityExpiresAt,groupId,groupName,groupRevision,member:{...structuredClone(member),inventory}};assert.ok(validGroupServiceChoiceView(choice,group.id,member.key));return[member.key,choice];
 }));
 const metadata=[...base.metadata,{...base.metadata[0],...third}],overview={product:'Tracebolt',mode:'lan',generatedAt:serverNow,stats:{totalDevices:devices.length,healthyDevices:0,attentionDevices:0,unknownDevices:devices.length,openCases:0,criticalCases:0},devices:metadata,cases:[],activity:[]};
 return{session,view,choices,overview,groups:{...base.view,groups:[group],devices},reads:[],writes:[]};
}
/** Every App API request is answered or rejected here. Only built UI assets may
 * continue; a deliberate policy POST changes in-memory fixture state alone. */
export function fleetGroupsServiceChecksRoute({base,fixture,external,unexpected}){
 const origin=new URL(base);assert.equal(origin.origin,base);assert.equal(origin.hostname,'127.0.0.1');assert.equal(origin.protocol,'http:');
 const servicePath=`/api/fleet/groups/${fixture.view.groupId}/service-checks`;
 return async route=>{
  const req=route.request(),url=new URL(req.url()),method=req.method(),raw=req.postData();
  if(url.origin!==base){external.push('external');return route.abort('blockedbyclient');}
  const block=()=>{unexpected.push('unexpected-group-service-route');return route.abort('blockedbyclient');},reply=(value,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(value)});
  if(url.search)return block();
  const key=url.pathname.startsWith(servicePath+'/')?url.pathname.slice(servicePath.length+1):null,choice=fixture.choices.get(key);
  if(method==='POST'&&choice){
   assert.equal(req.headers()['origin'],base);assert.equal(req.headers()['x-csrf-token'],fixture.session.csrfToken);assert.equal(req.headers()['content-type'],'application/json');
   const index=fixture.writes.length,member=fixture.view.members[index];assert.ok(index<2&&member);assert.equal(key,member.key);
   const body=JSON.parse(raw);assert.deepEqual(body,{groupRevision:fixture.view.groupRevision,expectedRevision:member.policy.revision,enabled:true,services:[index===1?'spooler':'Spooler'],consent:true});
   fixture.writes.push({key,body});
   if(index===1)return reply({error:{code:'group_service_conflict'}},409);
   choice.member.policy={enabled:body.enabled,services:[...body.services],revision:body.expectedRevision+1};member.policy=structuredClone(choice.member.policy);
   assert.ok(validGroupServiceChoiceView(choice,fixture.view.groupId,key));return reply(choice);
  }
  if(method!=='GET'||raw!==null)return block();
  fixture.reads.push(url.pathname);
  if(url.pathname==='/api/auth/session')return reply(fixture.session);
  if(url.pathname==='/api/session')return reply({csrfToken:fixture.session.csrfToken});
  if(url.pathname==='/api/overview')return reply(fixture.overview);
  const organizational=fleetGroupsOrganizationalRead(method,url.pathname,url.search,raw,fixture.session.serverNow);if(organizational)return reply(organizational);
  if(url.pathname==='/api/enrollment')return reply({schemaVersion:'tracebolt.enrollment-operator.v2',serverNow:fixture.session.serverNow,enabled:false,platforms:[],recordLimit:25,items:[]});
  if(url.pathname==='/api/fleet/identities')return reply({schemaVersion:'tracebolt.fleet-identities.v2',serverNow:fixture.session.serverNow,items:[]});
  if(url.pathname==='/api/fleet/groups'||url.pathname===`/api/fleet/groups/${fixture.view.groupId}`)return reply(fixture.groups);
  if(url.pathname===servicePath)return reply(fixture.view);
  if(choice)return reply(choice);
  if(url.pathname==='/'||url.pathname==='/favicon.svg'||url.pathname.startsWith('/assets/'))return route.continue();
  return block();
 };
}
/** The same semantic selectors exercise the compiled production App in the
 * hosted gate and in the inert DOM test. Only hosted execution renders pixels. */
export async function exerciseFleetGroupsServiceChecks({page,expect,fixture,locale,width,shot,verifyLayout}){
 assert.ok(locale==='en'&&width===1440||locale==='de'&&width===390);const de=locale==='de',original=structuredClone(fixture.view);
 const c=de?{groups:'Flottengruppen',open:'Dienstprüfungen anwenden',load:'Dienstoptionen der Auswahl laden',enable:'Dienstprüfungen aktivieren',review:'Exakte Dienstprüfungen prüfen',apply:'Geprüfte Dienstprüfungen anwenden',consent:'Diese exakten Dienstprüfungsrichtlinien einmal auf diese gewählten Mitglieder anwenden.',results:'Dienstprüfungsergebnisse je Gerät',close:'Abbrechen'}:{groups:'Fleet groups',open:'Apply service checks',load:'Load selected service choices',enable:'Enable service checks',review:'Review exact service checks',apply:'Apply reviewed service checks',consent:'Apply these exact service-check policies to these selected members once.',results:'Per-device service-check results',close:'Cancel'};
 await page.getByRole('button',{name:c.groups,exact:true}).click();await page.getByRole('combobox',{name:c.groups,exact:true}).selectOption(fixture.view.groupId);
 await page.getByRole('button',{name:c.open,exact:true}).click();const dialog=page.getByRole('dialog',{name:c.open,exact:true});
 await expect(dialog.getByRole('button',{name:c.load,exact:true})).toBeDisabled();
 for(const member of original.members){const select=dialog.getByRole('checkbox',{name:`${member.name} ${member.deviceId}`,exact:true});await expect(select).not.toBeChecked();await select.check();}
 await dialog.getByRole('button',{name:c.load,exact:true}).click();await expect(dialog).toContainText(de?'Vorhandene begrenzte Vorschau: bis zu 128':'Existing bounded preview: up to 128');await expect(dialog).toContainText(de?'bleiben unbekannt und gelten nie als gesund':'stay unknown and are never assumed healthy');
 for(const [index,member]of original.members.entries()){
  const details=dialog.locator('.fleet-service-device').nth(index);if(index>0)await details.locator('summary').first().click();
  const enable=details.getByRole('checkbox',{name:`${c.enable} · ${member.name}`,exact:true});await expect(enable).not.toBeChecked();await enable.check();
  await details.getByRole('checkbox',{name:index===1?/Separate case-sensitive selector/:/Print Spooler/}).check();
 }
 await dialog.getByRole('button',{name:c.review,exact:true}).click();const table=dialog.getByRole('table',{name:c.review,exact:true}),consent=dialog.getByRole('checkbox',{name:c.consent,exact:true}),apply=dialog.getByRole('button',{name:c.apply,exact:true});
 await expect(table.getByRole('row')).toHaveCount(4);await expect(consent).not.toBeChecked();await expect(apply).toBeDisabled();expect(fixture.writes.length).toBe(0);
 for(const [index,member]of original.members.entries()){const row=table.getByRole('row').nth(index+1);await expect(row).toContainText(member.deviceId);await expect(row.getByRole('cell').nth(1)).toContainText(String(member.policy.revision));await expect(row.getByRole('cell').nth(2)).toContainText(index===1?'spooler':'Spooler');}
 await verifyLayout();await consent.scrollIntoViewIfNeeded();await shot(page,fleetGroupsCaptureName('service-checks-review-unchecked',width,locale),fleetGroupsDisclosure);
 await consent.check();await apply.click();const results=dialog.getByRole('table',{name:c.results,exact:true});
 const outcomes=de?['Geändert · bestätigte Antwort','Konflikt · erneut prüfen','Nicht versucht']:['Changed · confirmed response','Conflict · review again','Not attempted'];
 for(const [index,status]of outcomes.entries())await expect(results.getByRole('row').nth(index+1).getByRole('cell').last()).toHaveText(status);
 expect(fixture.writes.length).toBe(2);expect(fixture.writes.map(write=>write.key)).toEqual(original.members.slice(0,2).map(member=>member.key));
 expect(fixture.view.members[0].policy).toEqual({enabled:true,services:['Spooler'],revision:original.members[0].policy.revision+1});expect(fixture.view.members.slice(1)).toEqual(original.members.slice(1));expect(fixture.view.authorityExpiresAt).toBe(original.authorityExpiresAt);await expect(apply).toHaveCount(0);
 await verifyLayout();await results.getByRole('row').nth(1).scrollIntoViewIfNeeded();await shot(page,fleetGroupsCaptureName('service-checks-partial-results',width,locale),fleetGroupsDisclosure);
 await dialog.getByRole('button',{name:c.close,exact:true}).click();await expect(dialog).toHaveCount(0);
}
