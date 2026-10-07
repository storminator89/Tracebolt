/** Invented metadata and Health DTOs, rendered by the production device page.
 * Extends the existing Investigations/Health case; no additional LAN case or
 * permission, target operation, provider send or real telemetry is introduced. */
import {validHealthView} from '../../web/src/health-types.ts';
export const healthDashboardPhases=['clear','healthy-services','issue','stale','awaiting','unavailable'];
const at='2026-10-06T12:02:03Z',before=seconds=>new Date(Date.parse(at)-seconds*1000).toISOString();
export function healthDashboardFixture(phase,deviceId){
 if(!healthDashboardPhases.includes(phase))throw new Error('Invalid synthetic Health phase');
 const metric=value=>({value,unit:'%',quality:'healthy',source:'Invented Health browser fixture',collectedAt:at});
 const device={id:deviceId,name:'Health fixture <Linux>',platform:'linux',os:'Linux fixture',site:'Fixture',group:'Fixture',ip:null,status:'unknown',source:'lan',synthetic:false,lastSeen:at,agentVersion:'fixture',cpu:metric(7.4),memory:metric(46.8),disk:metric(14.2),uptime:'',tags:[],capabilities:[],evidence:[],trend:[],caseIds:[]};
 const health={schemaVersion:'tracebolt.health-view.v1',deviceId,serverNow:at,evaluatedAt:at,status:'clear',maintenanceUntil:null,monitoredServices:[],checks:[{key:'offline:contact',kind:'offline',target:'agent',state:'ok',observedAt:at,value:null},{key:'filesystem:root',kind:'filesystem',target:'/',state:'ok',observedAt:at,value:14.2}],incidents:[]};
 if(phase==='healthy-services'){health.monitoredServices=['fixture-web.service','fixture-worker.service'];for(const unit of health.monitoredServices)health.checks.push({key:'service:'+unit,kind:'service',target:unit,state:'ok',observedAt:at,value:null});}
 if(phase==='issue'){
  health.status='attention';health.checks[1].state='open';health.checks[1].value=94.2;
  health.incidents=[{id:'health_0000000000000001',key:'filesystem:root',kind:'filesystem',target:'/',openedAt:before(420),lastObservedAt:at,resolvedAt:null,acknowledgedAt:null}];
  health.monitoredServices=['fixture-worker.service'];health.checks.push({key:'service:fixture-worker.service',kind:'service',target:'fixture-worker.service',state:'unknown',observedAt:null,value:null});
 }
 if(phase==='stale'||phase==='awaiting'){
  health.status='unknown';if(phase==='awaiting')health.evaluatedAt=null;
  for(const check of health.checks){check.state='unknown';check.observedAt=phase==='stale'?before(180):null;check.value=null;}
  device.cpu={...device.cpu,value:73.4,quality:phase==='stale'?'stale':'unknown',collectedAt:before(180)};
 }
 if(!validHealthView(health,deviceId))throw new Error('Invalid synthetic Health dashboard contract');
 return {device,health};
}
export async function healthDashboardLayout(page,health,expect,mark=()=>{},prefix='health-layout'){
 mark(`${prefix}-viewport`);
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1&&document.body.scrollWidth<=innerWidth+1)).toBe(true);
 for(const [kind,selector] of [['cards','.health-reading-card'],['issues','.health-issue'],['summaries','.health-disclosure > summary']]){
  mark(`${prefix}-${kind}`);
  for(const item of await health.locator(selector).all()){
   if(!await item.isVisible())continue;
   expect(await item.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
  }
 }
}
const layout=healthDashboardLayout;
// The parent case deliberately pauses its clock. Drain only two animation
// frames so production disclosure focus can settle, without changing deadlines.
export const healthDisclosureFrameMs=32;
export async function openHealthDisclosure(button,page){await button.click();await page.clock.runFor(healthDisclosureFrameMs);}
/** Use the existing real fixture login, read-only guards and source-bound shots. */
export async function healthDashboardBrowserCase({page,expect,shot,setPhase,mark,fixtureDisclosure}){
 const health=page.locator('.health-panel');
 const change=async phase=>{setPhase(phase);await page.reload();await expect(health.locator(phase==='unavailable'?'.health-unavailable':'.health-hero')).toBeVisible();};
 const capture=async name=>{mark(name);await layout(page,health,expect);await health.locator('.health-heading').scrollIntoViewIfNeeded();await shot(page,name,fixtureDisclosure);};
 mark('health-dashboard-clear');await page.setViewportSize({width:1440,height:1000});await change('clear');
 await expect(health.locator('[data-health-state]')).toHaveAttribute('data-health-state','clear');await expect(health).toContainText('Monitored checks clear');await expect(health).toContainText('Selected checks only');await expect(health.locator('.health-cards li')).toHaveCount(4);await expect(health.locator('.health-cards')).toContainText('7.4%');await expect(health.locator('.health-cards')).toContainText('46.8%');await expect(health).toContainText('No service checks selected');await expect(health.locator('.health-disclosure[open]')).toHaveCount(0);await expect(health.getByRole('searchbox')).toHaveCount(0);await capture('synthetic-http-test-health-clear-desktop-en');
 mark('health-dashboard-healthy-services');await change('healthy-services');await expect(health.locator('.health-cards')).toContainText('2/2');await expect(health.locator('.health-issues')).toHaveCount(0);await capture('synthetic-http-test-health-services-desktop-en');
 mark('health-dashboard-issues');await change('issue');await expect(health.locator('[data-health-state]')).toHaveAttribute('data-health-state','attention');await expect(health.locator('.health-issue')).toHaveCount(2);await expect(health.locator('.health-issues')).toContainText('Review disk usage');await expect(health.locator('.health-issues')).toContainText('Started');await capture('synthetic-http-test-health-desktop-en');
 await openHealthDisclosure(health.getByRole('button',{name:'Show evidence',exact:true}),page);await expect(health.locator('.health-policy')).toHaveAttribute('open','');await expect(health.locator('.health-policy summary')).toBeFocused();await health.locator('.health-policy summary').press('Enter');await expect(health.locator('.health-policy')).not.toHaveAttribute('open');
 await openHealthDisclosure(health.getByRole('button',{name:'Choose services',exact:true}),page);await expect(health.locator('.health-controls')).toBeVisible();await expect(health.locator('.health-disclosure').first().locator('summary')).toBeFocused();await health.locator('.health-disclosure').first().locator('summary').press('Enter');await expect(health.locator('.health-disclosure').first()).not.toHaveAttribute('open');
 await page.setViewportSize({width:390,height:844});await capture('synthetic-http-test-health-issue-mobile-en');
 await page.getByLabel('Language',{exact:true}).selectOption('de');await expect(health).toContainText('Aufmerksamkeit nötig');await capture('synthetic-http-test-health-mobile-de');
 mark('health-mobile-de-settings-open');
 await openHealthDisclosure(health.getByRole('button',{name:'Dienste auswählen',exact:true}),page);
 mark('health-mobile-de-settings-visible');await expect(health.locator('.health-controls')).toBeVisible();
 mark('health-mobile-de-settings-scroll');await health.locator('.health-controls').scrollIntoViewIfNeeded();
 try{await layout(page,health,expect,mark,'health-mobile-de-settings-layout');}catch(error){
  // Keep the failed geometry assertion and its exact finite stage. Capture only
  // this known invented, authenticated state, without credentials or full-page
  // expansion. The filename explicitly denotes failure, not visual acceptance.
  try{
   await expect(page.locator('input[type="password"]')).toHaveCount(0);
   await shot(page,'synthetic-http-test-health-controls-layout-failure-mobile-de',fixtureDisclosure);
  }finally{throw error;}
 }
 mark('synthetic-http-test-health-controls-mobile-de');await shot(page,'synthetic-http-test-health-controls-mobile-de',fixtureDisclosure);
 mark('health-mobile-de-clear-reload');await change('clear');
 mark('health-mobile-de-clear-summary');await expect(health).toContainText('Überwachte Prüfungen unauffällig');
 mark('health-mobile-de-clear-reading');await expect(health.locator('.health-cards')).toContainText('46,8%');await capture('synthetic-http-test-health-clear-mobile-de');
 await page.setViewportSize({width:1440,height:1000});await capture('synthetic-http-test-health-clear-desktop-de');await page.setViewportSize({width:390,height:844});await page.getByLabel('Sprache',{exact:true}).selectOption('en');
 await change('stale');await expect(health.locator('[data-health-state]')).toHaveAttribute('data-health-state','unknown');await expect(health).toContainText('Stale reading');await expect(health.locator('.health-cards')).not.toContainText('73.4%');await capture('synthetic-http-test-health-stale-mobile-en');
 await change('awaiting');await expect(health.locator('[data-health-state]')).toHaveAttribute('data-health-state','unknown');await expect(health).toContainText('Waiting for the first health evaluation');await capture('synthetic-http-test-health-unknown-mobile-en');
 await change('unavailable');await expect(health.locator('.health-cards')).toHaveCount(0);await expect(health).toContainText('Health checks unavailable');await expect(health).not.toContainText('not configured');await expect(health).not.toContainText('fixture unavailable reason');await capture('synthetic-http-test-health-unavailable-mobile-en');
 setPhase(null);
}
