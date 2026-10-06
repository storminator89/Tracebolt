/** Invented intercepted DTOs only. This is rendered UI acceptance, not the
 * Health API/evaluator/store or a live endpoint; those have separate Go tests. */
import {validHealthView} from '../../web/src/health-types.ts';
export const investigationsCaseName='Synthetic read-only Investigations distinguish retained warnings, unknown assessment and expired current evidence';
export const investigationsFixtureDisclosure='Rendered production UI with real loopback HTTP-test login and exact intercepted invented Investigations, Health and device DTOs. UI-only evidence; durable evaluator, API authority and persistence are tested separately in Go. No real telemetry, health mutation, log capture, provider, collector or native host operation.';
export const investigationsFixtureDevice='agent_'+('d'.repeat(32));
let stage='setup';
export const investigationsFailureStage=()=>stage;
const mark=value=>{stage=value;};
const originTime='2026-10-06T12:00:00Z';
const shifted=seconds=>new Date(Date.parse(originTime)+seconds*1000).toISOString();
export function investigationsFixture(phase='issue') {
 if(!['issue','stale','unknown','renewed'].includes(phase))throw new Error('Invalid investigation fixture phase');
 const unknown=phase==='unknown',stale=phase==='stale',now=shifted(phase==='issue'?0:phase==='stale'?121:phase==='unknown'?122:123),observed=phase==='renewed'?now:originTime;
 const incident={id:'health_0000000000000001',key:'filesystem:root',kind:'filesystem',target:'/',openedAt:shifted(-120),lastObservedAt:observed,resolvedAt:null,acknowledgedAt:null};
 const health={schemaVersion:'tracebolt.health-view.v1',deviceId:investigationsFixtureDevice,serverNow:now,evaluatedAt:unknown?null:observed,status:unknown||stale?'unknown':'attention',maintenanceUntil:null,monitoredServices:[],checks:[{key:'offline:contact',kind:'offline',target:'agent',state:unknown||stale?'unknown':'ok',observedAt:unknown?null:observed,value:null},{key:'filesystem:root',kind:'filesystem',target:'/',state:unknown||stale?'unknown':'open',observedAt:unknown?null:observed,value:unknown||stale?null:95}],incidents:[]};
 if(!validHealthView(health,investigationsFixtureDevice)||!validHealthView({...health,incidents:unknown?[]:[incident]},investigationsFixtureDevice))throw new Error('Invalid health fixture');
 const count=unknown?0:1;
 return {schemaVersion:'tracebolt.investigations.v1',serverNow:now,scope:'open',offset:0,total:count,counts:{open:count,recovered:0,closed:0,all:count},devices:[health],items:unknown?[]:[{deviceId:investigationsFixtureDevice,incident}]};
}
export function investigationsDeviceFixture(){
 const metric={value:null,unit:'%',quality:'unknown',source:'Invented browser fixture',collectedAt:originTime};
 return {id:investigationsFixtureDevice,name:'Investigation fixture <Linux>',platform:'linux',os:'Linux fixture',site:'Fixture',group:'Fixture',ip:null,status:'unknown',source:'lan',synthetic:false,lastSeen:originTime,agentVersion:'fixture',cpu:metric,memory:metric,disk:metric,uptime:'',tags:[],capabilities:[],evidence:[],trend:[],caseIds:[]};
}
async function layout(page,expect){
 // Inline text and <time> children must stay in block-flow paragraphs. The old
 // demo .investigation-note mobile grid split labels and timestamps into cells.
 const notes=page.locator('.investigations-note');expect(await notes.count()).toBeGreaterThan(0);
 for(const note of await notes.all()){
  if(!await note.isVisible())continue;
  const geometry=await note.evaluate(element=>{
   const style=getComputedStyle(element),parent=element.parentElement,parentStyle=getComputedStyle(parent),box=element.getBoundingClientRect();
   const availableWidth=parent.clientWidth-parseFloat(parentStyle.paddingLeft)-parseFloat(parentStyle.paddingRight),fragments=[];
   const walker=document.createTreeWalker(element,NodeFilter.SHOW_TEXT);let node,ordinal=0;
   while((node=walker.nextNode())){if(!node.textContent.trim())continue;const range=document.createRange();range.selectNodeContents(node);for(const rect of range.getClientRects())if(rect.width>0&&rect.height>0)fragments.push({node:ordinal,left:rect.left,right:rect.right,top:rect.top,bottom:rect.bottom});ordinal++;}
   let overlaps=0;for(let i=0;i<fragments.length;i++)for(let j=i+1;j<fragments.length;j++){const a=fragments[i],b=fragments[j];if(a.node!==b.node&&Math.min(a.right,b.right)-Math.max(a.left,b.left)>0.5&&Math.min(a.bottom,b.bottom)-Math.max(a.top,b.top)>0.5)overlaps++;}
   return {display:style.display,gridColumns:style.gridTemplateColumns,width:box.width,availableWidth,overlaps};
  });
  expect(geometry.display).toBe('block');expect(geometry.gridColumns).toBe('none');expect(Number.isFinite(geometry.width)&&Number.isFinite(geometry.availableWidth)).toBe(true);expect(geometry.width).toBeGreaterThanOrEqual(geometry.availableWidth-1);expect(geometry.width).toBeLessThanOrEqual(geometry.availableWidth+1);expect(geometry.overlaps).toBe(0);
 }
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1&&document.body.scrollWidth<=innerWidth+1)).toBe(true);
 for(const item of await page.locator('.investigation-item,.investigation-paging,.investigation-toolbar').all()){
  if(!await item.isVisible())continue;const box=await item.boundingBox();expect(box).not.toBe(null);expect(box.x).toBeGreaterThanOrEqual(0);expect(box.x+box.width).toBeLessThanOrEqual(page.viewportSize().width+1);expect(await item.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
 }
}
/** Reuses the repository runner's single browser, fixture login and captures. */
export async function investigationsBrowserCase({pageAt,login,expect,base,shot}){
 mark('setup');const page=await pageAt('/cases'),clockStart=Date.now();await page.clock.install({time:new Date(clockStart)});await page.clock.pauseAt(new Date(clockStart+1000));
 let phase='issue',reads=0;const unexpected=[],external=[],mutations=[];
 const prefix='/api/devices/'+investigationsFixtureDevice;
 await page.route('**/*',async route=>{
  const request=route.request(),url=new URL(request.url()),method=request.method();
  if(url.origin!==base){external.push('external-request');return route.abort('blockedbyclient');}
  if(method!=='GET'&&!(method==='POST'&&url.pathname==='/api/auth/login')){mutations.push('unexpected-write');return route.abort('blockedbyclient');}
  const fulfill=value=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(value)});
  if(url.pathname==='/api/investigations'){
   if(method!=='GET'||request.postData()!==null||url.search!=='?scope=open&offset=0'){unexpected.push('investigations-contract');return route.abort('blockedbyclient');}
   reads++;return fulfill(investigationsFixture(phase));
  }
  if(url.pathname==='/api/overview'){const view=investigationsFixture(phase);return fulfill({generatedAt:view.serverNow,devices:[investigationsDeviceFixture()],cases:[],activity:[],stats:{totalDevices:1,healthyDevices:0,attentionDevices:0,openCases:0,criticalCases:0}});}
  if(url.pathname===prefix)return fulfill(investigationsDeviceFixture());
  if(url.pathname===prefix+'/health'){const view=investigationsFixture(phase);return fulfill({...view.devices[0],incidents:view.items.map(item=>item.incident)});}
  if(url.pathname.startsWith(prefix+'/inventory/'))return route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({error:{code:'inventory_unavailable',message:'Invented inventory unavailable'}})});
  if(url.pathname.startsWith('/api/')&&!['/api/auth/session','/api/auth/login'].includes(url.pathname)){unexpected.push('unexpected-api-read');return route.abort('blockedbyclient');}
  return route.continue();
 });
 const panel=()=>page.getByRole('region',{name:/^(Health investigations|Health-Untersuchungen)$/});
 const refresh=()=>page.getByRole('button',{name:/^(Refresh investigations|Untersuchungen aktualisieren)$/});
 const reload=async()=>{const before=reads;await refresh().click();await expect.poll(()=>reads).toBe(before+1);await expect(refresh()).toBeEnabled();};
 const capture=async name=>{mark(name);await layout(page,expect);await panel().scrollIntoViewIfNeeded();await expect(page.getByLabel('Operator password',{exact:true})).toHaveCount(0);await shot(page,name,investigationsFixtureDisclosure);};
 await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();expect(reads).toBe(0);await login(page);
 mark('issue');await expect(page.getByRole('heading',{name:'Investigations',exact:true})).toBeVisible();await expect(page.getByRole('button',{name:'Open 1',exact:true})).toBeVisible();await expect(panel().getByRole('heading',{name:'Root filesystem nearly full',exact:true})).toBeVisible();await expect(panel()).toContainText('Investigation fixture <Linux>');await expect(panel().locator('img')).toHaveCount(0);
 await panel().locator('summary').click();await expect(panel()).toContainText('Cause undetermined.');await expect(panel()).toContainText('95.0 %');const opened=await panel().locator('time').first().getAttribute('datetime');
 await capture('synthetic-http-test-investigations-issue-desktop-en');
 mark('expired-current-evidence');phase='stale';await reload();await expect(panel()).toContainText('Unknown: current evidence is missing or stale');await expect(panel()).not.toContainText('95.0 %');await expect(page.getByRole('button',{name:'Open 1',exact:true})).toBeVisible();await expect(panel().locator('time').first()).toHaveAttribute('datetime',opened);await capture('synthetic-http-test-investigations-stale-desktop-en');
 mark('no-current-assessment');phase='unknown';await reload();await expect(panel()).toContainText('No cases in this view');await expect(panel()).toContainText('Missing cases do not mean a healthy device');await expect(page.locator('main')).toContainText('1 with incomplete current checks');await expect(panel().locator('.investigation-item')).toHaveCount(0);
 await page.setViewportSize({width:390,height:844});await capture('synthetic-http-test-investigations-unknown-mobile-en');
 mark('mobile-issue');phase='renewed';await reload();await expect(panel()).toContainText('Root filesystem nearly full');await expect(panel().locator('details')).not.toHaveAttribute('open','');await capture('synthetic-http-test-investigations-issue-mobile-en');
 await page.getByLabel('Language',{exact:true}).selectOption('de');await expect(page.getByRole('button',{name:'Offen 1',exact:true})).toBeVisible();await capture('synthetic-http-test-investigations-issue-mobile-de');await page.getByLabel('Sprache',{exact:true}).selectOption('en');
 mark('stable-device-navigation');await panel().locator('summary').click();const link=panel().getByRole('link',{name:'Open Health & history',exact:true});await expect(link).toHaveAttribute('href',`#/devices/${investigationsFixtureDevice}/health`);await link.click();await expect(page).toHaveURL(`${base}/#/devices/${investigationsFixtureDevice}/health`);await expect(page.getByRole('tab',{name:'Health & history',exact:true})).toHaveAttribute('aria-selected','true');await expect(page.getByRole('heading',{name:'Investigation fixture <Linux>',exact:true})).toBeVisible();
 mark('browser-back');await page.goBack();await expect(page.getByRole('heading',{name:'Investigations',exact:true})).toBeVisible();await expect(panel()).toContainText('Root filesystem nearly full');
 mark('final-read-only-guards');expect(mutations).toEqual([]);expect(unexpected).toEqual([]);expect(external).toEqual([]);expect(await page.evaluate(value=>JSON.stringify({...localStorage,...sessionStorage}).includes(value),investigationsFixtureDevice)).toBe(false);
}
