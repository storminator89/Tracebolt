/** Entirely invented chart samples. Rendered UI coverage only; durable history,
 * retry/revocation authority and retention are tested separately in Go. */
import {validResourceHistory} from '../../web/src/resource-history-types.ts';
export const resourceHistoryCaseName='Synthetic 24-hour resource charts preserve real sample times, missing intervals and protected access';
export const resourceHistoryFixtureDisclosure='Real loopback HTTP-test fixture login and production compiled UI with intercepted invented CPU, memory and root-filesystem history. UI-only evidence; no native telemetry, user VM, collection, external requests, or deployment.';
let stage='setup';
export const resourceHistoryFailureStage=()=>stage;
const mark=value=>{stage=value;};
const id='agent_'+('e'.repeat(32));
export function resourceBrowserFixture(now,phase='available'){
 const end=Date.parse(now),points=[];
 if(phase==='available')for(let i=0;i<=1440;i++){
  // A missing hour and explicit unknown observations remain separate gaps.
  if(i>600&&i<660)continue;
  const at=new Date(end-(1440-i)*60000).toISOString(),unknown=i%77===0;
  points.push({sequence:String(i+1),collectedAt:at,receivedAt:at,cpu:{value:unknown?null:i===1?0:Math.round((25+18*Math.sin(i/35))*10)/10,quality:unknown?'unknown':'healthy',collectedAt:at},memory:{value:Math.round((51+4*Math.cos(i/60))*10)/10,quality:'healthy',collectedAt:at},disk:{value:28.1+Math.floor(i/480)/10,quality:'healthy',collectedAt:at}});
 }
 const view={schemaVersion:'tracebolt.resource-history.v1',deviceId:id,serverNow:now,windowStart:new Date(end-86400000).toISOString(),status:phase==='available'?'available':phase,resolutionSeconds:60,gapAfterSeconds:120,points};
 if(!validResourceHistory(view,id))throw new Error('Invalid synthetic history fixture');return view;
}
function fixtureDevice(now){const metric={value:28.4,unit:'%',quality:'healthy',source:'Invented browser fixture',collectedAt:now};return{id,name:'Resource chart fixture',platform:'linux',os:'Linux fixture',site:'Fixture',group:'Fixture',ip:null,status:'unknown',source:'lan',synthetic:false,lastSeen:now,agentVersion:'fixture',cpu:{...metric,value:7.8},memory:{...metric,value:52.2},disk:metric,uptime:'',tags:[],capabilities:[],evidence:[],trend:[],caseIds:[],agentCertificate:{source:'guided-enrollment',checkedAt:now,expiresAt:new Date(Date.parse(now)+86400000).toISOString()}};}
export async function resourceHistoryBrowserCase({pageAt,login,expect,base,shot}){
 const page=await pageAt('/devices/'+id),start=Date.now()+1000;await page.clock.install({time:new Date(start)});await page.clock.pauseAt(new Date(start));let tick=0,phase='available',reads=0;const writes=[],external=[];const now=()=>new Date(start+tick).toISOString(),prefix='/api/devices/'+id;
 await page.route('**/*',async route=>{
  const r=route.request(),url=new URL(r.url());if(url.origin!==base){external.push('external');return route.abort('blockedbyclient');}
  if(r.method()!=='GET'&&!(r.method()==='POST'&&url.pathname==='/api/auth/login')){writes.push('write');return route.abort('blockedbyclient');}
  const fulfill=value=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(value)});
  if(url.pathname===prefix+'/resource-history'){if(r.method()!=='GET'||url.search&&!/^\?afterSequence=[1-9][0-9]{0,18}$/.test(url.search)||r.postData()!==null)throw new Error('Unexpected history read');reads++;if(phase==='session')return route.fulfill({status:401,contentType:'application/json',body:JSON.stringify({error:{code:'authentication_required'}})});return fulfill(resourceBrowserFixture(now(),phase));}
  if(url.pathname===prefix)return fulfill(fixtureDevice(now()));
  if(url.pathname==='/api/overview')return fulfill({generatedAt:now(),devices:[fixtureDevice(now())],cases:[],activity:[],stats:{totalDevices:1,healthyDevices:0,attentionDevices:0,openCases:0,criticalCases:0}});
  if(url.pathname.startsWith(prefix+'/inventory/')||url.pathname===prefix+'/health')return route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({error:{code:'inventory_unavailable'}})});
  return route.continue();
 });
 mark('initial-chart');await login(page);const panel=page.getByRole('region',{name:'Last 24 hours',exact:true});const settle=async()=>{await expect.poll(async()=>{tick+=500;await page.clock.runFor(500);return panel.getByRole('img').count();}).toBe(3);};await settle();await expect(panel.locator('.cpu .resource-chart-line')).not.toHaveCount(1);const cpu=panel.getByRole('img',{name:/^CPU/});await cpu.focus();await page.keyboard.press('Home');await expect(panel.locator('.resource-chart-inspection.visible')).toContainText('0%');await expect(panel.locator('.resource-chart-inspection.visible time')).toHaveAttribute('datetime',resourceBrowserFixture(now()).points[1].cpu.collectedAt);await page.keyboard.press('End');await expect(panel.locator('.resource-chart-inspection.visible time')).toHaveAttribute('datetime',now());
 mark('desktop-layout');await panel.scrollIntoViewIfNeeded();await shot(page,'synthetic-resource-history-desktop-en',resourceHistoryFixtureDisclosure);
 await page.getByRole('button',{name:'Switch to dark theme',exact:true}).click();await shot(page,'synthetic-resource-history-desktop-dark-en',resourceHistoryFixtureDisclosure);
 mark('mobile-layout');await page.setViewportSize({width:390,height:844});await panel.scrollIntoViewIfNeeded();expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);await shot(page,'synthetic-resource-history-mobile-en',resourceHistoryFixtureDisclosure);
 await page.getByLabel('Language',{exact:true}).selectOption('de');await expect(page.getByRole('region',{name:'Letzte 24 Stunden',exact:true})).toBeVisible();await shot(page,'synthetic-resource-history-mobile-de',resourceHistoryFixtureDisclosure);await page.getByLabel('Sprache',{exact:true}).selectOption('en');
 mark('empty-history');phase='awaiting';tick+=61000;await page.clock.runFor(61000);await expect(panel).toContainText('History will appear as reports arrive.');await expect(panel.locator('.resource-chart-line')).toHaveCount(0);
 mark('returning-history');phase='available';tick+=61000;await page.clock.runFor(61000);await expect(panel.locator('.resource-chart-line').first()).toBeVisible();
 // Navigation clears the chart reader; coming back performs a fresh read.
 mark('navigation');const before=reads;await page.getByRole('tab',{name:'Details',exact:true}).click();await expect(panel).toHaveCount(0);tick+=61000;await page.clock.runFor(61000);expect(reads).toBe(before);await page.getByRole('tab',{name:'Overview',exact:true}).click();await settle();expect(reads).toBeGreaterThan(before);
 mark('access-loss');phase='session';tick+=61000;await page.clock.runFor(61000);await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();await expect(panel).toHaveCount(0);const after=reads;await page.clock.runFor(60000);expect(reads).toBe(after);expect(writes).toEqual([]);expect(external).toEqual([]);
}
