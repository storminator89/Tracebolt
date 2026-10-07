/** Public synthetic package workflow only. All package requests terminate here;
 * the hosted fixture supplies only its existing real login and CSRF lifecycle. */
import fs from 'node:fs';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
const require=createRequire(new URL('../../web/package.json',import.meta.url));
const decoders=require('esbuild').buildSync({stdin:{contents:"export {validPackageUpdateView} from './src/package-update-types'; export {validCachedUpdatesView} from './src/cached-updates-types'; export {validCompleteUpdateView} from './src/complete-updates-types';",resolveDir:fileURLToPath(new URL('../../web/',import.meta.url)),loader:'ts'},bundle:true,write:false,platform:'node',format:'esm',logLevel:'silent'});
const {validPackageUpdateView,validCachedUpdatesView,validCompleteUpdateView}=await import('data:text/javascript;base64,'+Buffer.from(decoders.outputFiles[0].text).toString('base64'));

export const packageUpdatesCaseName='Synthetic selected package updates retain unavailable scope, exact simulation review and unknown outcomes without host changes';
export const packageUpdatesFixtureDisclosure='UI-only production rendering with real loopback HTTP-test login and CSRF reads. Named operator capabilities are an intercepted display proxy only, not a server grant. Invented Go-projected package DTOs retain exact package/version/source/digest data; only request binding, HTTP-test transport and a single original-time offset are adapted. The bounded inventory row is derived from that public projection. No actual preparation, install, grant, provider request, key entry or native operation. No native acceptance or signed-plan proof.';
const stored=JSON.parse(fs.readFileSync(new URL('../../web/src/package-update-go-fixtures.json',import.meta.url),'utf8'));
const inventoryStored=JSON.parse(fs.readFileSync(new URL('../../web/src/complete-updates-go-fixture.json',import.meta.url),'utf8'));
const clone=value=>structuredClone(value);
const stages=new Set(['setup','login','unavailable','selection','review','consent','unknown','guards']);
let stage='setup';
export const packageUpdatesFailureStage=()=>stage;
const mark=value=>{stage=stages.has(value)?value:'unknown';};
const requireFixture=value=>{if(!value)throw new Error('Unsupported synthetic package-update fixture request');};
const exact=(value,keys)=>value!==null&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
const validRequest=value=>typeof value==='string'&&/^update_[a-f0-9]{32}$/.test(value)&&value!=='update_'+'0'.repeat(32);
const shift=(value,offset)=>Array.isArray(value)?value.map(item=>shift(item,offset)):value&&typeof value==='object'?Object.fromEntries(Object.entries(value).map(([key,item])=>[key,shift(item,offset)])):typeof value==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/.test(value)?new Date(Date.parse(value)+offset).toISOString():value;
export function packageUpdatesWireFixtures(){return clone(stored);}

/** Deterministic in-memory receiver. A projection is display data, never a plan,
 * native adapter, capability grant, provider or privileged helper. */
export function createPackageUpdatesFixture({anchor=stored.idle.serverNow,now=()=>Date.parse(anchor)+5000}={}){
 const offset=Date.parse(anchor)-Date.parse(stored.idle.serverNow);
 requireFixture(Number.isFinite(offset));
 const device=stored.idle.deviceId,actor=stored.preview_ready.preview.actorId,prefix=`/api/devices/${device}/package-updates`;
 let phase='unavailable',requestId=null;
 const counts={reads:0,prepare:0,approve:0};
 const project=(name=phase)=>{
  requireFixture(['unavailable','idle','preview_ready','needs_intervention'].includes(name));
  const result=shift(clone(stored[name]),offset);
  if(result.preview){result.preview.requestId=requestId??result.preview.requestId;result.preview.transportProfile='disposable-http-test';}
  if(result.job)result.job.requestId=requestId??result.job.requestId;
  requireFixture(validPackageUpdateView(result,device));return result;
 };
 const items=clone(stored.preview_ready.preview.items),selection=items.map(({name,architecture})=>({name,architecture}));
 const at=milliseconds=>new Date(Date.parse(anchor)+milliseconds).toISOString();
 const complete={...clone(inventoryStored.view),deviceId:device,serverNow:at(0),status:'not_configured',complete:null,transfer:null,failure:null};
 // This one row is explicitly invented selection inventory derived from the
 // Go projection; cached candidates do not establish a prepared/native plan.
 const cached={schemaVersion:'tracebolt.cached-updates-view.v1',deviceId:device,status:'fresh',serverNow:at(0),maxAgeSeconds:120,sequence:'1',receivedAt:at(-1000),expiresAt:at(86398000),latest:{schemaVersion:'tracebolt.cached-apt-updates.v1',scope:'agent-visible-dpkg-and-existing-apt-cache',generationId:'sample_'+'a'.repeat(32),collectedAt:at(-2000),durationMs:1,release:{id:'debian',versionId:'13',versionCodename:'trixie'},coverage:'complete',reason:'none',metadata:{freshness:'unknown',oldestIndexModifiedAt:at(-3602000),ageSeconds:3600,ageBasis:'oldest-local-package-index-mtime',refresh:'not_attempted'},installedCount:items.length,checkedCount:items.length,candidateCount:items.length,heldCount:0,unknownCount:0,truncated:false,items:items.map(item=>({name:item.name,architecture:item.architecture,installedVersion:item.fromVersion,candidateVersion:item.toVersion,state:'candidate_only',installability:'not_evaluated'}))}};
 requireFixture(validCompleteUpdateView(complete,device)&&validCachedUpdatesView(cached,device));
 return {device,actor,prefix,selection,counts,complete,cached,project,get phase(){return phase;},get requestId(){return requestId;},
  loadSimulation(){requireFixture(phase==='unavailable'&&requestId===null);phase='idle';},
  handle(method,path,body){
   if(method==='GET'&&(path===prefix||requestId!==null&&path===`${prefix}/jobs/${requestId}`)){requireFixture(body===null);counts.reads++;return project();}
   if(method==='POST'&&path===`${prefix}/prepare`){
    requireFixture(phase==='idle'&&requestId===null&&exact(body,['requestId','packages'])&&validRequest(body.requestId)&&JSON.stringify(body.packages)===JSON.stringify(selection));
    requireFixture(now()<Date.parse(project('preview_ready').preview.expiresAt));requestId=body.requestId;phase='preview_ready';counts.prepare++;return project();
   }
   if(method==='POST'&&path===`${prefix}/approve`){
    requireFixture(phase==='preview_ready'&&exact(body,['requestId','previewDigest'])&&body.requestId===requestId&&body.previewDigest===project().preview.digest&&now()<Date.parse(project().preview.expiresAt));
    phase='needs_intervention';counts.approve++;return project();
   }
   requireFixture(false);
  },
 };
}

/** The proxy changes display metadata only. Preserve the actual auth/CSRF,
 * transport, server clock and original session expiry returned by the fixture. */
export function packageUpdatesNamedSession(session,actor){
 requireFixture(session?.mode==='lan'&&session.authenticated===true&&session.insecureTestMode===true&&session.transport==='http'&&session.transportWarning==='unencrypted_lan_test'&&typeof session.csrfToken==='string'&&session.csrfToken.length>0&&Date.parse(session.expiresAt)>Date.parse(session.serverNow));
 return {...session,loginMode:'named',actorId:actor,capabilities:['read','plan_updates','execute_updates']};
}

export function packageUpdatesRoute({base,fixture,state,now=()=>Date.now()}){
 const prefix=`/api/devices/${fixture.device}`;
 let csrf='',csrfSequence=0,consumedCSRF=0,authority=null,admission=null;
 const json=(route,value,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(value)});
 const device=()=>{const at=fixture.project().serverNow,metric={value:null,unit:'%',quality:'unknown',source:'Synthetic package UI fixture',collectedAt:at};return {id:fixture.device,name:'SYNTHETIC PACKAGE UI FIXTURE',platform:'linux',os:'Synthetic Debian display',site:'Fixture',group:'Fixture',ip:null,status:'unknown',source:'lan',synthetic:false,lastSeen:at,agentVersion:'fixture',cpu:metric,memory:metric,disk:metric,uptime:'',tags:[],capabilities:[],evidence:[],trend:[],caseIds:[]};};
 return async route=>{
  const request=route.request(),url=new URL(request.url()),method=request.method();
  const block=label=>{state.unexpected.push(label);return route.abort('blockedbyclient');};
  if(url.origin!==base){state.external.push('external-request');return route.abort('blockedbyclient');}
  if(method==='POST'&&url.pathname==='/api/auth/login'&&url.search===''){
   if(state.loginRequests!==0)return block('repeated-login');state.loginRequests++;return route.continue();
  }
  try{
   if(method==='GET'&&url.pathname==='/api/auth/session'&&url.search===''){
    requireFixture(request.postData()===null);const response=await route.fetch();
    if(response.status()!==200)return route.fulfill({response});
    const session=await response.json();if(!session.authenticated)return route.fulfill({response});
    const proxy=packageUpdatesNamedSession(session,fixture.actor);authority={actor:proxy.actorId,expiresAt:proxy.expiresAt,serverNow:proxy.serverNow,observedAt:now(),admission};state.namedReads++;
    return route.fulfill({response,json:proxy});
   }
   if(method==='GET'&&url.pathname==='/api/session'&&url.search===''){
    requireFixture(request.postData()===null);const response=await route.fetch();
    if(response.status()===200){const value=await response.json();requireFixture(typeof value.csrfToken==='string'&&value.csrfToken.length>0);csrf=value.csrfToken;csrfSequence++;}
    return route.fulfill({response});
   }
   if(url.pathname.startsWith(fixture.prefix)){
    requireFixture(url.search==='');
    if(method==='GET'){
     requireFixture(request.postData()===null);const value=fixture.handle(method,url.pathname,null);admission={phase:fixture.phase,observedAt:now()};return json(route,value);
    }
    const headers=await request.allHeaders();
    requireFixture(method==='POST'&&headers['content-type']==='application/json'&&csrf!==''&&headers['x-csrf-token']===csrf&&csrfSequence>consumedCSRF);
    requireFixture(authority!==null&&admission!==null&&authority.admission===admission&&authority.actor===fixture.actor&&now()>=admission.observedAt&&now()-admission.observedAt<10000&&now()>=authority.observedAt&&now()-authority.observedAt<10000&&Date.parse(authority.expiresAt)>now());
    requireFixture(Date.parse(authority.serverNow)>=Date.parse(fixture.project().serverNow));
    const value=fixture.handle(method,url.pathname,request.postDataJSON());consumedCSRF=csrfSequence;authority=null;admission=null;return json(route,value);
   }
   requireFixture(method==='GET'&&request.postData()===null);
   if(url.pathname===prefix&&url.search==='')return json(route,device());
   if(url.pathname===prefix+'/inventory/complete-updates'&&url.search==='')return json(route,fixture.complete);
   if(url.pathname===prefix+'/inventory/cached-updates'&&url.search==='')return json(route,fixture.cached);
   if(url.pathname===prefix+'/inventory/endpoint-identity'&&url.search==='')return json(route,{schemaVersion:'tracebolt.endpoint-identity-view.v1',deviceId:fixture.device,status:'not_collected',serverNow:fixture.project().serverNow,maxAgeSeconds:120,sequence:null,receivedAt:null,expiresAt:null,latest:null});
   if([prefix+'/health',prefix+'/resource-history'].includes(url.pathname)&&url.search==='')return json(route,{error:{code:'synthetic_display_unavailable',message:'No observation in this synthetic fixture'}},503);
   if(url.pathname==='/api/overview'&&url.search==='')return json(route,{generatedAt:fixture.project().serverNow,devices:[device()],cases:[],activity:[],stats:{totalDevices:1,healthyDevices:0,attentionDevices:0,unknownDevices:1,openCases:0,criticalCases:0}});
   if(url.pathname==='/api/investigations'&&url.search==='?scope=open&offset=0')return json(route,{schemaVersion:'tracebolt.investigations.v1',serverNow:fixture.project().serverNow,scope:'open',offset:0,total:0,counts:{open:0,recovered:0,closed:0,all:0},devices:[],items:[]});
   if(url.search===''&&(url.pathname==='/'||url.pathname==='/favicon.svg'||url.pathname.startsWith('/assets/')))return route.continue();
   return block('unexpected-request');
  }catch{return block('invalid-fixture-request');}
 };
}

/** Exactly one additive hosted case; does not launch a browser or a server. */
export async function packageUpdatesBrowserCase({pageAt,login,expect,base,shot}){
 mark('setup');const page=await pageAt('/devices/'+stored.idle.deviceId),start=Date.now();
 await page.clock.install({time:new Date(start)});await page.clock.pauseAt(new Date(start+100));
 const fixture=createPackageUpdatesFixture({anchor:new Date(start-5000).toISOString(),now:()=>Date.now()}),state={unexpected:[],external:[],loginRequests:0,namedReads:0};
 await page.route('**/*',packageUpdatesRoute({base,fixture,state}));
 mark('login');await login(page);await page.reload();
 await page.getByRole('button',{name:'View updates',exact:true}).click();
 const panel=page.locator('.package-update-workflow'),review=page.locator('.package-update-review');
 const language=()=>page.locator('select[aria-label="Language"],select[aria-label="Sprache"]');
 const prepare=()=>panel.getByRole('button',{name:/^(Prepare selected updates \(simulation\)|Ausgewählte Updates vorbereiten \(Simulation\))$/});
 const approve=()=>panel.getByRole('button',{name:/^(Confirm this exact update \(simulation\)|Dieses genaue Update bestätigen \(Simulation\))$/});
 const capture=async(name,anchor=panel)=>{
  await anchor.scrollIntoViewIfNeeded();await expect(page.locator('input[type="password"]')).toHaveCount(0);
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1&&document.body.scrollWidth<=innerWidth+1)).toBe(true);
  expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
  // A labelled test-only overlay prevents a cropped review/status image from
  // being mistaken for a native operation. Production content is untouched.
  await page.evaluate(()=>{let banner=document.getElementById('synthetic-package-capture-label');if(!banner){banner=document.createElement('aside');banner.id='synthetic-package-capture-label';banner.style.cssText='position:fixed;bottom:0;left:0;right:0;z-index:99999;background:#102a43;color:white;padding:6px 12px;font:12px/1.3 sans-serif;text-align:center;pointer-events:none';document.body.append(banner);}banner.textContent=document.documentElement.lang==='de'?'SYNTHETISCHE UI-FIXTURE · Keine Hostupdates oder Freigaben · Operator nur simuliert':'SYNTHETIC UI FIXTURE · No host updates or grants · Display-only named operator';});
  await expect(page.locator('#synthetic-package-capture-label')).toBeVisible();
  if(name.includes('-review-')){await anchor.evaluate(el=>el.scrollIntoView({block:'center'}));await expect(review.locator('ol > li').first()).toBeInViewport({ratio:1});await expect(review.getByText('1.0-1 → 1.0-2',{exact:true})).toBeInViewport({ratio:1});await expect(review.getByText('sample-bin 1.0-2 · Synthetic fixture repository / trixie / main',{exact:true})).toBeInViewport({ratio:1});}
  await shot(page,name,packageUpdatesFixtureDisclosure);
 };
 const gallery=async(name,anchor=panel)=>{for(const locale of ['en','de'])for(const width of [1440,390]){await page.setViewportSize({width,height:width===390?844:1000});await language().selectOption(locale);await expect(page.locator('html')).toHaveAttribute('lang',locale);await capture(`synthetic-package-updates-${name}-${width===390?'mobile':'desktop'}-${locale}`,anchor);}await language().selectOption('en');};
 mark('unavailable');await expect(panel).toContainText('Native package updates are not ready on this device.');await expect(page.getByText('Complete update storage is not configured',{exact:true})).toBeVisible();await expect(prepare()).toBeDisabled();await expect(panel.locator('.package-update-simulation')).toHaveCount(0);await gallery('unavailable');expect(fixture.counts.prepare).toBe(0);
 mark('selection');await page.getByLabel('Update view',{exact:true}).selectOption('preview');
 const selected=page.getByRole('checkbox',{name:'Select sample-bin:amd64',exact:true});await expect(selected).toBeEnabled();await selected.check();await expect(prepare()).toBeDisabled();
 fixture.loadSimulation();await panel.getByRole('button',{name:'Refresh saved update status',exact:true}).click();await expect(panel).toContainText('SIMULATION ONLY');await expect(prepare()).toBeEnabled();await gallery('selection');
 mark('review');await prepare().click();await expect(review).toBeVisible();
 const preview=fixture.project().preview;for(const value of [preview.requestId,preview.digest,preview.actorId,preview.expiresAt,'disposable-http-test','sample-bin:amd64','1.0-1 → 1.0-2','sample-bin 1.0-2 · Synthetic fixture repository / trixie / main',preview.items[0].archiveSHA256])await expect(review).toContainText(value);
 await expect(review.getByRole('checkbox')).not.toBeChecked();await expect(approve()).toBeDisabled();await expect(prepare()).toBeDisabled();expect(fixture.counts.prepare).toBe(1);const exactPackage=review.locator('ol > li').first();await gallery('review',exactPackage);
 mark('consent');await review.getByRole('checkbox').check();await expect(approve()).toBeEnabled();await review.getByRole('checkbox').uncheck();await expect(approve()).toBeDisabled();await review.getByRole('checkbox').check();await expect(review).toContainText('No automatic reboot or guaranteed rollback.');await capture('synthetic-package-updates-consent-mobile-en',review.locator('.package-update-ack'));
 await approve().click();
 mark('unknown');await expect(panel).toContainText('Needs intervention; outcome not verified');await expect(panel).toContainText('Observed version: Unknown');await expect(panel).toContainText('runner_state_unknown');await expect(panel).toContainText('Unknown · simulation');await expect(approve()).toHaveCount(0);await expect(prepare()).toBeDisabled();await expect(panel).not.toContainText('All approved versions verified');await gallery('unknown',panel.getByRole('region',{name:/^(Saved operation|Gespeicherter Vorgang)$/}));
 mark('guards');expect(fixture.counts.prepare).toBe(1);expect(fixture.counts.approve).toBe(1);expect(state.loginRequests).toBe(1);expect(state.namedReads).toBeGreaterThanOrEqual(3);expect(state.unexpected).toEqual([]);expect(state.external).toEqual([]);
 expect(await page.evaluate(()=>sessionStorage.getItem('tracebolt.package-update-intent'))).toBeNull();
}
