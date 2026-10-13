/** Inert fixture/schema checks. No browser launch or policy write. */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createWindowsServiceHealthFixtureState,exerciseWindowsServiceHealth,windowsServiceHealthCompleteLegacyRead,windowsServiceHealthBrowserFixture,windowsServiceHealthDisclosure,windowsServiceHealthFixturePath,windowsServiceHealthStageNames} from './windows-service-health-browser.mjs';
const origin='2026-10-07T12:00:10Z';
test('selected-service fixture starts default-off with readable exact-name chooser and no check',()=>{
 const view=windowsServiceHealthBrowserFixture(origin);assert.deepEqual(view.policy,{enabled:false,services:[],revision:0});assert.equal(view.status,'disabled');assert.deepEqual(view.checks,[]);assert.deepEqual(view.incidents,[]);assert.equal(view.inventory.services[0].displayName,'Fixture Background Service');assert.equal(view.inventory.services[1].name,'Spooler');assert.equal(view.inventory.services[2].name,'spooler');assert.match(windowsServiceHealthDisclosure,/read-only fixtures; no policy save/);
});
test('pending, attention, unknown and running recovery retain distinct meanings',()=>{
 const pending=windowsServiceHealthBrowserFixture(origin,origin,'services-pending'),open=windowsServiceHealthBrowserFixture(origin,origin,'services-attention'),unknown=windowsServiceHealthBrowserFixture(origin,origin,'services-unknown'),recovered=windowsServiceHealthBrowserFixture(origin,origin,'services-recovered');
 assert.equal(pending.status,'pending');assert.equal(open.status,'attention');assert.equal(open.checks[0].observation.state,'stopped');assert.equal(open.incidents[0].lastBadObservation.state,'paused');assert.equal(unknown.status,'unknown');assert.equal(unknown.checks[0].observation,null);assert.deepEqual(unknown.incidents,open.incidents);assert.equal(recovered.status,'running');assert.equal(recovered.incidents[0].closedReason,'running');assert.equal(recovered.incidents[0].recoveryObservation.state,'running');
});
test('elapsed time withholds source choices and current checks without renewing history',()=>{
 const open=windowsServiceHealthBrowserFixture(origin,origin,'services-attention'),later=windowsServiceHealthBrowserFixture('2026-10-07T12:02:11Z',origin,'services-attention');assert.equal(later.status,'unknown');assert.equal(later.inventory,null);assert.equal(later.checks[0].observation,null);assert.deepEqual(later.incidents,open.incidents);assert.equal(later.evaluatedAt,open.evaluatedAt);
});
test('policy-change closure never invents recovery',()=>{
 const closed=windowsServiceHealthBrowserFixture(origin,origin,'services-policy-changed');assert.equal(closed.policy.enabled,false);assert.equal(closed.policy.revision,2);assert.equal(closed.incidents[0].closedReason,'policy-changed');assert.equal(closed.incidents[0].recoveryObservation,null);
});
test('independent fixture ledger retains revisions and closure across sibling phases',()=>{
 const state=createWindowsServiceHealthFixtureState();state.setPhase('services-disabled',origin);state.setPhase('services-pending',origin);assert.equal(state.setPhase('cpu-disabled',origin),false);assert.equal(state.view(origin).policy.revision,1);state.setPhase('services-policy-changed',origin);const original=state.view(origin);assert.deepEqual(state.view('2026-10-07T12:00:11Z').incidents,original.incidents);assert.throws(()=>state.setPhase('services-disabled',origin),/rollback/);
});
test('exact read-only route never admits policy writes, aliases, encoded or trailing paths',()=>{
 const prefix='/api/devices/agent_'+'7'.repeat(32);assert.equal(windowsServiceHealthFixturePath(prefix+'/windows-services',prefix),true);for(const suffix of ['/windows-services/policy','/windows-services/','/windows-services?x=1','/windows-services%2fpolicy','/windows-services/cpu'])assert.equal(windowsServiceHealthFixturePath(prefix+suffix,prefix),false);
});
test('browser helper covers EN/DE chooser, passive refresh, discard, source age and all incident stages without mutation',()=>{
 const source=fs.readFileSync(new URL('./windows-service-health-browser.mjs',import.meta.url),'utf8');assert.equal(windowsServiceHealthStageNames.length,6);assert.match(source,/windowsServiceHealthCopy\[locale\]/);assert.match(source,/await choice\.check\(\)/);assert.match(source,/await metadata\.click\(\)/);assert.match(source,/c\.cancel/);assert.match(source,/toHaveAttribute\('datetime',original\)/);for(const label of ['disabled','pending','attention','unknown','recovered','policy-changed'])assert.ok(source.includes(`await capture('${label}')`));assert.doesNotMatch(source,/await save\.click|windows-services\/policy|chromium\.launch|newContext\(|execFile|spawn\(|writeFile|ignoreHTTPSErrors|grantPermissions/);
});
test('service stages are registered in the existing four-variant runner and inert suite allowlist',()=>{
 const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8'),runner=read('./windows-inventory-browser.mjs'),manifest=JSON.parse(read('./inert-suites.json'));
 assert.match(runner,/\.\.\.windowsServiceHealthStageNames/);assert.match(runner,/await exerciseWindowsServiceHealth\(/);assert.match(runner,/for\(const locale of \['en','de'\]\)for\(const width of \[1440,390\]\)/);assert.match(runner,/servicePolicyFixtures\.setPhase\(value,now\(\)\)/);assert.match(runner,/servicePolicyFixtures=createWindowsServiceHealthFixtureState\(\);phase='fresh';percentagePolicyFixtures=createWindowsPercentageFixtureState\(\);await page\.goto/);
 assert.match(read('./windows-inventory-fixtures.test.mjs'),/import '\.\/windows-service-health-fixtures\.test\.mjs'/);assert.ok(manifest.imported.includes('windows-service-health-fixtures.test.mjs'));assert.ok(!manifest.entries.includes('windows-service-health-fixtures.test.mjs'));
 for(const bucket of ['writes','external','unexpected'])assert.ok(runner.includes(`expect(${bucket}).toEqual([])`));
});
test('actual installed browser route permits only exact service GET and blocks writes/query/body before sampling time',async()=>{
 const {windowsInventoryBrowserCase,windowsHealthBrowserDevice}=await import(new URL('./windows-inventory-browser.mjs?inert-services-route',import.meta.url).href);
 const stop=new Error('inert service setup complete'),base='http://fixture.invalid',prefix='/api/devices/'+windowsHealthBrowserDevice(origin).id;let handler,evaluations=0;
 const page={clock:{install:async()=>{},pauseAt:async()=>{}},route:async(_pattern,read)=>{handler=read;},evaluate:async()=>{evaluations++;return Date.parse(origin);}};
 await assert.rejects(windowsInventoryBrowserCase({pageAt:async()=>page,login:async()=>{throw stop;},base}),error=>error===stop);
 async function route(path,{method='GET',body=null,requestOrigin=base}={}){let result;await handler({request:()=>({url:()=>requestOrigin+path,method:()=>method,postData:()=>body}),abort:async reason=>{result={abort:reason};},continue:async()=>{result={continue:true};},fulfill:async value=>{result=value;}});return result;}
 const target=prefix+'/windows-services';for(const method of ['POST','PUT','PATCH','DELETE'])for(const path of [target,target+'/policy'])assert.deepEqual(await route(path,{method,body:'{}'}),{abort:'blockedbyclient'});
 assert.deepEqual(await route(target+'?service=Spooler'),{abort:'blockedbyclient'});assert.deepEqual(await route(target,{body:'{}'}),{abort:'blockedbyclient'});assert.deepEqual(await route(target,{requestOrigin:'https://outside.invalid'}),{abort:'blockedbyclient'});
 for(const path of [target+'/',target+'/policy',prefix+'/windows-%73ervices',target+'/cpu'])assert.equal((await route(path)).status,404);assert.equal(evaluations,0);
 const response=await route(target),value=JSON.parse(response.body);assert.equal(response.status,200);assert.equal(value.schemaVersion,'tracebolt.windows-service-view.v1');assert.equal(value.status,'disabled');assert.equal(value.policy.enabled,false);assert.equal(evaluations,1);
});
test('inert helper walkthrough covers all 24 localized captures with chooser, refresh and discard but no Save click',async()=>{
 const captures=[];
 for(const locale of ['en','de'])for(const width of [1440,390]){
  let phase;const stages=[],actions=[],noop=async()=>{};
  function locator(description){return {locator:value=>locator(description+' '+value),getByText:value=>locator(description+' text '+value),getByRole:(role,{name})=>locator(description+' '+role+' '+name),first:()=>locator(description+' first'),click:async()=>{assert.doesNotMatch(description,/Save selected-service policy|Richtlinie für ausgewählte Dienste speichern/);actions.push(['click',description]);},check:async()=>{actions.push(['check',description]);},fill:async value=>{actions.push(['fill',value]);},scrollIntoViewIfNeeded:noop,getAttribute:async()=>origin,evaluate:async()=>true,selectOption:async value=>{actions.push(['select',value]);}};}
  const page={locator,getByRole:(role,{name})=>locator(role+' '+name)},expectation=new Proxy({}, {get(_target,key){return key==='not'?expectation:noop;}}),expect=()=>expectation;
  await exerciseWindowsServiceHealth({page,expect,locale,width,setPhase:value=>{phase=value;},mark:value=>{assert.ok(value==='services-source'||windowsServiceHealthStageNames.includes(value));stages.push(value);},shot:async(actual,name,disclosure)=>{assert.equal(actual,page);assert.equal(disclosure,windowsServiceHealthDisclosure);assert.equal(name,`synthetic-windows-service-health-${phase.slice(9)}-${width}-${locale}`);captures.push(name);}});
  assert.deepEqual(stages,['services-source',...windowsServiceHealthStageNames]);assert.deepEqual(actions.filter(([action])=>action==='select'),[['select','preview']]);assert.equal(actions.filter(([action])=>action==='check').length,2);assert.deepEqual(actions.filter(([action])=>action==='fill'),[['fill','background']]);assert.equal(actions.filter(([action,label])=>action==='click'&&label.endsWith(locale==='de'?'Änderungen verwerfen':'Discard changes')).length,1);
 }
 assert.equal(captures.length,24);assert.equal(new Set(captures).size,24);
});

// The actual installed interception, not an alternate test-only route.
test('initial complete status read represents retained legacy source conflict without granting complete access',async()=>{
 const {windowsInventoryBrowserCase,windowsHealthBrowserDevice}=await import(new URL('./windows-inventory-browser.mjs?inert-complete-status',import.meta.url).href);
 const stop=new Error('inert complete status setup'),base='http://fixture.invalid',prefix='/api/devices/'+windowsHealthBrowserDevice(origin).id;let handler,evaluations=0;
 const page={clock:{install:async()=>{},pauseAt:async()=>{}},route:async(_pattern,read)=>{handler=read;},evaluate:async()=>{evaluations++;return Date.parse(origin);}};
 await assert.rejects(windowsInventoryBrowserCase({pageAt:async()=>page,login:async()=>{throw stop;},base}),error=>error===stop);
 async function route(path,{method='GET',body=null,requestOrigin=base}={}){let result;await handler({request:()=>({url:()=>requestOrigin+path,method:()=>method,postData:()=>body}),abort:async reason=>{result={abort:reason};},continue:async()=>{result={continue:true};},fulfill:async value=>{result=value;}});return result;}
 const target=prefix+'/windows-services/complete',response=await route(target);
 assert.equal(response.status,409);assert.deepEqual(JSON.parse(response.body),{error:{code:'windows_service_source_conflict',message:'This policy uses another explicit source version.'}});
 for(const method of ['POST','PUT','PATCH','DELETE'])for(const path of [target,target+'/policy'])assert.deepEqual(await route(path,{method,body:'{}'}),{abort:'blockedbyclient'});
 for(const options of [{body:'{}'},{requestOrigin:'https://outside.invalid'}])assert.deepEqual(await route(target,options),{abort:'blockedbyclient'});
 assert.deepEqual(await route(target+'?x=1'),{abort:'blockedbyclient'});
 for(const path of [target+'/',target+'/policy',target.replace('/complete','/%63omplete')])assert.equal((await route(path)).status,404);
 assert.equal(evaluations,0);
});

test('real compiled App explicitly switches default complete source to preserved preview without policy writes',async()=>{
 const {createRequire}=await import('node:module'),require=createRequire(new URL('../../web/package.json',import.meta.url));
 const {JSDOM}=require('jsdom'),{build}=require('esbuild');
 // Keep this login-stopping walkthrough's diagnostic state out of sibling tests.
 const {windowsInventoryBrowserCase,windowsHealthBrowserDevice,windowsInventoryFailureStage}=await import(new URL('./windows-inventory-browser.mjs?inert-complete-source-app',import.meta.url).href);
 assert.equal(windowsInventoryFailureStage(),'setup');
 const compiled=await build({entryPoints:[new URL('../../web/src/main.tsx',import.meta.url).pathname],outdir:'memory-only',bundle:true,platform:'browser',format:'iife',jsx:'automatic',define:{'process.env.NODE_ENV':'"production"'},loader:{'.woff':'dataurl','.woff2':'dataurl'},write:false,logLevel:'silent'});
 const script=compiled.outputFiles.find(file=>file.path.endsWith('.js')).text;
 for(const locale of ['en','de']){
  const at=new Date().toISOString(),base='https://fixture.invalid',device=windowsHealthBrowserDevice(at),prefix='/api/devices/'+device.id,reads=[],errors=[];
  const session={mode:'lan',transport:'https',insecureTestMode:false,transportWarning:null,authenticationRequired:true,authenticated:true,csrfToken:'synthetic-only',serverNow:at,expiresAt:new Date(Date.parse(at)+3600000).toISOString(),expiresInSeconds:3600,loginMode:'shared',actorId:null,capabilities:['read']};
  let handler;const stop=new Error('inert App route setup'),page={clock:{install:async()=>{},pauseAt:async()=>{}},route:async(_pattern,read)=>{handler=read;},evaluate:async()=>Date.parse(at)};
  await assert.rejects(windowsInventoryBrowserCase({pageAt:async()=>page,login:async()=>{throw stop;},base}),error=>error===stop);
  assert.equal(windowsInventoryFailureStage(),'login');
  const dom=new JSDOM('<!doctype html><html><body><div id="root"></div></body></html>',{url:base+'/#/devices/'+device.id+'/health',runScripts:'outside-only',pretendToBeVisual:true});
  try{
   const w=dom.window;Object.assign(w,{TextEncoder,TextDecoder,structuredClone});w.localStorage.setItem('tracebolt.locale',locale);w.HTMLElement.prototype.scrollIntoView=()=>{};
   w.addEventListener('error',event=>{errors.push(event.error?.name);event.preventDefault();});
   w.fetch=async(url,options={})=>{
    const absolute=new URL(url,w.location),method=options.method??'GET';assert.equal(method,'GET');reads.push(absolute.pathname);
    let value;
    if(absolute.pathname==='/api/auth/session')value={status:200,body:JSON.stringify(session)};
    else if(absolute.pathname==='/api/session')value={status:200,body:JSON.stringify({csrfToken:session.csrfToken})};
    else await handler({request:()=>({url:()=>absolute.href,method:()=>method,postData:()=>options.body??null}),abort:async()=>{throw new Error('Unexpected aborted App route: '+absolute.pathname);},continue:async()=>{throw new Error('Unexpected App fallback: '+absolute.pathname);},fulfill:async response=>{value=response;}});
    assert.ok(value);return new Response(value.body,{status:value.status,headers:{'Content-Type':'application/json'}});
   };
   w.eval(script);
   for(let i=0;i<150&&!w.document.querySelector('.windows-service-source select');i++)await new Promise(resolve=>setTimeout(resolve,20));
   const chooser=w.document.querySelector('.windows-service-source select');assert.ok(chooser);assert.equal(chooser.value,'complete');assert.equal(chooser.labels[0].textContent.startsWith(locale==='de'?'Quelle der Dienstprüfungen':'Service-check source'),true);
   for(let i=0;i<150&&!reads.includes(prefix+'/windows-services/complete');i++)await new Promise(resolve=>setTimeout(resolve,20));
   assert(reads.includes(prefix+'/windows-services/complete'));assert.equal(reads.includes(prefix+'/windows-services'),false);
   chooser.value='preview';chooser.dispatchEvent(new w.Event('change',{bubbles:true}));
   for(let i=0;i<150&&!w.document.querySelector('.windows-service-health')?.textContent.includes(locale==='de'?'Richtlinie deaktiviert':'Policy disabled');i++)await new Promise(resolve=>setTimeout(resolve,20));
   assert(reads.includes(prefix+'/windows-services'));assert.equal(chooser.value,'preview');assert.ok(w.document.querySelector('.windows-service-health').textContent.includes(locale==='de'?'Richtlinie deaktiviert':'Policy disabled'));
   assert.deepEqual(errors,[]);
  }finally{dom.window.close();}
 }
});
