/** Inert fixture/schema checks. No browser launch or policy write. */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createWindowsServiceHealthFixtureState,exerciseWindowsServiceHealth,windowsServiceHealthBrowserFixture,windowsServiceHealthDisclosure,windowsServiceHealthFixturePath,windowsServiceHealthStageNames} from './windows-service-health-browser.mjs';
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
  function locator(description){return {locator:value=>locator(description+' '+value),getByText:value=>locator(description+' text '+value),getByRole:(role,{name})=>locator(description+' '+role+' '+name),first:()=>locator(description+' first'),click:async()=>{assert.doesNotMatch(description,/Save selected-service policy|Richtlinie für ausgewählte Dienste speichern/);actions.push(['click',description]);},check:async()=>{actions.push(['check',description]);},fill:async value=>{actions.push(['fill',value]);},scrollIntoViewIfNeeded:noop,getAttribute:async()=>origin,evaluate:async()=>true};}
  const page={locator,getByRole:(role,{name})=>locator(role+' '+name)},expectation=new Proxy({}, {get(_target,key){return key==='not'?expectation:noop;}}),expect=()=>expectation;
  await exerciseWindowsServiceHealth({page,expect,locale,width,setPhase:value=>{phase=value;},mark:value=>{assert.ok(windowsServiceHealthStageNames.includes(value));stages.push(value);},shot:async(actual,name,disclosure)=>{assert.equal(actual,page);assert.equal(disclosure,windowsServiceHealthDisclosure);assert.equal(name,`synthetic-windows-service-health-${phase.slice(9)}-${width}-${locale}`);captures.push(name);}});
  assert.deepEqual(stages,windowsServiceHealthStageNames);assert.equal(actions.filter(([action])=>action==='check').length,2);assert.deepEqual(actions.filter(([action])=>action==='fill'),[['fill','background']]);assert.equal(actions.filter(([action,label])=>action==='click'&&label.endsWith(locale==='de'?'Änderungen verwerfen':'Discard changes')).length,1);
 }
 assert.equal(captures.length,24);assert.equal(new Set(captures).size,24);
});
