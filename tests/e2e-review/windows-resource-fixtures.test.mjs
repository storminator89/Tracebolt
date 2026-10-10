/** Inert invented CPU/RAM fixture checks. No browser launch or policy mutation. */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {windowsCapacityBrowserFixture} from './windows-capacity-browser.mjs';
import {exerciseWindowsResources,windowsResourceBrowserFixture,windowsResourceDisclosure,windowsResourceFixtureMetric,windowsResourceStageNames} from './windows-resource-browser.mjs';
const origin='2026-10-07T12:00:10Z',prefix='/api/devices/agent_11111111111111111111111111111111';
const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8');
for(const metric of ['cpu','memory']){
 test(`${metric} policy display is independently disabled by default with exact resource binding`,()=>{
  const value=windowsResourceBrowserFixture(metric,origin);
  assert.equal(value.schemaVersion,'tracebolt.windows-resource-view.v1');assert.equal(value.metric,metric);assert.equal(value.status,'disabled');
  assert.deepEqual(value.policy,{enabled:false,thresholdPercent:90,revision:0});assert.equal(value.observation,null);assert.equal(value.evaluatedAt,null);assert.deepEqual(value.incidents,[]);
  assert.deepEqual(Object.keys(value).sort(),['schemaVersion','metric','deviceId','serverNow','certificateExpiresAt','policy','status','evaluatedAt','observation','incidents'].sort());
 });
 test(`${metric} injected pending, pressure and unknown preserve original observation/evaluation ages`,()=>{
  const pending=windowsResourceBrowserFixture(metric,origin,origin,`${metric}-pending`),pressure=windowsResourceBrowserFixture(metric,origin,origin,`${metric}-pressure`),unknown=windowsResourceBrowserFixture(metric,origin,origin,`${metric}-unknown`);
  assert.equal(pending.status,'pending');assert.equal(pending.policy.enabled,true);assert.equal(pending.incidents.length,0);assert.equal(pressure.status,'pressure');assert.equal(pressure.incidents.length,1);
  const boundary=new Date(Date.parse(pressure.observation.collectedAt)+120000).toISOString(),expired=new Date(Date.parse(boundary)+1).toISOString();
  const stillCurrent=windowsResourceBrowserFixture(metric,boundary,origin,`${metric}-pressure`),later=windowsResourceBrowserFixture(metric,expired,origin,`${metric}-pressure`);
  assert.equal(stillCurrent.status,'pressure');assert.deepEqual(stillCurrent.observation,pressure.observation);assert.equal(stillCurrent.evaluatedAt,pressure.evaluatedAt);
  assert.equal(later.status,'unknown');assert.equal(later.observation,null);assert.equal(unknown.status,'unknown');assert.equal(unknown.observation,null);
  for(const value of [unknown,later]){assert.equal(value.evaluatedAt,pressure.evaluatedAt);assert.deepEqual(value.incidents,pressure.incidents);assert.equal(value.incidents[0].resolvedAt,null);assert.equal(value.incidents[0].recoveryObservation,null);}
 });
 test(`${metric} policy-change closure retains high evidence and never fabricates recovery`,()=>{
  const pressure=windowsResourceBrowserFixture(metric,origin,origin,`${metric}-pressure`),closed=windowsResourceBrowserFixture(metric,origin,origin,`${metric}-policy-changed`);
  assert.equal(closed.status,'disabled');assert.equal(closed.policy.enabled,false);assert.equal(closed.policy.revision,2);assert.equal(closed.observation,null);
  const incident=closed.incidents[0],original=pressure.incidents[0];assert.equal(incident.closedReason,'policy-changed');assert.equal(incident.recoveryObservation,null);assert.equal(incident.resolvedAt,origin);
  assert.equal(incident.policyRevision,original.policyRevision);assert.equal(incident.thresholdPercent,original.thresholdPercent);assert.deepEqual(incident.openingObservation,original.openingObservation);assert.deepEqual(incident.lastHighObservation,original.lastHighObservation);
 });
 test(`${metric} fixtures cannot enable another resource or disk through a shared phase`,()=>{
  const sibling=metric==='cpu'?'memory':'cpu';
  for(const phase of windowsResourceStageNames.filter(name=>name.startsWith(metric+'-'))){
   const other=windowsResourceBrowserFixture(sibling,origin,origin,phase),disk=windowsCapacityBrowserFixture(origin,origin,phase);
   for(const value of [other,disk]){assert.equal(value.status,'disabled');assert.deepEqual(value.policy,{enabled:false,thresholdPercent:90,revision:0});assert.equal(value.observation,null);assert.deepEqual(value.incidents,[]);}
  }
  for(const phase of ['capacity-enabled','capacity-pressure','capacity-unknown','capacity-closed'])assert.equal(windowsResourceBrowserFixture(metric,origin,origin,phase).policy.enabled,false);
 });
}
test('resource fixtures return separate objects without mutating other reads',()=>{
 const cpu=windowsResourceBrowserFixture('cpu',origin,origin,'cpu-pressure'),memory=windowsResourceBrowserFixture('memory',origin,origin,'memory-pressure');
 cpu.policy.thresholdPercent=95;cpu.incidents[0].lastHighObservation.value=99;
 assert.equal(memory.policy.thresholdPercent,90);assert.equal(memory.incidents[0].lastHighObservation.value,92);
 assert.equal(windowsResourceBrowserFixture('cpu',origin,origin,'cpu-pressure').policy.thresholdPercent,90);
 for(const metric of ['disk','ram','CPU','',null,undefined])assert.throws(()=>windowsResourceBrowserFixture(metric,origin),/Invalid invented resource metric/);
});
test('resource GET path allowlist never admits policy paths, aliases, encoded or ambiguous paths',()=>{
 for(const metric of ['cpu','memory']){
  const exact=prefix+'/windows-resource/'+metric;assert.equal(windowsResourceFixtureMetric(exact,prefix),metric);
  for(const pathname of [exact+'/',exact+'/policy',exact+'?enabled=true',exact+'/extra',exact.replace(metric,metric.toUpperCase()),exact.replace('/windows-resource/','/windows-resource//'),exact.replace('/windows-resource/','/windows-resource%2f/'),'/api/devices/other/windows-resource/'+metric])assert.equal(windowsResourceFixtureMetric(pathname,prefix),null);
 }
 for(const suffix of ['','/','/ram','/disk','/%63pu','/cpu%2fpolicy'])assert.equal(windowsResourceFixtureMetric(prefix+'/windows-resource'+suffix,prefix),null);
});
test('CPU and RAM fixture disclosures preserve native semantics and source-only evidence limits',()=>{
 assert.match(windowsResourceDisclosure,/GetSystemTimes observed processor group, not an all-group aggregate/);
 assert.match(windowsResourceDisclosure,/physical RAM not immediately available: 100 × \(ullTotalPhys − ullAvailPhys\) \/ ullTotalPhys from GlobalMemoryStatusEx/);
 assert.match(windowsResourceDisclosure,/Enabled policies are injected by read-only fixtures; no policy save/);
 for(const boundary of ['native Windows read','local grant','installed-service acceptance','notification','AI call','deployment'])assert.ok(windowsResourceDisclosure.includes(boundary));
});
test('resource browser source is registered for EN/DE desktop/mobile stages and scopes every panel',()=>{
 const source=read('./windows-resource-browser.mjs'),runner=read('./windows-inventory-browser.mjs'),disk=read('./windows-capacity-browser.mjs');
 assert.deepEqual(windowsResourceStageNames,['cpu-disabled','cpu-pending','cpu-pressure','cpu-unknown','cpu-policy-changed','memory-disabled','memory-pending','memory-pressure','memory-unknown','memory-policy-changed']);
 assert.match(runner,/\.\.\.windowsResourceStageNames/);assert.match(runner,/await exerciseWindowsResources\(/);assert.match(runner,/for\(const locale of \['en','de'\]\)for\(const width of \[1440,390\]\)/);
 for(const metric of ['cpu','memory'])assert.ok(runner.includes(`prefix+'/windows-resource/${metric}'`));
 assert.match(runner,/percentagePolicyFixtures=createWindowsPercentageFixtureState\(\)/);assert.match(runner,/percentagePolicyFixtures\.resource\(resourceMetric,at\)/);
 assert.match(source,/\.windows-capacity\[data-metric="\$\{metric\}"\]/);assert.match(disk,/\.windows-capacity\[data-metric="disk"\]/);
 assert.match(source,/await enabled\.check\(\)/);assert.match(source,/Änderungen verwerfen/);assert.match(source,/await assertIndependent\(\)/);
 for(const state of ['disabled','pending','pressure','unknown','policy-changed'])assert.ok(source.includes(`await capture('${state}')`));
 for(const label of ['CPU percentage policy','Physical RAM percentage policy','CPU-Prozentrichtlinie','Prozentrichtlinie für physischen RAM','Refresh CPU policy','Refresh RAM policy','CPU-Richtlinie aktualisieren','RAM-Richtlinie aktualisieren'])assert.ok(source.includes(label));
 assert.match(source,/synthetic-windows-\$\{metric\}-policy-\$\{state\}-\$\{width\}-\$\{locale\}/);
});
test('browser interception blocks all policy writes before synthetic resource dispatch and rejects GET query/body',()=>{
 const source=read('./windows-resource-browser.mjs'),runner=read('./windows-inventory-browser.mjs');
 const writeGuard="if(request.method()!=='GET'&&!(request.method()==='POST'&&url.pathname==='/api/auth/login')){writes.push('write');return route.abort('blockedbyclient');}";
 assert.ok(runner.includes(writeGuard));assert.ok(runner.indexOf(writeGuard)<runner.indexOf('const resourceMetric=windowsResourceFixtureMetric'));
 assert.match(runner,/if\(resourceMetric&&\(url\.search\|\|request\.postData\(\)!==null\)\)\{unexpected\.push\('unexpected-resource-query'\);return route\.abort\('blockedbyclient'\);\}/);
 for(const bucket of ['writes','external','unexpected'])assert.ok(runner.includes(`expect(${bucket}).toEqual([])`));
 assert.doesNotMatch(source,/await save\.click|\/policy['"`]|chromium\.launch|newContext\(|execFile|spawn\(|writeFile|ignoreHTTPSErrors|grantPermissions/);
});


test('actual installed browser route handler admits exact CPU/RAM GETs and blocks writes before clock sampling',async()=>{
 const {windowsInventoryBrowserCase,windowsHealthBrowserDevice}=await import(new URL('./windows-inventory-browser.mjs?inert-resource-route-guards',import.meta.url).href);
 const stop=new Error('inert resource setup complete'),base='http://fixture.invalid',devicePrefix='/api/devices/'+windowsHealthBrowserDevice(origin).id;
 let handler,evaluations=0;
 const page={clock:{install:async()=>{},pauseAt:async()=>{}},route:async(_pattern,read)=>{handler=read;},evaluate:async()=>{evaluations++;return Date.parse(origin);}};
 await assert.rejects(windowsInventoryBrowserCase({pageAt:async()=>page,login:async()=>{throw stop;},base}),error=>error===stop);
 async function route(path,{method='GET',body=null,requestOrigin=base}={}){
  let result;
  await handler({request:()=>({url:()=>requestOrigin+path,method:()=>method,postData:()=>body}),abort:async reason=>{result={abort:reason};},continue:async()=>{result={continue:true};},fulfill:async value=>{result=value;}});
  return result;
 }
 for(const metric of ['cpu','memory']){
  const target=devicePrefix+'/windows-resource/'+metric;
  for(const method of ['POST','PUT','PATCH','DELETE'])for(const path of [target,target+'/policy'])assert.deepEqual(await route(path,{method,body:'{}'}),{abort:'blockedbyclient'});
  for(const path of [target+'?unexpected=1',target+'?metric='+metric])assert.deepEqual(await route(path),{abort:'blockedbyclient'});
  assert.deepEqual(await route(target,{body:'{}'}),{abort:'blockedbyclient'});assert.deepEqual(await route(target,{requestOrigin:'https://outside.invalid'}),{abort:'blockedbyclient'});
  for(const path of [target+'/',target+'/policy',target+'/extra'])assert.equal((await route(path)).status,404);
 }
 for(const path of ['/ram','/disk','/%63pu','/cpu%2fpolicy'])assert.equal((await route(devicePrefix+'/windows-resource'+path)).status,404);
 assert.equal(evaluations,0,'rejected paths, methods, bodies and external origins must not observe the synthetic clock');
 for(const metric of ['cpu','memory']){
  const response=await route(devicePrefix+'/windows-resource/'+metric);assert.equal(response.status,200);
  const value=JSON.parse(response.body);assert.equal(value.schemaVersion,'tracebolt.windows-resource-view.v1');assert.equal(value.metric,metric);assert.equal(value.serverNow,new Date(Date.parse(origin)).toISOString());assert.equal(value.policy.enabled,false);assert.equal(value.status,'disabled');
 }
 assert.equal(evaluations,2,'one synthetic clock sample per accepted metric GET');
});

test('inert helper walk registers all 40 localized metric/phase captures with edit/discard and no save clicks',async()=>{
 const captures=[];
 for(const locale of ['en','de'])for(const width of [1440,390]){
  let phase;const stages=[],actions=[],noop=async()=>{};
  function locator(description){const loc={
   locator:value=>locator(description+' '+value),getByText:value=>locator(description+' text '+value),getByRole:(role,{name})=>locator(description+' '+role+' '+name),nth:index=>locator(description+' nth '+index),first:()=>locator(description+' first'),
   click:async()=>{assert.doesNotMatch(description,/Save (?:CPU|RAM) policy|(?:CPU|RAM)-Richtlinie speichern/);actions.push(['click',description]);},
   check:async()=>{actions.push(['check',description]);},scrollIntoViewIfNeeded:noop,getAttribute:async()=>origin,evaluate:async()=>true,
  };return loc;}
  const page={locator,getByRole:(role,{name})=>locator(role+' '+name)};
  const expectation=new Proxy({}, {get(_target,key){return key==='not'?expectation:noop;}}),expect=()=>expectation;
  await exerciseWindowsResources({page,expect,locale,width,setPhase:value=>{phase=value;},mark:value=>{assert.ok(windowsResourceStageNames.includes(value));stages.push(value);},shot:async(actual,name,disclosure)=>{
   assert.equal(actual,page);assert.equal(disclosure,windowsResourceDisclosure);assert.equal(name,`synthetic-windows-${phase.split('-')[0]}-policy-${phase.split('-').slice(1).join('-')}-${width}-${locale}`);captures.push(name);
  }});
  assert.deepEqual(stages,windowsResourceStageNames);assert.equal(actions.filter(([action])=>action==='check').length,2);
  assert.equal(actions.filter(([action,label])=>action==='click'&&label.endsWith(locale==='de'?'Änderungen verwerfen':'Discard changes')).length,2);
  assert.equal(actions.filter(([action,label])=>action==='click'&&label.includes('data-metric="disk"')&&label.endsWith(locale==='de'?'Kapazitätsrichtlinie aktualisieren':'Refresh capacity policy')).length,6);
 }
 assert.equal(captures.length,40);assert.equal(new Set(captures).size,40);
});


test('actual percentage fixture state retains sibling revisions, history and closure times across helper phases',async()=>{
 const {createWindowsPercentageFixtureState}=await import('./windows-inventory-browser.mjs');
 const fixture=createWindowsPercentageFixtureState(),later=new Date(Date.parse(origin)+1000).toISOString();
 fixture.setPhase('capacity-disabled',origin);fixture.setPhase('capacity-enabled',origin);fixture.setPhase('capacity-pressure',origin);fixture.setPhase('capacity-closed',origin);
 const disk=fixture.capacity(origin);assert.equal(disk.policy.revision,2);assert.equal(disk.incidents[0].closedReason,'policy-changed');
 for(const phase of windowsResourceStageNames){
  fixture.setPhase(phase,origin);
  const currentDisk=fixture.capacity(later);assert.deepEqual(currentDisk.policy,disk.policy);assert.deepEqual(currentDisk.incidents,disk.incidents);
  if(phase.startsWith('cpu-'))assert.equal(fixture.resource('memory',later).policy.revision,0);
  else {const cpu=fixture.resource('cpu',later);assert.equal(cpu.status,'disabled');assert.equal(cpu.policy.revision,2);assert.equal(cpu.incidents[0].closedReason,'policy-changed');assert.equal(cpu.incidents[0].resolvedAt,origin);}
 }
 const cpu=fixture.resource('cpu',later),memory=fixture.resource('memory',later);
 assert.equal(memory.policy.revision,2);assert.equal(memory.incidents[0].resolvedAt,origin);
 assert.throws(()=>fixture.setPhase('cpu-disabled',later),/revision rollback/);assert.throws(()=>fixture.setPhase('capacity-disabled',later),/revision rollback/);
 assert.equal(fixture.setPhase('updates',later),false);assert.deepEqual(fixture.resource('cpu',later),cpu);assert.deepEqual(fixture.resource('memory',later),memory);
 // A new detail walkthrough remounts hook-local revision floors after the runner
 // leaves the previous detail. Only that reset starts another default-off walkthrough.
 const next=createWindowsPercentageFixtureState();assert.equal(next.capacity(later).policy.revision,0);
 for(const metric of ['cpu','memory'])assert.equal(next.resource(metric,later).policy.revision,0);
 const source=read('./windows-inventory-browser.mjs');assert.match(source,/phase='fresh';percentagePolicyFixtures=createWindowsPercentageFixtureState\(\);await page\.goto/);
 assert.equal((source.match(/percentagePolicyFixtures\.setPhase\(value,now\(\)\)/g)||[]).length,2);
});
