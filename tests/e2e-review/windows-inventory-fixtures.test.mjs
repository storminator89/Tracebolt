import './windows-update-download-fixtures.test.mjs';
import './windows-update-retirement-fixtures.test.mjs';
import './windows-software-jobs-fixtures.test.mjs';
import './windows-update-schedule-fixtures.test.mjs';
import './windows-resource-context-fixtures.test.mjs';
import './windows-security-coverage-fixtures.test.mjs';
import './windows-hardware-context-fixtures.test.mjs';
import './windows-storage-context-fixtures.test.mjs';
import './windows-session-context-fixtures.test.mjs';
import './windows-service-actions-fixtures.test.mjs';
import './windows-security-posture-fixtures.test.mjs';
import './windows-patch-context-fixtures.test.mjs';
import './windows-service-health-fixtures.test.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {requireWindowsAdapterContextEvidence} from './windows-adapter-context-browser.mjs';
import {remountWindowsDevice,settleWindowsHistory,windowsBrowserFixture,windowsInventoryFixtureDisclosure,windowsInventoryFailureStage,windowsFixtureSessionExpiry,windowsEventHistoryLegacyRead} from './windows-inventory-browser.mjs';
function fixtureSessionRead({status=200,value={authenticated:true,serverNow:'2026-10-10T12:00:00Z',expiresAt:'2026-10-10T12:20:00Z',csrfToken:'PRIVATE_INERT_SESSION_VALUE'},fetchFailure=false,bodyFailure=false,disposeFailure=false}={}){
 const calls=[],response={status:()=>status,async json(){calls.push('json');if(bodyFailure)throw new Error('PRIVATE_INERT_BODY_FAILURE');return value;},async dispose(){calls.push('dispose');if(disposeFailure)throw new Error('PRIVATE_INERT_DISPOSE_FAILURE');}};
 return {calls,page:{request:{async get(url,options){calls.push({url,options});if(fetchFailure)throw new Error('PRIVATE_INERT_REQUEST_FAILURE');return response;}}}};
}
test('Windows fixture session expiry uses one awaited cookie-sharing read and retains only the original expiry',async()=>{
 const f=fixtureSessionRead(),expiry=await windowsFixtureSessionExpiry(f.page,'http://127.0.0.1:19886');
 assert.equal(expiry,'2026-10-10T12:20:00Z');
 assert.deepEqual(f.calls,[{url:'http://127.0.0.1:19886/api/auth/session',options:{maxRedirects:0,timeout:5000}},'json','dispose']);
 assert.equal(JSON.stringify(expiry).includes('PRIVATE_INERT'),false);
 const source=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8');
 assert.match(source,/await login\(page\);eventSessionExpires=await windowsFixtureSessionExpiry\(page,base\)/);
 assert.doesNotMatch(source,/page\.on\('response'/);
 assert.equal((source.match(/eventSessionExpires=/g)||[]).length,2,'one initial null and one awaited assignment only');
});
test('Windows fixture session read rejects redirected or unauthenticated status without reading a body',async()=>{
 for(const status of [201,204,301,302,307,401,403,500]){
  const f=fixtureSessionRead({status});await assert.rejects(windowsFixtureSessionExpiry(f.page,'http://127.0.0.1:19886'),{message:'Windows fixture session expiry unavailable'});
  assert.equal(f.calls.length,2);assert.equal(f.calls[1],'dispose');
 }
});
test('Windows fixture session read requires authenticated finite future expiry without fallback',async()=>{
 const valid={authenticated:true,serverNow:'2026-10-10T12:00:00Z',expiresAt:'2026-10-10T12:20:00Z'};
 for(const value of [null,{}, {...valid,authenticated:false},{...valid,authenticated:'true'},{...valid,expiresAt:null},{...valid,expiresAt:'invalid'},{...valid,serverNow:'invalid'},{...valid,serverNow:null},{...valid,expiresAt:valid.serverNow},{...valid,expiresAt:'2026-10-10T11:59:59Z'}]){
  const f=fixtureSessionRead({value});await assert.rejects(windowsFixtureSessionExpiry(f.page,'http://127.0.0.1:19886'),{message:'Windows fixture session expiry unavailable'});
  assert.deepEqual(f.calls.slice(1),['json','dispose']);
 }
});
test('Windows fixture session read rejects every non-exact loopback origin before making a request',async()=>{
 for(const base of ['https://127.0.0.1:19886','http://example.invalid','http://localhost:19886','http://127.0.0.1:19886/other','http://user:password@127.0.0.1:19886','not a URL']){
  const f=fixtureSessionRead();await assert.rejects(windowsFixtureSessionExpiry(f.page,base),{message:'Windows fixture session expiry unavailable'});assert.deepEqual(f.calls,[]);
 }
});
test('Windows fixture session transport and body failures stay awaited, finite and never retry',async()=>{
 for(const options of [{fetchFailure:true},{bodyFailure:true},{disposeFailure:true}]){
  const f=fixtureSessionRead(options);await assert.rejects(windowsFixtureSessionExpiry(f.page,'http://127.0.0.1:19886'),{message:'Windows fixture session expiry unavailable'});
  assert.equal(f.calls.filter(x=>typeof x==='object').length,1);assert.equal(f.calls.filter(x=>x==='dispose').length,options.fetchFailure?0:1);
 }
});
test('invented Windows views preserve finite scope, truncation and denied distinction',()=>{
 const now='2026-10-07T12:00:10Z',fresh=windowsBrowserFixture(now),stale=windowsBrowserFixture(now,'stale');
 assert.equal(fresh.events.scope,'windows-application-system-event-headers-v1');assert.equal(fresh.events.channels[0].rows[0].recordId,'18446744073709551615');assert.equal(fresh.events.channels[1].quality,'denied');assert.equal(stale.events.collectedAt,stale.snapshot.collectedAt);
 assert.equal(fresh.volumes.scope,'windows-visible-volumes-v1');assert.equal(fresh.volumes.rows[0].capacity.freeBytes,'18446744073709551615');assert.equal(fresh.volumes.rows[1].quality,'denied');assert.equal(fresh.volumes.rows[1].capacity,null);assert.notEqual(fresh.volumes.collectedAt,fresh.snapshot.collectedAt);
 assert.equal(stale.volumes.collectedAt,stale.snapshot.collectedAt);
 const legacy=windowsBrowserFixture(now,'legacy');assert.equal(legacy.status,'fresh');assert.equal(Object.hasOwn(legacy,'events'),false);assert.equal(Object.hasOwn(legacy,'volumes'),false);
 assert.equal(fresh.status,'fresh');assert.equal(fresh.snapshot.processes.complete,true);
 assert.equal(stale.status,'stale');assert.equal(stale.snapshot.processes.observedCount,200);assert.equal(stale.snapshot.processes.countExact,false);
 assert.equal(stale.snapshot.services.quality,'denied');assert.deepEqual(stale.snapshot.services.rows,[]);
 assert.equal(windowsInventoryFailureStage(),'setup');assert.match(windowsInventoryFixtureDisclosure,/no native endpoint acceptance/);
});
test('hosted Windows UI case is additive and keeps finite diagnostics and real fixture login',()=>{
 const runner=fs.readFileSync(new URL('./lan-browser.mjs',import.meta.url),'utf8'),source=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8');
 assert.equal((runner.match(/await check\(/g)||[]).length,27);assert.equal((runner.match(/await check\(windowsInventoryCaseName/g)||[]).length,1);
 assert.match(runner,/stage:windowsInventoryFailureStage\(\)/);assert.match(source,/await login\(page\)/);assert.match(source,/writes\.push\('write'\)/);assert.match(source,/external\.push\('external'\)/);
 assert.doesNotMatch(source,/chromium\.launch|createServer|writeFile|error\.message/);
});
test('synthetic process metrics distinguish real zero, large exact RAM and null qualities',()=>{
 const now='2026-10-07T12:00:10Z',fresh=windowsBrowserFixture(now),metrics=fresh.processMetrics;
 assert.equal(metrics.scope,'windows-process-metrics-v1');assert.equal(metrics.generationId,fresh.snapshot.generationId);assert.equal(metrics.observedCount,6);assert.equal(metrics.truncated,false);
 assert.deepEqual(metrics.rows.map(row=>row.pid),fresh.snapshot.processes.rows.map(row=>row.pid));
 assert.equal(metrics.rows[0].cpuPercent,125.25);assert.equal(metrics.rows[0].memoryBytes,'9007199254740993');
 assert.deepEqual(metrics.rows[1],{pid:45,cpuPercent:0,cpuQuality:'observed',memoryBytes:'0',memoryQuality:'observed'});
 assert.deepEqual(metrics.rows.slice(2).map(row=>row.cpuQuality),['first-sample','reset','denied','unavailable']);assert.ok(metrics.rows.slice(2).every(row=>row.cpuPercent===null));
 assert.equal(metrics.rows[4].memoryBytes,null);assert.equal(metrics.rows[4].memoryQuality,'denied');assert.equal(metrics.rows[5].memoryBytes,null);assert.equal(metrics.rows[5].memoryQuality,'unavailable');
 assert.equal(Object.hasOwn(windowsBrowserFixture(now,'legacy'),'processMetrics'),false);
});
test('synthetic metrics age independently while inventory, events and volumes remain young',()=>{
 const now='2026-10-07T12:00:10Z',stale=windowsBrowserFixture(now,'metrics-stale'),expiring=windowsBrowserFixture(now,'metrics-expiring');
 for(const view of [stale,expiring]){
  assert.equal(view.status,'fresh');assert.equal(Date.parse(now)-Date.parse(view.snapshot.collectedAt),2000);assert.equal(Date.parse(now)-Date.parse(view.volumes.collectedAt),1500);assert.equal(view.events.collectedAt,view.snapshot.collectedAt);
 }
 assert.equal(Date.parse(now)-Date.parse(stale.processMetrics.collectedAt),300000);
 const age=Date.parse(now)-Date.parse(expiring.processMetrics.collectedAt);assert.ok(age<86400000);assert.ok(age+6000>=86400000);
});
test('hosted process overlay covers translated desktop/mobile display and real TTL crossing',()=>{
 const source=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8');
 for(const suffix of ['process-metrics','process-metrics-null','process-metrics-stale','process-metrics-expired'])assert.ok(source.includes('synthetic-windows-'+suffix+'-${width}-${locale}'));
 assert.match(source,/for\(const locale of \['en','de'\]\)for\(const width of \[1440,390\]\)/);
 assert.match(source,/page\.clock\.runFor\(6000\)/);assert.match(source,/125,25 %/);assert.match(source,/9\.007\.199\.254\.740\.993/);
 assert.match(source,/expect\(unexpected\)\.toEqual\(\[\]\)/);assert.match(source,/expect\(writes\)\.toEqual\(\[\]\)/);assert.match(source,/expect\(external\)\.toEqual\(\[\]\)/);
 assert.doesNotMatch(source,/chromium\.launch|newContext\(|execFile|spawn\(|writeFile|ignoreHTTPSErrors/);
});

test('mobile metric labels assert rendered pseudo-elements rather than clipped headers',()=>{
 const source=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8');
 assert.match(source,/if\(width===1440\)await expect\(table\.getByRole\('columnheader'/);
 assert.ok(source.includes('td[data-label="${label}"]'));assert.match(source,/getComputedStyle\(el,'::before'\)/);assert.match(source,/expect\(before\.content\)\.toBe\(JSON\.stringify\(label\)\)/);assert.match(source,/expect\(before\.visibility\)\.toBe\('visible'\)/);
 assert.doesNotMatch(source,/getByRole\('cell'/);
});

test('synthetic network has TCP and UDP v4/v6, scoped numeric addresses and API PID only',()=>{
 const now='2026-10-07T12:00:10Z',view=windowsBrowserFixture(now),network=view.network;
 assert.equal(network.scope,'windows-network-endpoints-v1');assert.equal(network.generationId,view.snapshot.generationId);assert.equal(network.quality,'observed');assert.equal(network.countExact,true);assert.equal(network.observedCount,4);assert.equal(network.truncated,false);
 assert.deepEqual(network.rows.map(row=>row.protocol+'/'+row.family),['tcp/ipv4','tcp/ipv6','udp/ipv4','udp/ipv6']);
 assert.equal(network.rows[0].state,'listen');assert.equal(network.rows[0].remoteAddress,null);assert.equal(network.rows[0].remotePort,null);assert.equal(network.rows[1].remoteAddress,'2001:db8::80');assert.equal(network.rows[1].state,'established');assert.equal(network.rows[3].localAddress,'fe80::40%4');assert.equal(network.rows[3].pid,0);
 for(const row of network.rows){assert.equal(Object.hasOwn(row,'processName'),false);if(row.protocol==='udp'){assert.equal(row.remoteAddress,null);assert.equal(row.remotePort,null);assert.equal(row.state,null);}}
 assert.equal(Object.hasOwn(windowsBrowserFixture(now,'legacy'),'network'),false);
});
test('synthetic network state fixtures distinguish empty, denied, unavailable, partial and truncated',()=>{
 const now='2026-10-07T12:00:10Z',empty=windowsBrowserFixture(now,'network-empty').network;
 assert.equal(empty.quality,'observed');assert.equal(empty.countExact,true);assert.equal(empty.observedCount,0);assert.deepEqual(empty.rows,[]);
 for(const state of ['denied','unavailable','partial']){const network=windowsBrowserFixture(now,'network-'+state).network;assert.equal(network.quality,state);assert.equal(network.countExact,false);assert.equal(network.observedCount,0);assert.deepEqual(network.rows,[]);}
 const bounded=windowsBrowserFixture(now,'network-truncated').network;assert.equal(bounded.quality,'observed');assert.equal(bounded.countExact,true);assert.equal(bounded.truncated,true);assert.equal(bounded.observedCount,100);assert.equal(bounded.rows.length,4);
});
test('synthetic network age respects its base capture floor while sibling captures remain young',()=>{
 const now='2026-10-07T12:00:10Z',stale=windowsBrowserFixture(now,'network-stale'),expiring=windowsBrowserFixture(now,'network-expiring');
 assert.equal(Date.parse(now)-Date.parse(stale.network.collectedAt),300000);
 for(const view of [stale,expiring]){assert.equal(view.status,'stale');assert.equal(view.snapshot.collectedAt,view.network.collectedAt);for(const key of ['volumes','processMetrics'])assert.equal(Date.parse(now)-Date.parse(view[key].collectedAt),1500);assert.equal(Date.parse(now)-Date.parse(view.events.collectedAt),2000);}
 const age=Date.parse(now)-Date.parse(expiring.network.collectedAt);assert.ok(age<86400000);assert.ok(age+6000>=86400000);
});
test('additive network overlay keeps hosted browser safeguards and desktop/mobile EN/DE coverage',()=>{
 const source=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8');
 for(const suffix of ['network','network-udp','network-expired'])assert.ok(source.includes('synthetic-windows-'+suffix+'-${width}-${locale}'));
 assert.ok(source.includes('synthetic-windows-network-${state}-${width}-${locale}'));assert.match(source,/for\(const state of \['empty','denied','unavailable','partial','truncated','stale'\]\)/);
 assert.match(source,/clockNow\+=6000;await page\.clock\.runFor\(6000\)/);assert.match(source,/API owning PID/);assert.match(source,/Besitzende PID laut API/);assert.match(source,/networkTable\.getByRole\('link'\)/);
 assert.ok(source.includes("await expect(networkTable.getByText('fixture.exe',{exact:true})).toHaveCount(0)"));
 assert.doesNotMatch(source,/chromium\.launch|newContext\(|execFile|spawn\(|writeFile|ignoreHTTPSErrors/);
});

test('hosted adapter rows use the production fixture with distinct grant and exact base capture binding',async()=>{
 const require=createRequire(new URL('../../web/package.json',import.meta.url)),{build}=require('esbuild');
 const built=await build({stdin:{contents:"export {windowsAdapterContext} from './windows-adapter-context-fixture'; export {validWindowsInventoryView} from './windows-inventory-types';",resolveDir:fileURLToPath(new URL('../../web/src/',import.meta.url)),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
 const {windowsAdapterContext,validWindowsInventoryView}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
 const now='2026-10-07T12:00:10Z',fixture=windowsAdapterContext();
 for(const phase of ['fresh','stale','metrics-stale','network-empty','network-denied','network-unavailable','network-partial','network-truncated','network-stale','network-expiring']){
  const view=windowsBrowserFixture(now,phase),adapter=view.adapterContext;
  assert.equal(validWindowsInventoryView(view,view.deviceId),true);
  assert.deepEqual(adapter,{...fixture,generationId:view.snapshot.generationId,collectedAt:view.snapshot.collectedAt});
  for(const key of ['events','volumes','processMetrics','network'])assert.notEqual(adapter.grantId,view[key].grantId);
  for(const change of [{collectedAt:new Date(Date.parse(adapter.collectedAt)+1).toISOString()},{generationId:`sample_${'b'.repeat(32)}`},{grantId:view.network.grantId}])assert.equal(validWindowsInventoryView({...view,adapterContext:{...adapter,...change}},view.deviceId),false);
 }
 assert.deepEqual(fixture.rows.map(row=>row.state),['up','down','unknown']);
 assert.deepEqual([fixture.rows[0].txLinkBps,fixture.rows[0].rxLinkBps],[1000000000,2500000000]);
 const expired=windowsBrowserFixture('2026-10-07T12:00:16Z','network-expiring',now);
 assert.equal(expired.snapshot,null);assert.equal(Object.hasOwn(expired,'adapterContext'),false);
 assert.equal(Object.hasOwn(windowsBrowserFixture(now,'legacy'),'adapterContext'),false);
 const mutated=windowsBrowserFixture(now);mutated.adapterContext.rows[0].dnsServers.addresses.length=0;
 assert.deepEqual(windowsBrowserFixture(now).adapterContext.rows,fixture.rows,'independent responses cannot mutate the source rows');
});

test('adapter screenshot completion requires every source-bound locale and viewport without a browser',()=>{
 const sourceSha='a'.repeat(40),testName='Invented Windows case';
 const fixture=()=>['en','de'].flatMap(locale=>[1440,390].map(width=>({file:`synthetic-windows-adapter-context-${width}-${locale}.png`,sourceSha,test:testName,locale,viewport:{width,height:width===390?844:1000},publicSafe:true,fullPage:false,fixtureDisclosure:'Invented adapter context; no native collection.'})));
 assert.deepEqual(requireWindowsAdapterContextEvidence(fixture(),sourceSha,testName),{adapters:4});
 assert.throws(()=>requireWindowsAdapterContextEvidence([],sourceSha,testName),/completion evidence/);
 for(let index=0;index<4;index++){
  const missing=fixture();missing.splice(index,1);assert.throws(()=>requireWindowsAdapterContextEvidence(missing,sourceSha,testName),/completion evidence/);
  const duplicate=fixture();duplicate[index]={...duplicate[(index+1)%4]};assert.throws(()=>requireWindowsAdapterContextEvidence(duplicate,sourceSha,testName),/completion evidence/);
 }
 for(const mutate of [item=>{item.sourceSha='b'.repeat(40);},item=>{item.test='Another case';},item=>{item.locale='de';},item=>{item.viewport.width=390;},item=>{item.viewport.height=844;},item=>{item.publicSafe=false;},item=>{item.fullPage=true;},item=>{item.fixtureDisclosure='';}]){
  const invalid=fixture();mutate(invalid[0]);assert.throws(()=>requireWindowsAdapterContextEvidence(invalid,sourceSha,testName),/completion evidence/);
 }
});

test('adapter checks extend the existing Network flow without changing sessions, clocks or endpoint scope',()=>{
 const source=fs.readFileSync(new URL('./windows-adapter-context-browser.mjs',import.meta.url),'utf8'),flow=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8');
 assert.match(flow,/exerciseWindowsAdapterContext\(\{page,expect,locale,width,shot,disclosure:windowsInventoryFixtureDisclosure\}\)/);
 assert.match(flow,/networkTable=networkPanel\.locator\('\.windows-inventory-table'\)/);assert.match(flow,/const panel=networkPanel/);
 assert.ok(source.includes('synthetic-windows-adapter-context-${width}-${locale}'));
 assert.match(source,/details\[open\]/);assert.match(source,/toBeHidden\(\)/);assert.match(source,/toHaveCount\(1\)/);assert.match(source,/toBeInViewport\(\{ratio:1\}\)/);assert.match(source,/bounds\.right<=panel\.right\+1/);
 assert.doesNotMatch(source,/chromium\.launch|newContext\(|execFile|spawn\(|writeFile|fetch\(|page\.route|page\.clock|setDefaultTimeout|waitForTimeout/);
});


test('paused Windows overview advances the same fixture clock before requiring all three charts',async()=>{
 let now=0,reads=0;const calls=[];
 const page={locator(selector){assert.equal(selector,'.resource-history');return {getByRole(role){assert.equal(role,'img');return {async count(){calls.push('count');reads++;return now<1000?0:3;}};}};}};
 const expect={poll(probe){return {async toBe(wanted){assert.equal(wanted,3);for(let n=0;n<4;n++)if(await probe()===wanted)return;assert.fail('all three real charts required');}};}};
 await settleWindowsHistory(page,expect,async ms=>{assert.equal(ms,500);calls.push('advance');now+=ms;});
 assert.equal(now,1000);assert.equal(reads,2);assert.deepEqual(calls,['advance','count','advance','count']);
 const source=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8');
 assert.match(source,/settleWindowsHistory\(page,expect,async ms=>\{clockNow\+=ms;await page\.clock\.runFor\(ms\);\}\)/);
 assert.match(source,/getByRole\('img',\{name:\/\^\(System volume\|Systemvolume\)\/\}\)\)\.toBeVisible\(\)/);
 assert.doesNotMatch(source,/setDefaultTimeout|waitForTimeout|\.skip\(|test\.skip/);
});


test('paused overview still rejects incomplete chart evidence',async()=>{
 let advances=0;
 const page={locator(){return {getByRole(){return {async count(){return 2;}};}};}};
 const expect={poll(probe){return {async toBe(wanted){for(let n=0;n<3;n++)if(await probe()===wanted)return;throw new Error('incomplete chart evidence');}};}};
 await assert.rejects(settleWindowsHistory(page,expect,async ms=>{assert.equal(ms,500);advances++;}),/incomplete chart evidence/);assert.equal(advances,3);
});


test('expiry remount waits for the actual device unmount and fleet before returning',async()=>{
 const calls=[];let pending=false,unmounted=false;
 const page={async goto(url){calls.push(url);if(url.endsWith('/#/devices'))pending=true;else assert.equal(unmounted,true,'return must not overtake the away commit');},locator(selector){return selector;}};
 const expect=selector=>({async toHaveCount(count){assert.equal(selector,'.device-page');assert.equal(count,0);assert.equal(pending,true);calls.push('unmount');unmounted=true;},async toBeVisible(){assert.equal(selector,'.device-table');assert.equal(unmounted,true);calls.push('fleet');}});
 await remountWindowsDevice(page,expect,'https://fixture.invalid');
 assert.deepEqual(calls,['https://fixture.invalid/#/devices','unmount','fleet',`https://fixture.invalid/#/devices/agent_${'7'.repeat(32)}`]);
 const source=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8');
 assert.equal((source.match(/await remountWindowsDevice\(page,expect,base\)/g)||[]).length,2);
 assert.doesNotMatch(source,/setDefaultTimeout|waitForTimeout|\.skip\(|test\.skip/);
});

test('expiry remount refuses to return if the device never unmounts',async()=>{
 const visits=[];
 const page={async goto(url){visits.push(url);},locator(selector){return selector;}};
 const expect=()=>({async toHaveCount(){throw new Error('device still mounted');}});
 await assert.rejects(remountWindowsDevice(page,expect,'https://fixture.invalid'),/device still mounted/);
 assert.deepEqual(visits,['https://fixture.invalid/#/devices']);
});


test('repeated intended network generations age while trusted server time advances',()=>{
 const origin='2026-10-08T12:00:00.000Z';
 for(const phase of ['network-stale','network-expiring']){
  const first=windowsBrowserFixture(origin,phase,origin);
  const later=windowsBrowserFixture('2026-10-08T12:00:04.000Z',phase,origin);
  assert.equal(later.serverNow,'2026-10-08T12:00:04.000Z');
  assert.equal(later.snapshot.generationId,first.snapshot.generationId);
  assert.equal(later.network.collectedAt,first.network.collectedAt);
  assert.equal(later.snapshot.collectedAt,first.snapshot.collectedAt);
  assert.equal(Date.parse(later.serverNow)-Date.parse(later.network.collectedAt),Date.parse(first.serverNow)-Date.parse(first.network.collectedAt)+4000);
 }
 const expired=windowsBrowserFixture('2026-10-08T12:00:05.000Z','network-expiring',origin);
 assert.equal(expired.serverNow,'2026-10-08T12:00:05.000Z');assert.equal(expired.status,'unavailable');assert.equal(expired.snapshot,null);
 for(const key of ['events','volumes','processMetrics','network'])assert.equal(Object.hasOwn(expired,key),false);
 const source=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8');
 assert.match(source,/windowsBrowserFixture\(at,phase,networkPhaseAt\?\?at,logsPhaseAt\?\?at\)/);
 assert.match(source,/phase='network-expiring';networkPhaseAt=now\(\)/);
});

test('actual route parser demonstrates queued hash coalescence and the remount barrier',async()=>{
 const {createRequire}=await import('node:module'),{default:vm}=await import('node:vm');
 const require=createRequire(new URL('../../web/package.json',import.meta.url));
 const app=fs.readFileSync(new URL('../../web/src/App.tsx',import.meta.url),'utf8');
 const source=app.slice(app.indexOf('function useRoute()'),app.indexOf('\nconst navigate ='));
 const {code}=await require('esbuild').transform(source,{loader:'ts'});
 function harness(){
  const id=`agent_${'7'.repeat(32)}`,states=[],listeners=[],queued=[];
  const window={location:{hash:`#/devices/${id}`},addEventListener(type,fn){if(type==='hashchange')listeners.push(fn);},removeEventListener(){}};
  const context=vm.createContext({window,document:{getElementById:()=>null},decodeRouteId:value=>value,useState:init=>{let current=init();return [current,value=>{current=typeof value==='function'?value(current):value;states.push(current);}];},useRef:value=>({current:value}),useLayoutEffect:fn=>fn(),useEffect:fn=>fn(),Map});
  vm.runInContext(code+'\nuseRoute();',context);
  const flush=()=>{while(queued.length)queued.shift()();};
  const page={async goto(url){window.location.hash=new URL(url).hash;queued.push(()=>listeners.forEach(fn=>fn()));},locator:selector=>selector};
  return {page,flush,states,id};
 }
 const old=harness();
 await old.page.goto('https://fixture.invalid/#/devices');await old.page.goto(`https://fixture.invalid/#/devices/${old.id}`);old.flush();
 assert.equal(old.states.length,2);assert.ok(old.states.every(route=>route.id===old.id),'both queued events can read only the final route');
 assert.deepEqual(old.states.map(route=>route.revision),[1,2],'each queued navigation advances the remount revision');
 const fixed=harness();
 const expect=selector=>({async toHaveCount(count){assert.equal(selector,'.device-page');assert.equal(count,0);fixed.flush();assert.equal(fixed.states.at(-1).id,undefined);},async toBeVisible(){assert.equal(selector,'.device-table');assert.equal(fixed.states.at(-1).id,undefined);}});
 await remountWindowsDevice(fixed.page,expect,'https://fixture.invalid');fixed.flush();
 assert.equal(fixed.states.length,2);assert.equal(fixed.states[0].id,undefined);assert.equal(fixed.states[1].id,fixed.id);
});

test('bounded process-control fixture preserves disclosed counts and exact source values',()=>{
 const view=windowsBrowserFixture('2026-10-07T12:00:10Z','process-controls'),section=view.snapshot.processes,metrics=view.processMetrics;
 assert.equal(section.rows.length,61);assert.equal(section.observedCount,200);assert.equal(section.countExact,false);assert.equal(section.complete,false);assert.equal(section.truncated,true);assert.equal(section.quality,'partial');
 assert.equal(metrics.rows.length,61);assert.equal(metrics.observedCount,61);assert.equal(metrics.truncated,false);assert.equal(metrics.generationId,view.snapshot.generationId);
 assert.deepEqual(metrics.rows.slice(0,3).map(row=>row.cpuPercent),[2,10,125.25]);
 assert.equal(metrics.rows[0].memoryBytes,'9007199254740993');assert.equal(metrics.rows[1].memoryBytes,'9007199254740992');assert.equal(metrics.rows[59].memoryBytes,'18446744073709551615');
 assert.equal(metrics.rows[60].cpuPercent,null);assert.equal(metrics.rows[60].cpuQuality,'denied');assert.equal(metrics.rows[60].memoryBytes,null);assert.equal(metrics.rows[60].memoryQuality,'denied');
 assert.deepEqual(metrics.rows.map(row=>row.pid),section.rows.map(row=>row.pid));
});
test('hosted process-control checks are additive and preserve read-only desktop/mobile safety',()=>{
 const source=fs.readFileSync(new URL('./windows-process-browser.mjs',import.meta.url),'utf8'),runner=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8');
 for(const sort of ['cpu-desc','cpu-asc','ram-desc','ram-asc','pid-asc'])assert.ok(source.includes(`selectOption('${sort}')`));
 assert.match(source,/toHaveCount\(25\)/);assert.match(source,/toHaveCount\(11\)/);assert.match(source,/toHaveCount\(1\)/);assert.match(source,/Rows 51–61 of 61 matching · 61 captured/);assert.match(source,/61 captured · 61 observed within bounded scope/);
 assert.match(source,/page\.keyboard\.press\('Enter'\)/);assert.match(source,/scrollWidth<=el\.clientWidth\+1/);assert.ok(source.includes('synthetic-windows-process-controls-${width}-${locale}'));
 assert.match(runner,/exerciseWindowsProcessControls\(\{page,expect,locale,width,shot,disclosure:windowsInventoryFixtureDisclosure\}\)/);
 assert.match(runner,/for\(const locale of \['en','de'\]\)for\(const width of \[1440,390\]\)/);
 assert.doesNotMatch(source,/chromium\.launch|newContext\(|execFile|spawn\(|writeFile|ignoreHTTPSErrors|fetch\(/);
});

// Additive Logs contracts remain in the hosted fixture gate.
import './windows-logs-fixtures.test.mjs';

// Bounded service/software display contracts share the existing hosted fixture gate.
import './windows-service-software-fixtures.test.mjs';

// Keep positive Health fixture assertions in the existing hosted source-check entry.
import './windows-health-fixtures.test.mjs';

// OS evidence stays an invented overlay in this same hosted fixture gate.
import './windows-os-provenance-fixtures.test.mjs';

// Cached update source/hosted-helper contracts use this same existing CI gate.
import './windows-updates-fixtures.test.mjs';

// Selected event-content source contracts extend the same explicit CI entry.
import './windows-event-content-fixtures.test.mjs';

// Additive, reviewed read-only system-volume capacity display fixtures.
import './windows-capacity-fixtures.test.mjs';

// History metadata is a separate disabled source in the older inventory walk.
import {guardWindowsEventHistoryRoute,windowsEventHistoryRouteState} from './windows-event-history-browser.mjs';
test('legacy inventory permits only a disabled history status read, never a history action',async()=>{
 const base='http://127.0.0.1:19886',prefix='/api/devices/agent_'+'7'.repeat(32),serverNow='2026-10-11T20:00:00.123456789Z',sessionExpiresAt='2026-10-11T21:00:00Z';
 const call=async({url=base+prefix+'/windows-event-history',method='GET',body=null}={})=>{
  let response=null;const route={request:()=>({url:()=>url,method:()=>method,postData:()=>body}),fulfill:async value=>{response=value;}};
  await windowsEventHistoryLegacyRead({route,base,prefix,serverNow,sessionExpiresAt});return response;
 };
 const response=await call(),view=JSON.parse(response.body);assert.equal(response.status,200);assert.equal(view.localStatus,'disabled');assert.equal(view.capability.enabled,false);assert.equal(view.request,null);assert.equal(view.contentStatus,'unavailable');assert.equal(view.capability.expiresAt,'2026-10-11T20:05:00.123456789Z');
 for(const input of [{method:'POST'},{body:'{}'},{url:base+prefix+'/windows-event-history?all=1'},{url:base+prefix+'/windows-event-history/create'},{url:base+prefix+'/windows-event-history/messages'},{url:'https://example.invalid'+prefix+'/windows-event-history'}])await assert.rejects(call(input),/Unexpected synthetic history status request/);
});
test('history route diagnostics retain late failure and pending state through teardown',async()=>{
 const before=windowsEventHistoryRouteState();let release;const gate=new Promise(resolve=>{release=resolve;});let aborted=0;
 const pending=guardWindowsEventHistoryRoute({abort:async()=>{aborted++;}},async()=>{await gate;throw new Error('INERT_ROUTE_FAILURE');});
 assert.deepEqual(windowsEventHistoryRouteState(),{failures:before.failures,pending:before.pending+1});
 release();await pending;assert.equal(aborted,1);assert.deepEqual(windowsEventHistoryRouteState(),{failures:before.failures+1,pending:before.pending});
 const runner=fs.readFileSync(new URL('./windows-event-history-runner.mjs',import.meta.url),'utf8');
 assert.ok(runner.indexOf('const routes=windowsEventHistoryRouteState()')>runner.indexOf('await context.close()'));
 assert.match(runner,/if\(routes\.failures!==0\|\|routes\.pending!==0\)passed=false/);
});
