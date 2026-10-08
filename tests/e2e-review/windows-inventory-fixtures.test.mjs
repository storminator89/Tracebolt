import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {settleWindowsHistory,windowsBrowserFixture,windowsInventoryFixtureDisclosure,windowsInventoryFailureStage} from './windows-inventory-browser.mjs';
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
 assert.equal((runner.match(/await check\(/g)||[]).length,26);assert.equal((runner.match(/await check\(windowsInventoryCaseName/g)||[]).length,1);
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
