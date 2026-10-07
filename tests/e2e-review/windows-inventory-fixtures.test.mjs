import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {windowsBrowserFixture,windowsInventoryFixtureDisclosure,windowsInventoryFailureStage} from './windows-inventory-browser.mjs';
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
