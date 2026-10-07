import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {windowsBrowserFixture,windowsInventoryFixtureDisclosure,windowsInventoryFailureStage} from './windows-inventory-browser.mjs';
test('invented Windows views preserve finite scope, truncation and denied distinction',()=>{
 const now='2026-10-07T12:00:10Z',fresh=windowsBrowserFixture(now),stale=windowsBrowserFixture(now,'stale');
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
