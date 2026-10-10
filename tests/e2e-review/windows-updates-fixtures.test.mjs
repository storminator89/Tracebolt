import fs from 'node:fs';
import assert from 'node:assert/strict';
import test from 'node:test';
import {windowsUpdatesBrowserFixture,windowsUpdatesFixtureDisclosure,exerciseWindowsUpdates} from './windows-updates-browser.mjs';
const serverNow='2026-10-07T12:00:10Z',capturedAt='2026-10-07T12:00:00Z';
test('synthetic helper bounds and explicit evidence boundary',()=>{
 assert.match(windowsUpdatesFixtureDisclosure,/UI-only fixture/);assert.equal(typeof exerciseWindowsUpdates,'function');
 for(const phase of ['bounded','empty','partial','partial-empty','denied','unavailable','legacy']){
  const view=windowsUpdatesBrowserFixture({serverNow,capturedAt,phase});assert.equal(view.snapshot.collectedAt,capturedAt);
  if(phase==='legacy')assert.equal(view.updates,undefined);else {assert.equal(view.updates.collectedAt,capturedAt);assert.equal(view.updates.source,'wua-cache');assert.equal(view.updates.cacheFreshness,'unknown');assert.ok(view.updates.rows.length<=64);}
 }
});
test('fresh, stale, skew and expiry retain original inspection age',()=>{
 const first=windowsUpdatesBrowserFixture({serverNow,capturedAt});
 assert.equal(first.status,'fresh');
 const stale=windowsUpdatesBrowserFixture({serverNow:'2026-10-07T12:02:01Z',capturedAt});assert.equal(stale.status,'stale');assert.equal(stale.updates.collectedAt,capturedAt);
 const skew=windowsUpdatesBrowserFixture({serverNow,capturedAt:'2026-10-07T12:00:40Z'});assert.equal(skew.status,'stale');
 assert.throws(()=>windowsUpdatesBrowserFixture({serverNow,capturedAt:'2026-10-07T12:00:41Z'}));
 const expired=windowsUpdatesBrowserFixture({serverNow:'2026-10-08T12:00:00Z',capturedAt});assert.equal(expired.status,'unavailable');assert.equal(expired.snapshot,null);assert.equal(expired.updates,undefined);
});

test('cached Updates is wired once per existing locale/viewport loop with a fixed capture and no new scope',()=>{
 const source=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8'),runner=fs.readFileSync(new URL('./lan-browser.mjs',import.meta.url),'utf8'),gate=fs.readFileSync(new URL('./windows-inventory-fixtures.test.mjs',import.meta.url),'utf8');
 assert.equal((runner.match(/await check\(/g)||[]).length,26);
 assert.match(source,/windowsUpdatesBrowserFixture\(\{serverNow:at,capturedAt:updatesCapturedAt\}\)/);
 assert.match(source,/mark\('updates'\);phase='updates';updatesCapturedAt=new Date\(clockNow-2000\).toISOString\(\)/);
 assert.match(source,/exerciseWindowsUpdates\(\{page,expect,locale,width,shot\}\)/);
 assert.match(source,/for\(const locale of \['en','de'\]\)for\(const width of \[1440,390\]\)/);
 const segment=source.slice(source.indexOf("mark('updates')"),source.indexOf("mark('legacy')"));
 assert.doesNotMatch(segment,/clock\.runFor|clockNow\+=|waitForTimeout|setDefaultTimeout|route\(|request\(/);
 assert.ok(source.indexOf("mark('logs')")<source.indexOf("mark('updates')"));
 assert.match(gate,/import '\.\/windows-updates-fixtures\.test\.mjs'/);
 for(const guard of ['unexpected','writes','external'])assert.ok(source.includes(`expect(${guard}).toEqual([])`));
 const helper=fs.readFileSync(new URL('./windows-updates-browser.mjs',import.meta.url),'utf8');
 assert.match(helper,/synthetic-windows-updates-\$\{width\}-\$\{locale\}/);
 assert.doesNotMatch(helper,/chromium\.launch|newContext\(|spawn\(|execFile|writeFile|ignoreHTTPSErrors|fetch\(|localStorage|sessionStorage|waitForTimeout|setDefaultTimeout/);
});
