/** Inert fixture and assertion-source checks; no browser or host collection. */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {windowsBrowserFixture,windowsHealthBrowserDevice} from './windows-inventory-browser.mjs';
import {windowsHealthStageNames} from './windows-health-browser.mjs';
const now='2026-10-08T18:00:00.000Z';
test('positive hosted Health fixture mirrors manager activation authority and original metric ages',()=>{
 const d=windowsHealthBrowserDevice(now),view=windowsBrowserFixture(now);
 assert.equal(d.id,view.deviceId);assert.equal(d.platform,'windows');assert.equal(d.source,'lan');assert.equal(d.synthetic,false);assert.equal(d.status,'unknown');
 assert.deepEqual(d.capabilities.map(({id,status})=>({id,status})),[{id:'agent_identity',status:'supported'}]);
 assert.equal(d.agentCertificate.source,'guided-enrollment');assert.equal(d.agentCertificate.checkedAt,now);assert.ok(Date.parse(d.agentCertificate.expiresAt)>Date.parse(now));
 assert.equal(d.disk.value,61);assert.equal(d.disk.unit,'%');assert.equal(d.disk.quality,'healthy');assert.match(d.disk.source,/Synthetic/);
 assert.equal(Date.parse(now)-Date.parse(d.disk.collectedAt),10000);assert.equal(d.lastSeen,d.disk.collectedAt);assert.equal(Date.parse(now)-Date.parse(view.receivedAt),1000);
});
test('missing-authority fixture changes no accepted readings or inventory to fabricate health',()=>{
 const positive=windowsHealthBrowserDevice(now),missing=windowsHealthBrowserDevice(now,'health-unverified');
 assert.deepEqual(missing.capabilities,[]);assert.deepEqual({...positive,capabilities:[]},missing);
 assert.deepEqual(windowsBrowserFixture(now,'health-unverified'),windowsBrowserFixture(now));
 assert.equal(windowsHealthBrowserDevice(now).capabilities.length,1,'a missing case cannot taint the next positive fixture');
});
test('hosted Health asserts positive and missing-authority states at each locale and viewport',()=>{
 const source=fs.readFileSync(new URL('./windows-health-browser.mjs',import.meta.url),'utf8'),runner=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8');
 assert.deepEqual(windowsHealthStageNames,['health-current','health-unverified','health-restored']);
 assert.match(runner,/for\(const locale of \['en','de'\]\)for\(const width of \[1440,390\]\)/);assert.match(runner,/\.\.\.windowsHealthStageNames/);assert.match(runner,/await exerciseWindowsHealth\(/);
 for(const text of ['Recent report','Aktuelle Meldung','Current reading','Aktuelle Messung','61.0 %','61,0 %','Unknown','Unbekannt','Observed events','Beobachtete Ereignisse'])assert.ok(source.includes(text));
 assert.match(source,/contact\.locator\('time'\)\)\.toHaveCount\(1\)/);assert.match(source,/disk\.locator\('time'\)\)\.toHaveCount\(1\)/);assert.match(source,/health\.locator\('time'\)\)\.toHaveCount\(0\)/);
 assert.ok(source.includes('synthetic-windows-health-current-${width}-${locale}'));assert.ok(source.includes('synthetic-windows-health-unverified-${width}-${locale}'));
 assert.match(source,/await positive\(\)/);assert.match(source,/await expect\(disk\.getByText\(value,\{exact:true\}\)\)\.toHaveCount\(0\)/);
 assert.doesNotMatch(source,/chromium\.launch|newContext\(|fetch\(|spawn\(|execFile|writeFile|ignoreHTTPSErrors|waitForTimeout|setDefaultTimeout|\.skip\(/);
 assert.match(runner,/expect\(unexpected\)\.toEqual\(\[\]\)/);assert.match(runner,/expect\(writes\)\.toEqual\(\[\]\)/);assert.match(runner,/expect\(external\)\.toEqual\(\[\]\)/);
});
