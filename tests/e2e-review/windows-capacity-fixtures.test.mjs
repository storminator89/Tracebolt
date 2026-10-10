/** Inert invented fixture checks. No browser launch or policy mutation. */
import './windows-resource-fixtures.test.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {windowsCapacityBrowserFixture,windowsCapacityDisclosure,windowsCapacityStageNames} from './windows-capacity-browser.mjs';
const origin='2026-10-07T12:00:10Z';
test('capacity display fixture remains disabled by default and exposes exact bounded policy shape',()=>{
 const v=windowsCapacityBrowserFixture(origin);assert.equal(v.status,'disabled');assert.deepEqual(v.policy,{enabled:false,thresholdPercent:90,revision:0});assert.equal(v.observation,null);assert.deepEqual(v.incidents,[]);assert.match(windowsCapacityDisclosure,/Enabled policy is injected by read-only fixtures; no policy save/);
});
test('injected enable, pressure and unknown remain distinct without renewing observations',()=>{
 const enabled=windowsCapacityBrowserFixture(origin,origin,'capacity-enabled'),pressure=windowsCapacityBrowserFixture(origin,origin,'capacity-pressure'),later=windowsCapacityBrowserFixture('2026-10-07T12:02:11Z',origin,'capacity-pressure'),unknown=windowsCapacityBrowserFixture(origin,origin,'capacity-unknown');
 assert.equal(enabled.status,'pending');assert.equal(enabled.policy.enabled,true);assert.equal(pressure.status,'pressure');assert.equal(later.status,'unknown');assert.equal(unknown.status,'unknown');assert.equal(later.observation,null);assert.equal(unknown.observation,null);assert.deepEqual(later.incidents,pressure.incidents);assert.equal(later.evaluatedAt,pressure.evaluatedAt);assert.equal(later.incidents[0].resolvedAt,null);
});
test('policy-changed fixture retains original high observations without fabricating recovery',()=>{
 const pressure=windowsCapacityBrowserFixture(origin,origin,'capacity-pressure'),closed=windowsCapacityBrowserFixture(origin,origin,'capacity-closed');assert.equal(closed.policy.enabled,false);assert.equal(closed.policy.revision,2);assert.equal(closed.incidents[0].closedReason,'policy-changed');assert.equal(closed.incidents[0].recoveryObservation,null);assert.deepEqual(closed.incidents[0].openingObservation,pressure.incidents[0].openingObservation);assert.deepEqual(closed.incidents[0].lastHighObservation,pressure.incidents[0].lastHighObservation);
});
test('read-only capacity stages and EN/DE mobile captures are registered in the existing runner',()=>{
 const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8'),source=read('./windows-capacity-browser.mjs'),runner=read('./windows-inventory-browser.mjs');
 assert.equal(windowsCapacityStageNames.length,5);assert.match(runner,/\.\.\.windowsCapacityStageNames/);assert.match(runner,/await exerciseWindowsCapacity\(/);assert.match(runner,/for\(const locale of \['en','de'\]\)for\(const width of \[1440,390\]\)/);assert.match(runner,/prefix\+'\/windows-capacity'/);assert.match(runner,/unexpected-capacity-query/);assert.match(runner,/expect\(writes\)\.toEqual\(\[\]\)/);assert.match(runner,/expect\(external\)\.toEqual\(\[\]\)/);assert.match(runner,/expect\(unexpected\)\.toEqual\(\[\]\)/);
 assert.match(source,/await enabled\.check\(\)/);assert.match(source,/Änderungen verwerfen/);assert.doesNotMatch(source,/await save\.click|windows-capacity\/policy|chromium\.launch|newContext\(|execFile|spawn\(|writeFile|ignoreHTTPSErrors|grantPermissions/);for(const label of ['disabled','enabled','pressure','unknown','closed'])assert.ok(source.includes(`await capture('${label}')`));
});
test('container build explicitly admits the shared capacity wire fixture before TypeScript compilation',()=>{
 const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8'),docker=read('../../Dockerfile'),ignore=read('../../.dockerignore');assert.match(docker,/COPY tests\/fixtures\/windows-capacity-view.json \/src\/tests\/fixtures\/windows-capacity-view.json/);assert.ok(docker.indexOf('COPY tests/fixtures/windows-capacity-view.json ')<docker.indexOf('RUN npm run build'));assert.match(ignore,/^!tests\/fixtures\/windows-capacity-view.json$/m);assert.doesNotMatch(docker.split('FROM --platform=$BUILDPLATFORM golang:')[0],/^COPY tests\/\s/m);
});
