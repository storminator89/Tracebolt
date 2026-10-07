import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {resourceBrowserFixture,resourceHistoryFixtureDisclosure} from './resource-history-browser.mjs';
import {resourceSegments,validResourceHistory} from '../../web/src/resource-history-types.ts';
test('synthetic resource history remains bounded, valid and explicit about gaps',()=>{
 const v=resourceBrowserFixture('2026-10-07T12:00:00Z');assert.equal(validResourceHistory(v,v.deviceId),true);assert.ok(v.points.length<=1441);assert.ok(resourceSegments(v,'cpu').length>2);assert.ok(resourceSegments(v,'memory').length===2);assert.equal(v.points[0].cpu.value,null);assert.equal(v.points[1].cpu.value,0);assert.match(resourceHistoryFixtureDisclosure,/invented/);assert.match(resourceHistoryFixtureDisclosure,/no native telemetry/);
 for(const phase of ['awaiting','revoked','expired','not_configured']){const view=resourceBrowserFixture(v.serverNow,phase);assert.equal(validResourceHistory(view,view.deviceId),true);assert.equal(view.points.length,0);}
});
test('hosted LAN runner includes resource history without changing other case coverage',()=>{
 const runner=fs.readFileSync(new URL('./lan-browser.mjs',import.meta.url),'utf8');assert.equal((runner.match(/await check\(/g)||[]).length,20);assert.equal((runner.match(/await check\(resourceHistoryCaseName/g)||[]).length,1);
});
