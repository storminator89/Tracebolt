import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {resourceBrowserFixture,resourceHistoryFixtureDisclosure,resourceHistoryInspection} from './resource-history-browser.mjs';
import {resourceSegments,validResourceHistory} from '../../web/src/resource-history-types.ts';
test('synthetic resource history remains bounded, valid and explicit about gaps',()=>{
 const v=resourceBrowserFixture('2026-10-07T12:00:00Z');assert.equal(validResourceHistory(v,v.deviceId),true);assert.ok(v.points.length<=1441);assert.ok(resourceSegments(v,'cpu').length>2);assert.ok(resourceSegments(v,'memory').length===2);assert.equal(v.points[0].cpu.value,null);assert.equal(v.points[1].cpu.value,0);assert.match(resourceHistoryFixtureDisclosure,/invented/);assert.match(resourceHistoryFixtureDisclosure,/no native telemetry/);
 for(const phase of ['awaiting','revoked','expired','not_configured']){const view=resourceBrowserFixture(v.serverNow,phase);assert.equal(validResourceHistory(view,view.deviceId),true);assert.equal(view.points.length,0);}
});
test('hosted LAN runner includes resource history without changing other case coverage',()=>{
 const runner=fs.readFileSync(new URL('./lan-browser.mjs',import.meta.url),'utf8');assert.equal((runner.match(/await check\(/g)||[]).length,25);assert.equal((runner.match(/await check\(resourceHistoryCaseName/g)||[]).length,1);
});


test('keyboard expectations stay bound to the fulfilled sample while settle advances the clock',()=>{
 const fulfilled=resourceBrowserFixture('2026-10-07T12:00:00.500Z');
 const expected=resourceHistoryInspection(fulfilled);
 const laterClock=resourceBrowserFixture('2026-10-07T12:00:01.000Z');
 // This is the legal asynchronous ordering that the old browser assertion
 // mishandled: fetch fulfills, a later settle poll advances500ms, React renders.
 assert.notEqual(laterClock.points[1].cpu.collectedAt,expected.firstAt);
 assert.notEqual(laterClock.serverNow,expected.lastAt);
 assert.deepEqual(expected,{firstAt:fulfilled.points[1].cpu.collectedAt,lastAt:fulfilled.points.at(-1).cpu.collectedAt,firstValue:0});
 assert.deepEqual(resourceHistoryInspection(fulfilled),expected);
 const source=fs.readFileSync(new URL('./resource-history-browser.mjs',import.meta.url),'utf8');
 assert.match(source,/lastHistoryView=resourceBrowserFixture\(now\(\),phase\);return fulfill\(lastHistoryView\)/);
 assert.match(source,/const inspection=resourceHistoryInspection\(lastHistoryView\)/);
 assert.doesNotMatch(source,/toHaveAttribute\('datetime',(?:resourceBrowserFixture\(now\(\)\)|now\(\))/);
 for(const stage of ['initial-login','initial-chart-read','initial-cpu-gap','initial-cpu-home','initial-cpu-home-time','initial-cpu-end-time'])assert.ok(source.includes(`mark('${stage}')`));
});
