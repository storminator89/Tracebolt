/** Pure source/DTO checks. No browser or native event reader is started. */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {remountWindowsLogsDevice} from './windows-logs-browser.mjs';
import {windowsBrowserFixture} from './windows-inventory-browser.mjs';

test('invented Logs headers stay inside the existing bounded validated Windows envelope',()=>{
 const now='2026-10-07T12:00:10Z',view=windowsBrowserFixture(now,'logs'),events=view.events;
 assert.equal(events.scope,'windows-application-system-event-headers-v1');assert.equal(events.generationId,view.snapshot.generationId);assert.equal(Buffer.byteLength(JSON.stringify(events))<=6*1024,true);
 assert.deepEqual(events.channels.map(c=>c.channel),['Application','System']);assert.deepEqual(events.channels.map(c=>c.rows.length),[12,12]);
 for(const channel of events.channels){assert.equal(channel.quality,'bounded');assert.equal(channel.complete,false);assert.equal(channel.truncated,true);for(const row of channel.rows)assert.deepEqual(Object.keys(row).sort(),['eventId','level','provider','recordId','timestamp']);}
 assert.equal(events.channels[0].rows[0].recordId,'18446744073709551615');
 const expiring=windowsBrowserFixture(now,'logs-expiring');assert.equal(expiring.status,'fresh');assert.equal(Date.parse(now)-Date.parse(expiring.snapshot.collectedAt),2000);assert.equal(Date.parse(now)-Date.parse(expiring.events.collectedAt),86400000-5000);
});

test('hosted Logs coverage is additive, bilingual/mobile and never launches or grants a source',()=>{
 const source=fs.readFileSync(new URL('./windows-logs-browser.mjs',import.meta.url),'utf8'),runner=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8');
 assert.match(runner,/mark\('logs'\);await windowsLogsBrowserCase/);assert.match(runner,/windowsLogsFixture\(view,now,phase,logsPhaseAt\)/);
 assert.match(source,/synthetic-windows-logs-\$\{width\}-\$\{locale\}/);assert.match(source,/synthetic-windows-logs-expired-\$\{width\}-\$\{locale\}/);assert.match(source,/await advance\(15000\)/);assert.match(source,/await advance\(6000\)/);assert.match(source,/await expect\(next\)\.toBeFocused\(\)/);assert.match(source,/await expect\(provider\)\.toHaveValue\(''\)/);assert.match(source,/getComputedStyle\(el,'::before'\)/);
 assert.doesNotMatch(source,/chromium\.launch|newContext\(|execFile|spawn\(|writeFile|ignoreHTTPSErrors|waitForTimeout|setDefaultTimeout|postData|fetch\(/);
});


test('intended Logs expiry capture stays fixed on repeated replies and expired headers are omitted',()=>{
 const phaseAt='2026-10-08T12:00:00.000Z',first=windowsBrowserFixture(phaseAt,'logs-expiring',undefined,phaseAt),later=windowsBrowserFixture('2026-10-08T12:00:04.000Z','logs-expiring',undefined,phaseAt);
 assert.equal(later.events.generationId,first.events.generationId);assert.equal(later.events.collectedAt,first.events.collectedAt);assert.equal(Date.parse(later.serverNow)-Date.parse(later.events.collectedAt),86400000-1000);
 const expired=windowsBrowserFixture('2026-10-08T12:00:05.000Z','logs-expiring',undefined,phaseAt);assert.equal(Object.hasOwn(expired,'events'),false);assert.equal(expired.status,'fresh');assert.ok(expired.snapshot);
});

test('Logs expiry remount waits for unmount and fleet visibility before returning to the device',async()=>{
 const steps=[],page={async goto(url){steps.push(url);},locator:selector=>selector},expect=selector=>({async toHaveCount(count){assert.equal(count,0);steps.push(selector);},async toBeVisible(){steps.push(selector);}});
 await remountWindowsLogsDevice(page,expect,'https://fixture.invalid','fixture-id');assert.deepEqual(steps,['https://fixture.invalid/#/devices','.device-page','.device-table','https://fixture.invalid/#/devices/fixture-id']);
 const visits=[],blocked={async goto(url){visits.push(url);},locator:selector=>selector};
 await assert.rejects(remountWindowsLogsDevice(blocked,()=>({async toHaveCount(){throw new Error('device still mounted');}}),'https://fixture.invalid','fixture-id'),/device still mounted/);assert.deepEqual(visits,['https://fixture.invalid/#/devices']);
 const source=fs.readFileSync(new URL('./windows-logs-browser.mjs',import.meta.url),'utf8');assert.match(source,/await remountWindowsLogsDevice\(page,expect,base,deviceId,mark\)/);assert.match(source,/page\.waitForResponse/);assert.match(source,/await poll;\s*mark\('logs-poll-ready'\);await expect\(refresh\)\.toBeEnabled\(\)/);assert.match(source,/not\.toHaveAttribute\('datetime',beforeCapture\)/);
});

// Finite source-only diagnostics; never launches a browser.
import './windows-logs-diagnostics.test.mjs';

// Use the same exact-label engine as the hosted Playwright gate.
import './windows-logs-labels.test.mjs';
