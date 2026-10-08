import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {windowsContactBrowserFixture,windowsContactHistoryDisclosure} from './windows-contact-history-browser.mjs';
test('invented contact GET advances manager time without renewing acceptance or evaluation',()=>{
 const origin='2026-10-07T12:00:10Z',first=windowsContactBrowserFixture(origin),later=windowsContactBrowserFixture('2026-10-07T12:02:11Z',origin);
 assert.equal(first.status,'overdue');assert.equal(later.status,'unknown');assert.equal(first.lastAcceptedAt,later.lastAcceptedAt);assert.equal(first.sequence,later.sequence);assert.equal(first.evaluatedAt,later.evaluatedAt);assert.deepEqual(first.incidents,later.incidents);assert.equal(later.incidents[0].resolvedAt,null);assert.match(windowsContactHistoryDisclosure,/Source-only test; no native Windows read/);
});
test('bounded contact case is integrated in the authenticated EN/DE desktop/mobile runner',()=>{
 const source=fs.readFileSync(new URL('./windows-contact-history-browser.mjs',import.meta.url),'utf8'),runner=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8');
 assert.match(runner,/await login\(page\)/);assert.match(runner,/for\(const locale of \['en','de'\]\)for\(const width of \[1440,390\]\)/);assert.match(source,/await advance\(121000\)/);
 assert.match(runner,/await exerciseWindowsContactHistory\(/);assert.match(runner,/\.\.\.windowsContactHistoryStageNames/);assert.match(runner,/prefix\+'\/windows-contact'/);
 assert.match(runner,/expect\(writes\)\.toEqual\(\[\]\)/);assert.match(runner,/expect\(external\)\.toEqual\(\[\]\)/);assert.match(runner,/expect\(unexpected\)\.toEqual\(\[\]\)/);assert.doesNotMatch(source,/chromium\.launch|newContext\(|execFile|spawn\(|writeFile|ignoreHTTPSErrors|grantPermissions/);
});
test('injected completed recovery keeps the original incident receipt and adds separate recovery evidence',()=>{
 const origin='2026-10-07T12:00:10Z',opened=windowsContactBrowserFixture(origin),recovered=windowsContactBrowserFixture('2026-10-07T12:02:11Z',origin,'contact-recovered');
 assert.equal(recovered.status,'recent');assert.equal(recovered.incidents[0].id,opened.incidents[0].id);assert.equal(recovered.incidents[0].lastAcceptedAt,opened.incidents[0].lastAcceptedAt);assert.equal(recovered.incidents[0].sequence,opened.incidents[0].sequence);assert.equal(recovered.incidents[0].closedReason,'reports-resumed');assert.equal(Date.parse(recovered.incidents[0].resolvedAt)-Date.parse(recovered.incidents[0].recoveryAcceptedAt),60000);
});

test('only the Windows case receives a bounded session TTL above its full virtual-time budget',()=>{
 const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8');
 const runner=read('./lan-browser.mjs'),windows=read('./windows-inventory-browser.mjs'),logs=read('./windows-logs-browser.mjs'),contact=read('./windows-contact-history-browser.mjs');
 const windowsCheck=runner.match(/await check\(windowsInventoryCaseName,\(\)=>windowsInventoryBrowserCase\(\{pageAt,login,expect,base,shot\}\),'(\d+)m'\);/);
 assert.ok(windowsCheck,'one explicit Windows fixture session TTL is required');
 const ttlMS=Number(windowsCheck[1])*60000;
 assert.equal(ttlMS,1200000,'Windows fixture TTL stays bounded at 20 minutes');
 assert.equal((runner.match(/,'20m'\);/g)||[]).length,1,'no other fixture session TTL is expanded');
 assert.match(runner,/await check\(resourceHistoryCaseName,[^\n]+,'10m'\);/);
 assert.match(runner,/await check\(capabilityCaseName,[^\n]+,'10m'\);/);
 assert.match(runner,/await check\(journalBrowseCaseName,[^\n]+,'30m'\);/);
 assert.match(runner,/async function check\(name,run,ttl='60s'\)/);
 assert.match(windows,/for\(const locale of \['en','de'\]\)for\(const width of \[1440,390\]\)/);
 const amounts=(source,pattern)=>[...source.matchAll(pattern)].map(match=>Number(match[1]));
 const fixedWindows=amounts(windows,/await page\.clock\.runFor\((\d+)\)/g),fixedLogs=amounts(logs,/await advance\((\d+)\)/g),fixedContact=amounts(contact,/await advance\((\d+)\)/g);
 assert.deepEqual(fixedWindows,[6000,6000]);assert.deepEqual(fixedLogs,[15000,6000]);assert.deepEqual(fixedContact,[121000]);
 // Preserve the single 500-ms history-settling probe. Its unchanged default
 // five-second Playwright poll cannot exhaust this conservative 30-second
 // virtual allowance at the default minimum 100-ms wall-time polling interval.
 assert.equal((windows.match(/await settleWindowsHistory\(/g)||[]).length,1);
 assert.match(windows,/expect\.poll\(async\(\)=>\{await advance\(500\);/);
 assert.doesNotMatch(windows,/setDefaultTimeout|expect\.configure/);
 assert.doesNotMatch(runner,/expect\.configure|setDefaultTimeout/);
 const iterations=2*2,historyAllowancePerIteration=30000,initialClockAdvance=1000;
 const fixedMS=initialClockAdvance+iterations*[...fixedWindows,...fixedLogs,...fixedContact].reduce((sum,n)=>sum+n,0);
 assert.equal(fixedMS,617000);
 assert.ok(fixedMS>600000,'fixed virtual advances alone exceed the previous 10-minute fixture TTL');
 assert.equal(fixedMS-iterations*fixedContact.reduce((sum,n)=>sum+n,0),133000,'pre-contact fixed virtual advance is unchanged');
 const plannedMS=fixedMS+iterations*historyAllowancePerIteration;
 assert.equal(plannedMS,737000);
 assert.ok(plannedMS<ttlMS,`planned virtual time ${plannedMS} must fit below fixture TTL ${ttlMS}`);
});
