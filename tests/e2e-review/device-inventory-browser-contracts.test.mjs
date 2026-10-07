/** Exact browser-selector/copy contracts. Pure source checks; no browser, server,
 * native collection, private endpoint data or network access is started. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8');
const conditional=read('./conditional-browser.mjs'),v3=read('./v3-mvp-browser.mjs');
function scenario(source,name){const begin=source.indexOf(`await check('${name}'`);assert.notEqual(begin,-1);const end=source.indexOf('await check(',begin+12);return source.slice(begin,end===-1?undefined:end);}
function firstCopy(source,key){const value=source.match(new RegExp(`\\b${key}: '([^']*)'`));assert.ok(value);return value[1];}
const coverage=scenario(conditional,'Device tabs and package/review disclosures issue only their lazy device-bound reads');
const compact=scenario(v3,'Compact Packages and Updates remain explicit about source, stale cache and unknown comparisons');
const sockets=scenario(v3,'Socket pages distinguish TCP listeners, connections, UDP bounds and unknown ownership');

test('held coverage retry asserts the current visible uncertainty warning, without relaxing cleared-state checks',()=>{
 const current=firstCopy(read('../../web/src/security-coverage.tsx'),'caution'),warning=current.slice(current.indexOf('Missing'));
 assert.ok(warning.includes('not zero vulnerabilities'));
 assert.ok(coverage.includes(`toContainText('${warning}')`),'held-view warning must match the actual current component copy');
 assert.ok(coverage.includes(".security-grid,.security-status-line,.security-gaps,.security-details')).toHaveCount(0)"));
 assert.ok(coverage.includes("expect(refreshCoverage).toBeDisabled()"));
});
test('compact gallery opens the actual accessible Security tab rather than its shorter visible label',()=>{
 const details=read('../../web/src/details.tsx'),match=details.match(/const securityTabLabel = locale === 'de' \? '[^']+' : '([^']+)'/);
 assert.ok(match);assert.equal(match[1],'Security coverage');
 assert.ok(compact.includes(`getByRole('tab',{name:'${match[1]}',exact:true}).click()`));
 assert.ok(!compact.includes("getByRole('tab',{name:'Security',exact:true})"));
 assert.ok(compact.includes("mark('select current Security coverage tab after package captures')"));
});
test('socket coverage locator and denial assertion match the real source note independently of table data',()=>{
 const note=firstCopy(read('../../web/src/system-inventory.tsx'),'network'),split=note.indexOf('“');assert.ok(split>0);
 const intro=note.slice(0,split).trim(),denial=note.slice(split);
 assert.ok(sockets.includes(`filter({hasText:'${intro}'})`),'attribution note must not be filtered out by obsolete wording');
 assert.ok(sockets.includes(`toContainText('${denial}')`),'denial remains an owner-field result, distinct from section failure');
 assert.ok(sockets.includes("toContainText('42 / qa-fixture-worker')"));
 assert.ok(sockets.includes("toContainText('Numeric endpoints may expose private topology; a listener does not establish external reachability.')"));
});
test('repairs preserve retry budgets, read-only evidence and safe fixed diagnostic fields',()=>{
 for(const text of ['},8000)','route.fetch({timeout:4000,maxRedirects:0,maxRetries:0})','{timeout:7000}',"expect(coverageStatuses).toEqual([429,200])",'expect(mutations).toBe(0)','expect(holdExpired).toBe(false)'])assert.ok(coverage.includes(text),text);
 assert.ok(coverage.includes('coverageStatuses.slice(0,3)'));assert.ok(coverage.includes("coverageStep='uncertainty warning retained'"));
 assert.doesNotMatch(coverage+compact+sockets,/\.skip\(|setDefaultTimeout|waitForTimeout|ignoreHTTPSErrors/);
 assert.ok(v3.includes("expect(text.includes(password))")||v3.includes("document.body.innerText.includes(p)||[...document.querySelectorAll('input')]"));
});
