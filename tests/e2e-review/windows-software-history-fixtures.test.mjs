/** Source/fixture checks only. No socket, browser launch or native operation. */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {windowsSoftwareHistoryCaseName,windowsSoftwareHistoryDisclosure,windowsSoftwareHistoryFixtureQuery,windowsSoftwareHistoryFixture,requireWindowsSoftwareHistoryEvidence} from './windows-software-history-browser.mjs';
const device='agent_'+'a'.repeat(32),prefix='/api/devices/'+device,query={search:'',sort:'observed-desc',limit:100,cursor:''};
const input=(changes={})=>({pathname:prefix+'/windows-software-history/query',search:'',method:'POST',headers:{'x-csrf-token':'synthetic-csrf'},raw:JSON.stringify(query),...changes});
const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8');
test('history is a strict private read-only POST body and never a manager grant',()=>{
 assert.deepEqual(windowsSoftwareHistoryFixtureQuery(input(),prefix),query);
 for(const changes of [{pathname:prefix+'/windows-software-history/enable'},{search:'?search=private'},{method:'GET'},{headers:{}},{raw:'null'},{raw:'{}'},{raw:'[]'},{raw:JSON.stringify({...query,sort:'version-desc'})},{raw:JSON.stringify({...query,limit:101})},{raw:JSON.stringify({...query,limit:0})},{raw:JSON.stringify({...query,grant:true})},{raw:JSON.stringify({...query,search:'😀'.repeat(65)})},{raw:JSON.stringify({...query,cursor:'https://external.invalid'})},{raw:'{"search":"","sort":"observed-desc","limit":100,"cursor":"","search":"private"}'}])assert.equal(windowsSoftwareHistoryFixtureQuery(input(changes),prefix),null);
});
test('default-off, baseline, unknown fields, removals, gaps and bounded paging stay distinct',()=>{
 const off=windowsSoftwareHistoryFixture('not_configured');assert.equal(off.grantId,null);assert.equal(off.comparison,null);assert.deepEqual(off.rows,[]);
 const baseline=windowsSoftwareHistoryFixture('baseline');assert.equal(baseline.status,'ready');assert.equal(baseline.comparison.status,'baseline');assert.equal(baseline.comparison.reason,'no_baseline');assert.deepEqual(baseline.rows,[]);
 const p=windowsSoftwareHistoryFixture();assert.equal(p.retainedCount,205);assert.equal(p.rows.length,100);assert.equal(p.rows[1].kind,'registration_removed');assert.equal(p.rows[1].after,null);assert.deepEqual(p.rows[2].changedFields,['version']);assert.equal(p.rows[3].before.version,null);assert.deepEqual(p.rows[3].changedFields,['name']);
 const next=windowsSoftwareHistoryFixture('normal',{...query,cursor:p.nextCursor});assert.equal(next.offset,100);assert.equal(next.rows.length,100);assert.equal(windowsSoftwareHistoryFixture('normal',{...query,cursor:next.nextCursor}).rows.length,5);
 const search=windowsSoftwareHistoryFixture('normal',{...query,search:'[.*]'});assert.equal(search.matchingCount,1);assert.match(search.rows[0].after.publisher,/<img/);
 for(const reason of ['source_gap','incomparable','resource_limit']){const gap=windowsSoftwareHistoryFixture(reason);assert.equal(gap.comparison.status,'gap');assert.equal(gap.comparison.reason,reason);assert.equal(gap.gapCount,1);assert.equal(gap.expiredChanges,3);assert.equal(gap.omittedChanges,reason==='resource_limit'?1500:0);}
 const expired=windowsSoftwareHistoryFixture('expired-counts');assert.equal(expired.comparison,null);assert.equal(expired.expiredChanges,205);assert.deepEqual(expired.rows,[]);
 const later=windowsSoftwareHistoryFixture('normal',query,1000);assert.equal(Date.parse(later.serverNow)-Date.parse(p.serverNow),1000);assert.deepEqual(later.rows,p.rows);assert.equal(later.cursorExpiresAt,p.cursorExpiresAt);
});
test('registered hosted runner requires all EN/DE desktop/mobile screenshots and privacy cases',()=>{
 const flow=read('./windows-software-history-browser.mjs'),runner=read('./windows-software-history-runner.mjs'),workflow=read('../../.github/workflows/validate.yml'),manifest=JSON.parse(read('./inert-suites.json'));
 assert.match(windowsSoftwareHistoryCaseName,/synthetic transport/);assert.match(windowsSoftwareHistoryDisclosure,/not live manager\/store acceptance/);assert.match(windowsSoftwareHistoryDisclosure,/No native Windows read/);
 for(const value of ['default-off','baseline','gap','pagination','search','pending','navigation','focus','visibility','restart','expiry','session'])assert.ok(flow.includes(`stage='${value}'`));
 assert.match(flow,/currentToken\(page,base,request\)/);assert.match(flow,/for\(const locale of \['en','de'\]\)for\(const width of \[1440,390\]\)/);assert.match(flow,/\.not\.toHaveAttribute\('open'\)/);assert.match(runner,/requireWindowsSoftwareHistoryEvidence\(screenshots,sourceSha\)/);assert.match(runner,/chromium\.launch/);assert.doesNotMatch(runner,/executablePath|CHROMIUM_PATH|ignoreHTTPSErrors|grantPermissions/);
 assert.ok(manifest.entries.includes('windows-software-history-fixtures.test.mjs'));assert.match(workflow,/node tests\/e2e-review\/windows-software-history-runner\.mjs/);assert.match(workflow,/node --test tests\/e2e-review\/windows-software-history-fixtures\.test\.mjs/);assert.match(workflow,/artifacts\/review\/windows-software-history-results\.json/);assert.match(workflow,/artifacts\/review\/windows-software-history-manifest\.json/);
 assert.doesNotMatch(flow,/chromium\.launch|createServer|writeFile|execFileSync|spawn\(/);
});
test('screenshot evidence fails closed on omissions, duplicates and false provenance',()=>{
 const sha='f'.repeat(40),rows=['summary','details','baseline','default-off','gap'].flatMap(kind=>['en','de'].flatMap(locale=>[1440,390].map(width=>({file:`synthetic-windows-software-history-${kind}-${width}-${locale}.png`,sourceSha:sha,test:windowsSoftwareHistoryCaseName,locale,viewport:{width,height:width===390?844:1000},fullPage:false,publicSafe:true,fixtureDisclosure:windowsSoftwareHistoryDisclosure}))));
 assert.deepEqual(requireWindowsSoftwareHistoryEvidence(rows,sha),{summary:4,details:4,baseline:4,defaultOff:4,gap:4});
 assert.throws(()=>requireWindowsSoftwareHistoryEvidence(rows.slice(1),sha));assert.throws(()=>requireWindowsSoftwareHistoryEvidence([...rows.slice(1),rows[1]],sha));
 for(const change of [{sourceSha:'a'.repeat(40)},{locale:'fr'},{viewport:{width:390,height:1000}},{fullPage:true},{publicSafe:false},{fixtureDisclosure:'native acceptance'}]){const broken=structuredClone(rows);Object.assign(broken[0],change);assert.throws(()=>requireWindowsSoftwareHistoryEvidence(broken,sha));}
});
