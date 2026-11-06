/** Inert source/fixture checks; no browser, listener, native helper or Go command. */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {windowsUserSoftwareCaseName,windowsUserSoftwareDisclosure,windowsUserSoftwareFixtureQuery,windowsUserSoftwareFixture,requireWindowsUserSoftwareEvidence,guardWindowsUserSoftwareRoute,windowsUserSoftwareRouteState} from './windows-user-software-browser.mjs';
const prefix='/api/devices/agent_'+'0'.repeat(31)+'1',query={accountContextId:'',source:'',search:'',sort:'name-asc',limit:100,cursor:''};
const input=(changes={})=>({pathname:prefix+'/windows-selected-user-software/query',search:'',method:'POST',headers:{'x-csrf-token':'synthetic-csrf'},raw:JSON.stringify(query),...changes});
const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8');
test('selected-account fixture accepts only exact CSRF read bodies',()=>{
 assert.deepEqual(windowsUserSoftwareFixtureQuery(input(),prefix),query);
 for(const change of [{pathname:prefix+'/windows-selected-user-software/capture'},{search:'?account=private'},{method:'GET'},{headers:{}},{raw:'null'},{raw:'{}'},{raw:'[]'},{raw:JSON.stringify({...query,accountContextId:'other-user'})},{raw:JSON.stringify({...query,source:'hklm'})},{raw:JSON.stringify({...query,limit:101})},{raw:JSON.stringify({...query,consent:true})},{raw:JSON.stringify({...query,search:'😀'.repeat(65)})},{raw:JSON.stringify({...query,cursor:'https://external.invalid'})},{raw:JSON.stringify(query).replace('"source":""','"source":"","source":""')}])assert.equal(windowsUserSoftwareFixtureQuery(input(change),prefix),null);
});
test('Go-derived metadata retains original identity/times with selected source and bounded full-data pages',()=>{
 const first=windowsUserSoftwareFixture();assert.equal(first.complete.manifest.rowCount,205);assert.equal(first.rows.length,100);assert.equal(first.rows[0].name,'Selected App 0000');assert.equal(first.accountContextId,'d'.repeat(64));
 const next=windowsUserSoftwareFixture('complete',{...query,accountContextId:first.accountContextId,cursor:first.nextCursor});assert.equal(next.offset,100);assert.equal(next.rows[0].name,'Selected App 0100');assert.equal(next.rows.length,100);
 const msix=windowsUserSoftwareFixture('complete',{...query,accountContextId:first.accountContextId,source:'msix'});assert.equal(msix.matchingCount,102);assert.ok(msix.rows.every(row=>row.source==='msix'));assert.equal(msix.rows[0].name,'Selected App 0001');
 const search=windowsUserSoftwareFixture('complete',{...query,accountContextId:first.accountContextId,source:'msix',search:'0203'});assert.equal(search.matchingCount,1);assert.equal(search.rows[0].name,'Selected App 0203');
 const later=windowsUserSoftwareFixture('complete',query,1000);assert.equal(Date.parse(later.serverNow)-Date.parse(first.serverNow),1000);assert.deepEqual(later.complete,first.complete);assert.equal(later.cursorExpiresAt,first.cursorExpiresAt);
 const failed=windowsUserSoftwareFixture('bothUnavailable');assert.equal(failed.complete.manifest.coverage,'selected_account_partial');assert.equal(failed.complete.manifest.hkcuStatus,'access_denied');assert.equal(failed.complete.manifest.msixStatus,'unsupported');assert.deepEqual(failed.rows,[]);
 assert.throws(()=>windowsUserSoftwareFixture('complete',{...query,accountContextId:'e'.repeat(64)}));assert.throws(()=>windowsUserSoftwareFixture('complete',query,600001));
});
test('screenshots require exact source-bound EN/DE desktop/mobile capture and unavailable records',()=>{
 const sha='f'.repeat(40),rows=['capture','unavailable'].flatMap(kind=>['en','de'].flatMap(locale=>[1440,390].map(width=>({file:`synthetic-windows-user-software-${kind}-${width}-${locale}.png`,sourceSha:sha,test:windowsUserSoftwareCaseName,locale,viewport:{width,height:width===390?844:1000},fullPage:false,publicSafe:true,fixtureDisclosure:windowsUserSoftwareDisclosure}))));
 assert.deepEqual(requireWindowsUserSoftwareEvidence(rows,sha),{capture:4,unavailable:4});
 for(let i=0;i<rows.length;i++)assert.throws(()=>requireWindowsUserSoftwareEvidence(rows.filter((_,n)=>n!==i),sha));
 assert.throws(()=>requireWindowsUserSoftwareEvidence([...rows.slice(1),rows[1]],sha));
 for(const change of [{sourceSha:'a'.repeat(40)},{locale:'fr'},{viewport:{width:390,height:1000}},{fullPage:true},{publicSafe:false},{fixtureDisclosure:'native acceptance'},{extra:'unreviewed'}]){const bad=structuredClone(rows);Object.assign(bad[0],change);assert.throws(()=>requireWindowsUserSoftwareEvidence(bad,sha));}
});
test('route assertion failure is counted and cannot disappear in detached callbacks',async()=>{
 const before=windowsUserSoftwareRouteState();await guardWindowsUserSoftwareRoute({abort:async()=>{}},async()=>{throw new Error('inert failure')});assert.deepEqual(windowsUserSoftwareRouteState(),{failures:before.failures+1,pending:0});
});
test('inert contracts remain in CI while the manual browser flow is not executed',()=>{
 const flow=read('./windows-user-software-browser.mjs'),runner=read('./windows-user-software-runner.mjs'),workflow=read('../../.github/workflows/validate.yml'),manifest=JSON.parse(read('./inert-suites.json'));
 assert.equal(manifest.entries.filter(name=>name==='windows-user-software-fixtures.test.mjs').length,1);
 assert.equal(workflow.split('windows-user-software-fixtures.test.mjs').length-1,1);
 for(const name of ['windows-user-software-runner.mjs','windows-user-software-results.json','windows-user-software-manifest.json'])assert.equal(workflow.split(name).length-1,0);
 assert.match(flow,/getByRole\('combobox',\{name:locale==='de'\?'Konto':'Account'/);assert.match(flow,/toHaveCount\(0\);await page.goto\(base\+'\/#\/devices\/'\+deviceId\)/);
 for(const name of ['account','paging','source','search','unavailable','access-loss'])assert.ok(flow.includes(`stage='${name}'`));
 assert.match(flow,/currentToken\(page,base,request\)/);assert.match(flow,/for\(const locale of \['en','de'\]\)for\(const width of \[1440,390\]\)/);assert.match(flow,/queries.length\).toBe\(count\+1\)/);assert.match(runner,/requireWindowsUserSoftwareEvidence\(screenshots,sourceSha\)/);assert.match(runner,/routeFailureCount:routes.failures/);assert.match(runner,/process.exitCode=passed\?0:1/);
 assert.doesNotMatch(flow,/chromium\.launch|newContext\(|createServer|writeFile|execFileSync|spawn\(/);assert.doesNotMatch(runner,/executablePath|CHROMIUM_PATH|ignoreHTTPSErrors|grantPermissions/);
});
