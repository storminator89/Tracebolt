/** Inert source/DTO checks only. Never starts a browser or a listening socket. */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {windowsFullProcessesFixtureQuery,windowsFullProcessesAbsentPage,windowsFullProcessesLegacyRead,windowsFullProcessesVector,windowsFullProcessesCaseName,windowsFullProcessesDisclosure} from './windows-full-processes-browser.mjs';
const device='agent_'+'a'.repeat(32),prefix='/api/devices/'+device,base='http://127.0.0.1:19889';
const query={search:'',sort:'pid-asc',limit:100,cursor:''};
const input=(changes={})=>({pathname:prefix+'/windows-full-processes/query',search:'',method:'POST',headers:{'x-csrf-token':'synthetic-csrf'},raw:JSON.stringify(query),...changes});
const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8');
test('process inventory requires the exact bounded protected POST, never URL search or grant flags',()=>{
 assert.deepEqual(windowsFullProcessesFixtureQuery(input(),prefix),query);
 for(const changes of [{pathname:prefix+'/windows-full-processes'},{pathname:prefix+'/windows-full-processes/query/extra'},{pathname:prefix+'/windows-full-processes/enable'},{search:'?search=private'},{method:'GET'},{method:'DELETE'},{headers:{}},{raw:'{}'},{raw:'null'},{raw:'[]'},{raw:'{"search":"","sort":"pid-asc","limit":100,"cursor":"","search":"private"}'},{raw:JSON.stringify({...query,limit:101})},{raw:JSON.stringify({...query,limit:0})},{raw:JSON.stringify({...query,sort:'cpu-desc'})},{raw:JSON.stringify({...query,search:'😀'.repeat(65)})},{raw:JSON.stringify({...query,search:'\u0000'})},{raw:JSON.stringify({...query,cursor:'a'.repeat(4097)})},{raw:JSON.stringify({...query,cursor:'https://external.invalid'})},{raw:JSON.stringify({...query,grant:true})}])assert.equal(windowsFullProcessesFixtureQuery(input(changes),prefix),null);
 for(const sort of ['pid-asc','pid-desc','name-asc','name-desc','parentPid-asc','parentPid-desc','threads-asc','threads-desc'])assert.equal(windowsFullProcessesFixtureQuery(input({raw:JSON.stringify({...query,sort})}),prefix).sort,sort);
});
test('old-preview fixture is explicitly unconfigured, never a completed empty snapshot',()=>{
 const page=windowsFullProcessesAbsentPage(device,query,'2026-10-11T00:00:00Z');assert.equal(page.status,'not_configured');assert.equal(page.complete,null);assert.equal(page.authorityUntil,null);assert.deepEqual(page.rows,[]);assert.equal(page.cursorExpiresAt,null);assert.equal(Object.hasOwn(page,'cursor'),false);
});
function legacyFixture({headers={'x-csrf-token':'synthetic-csrf'},status=200,token='synthetic-csrf',url=base+prefix+'/windows-full-processes/query',raw=JSON.stringify(query)}={}){
 const calls=[];const route={request:()=>({url:()=>url,method:()=> 'POST',headers:()=>headers,postData:()=>raw}),fulfill:async value=>{calls.push({fulfill:value});return value;}};
 const page={request:{get:async(url,options)=>{calls.push({url,options});return{status:()=>status,json:async()=>({csrfToken:token}),dispose:async()=>calls.push('dispose')};}}};return{route,page,calls,base,prefix,serverNow:'2026-10-11T00:00:00Z'};
}
test('legacy process seam verifies the actual cookie-sharing operator session first',async()=>{
 const fixture=legacyFixture();await windowsFullProcessesLegacyRead(fixture);assert.equal(fixture.calls[0].url,base+'/api/session');assert.deepEqual(fixture.calls[0].options,{maxRedirects:0,timeout:5000});assert.equal(fixture.calls[1],'dispose');assert.equal(fixture.calls[2].fulfill.status,200);
 for(const options of [{headers:{}},{token:'wrong-token'},{status:401},{url:'http://external.invalid'+prefix+'/windows-full-processes/query'},{raw:'{}'}]){const value=legacyFixture(options);await assert.rejects(windowsFullProcessesLegacyRead(value));assert.equal(value.calls.some(call=>call?.fulfill),false);}
});
test('SQLite process vectors retain PID zero, unavailable names and original capture age after failure',()=>{
 for(const name of ['unavailable','first2051','second100','offset700','search2049','priorCompleteLatestFailed','duplicateNamesUnavailableZero','completeZero']){
  const a=windowsFullProcessesVector(name),b=windowsFullProcessesVector(name,2500);assert.equal(Date.parse(b.page.serverNow)-Date.parse(a.page.serverNow),2500);assert.deepEqual(b.page.complete,a.page.complete);assert.equal(b.page.cursorExpiresAt,a.page.cursorExpiresAt);assert.deepEqual(b.page.rows,a.page.rows);assert.deepEqual(b.query,a.query);
 }
 const first=windowsFullProcessesVector('first2051'),later=windowsFullProcessesVector('search2049');assert.equal(first.page.complete.manifest.rowCount,2051);assert.equal(first.page.rows.length,100);assert.equal(first.page.rows[0].pid,0);assert.equal(later.page.rows.length,1);assert.equal(later.page.rows[0].pid,2049);
 const second=windowsFullProcessesVector('second100');assert.equal(first.page.nextCursor,second.query.cursor);assert.equal(second.page.offset,100);assert.equal(second.page.rows[0].pid,100);const zero=windowsFullProcessesVector('completeZero').page;assert.equal(zero.status,'ready');assert.equal(zero.complete.manifest.rowCount,0);assert.deepEqual(zero.rows,[]);
 const rows=windowsFullProcessesVector('duplicateNamesUnavailableZero').page.rows;assert.equal(rows[0].pid,0);assert.equal(rows[0].name,null);assert.equal(rows[0].nameQuality,'unavailable');assert.ok(new Set(rows.filter(row=>row.name).map(row=>row.name)).size<rows.filter(row=>row.name).length);
 const failed=windowsFullProcessesVector('priorCompleteLatestFailed');assert.equal(failed.page.latestAttempt.status,'source_failed');assert.deepEqual(failed.page.complete,first.page.complete);
 assert.throws(()=>windowsFullProcessesVector('unknown'));assert.throws(()=>windowsFullProcessesVector('first2051',-1));
});
test('hosted process fixture declares its interception boundary, original age and EN/DE mobile coverage',()=>{
 const flow=read('./windows-full-processes-browser.mjs'),runner=read('./windows-full-processes-runner.mjs'),legacy=read('./windows-inventory-browser.mjs'),manifest=JSON.parse(read('./inert-suites.json'));
 assert.match(windowsFullProcessesCaseName,/synthetic transport/);assert.match(windowsFullProcessesDisclosure,/not live manager\/store acceptance/);assert.match(windowsFullProcessesDisclosure,/No native Windows read/);
 assert.match(flow,/for\(const locale of \['en','de'\]\)for\(const width of \[1440,390\]\)/);for(const value of ['duplicates','failed-attempt','pending','navigation','focus','restart','expiry','session'])assert.ok(flow.includes(`stage='${value}'`));
 assert.match(flow,/windows-full-processes-details'\)\)\.not\.toHaveAttribute\('open'\)/);assert.match(flow,/currentToken\(page,base,request\)/);assert.match(flow,/queries\.at\(-1\)\.cursor/);assert.match(flow,/liveStoreAcceptance:false/);assert.match(flow,/data-snapshot-pid/);assert.match(flow,/windows-full-processes-preview>summary/);
 assert.match(legacy,/windowsFullProcessesLegacyRead/);assert.match(legacy,/unexpected-full-processes-query/);assert.ok(manifest.entries.includes('windows-full-processes-fixtures.test.mjs'));
 assert.match(runner,/--ttl','10m'/);assert.match(runner,/300000/);assert.doesNotMatch(runner,/--full-processes|CHROMIUM_PATH|executablePath|ignoreHTTPSErrors|grantPermissions|setDefaultTimeout/);assert.doesNotMatch(flow,/chromium\.launch|createServer|writeFile|execFileSync|spawn\(/);
});
