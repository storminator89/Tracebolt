/** Inert source/DTO checks only. Does not start a browser or listen on a socket. */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {windowsFullSoftwareFixtureQuery,windowsFullSoftwareAbsentPage,windowsFullSoftwareLegacyRead,windowsFullSoftwareVector,windowsFullSoftwareCaseName,windowsFullSoftwareDisclosure} from './windows-full-software-browser.mjs';
const device='agent_'+'a'.repeat(32),prefix='/api/devices/'+device,base='http://127.0.0.1:19888';
const query={search:'',sort:'name-asc',limit:100,cursor:''};
const input=(changes={})=>({pathname:prefix+'/windows-full-software/query',search:'',method:'POST',headers:{'x-csrf-token':'synthetic-csrf'},raw:JSON.stringify(query),...changes});
const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8');
test('software reads require the exact protected POST body without URL search or mutation flags',()=>{
 assert.deepEqual(windowsFullSoftwareFixtureQuery(input(),prefix),query);
 for(const changes of [{pathname:prefix+'/windows-full-software'},{pathname:prefix+'/windows-full-software/query/extra'},{pathname:prefix+'/windows-full-software/enable'},{search:'?search=private'},{method:'GET'},{method:'DELETE'},{headers:{}},{raw:'{}'},{raw:'null'},{raw:'[]'},{raw:'{"search":"","sort":"name-asc","limit":100,"cursor":"","search":"private"}'},{raw:JSON.stringify({...query,limit:101})},{raw:JSON.stringify({...query,limit:0})},{raw:JSON.stringify({...query,sort:'arbitrary-sql'})},{raw:JSON.stringify({...query,search:'😀'.repeat(65)})},{raw:JSON.stringify({...query,search:'\u0000'})},{raw:JSON.stringify({...query,cursor:'a'.repeat(4097)})},{raw:JSON.stringify({...query,cursor:'https://external.invalid'})},{raw:JSON.stringify({...query,grant:true})}])assert.equal(windowsFullSoftwareFixtureQuery(input(changes),prefix),null);
 for(const sort of ['name-asc','name-desc','version-asc','version-desc','publisher-asc','publisher-desc','view-asc','view-desc'])assert.equal(windowsFullSoftwareFixtureQuery(input({raw:JSON.stringify({...query,sort})}),prefix).sort,sort);
});
test('older preview fixtures report unconfigured, never successful empty software',()=>{
 const page=windowsFullSoftwareAbsentPage(device,query,'2026-10-11T00:00:00Z');assert.equal(page.status,'not_configured');assert.equal(page.complete,null);assert.equal(page.authorityUntil,null);assert.deepEqual(page.rows,[]);assert.equal(page.cursorExpiresAt,null);assert.equal(Object.hasOwn(page,'cursor'),false);
});
function legacyFixture({headers={'x-csrf-token':'synthetic-csrf'},status=200,token='synthetic-csrf',url=base+prefix+'/windows-full-software/query',raw=JSON.stringify(query)}={}){
 const calls=[];const route={request:()=>({url:()=>url,method:()=> 'POST',headers:()=>headers,postData:()=>raw}),fulfill:async value=>{calls.push({fulfill:value});return value;}};
 const page={request:{get:async(url,options)=>{calls.push({url,options});return{status:()=>status,json:async()=>({csrfToken:token}),dispose:async()=>calls.push('dispose')};}}};return{route,page,calls,base,prefix,serverNow:'2026-10-11T00:00:00Z'};
}
test('the legacy software seam checks the actual cookie-sharing session token first',async()=>{
 const fixture=legacyFixture();await windowsFullSoftwareLegacyRead(fixture);assert.equal(fixture.calls[0].url,base+'/api/session');assert.deepEqual(fixture.calls[0].options,{maxRedirects:0,timeout:5000});assert.equal(fixture.calls[1],'dispose');assert.equal(fixture.calls[2].fulfill.status,200);
 for(const options of [{headers:{}},{token:'wrong-token'},{status:401},{url:'http://external.invalid'+prefix+'/windows-full-software/query'},{raw:'{}'}]){const value=legacyFixture(options);await assert.rejects(windowsFullSoftwareLegacyRead(value));assert.equal(value.calls.some(call=>call?.fulfill),false);}
});
test('actual SQLite vectors retain exact original ages, opaque duplicate identities and byte-short cursors',()=>{
 for(const name of ['unavailable','first2051','offset700','unicode2049','priorCompleteLatestFailed','duplicatesMissing','byteShort','byteShortContinuation']){
  const a=windowsFullSoftwareVector(name),b=windowsFullSoftwareVector(name,2500);assert.equal(Date.parse(b.page.serverNow)-Date.parse(a.page.serverNow),2500);assert.deepEqual(b.page.complete,a.page.complete);assert.equal(b.page.cursorExpiresAt,a.page.cursorExpiresAt);assert.deepEqual(b.page.rows,a.page.rows);assert.deepEqual(b.query,a.query);
 }
 const first=windowsFullSoftwareVector('first2051'),later=windowsFullSoftwareVector('unicode2049');assert.equal(first.page.complete.manifest.rowCount,2051);assert.equal(first.page.rows.length,100);assert.equal(later.page.rows.length,1);assert.match(later.page.rows[0].publisher,/東京/);
 const rows=windowsFullSoftwareVector('duplicatesMissing').page.rows;assert.equal(rows.length,4);assert.equal(new Set(rows.map(row=>row.registrationId)).size,4);assert.ok(rows.some(row=>row.name===null));assert.ok(rows.some(row=>row.name===''));assert.ok(new Set(rows.filter(row=>row.name).map(row=>row.name)).size<rows.filter(row=>row.name).length);
 const short=windowsFullSoftwareVector('byteShort'),next=windowsFullSoftwareVector('byteShortContinuation');assert.equal(short.page.rows.length,26);assert.equal(short.page.nextCursor,next.query.cursor);assert.equal(next.page.offset,26);assert.equal(next.page.rows.length,26);assert.ok(next.page.nextCursor);
 const failed=windowsFullSoftwareVector('priorCompleteLatestFailed');assert.equal(failed.page.latestAttempt.status,'source_failed');assert.deepEqual(failed.page.complete,first.page.complete);
 assert.throws(()=>windowsFullSoftwareVector('unknown'));assert.throws(()=>windowsFullSoftwareVector('first2051',-1));
});
test('hosted software gate declares its intercepted boundary and compact EN/DE mobile lifecycle coverage',()=>{
 const flow=read('./windows-full-software-browser.mjs'),runner=read('./windows-full-software-runner.mjs'),legacy=read('./windows-inventory-browser.mjs'),controls=read('./windows-service-software-browser.mjs'),manifest=JSON.parse(read('./inert-suites.json'));
 assert.match(windowsFullSoftwareCaseName,/synthetic transport/);assert.match(windowsFullSoftwareDisclosure,/not live manager\/store acceptance/);assert.match(windowsFullSoftwareDisclosure,/No native Windows read/);
 assert.match(flow,/for\(const locale of \['en','de'\]\)for\(const width of \[1440,390\]\)/);for(const value of ['byte-short','duplicates','failed-attempt','pending','navigation','focus','restart','expiry','session'])assert.ok(flow.includes(`stage='${value}'`));
 assert.match(flow,/windows-full-software-details'\)\)\.not\.toHaveAttribute\('open'\)/);assert.match(flow,/currentToken\(page,base,request\)/);assert.match(flow,/queries\.at\(-1\)\.cursor/);assert.match(flow,/liveStoreAcceptance:false/);
 assert.match(legacy,/windowsFullSoftwareLegacyRead/);assert.match(legacy,/unexpected-full-software-query/);assert.match(controls,/windows-full-software-preview>summary/);assert.ok(manifest.entries.includes('windows-full-software-fixtures.test.mjs'));
 assert.match(runner,/--ttl','10m'/);assert.match(runner,/300000/);assert.match(runner,/liveStoreAcceptance:false/);assert.doesNotMatch(runner,/--full-software|CHROMIUM_PATH|executablePath|ignoreHTTPSErrors|grantPermissions|setDefaultTimeout/);
 assert.doesNotMatch(flow,/chromium\.launch|createServer|writeFile|execFileSync|spawn\(/);
});
