/** Inert page/source contract checks. No browser, listener or native provider. */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {windowsNetworkContextCaseName,windowsNetworkContextDisclosure,windowsNetworkContextFixtureQuery,windowsNetworkContextFixtureServer} from './windows-network-context-browser.mjs';
const device='agent_'+'1'.repeat(32),prefix='/api/devices/'+device,query={kind:'route',search:'',sort:'source-asc',limit:100,cursor:''};
const input=(changes={})=>({pathname:prefix+'/windows-network-context/query',search:'',method:'POST',headers:{'x-csrf-token':'synthetic-csrf'},raw:JSON.stringify(query),...changes});
const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8');
test('network context requires exact bounded kind-bound protected POST and never URL search or consent writes',()=>{
 assert.deepEqual(windowsNetworkContextFixtureQuery(input(),prefix),query);
 for(const changes of [{pathname:prefix+'/windows-network-context'},{pathname:prefix+'/windows-network-context/query/more'},{search:'?search=private'},{method:'GET'},{method:'DELETE'},{headers:{}},{raw:'{}'},{raw:'null'},{raw:'[]'},{raw:'{"kind":"route","kind":"interface","search":"","sort":"source-asc","limit":100,"cursor":""}'},{raw:JSON.stringify({...query,kind:'adapter'})},{raw:JSON.stringify({...query,limit:101})},{raw:JSON.stringify({...query,limit:0})},{raw:JSON.stringify({...query,sort:'rates-desc'})},{raw:JSON.stringify({...query,search:'😀'.repeat(65)})},{raw:JSON.stringify({...query,cursor:'https://external.invalid'})},{raw:JSON.stringify({...query,grant:true})}])assert.equal(windowsNetworkContextFixtureQuery(input(changes),prefix),null);
 for(const kind of ['all','route','interface'])for(const sort of ['source-asc','source-desc','interface-asc','interface-desc'])assert.deepEqual(windowsNetworkContextFixtureQuery(input({raw:JSON.stringify({...query,kind,sort})}),prefix),{...query,kind,sort});
});
test('invented full-generation fixture supports later search and distinct exact counters without numeric rounding',()=>{
 const server=windowsNetworkContextFixtureServer(),first=server.read(query),second=server.read({...query,cursor:first.body.nextCursor});
 assert.equal(first.body.rows.length,100);assert.equal(second.body.offset,100);assert.equal(second.body.rows[0].id,101);
 assert.equal(server.read({...query,kind:'interface',cursor:first.body.nextCursor}).status,409);
 assert.equal(server.read({...query,search:'private',cursor:first.body.nextCursor}).status,409);
 const late=server.read({...query,search:'2001:db8::'}).body;assert.equal(late.rows.length,1);assert.equal(late.rows[0].route.nextHop,'fe80::1%7');assert.equal(late.rows[0].route.destinationScopeId,7);assert.equal(late.rows[0].route.metric,4294967295);
 const counters=server.read({...query,kind:'interface'}).body;assert.equal(counters.rows[0].counters.inOctets,'18446744073709551615');assert.equal(counters.rows[0].counters.outOctets,'9007199254740993');assert.equal(counters.rows[1].counters.inOctets,'0');assert.equal(counters.rows[1].counters.alias,null);
 const failed=server.read(query,{elapsed:2500,mode:'failed-attempt'}).body;assert.deepEqual(failed.complete,first.body.complete);assert.equal(failed.latestAttempt.reason,'resource_limit');
 const absent=server.read(query,{mode:'not_configured'}).body;assert.equal(absent.status,'not_configured');assert.equal(absent.complete,null);assert.deepEqual(absent.rows,[]);
 assert.throws(()=>server.read(query,{elapsed:-1}));
});
test('hosted flow and outputs are explicitly registered with precise synthetic boundaries',()=>{
 const flow=read('./windows-network-context-browser.mjs'),runner=read('./windows-network-context-runner.mjs'),manifest=JSON.parse(read('./inert-suites.json')),workflow=read('../../.github/workflows/validate.yml');
 assert.match(windowsNetworkContextCaseName,/invented private page/);assert.match(windowsNetworkContextDisclosure,/not live manager\/store or native Windows acceptance/);
 assert.match(flow,/for\(const locale of \['en','de'\]\)for\(const width of \[1440,390\]\)/);
 for(const stage of ['routes','search','counters','source-switch','failed-attempt','pending','navigation','focus','restart','expiry','session'])assert.ok(flow.includes(`stage='${stage}'`));
 assert.match(flow,/currentToken\(page,base,request\)/);assert.match(flow,/queries\.at\(-1\)\.kind/);assert.match(flow,/windows-network-context-details'\)\)\.not\.toHaveAttribute\('open'\)/);
 assert.ok(manifest.entries.includes('windows-network-context-fixtures.test.mjs'));assert.match(workflow,/node --test tests\/e2e-review\/windows-network-context-fixtures.test.mjs/);assert.match(workflow,/node tests\/e2e-review\/windows-network-context-runner.mjs/);
 for(const file of ['windows-network-context-results.json','windows-network-context-manifest.json']){assert.ok(runner.includes(file));assert.ok(workflow.includes('artifacts/review/'+file));}
 assert.match(runner,/synthetic-windows-network-context-\(routes\|counters\)/);assert.match(runner,/screenshots\.length!==expected\.size/);assert.match(runner,/--ttl','10m'/);assert.match(runner,/300000/);
 assert.doesNotMatch(runner,/CHROMIUM_PATH|executablePath|ignoreHTTPSErrors|grantPermissions|setDefaultTimeout/);assert.doesNotMatch(flow,/chromium\.launch|createServer|writeFile|execFileSync|spawn\(/);
});
