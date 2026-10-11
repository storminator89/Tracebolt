import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {windowsFullServicesFixtureQuery,windowsFullServicesAbsentPage,windowsFullServicesLegacyRead,windowsFullServicesFixtureControl,windowsFullServicesBrowserCase,windowsFullServicesCaseName,windowsFullServicesDisclosure} from './windows-full-services-browser.mjs';
const device='agent_'+'a'.repeat(32),prefix='/api/devices/'+device,base='http://127.0.0.1:19887';
const query={search:'',sort:'name-asc',limit:100,cursor:''};
const input=(changes={})=>({pathname:prefix+'/windows-full-services/query',search:'',method:'POST',headers:{'x-csrf-token':'synthetic-csrf'},raw:JSON.stringify(query),...changes});
const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8');
test('only the exact bounded protected read-only POST shape is admitted in the old Windows fixture',()=>{
 assert.deepEqual(windowsFullServicesFixtureQuery(input(),prefix),query);
 for(const changes of [{pathname:prefix+'/windows-full-services'},{pathname:prefix+'/windows-full-services/query/extra'},{pathname:prefix+'/windows-full-services/grant'},{search:'?search=private'},{method:'GET'},{method:'DELETE'},{headers:{}},{raw:'{}'},{raw:'null'},{raw:'[]'},{raw:'{"search":"","sort":"name-asc","limit":100,"cursor":"","search":"private"}'},{raw:JSON.stringify({...query,limit:101})},{raw:JSON.stringify({...query,limit:0})},{raw:JSON.stringify({...query,sort:'arbitrary-sql'})},{raw:JSON.stringify({...query,search:'😀'.repeat(65)})},{raw:JSON.stringify({...query,search:'\u0000'})},{raw:JSON.stringify({...query,cursor:'a'.repeat(4097)})},{raw:JSON.stringify({...query,cursor:'https://external.invalid'})},{raw:JSON.stringify({...query,grant:true})}])assert.equal(windowsFullServicesFixtureQuery(input(changes),prefix),null);
});
test('older preview fixtures return explicit unconfigured full scope, never fake healthy zero',()=>{
 const page=windowsFullServicesAbsentPage(device,query,'2026-10-11T00:00:00Z');assert.equal(page.status,'not_configured');assert.equal(page.complete,null);assert.equal(page.authorityUntil,null);assert.deepEqual(page.rows,[]);assert.equal(page.cursorExpiresAt,null);assert.equal(Object.hasOwn(page,'cursor'),false);
});
function legacyFixture({headers={'x-csrf-token':'synthetic-csrf'},status=200,token='synthetic-csrf',url=base+prefix+'/windows-full-services/query',raw=JSON.stringify(query)}={}){
 const calls=[];const route={request:()=>({url:()=>url,method:()=> 'POST',headers:()=>headers,postData:()=>raw}),fulfill:async value=>{calls.push({fulfill:value});return value;}};
 const page={request:{get:async(url,options)=>{calls.push({url,options});return{status:()=>status,json:async()=>({csrfToken:token}),dispose:async()=>calls.push('dispose')};}}};return{route,page,calls,base,prefix,serverNow:'2026-10-11T00:00:00Z'};
}
test('legacy read uses actual cookie-sharing session and requires the exact current token',async()=>{
 const fixture=legacyFixture();await windowsFullServicesLegacyRead(fixture);assert.equal(fixture.calls[0].url,base+'/api/session');assert.deepEqual(fixture.calls[0].options,{maxRedirects:0,timeout:5000});assert.equal(fixture.calls[1],'dispose');assert.equal(fixture.calls[2].fulfill.status,200);
 for(const options of [{headers:{}},{token:'wrong-token'},{status:401},{url:'http://external.invalid'+prefix+'/windows-full-services/query'},{raw:'{}'}]){const value=legacyFixture(options);await assert.rejects(windowsFullServicesLegacyRead(value));assert.equal(value.calls.some(call=>call?.fulfill),false);}
});
test('fixture controls reject unknown actions and non-exact loopback origins before any request',async()=>{
 const page={request:{get:()=>{throw Error('must not request');},post:()=>{throw Error('must not request');}}};
 for(const target of ['https://127.0.0.1:19887','http://localhost:19887','http://user:secret@127.0.0.1:19887','http://127.0.0.1:19887/path','https://external.invalid','invalid'])await assert.rejects(windowsFullServicesFixtureControl(page,target));
 await assert.rejects(windowsFullServicesFixtureControl(page,base,'install-service'));
});
test('fixture control retains same-origin CSRF and finite response without exporting credentials',async()=>{
 const calls=[],info={deviceId:device,rowCount:2051,firstName:'InventedService00000',laterName:'InventedService02049',laterSearch:'東京2049'};
 const response=body=>({status:()=>200,json:async()=>body,dispose:async()=>calls.push('dispose')});
 const page={request:{get:async(url,options)=>{calls.push({method:'GET',url,options});return response({csrfToken:'SYNTHETIC-PRIVATE-TOKEN'});},post:async(url,options)=>{calls.push({method:'POST',url,options});return response(info);}}};
 assert.deepEqual(await windowsFullServicesFixtureControl(page,base,'replace'),info);assert.equal(calls[2].url,base+'/__fixture/windows-full-services');assert.deepEqual(calls[2].options,{headers:{Origin:base,'X-CSRF-Token':'SYNTHETIC-PRIVATE-TOKEN'},data:{action:'replace'},maxRedirects:0,timeout:5000});assert.equal(JSON.stringify(info).includes('SYNTHETIC-PRIVATE'),false);
});
test('new gate is independent and preserves all existing ordinary and native case counts/budgets',()=>{
 const runner=read('./windows-full-services-runner.mjs'),flow=read('./windows-full-services-browser.mjs'),legacy=read('./lan-browser.mjs'),workflow=read('../../.github/workflows/validate.yml'),manifest=JSON.parse(read('./inert-suites.json'));
 assert.equal((legacy.match(/await check\(/g)||[]).length,26);assert.match(legacy,/windowsInventoryBrowserCase\(\{pageAt,login,expect,base,shot\}\),'20m'/);
 assert.equal((read('./enrollment-browser.mjs').match(/await check\('/g)||[]).length,13);
 assert.match(workflow,/Guided enrollment full browser gate \(13 required, no skips\)/);assert.match(workflow,/node tests\/e2e-review\/windows-full-services-runner\.mjs/);assert.match(workflow,/node --test tests\/e2e-review\/windows-full-services-fixtures\.test\.mjs/);assert.ok(manifest.entries.includes('windows-full-services-fixtures.test.mjs'));
 assert.ok(workflow.includes('            artifacts/review/windows-full-services-results.json\n'));assert.ok(workflow.includes('            artifacts/review/windows-full-services-manifest.json\n'));
 assert.match(runner,/--full-services/);assert.match(runner,/--ttl','10m'/);assert.match(runner,/300000/);assert.doesNotMatch(runner,/CHROMIUM_PATH|executablePath|ignoreHTTPSErrors|grantPermissions|setDefaultTimeout/);
 assert.match(flow,/for\(const locale of \['en','de'\]\)for\(const width of \[1440,390\]\)/);assert.match(flow,/pageNumber<=7/);assert.match(flow,/info\.laterSearch/);assert.match(flow,/byte-short/);assert.ok(flow.indexOf("stage='expiry'")<flow.indexOf("stage='disabled'"));assert.match(flow,/cursor-binding/);assert.match(flow,/response\.status\(\)\)\.toBe\(409\)/);assert.match(flow,/near-expiry/);assert.match(flow,/route\.continue\(\)/);assert.match(flow,/route\.fetch\(\{timeout:5000\}\)/);assert.match(flow,/queries\.slice\(stopped\)\.every\(query=>query\.cursor===''/);
 assert.match(windowsFullServicesCaseName,/SQLite-backed/);assert.match(windowsFullServicesDisclosure,/no native Windows read/);assert.match(flow,/Läuft \(running\)/);assert.match(flow,/search\.fill\('Läuft'\)/);assert.doesNotMatch(flow,/chromium\.launch|createServer|writeFile|execFileSync|spawn\(/);
});

test('revocation failure reports fixed assertion checkpoints without raw diagnostics',()=>{
 const flow=read('./windows-full-services-browser.mjs'),runner=read('./windows-full-services-runner.mjs');
 const checkpoints=[['revoked-control',"await windowsFullServicesFixtureControl(page,base,'revoke')"],['revoked-refresh',"await panel.getByRole('button',{name:'Refresh service page',exact:true}).click()"],['revoked-alert',"await expect(panel.getByRole('alert')).toContainText('no longer authorized')"],['revoked-clear','await expect(rows).toHaveCount(0)'],['final-external','expect(external).toEqual([])'],['final-writes','expect(unexpected).toEqual([])'],['final-query-limits','expect(queries.every(query=>query.limit===100)).toBe(true)'],['final-storage','const stored=await page.evaluate'],['final-cursor-count','expect(bindingRejects).toBe(13)']];
 const tail=flow.slice(flow.indexOf("stage='revoked';"));let previous=-1;
 for(const [name,assertion] of checkpoints){const mark="stage='"+name+"';";const offset=tail.indexOf(mark);assert.ok(offset>previous,name);assert.ok(tail.slice(offset+mark.length).startsWith(assertion),name);assert.ok(flow.slice(0,flow.indexOf("let stage=")).includes("'"+name+"'"),name);previous=offset;}
 assert.match(flow,/windowsFullServicesFailureStage=\(\)=>stages\.has\(stage\)\?stage:'setup'/);
 assert.match(runner,/catch\{console\.log\('FAIL: complete Windows services hosted browser gate; raw diagnostics withheld\.'\);\}/);
 assert.doesNotMatch(runner,/console\.(?:log|error)\((?:error|err|raw|details|response)/);
});

test('actual service browser route admits only the exact software navigation read and retains mutation rejection',async()=>{
 let handler;const stopped=new Error('stop after route registration');
 const page={request:{get:async()=>({status:()=>200,json:async()=>({deviceId:device,rowCount:1,firstName:'InventedService',laterName:'InventedService',laterSearch:'Invented'}),dispose:async()=>{}})},route:async(pattern,callback)=>{assert.equal(pattern,'**/*');handler=callback;},locator:()=>{throw stopped;}};
 await assert.rejects(windowsFullServicesBrowserCase({page,base,login:async()=>{},expect:()=>{throw Error('unexpected assertion');},shot:async()=>{throw Error('unexpected screenshot');}}),error=>error===stopped);
 const invoke=async(changes={})=>{const data={url:base+prefix+'/windows-full-software/query',method:'POST',headers:{'x-csrf-token':'synthetic-csrf'},raw:JSON.stringify(query),...changes},actions=[];await handler({request:()=>({url:()=>data.url,method:()=>data.method,headers:()=>data.headers,postData:()=>data.raw}),continue:async()=>actions.push('continue'),abort:async reason=>actions.push('abort:'+reason)});return actions;};
 assert.deepEqual(await invoke(),['continue']);
 for(const changes of [{url:'http://external.invalid'+prefix+'/windows-full-software/query'},{url:base+prefix+'/windows-full-software/query?query=private'},{url:base+'/api/devices/agent_'+'b'.repeat(32)+'/windows-full-software/query'},{url:base+prefix+'/windows-full-software/grant'},{url:base+prefix+'/windows-full-services/grant'},{method:'GET'},{method:'DELETE'},{headers:{}},{raw:'{}'},{raw:'null'},{raw:JSON.stringify({...query,scope:true})},{raw:JSON.stringify({...query,limit:101})},{raw:JSON.stringify({...query,sort:'arbitrary-sql'})}])assert.deepEqual(await invoke(changes),['abort:blockedbyclient']);
 assert.deepEqual(await invoke({url:base+prefix+'/windows-full-services/query'}),['continue']);
 assert.deepEqual(await invoke({url:base+prefix,method:'GET'}),['continue']);
});
