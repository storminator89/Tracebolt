/** Inert fixture/source contracts. No browser, network listener or native read. */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {windowsFleetFixture,windowsFleetOverview,windowsFleetProtectedRead,windowsFleetDeviceIds,windowsFleetCaseName,windowsFleetDisclosure,windowsFleetFrameRows} from './windows-fleet-browser.mjs';
const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8');
const vectors=JSON.parse(read('../../web/src/windows-fleet-identity-vectors.json'));
test('Windows browser data keeps the strict v2 contract and original production-vector deadlines',()=>{
 const a=windowsFleetFixture(),b=windowsFleetFixture('ready',2500);
 assert.equal(a.schemaVersion,'tracebolt.fleet-identities.v2');assert.equal(a.items.length,2);assert.deepEqual(a.items.map(item=>item.deviceId),windowsFleetDeviceIds);
 assert.equal(Date.parse(b.serverNow)-Date.parse(a.serverNow),2500);
 for(const [index,name] of ['fresh','partial'].entries()){
  const original=vectors[name].items[0],row=b.items[index];
  assert.deepEqual(row,{...original,deviceId:windowsFleetDeviceIds[index],serverNow:b.serverNow});
  assert.deepEqual(row.latest,original.latest);assert.equal(row.receivedAt,original.receivedAt);assert.equal(row.expiresAt,original.expiresAt);
 }
 const expired=windowsFleetFixture('expired');for(const item of expired.items){assert.equal(item.status,'expired');assert.equal(item.latest,null);assert.equal(item.sequence,null);assert.equal(item.expiresAt,null);}
 assert.deepEqual(windowsFleetFixture(),a,'fixture consumers cannot mutate the source vectors');b.items[0].latest.hostname.rows[0].value='changed';assert.deepEqual(windowsFleetFixture(),a);
 for(const [mode,elapsed] of [['unknown',0],['ready',-1],['ready',NaN],['ready',90001]])assert.throws(()=>windowsFleetFixture(mode,elapsed));
});
test('invented Windows overview identities are separate from hostname and numeric address evidence',()=>{
 const input={devices:[{id:'unchanged'}],stats:{totalDevices:1}},before=structuredClone(input),value=windowsFleetOverview(input);
 assert.deepEqual(input,before);assert.equal(value.devices.length,2);
 for(const [index,device] of value.devices.entries()){assert.equal(device.id,windowsFleetDeviceIds[index]);assert.equal(device.name,device.id);assert.equal(device.platform,'windows');assert.equal(device.ip,null);assert.equal(device.status,'unknown');assert.equal(device.cpu.value,null);assert.equal(device.memory.value,null);assert.equal(device.disk.value,null);}
 assert.throws(()=>windowsFleetOverview({}));
});
function fixture({url='http://127.0.0.1:19907/api/fleet/identities',method='GET',status=200}={}){
 const calls=[],response={status:()=>status,headers:()=>({'content-length':'1','content-encoding':'gzip','cache-control':'no-store','content-security-policy':"default-src 'self'"}),json:async()=>{calls.push('json');return{original:true};},dispose:async()=>calls.push('dispose')};
 const route={request:()=>({url:()=>url,method:()=>method}),fetch:async options=>{calls.push({fetch:options});return response;},fulfill:async value=>{calls.push({fulfill:value});}};
 return{route,base:'http://127.0.0.1:19907',pathname:'/api/fleet/identities',transform:value=>{calls.push({transform:value});return windowsFleetFixture();},calls,response};
}
test('Windows response interception first reads the exact real authenticated GET with original short bounds',async()=>{
 const f=fixture();await windowsFleetProtectedRead(f);assert.deepEqual(f.calls[0],{fetch:{maxRedirects:0,timeout:5000}});assert.equal(f.calls[1],'json');assert.deepEqual(f.calls[2],{transform:{original:true}});assert.equal(f.calls[3].fulfill.response,f.response);assert.deepEqual(f.calls[3].fulfill.headers,{'cache-control':'no-store','content-security-policy':"default-src 'self'"});assert.equal(f.calls[3].fulfill.json.schemaVersion,'tracebolt.fleet-identities.v2');assert.equal(f.calls[4],'dispose');
 for(const status of [301,401,403,429,503]){const denied=fixture({status});await windowsFleetProtectedRead(denied);assert.deepEqual(denied.calls,[{fetch:{maxRedirects:0,timeout:5000}},{fulfill:{response:denied.response}},'dispose']);}
 for(const change of [{method:'POST'},{method:'DELETE'},{url:'http://external.invalid/api/fleet/identities'},{url:'http://127.0.0.1:19907/api/fleet/endpoint-identities'},{url:'http://127.0.0.1:19907/api/fleet/identities?extra=1'},{url:'http://127.0.0.1:19907/api/fleet/identities/'}]){const invalid=fixture(change);await assert.rejects(windowsFleetProtectedRead(invalid));assert.deepEqual(invalid.calls,[]);}
 const unknown=fixture({url:'http://127.0.0.1:19907/api/session'});unknown.pathname='/api/session';await assert.rejects(windowsFleetProtectedRead(unknown));assert.deepEqual(unknown.calls,[]);
});
test('hosted fleet runner preserves five Linux cases and requires explicit Windows coverage and four screenshots',()=>{
 const flow=read('./windows-fleet-browser.mjs'),runner=read('./fleet-identity-browser.mjs'),workflow=read('../../.github/workflows/validate.yml'),manifest=JSON.parse(read('./inert-suites.json'));
 assert.match(windowsFleetCaseName,/synthetic transport/);assert.match(windowsFleetDisclosure,/not live Windows manager\/store acceptance/);assert.match(windowsFleetDisclosure,/No native Windows read/);
 assert.equal((runner.match(/await check\('/g)||[]).length,5);assert.match(runner,/await check\(windowsFleetCaseName/);assert.match(runner,/await prepare\(page\);await page\.goto/);assert.match(runner,/fixtureDisclosure:fixtureDisclosure\?\?/);
 assert.match(flow,/for\(const locale of \['en','de'\]\)for\(const width of \[1440,390\]\)/);for(const value of ['hostname,ipv4,ipv6','Windows suspension clears display and search','Windows exported expiry clears display and search','Windows real session revocation clears intercepted values',"'X-CSRF-Token':auth.csrfToken",'expect(fleetReads).toBe(before)','liveStoreAcceptance:false,nativeAcceptance:false'])assert.ok(flow.includes(value));
 assert.match(flow,/locator\('details'\)\)\.not\.toHaveAttribute\('open'\)/);assert.match(workflow,/summary\['passed'\] != 6/);assert.match(workflow,/missing Windows screenshots/);assert.match(workflow,/hashlib\.sha256\(Path\('artifacts\/review', item\['file'\]\)/);assert.ok(manifest.entries.includes('windows-fleet-fixtures.test.mjs'));
 assert.doesNotMatch(flow,/chromium\.launch|createServer|writeFile|execFileSync|spawn\(|setDefaultTimeout|ignoreHTTPSErrors|grantPermissions/);
});

test('Windows fleet capture centers the complete row group after each viewport change without weakening visibility',async()=>{
 const calls=[],body={evaluate:async callback=>callback({scrollIntoView:options=>calls.push(options)})};
 for(let variant=0;variant<4;variant++)await windowsFleetFrameRows(body);
 assert.deepEqual(calls,Array.from({length:4},()=>({block:'center',inline:'nearest',behavior:'instant'})));
 const flow=read('./windows-fleet-browser.mjs');
 assert.ok(flow.includes("await windowsFleetFrameRows(page.locator('.device-table tbody'));await expect(fresh).toBeInViewport({ratio:1});await expect(partial).toBeInViewport({ratio:1});await shot"));
 assert.ok(!flow.includes('await rows.last().scrollIntoViewIfNeeded()'));
 assert.equal((flow.match(/toBeInViewport\(\{ratio:1\}\)/g)||[]).length,2);
});
