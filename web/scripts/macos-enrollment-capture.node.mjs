import assert from 'node:assert/strict';
import {test} from 'node:test';
import {captureMatrix,compile,origin,routeFixture} from './capture-macos-enrollment.mjs';
const compiled=await compile();
function harness(scene){
 const state={external:0,unexpected:0,writes:0,reads:0,syntheticCreates:0},handler=routeFixture(compiled,scene,state);
 const request=async(method,path,body,headers={})=>{let response,aborted=false;await handler({request:()=>({method:()=>method,url:()=>path.startsWith('https:')?path:origin+path,postData:()=>body===undefined?null:JSON.stringify(body),headers:()=>headers}),fulfill:value=>{response=value;},abort:()=>{aborted=true;}});return {response,aborted};};
 return {state,request};
}
const body={requestId:`request_${'5'.repeat(32)}`,platform:'darwin'},headers={'x-csrf-token':'synthetic-csrf-not-a-session'};
test('16 exact EN/DE desktop/mobile cases, every file unique',()=>{assert.equal(captureMatrix.length,16);assert.equal(new Set(captureMatrix.map(row=>row.file)).size,16);assert(captureMatrix.every(row=>['ready','unavailable','created','review'].includes(row.scene)));});
test('Mac is isolated while the ordinary Linux picker remains a Linux list',async()=>{const h=harness('ready');for(const [route,platform] of [['/api/enrollment','linux'],['/api/macos/enrollment','darwin']]){const {response}=await h.request('GET',route);assert.deepEqual(JSON.parse(response.body).platforms,[platform]);}});
test('only unavailable scene disables the Mac store',async()=>{const h=harness('unavailable'),{response}=await h.request('GET','/api/macos/enrollment');assert.equal(JSON.parse(response.body).enabled,false);});
test('creates one inert fixture only after exact body and CSRF, never a second invite',async()=>{const h=harness('created');const first=await h.request('POST','/api/macos/enrollment/invitations',body,headers);assert.equal(first.aborted,false);assert.equal(JSON.parse(first.response.body).snapshot.platform,'darwin');assert.equal((await h.request('POST','/api/macos/enrollment/invitations',body,headers)).aborted,true);assert.equal(h.state.syntheticCreates,1);});
test('rejects wrong platform, unexpected fields, wrong CSRF and absent request ID',async()=>{for(const [payload,requestHeaders] of [[{...body,platform:'linux'},headers],[{...body,collectionAcknowledged:true},headers],[body,{}],[{platform:'darwin'},headers]]){const h=harness('created');assert.equal((await h.request('POST','/api/macos/enrollment/invitations',payload,requestHeaders)).aborted,true);assert.equal(h.state.syntheticCreates,0);}});
test('blocks actual approval, termination, other-origin, query and unknown routes',async()=>{const h=harness('review');for(const [method,path] of [['POST','/api/macos/enrollment/invite_1/approve'],['POST','/api/macos/enrollment/invite_1/terminate'],['GET','https://external.invalid/'],['GET','/api/macos/enrollment?token=unsafe'],['GET','/api/windows/enrollment']])assert.equal((await h.request(method,path,method==='POST'?{}:undefined)).aborted,true);assert.equal(h.state.syntheticCreates,0);assert.equal(h.state.external,1);assert.equal(h.state.writes,2);assert.equal(h.state.unexpected,2);});
