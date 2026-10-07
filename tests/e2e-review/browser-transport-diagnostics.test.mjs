import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import fs from 'node:fs';
import test from 'node:test';
import {classifyTransportError,createBrowserTransportDiagnostics,reportTransportFailure,sanitizeTransportLayout} from './browser-transport-diagnostics.mjs';

function fixture(){
 const context=new EventEmitter(),browser=new EventEmitter(),page=new EventEmitter();
 let closed=false,connected=true;
 Object.assign(page,{context:()=>context,isClosed:()=>closed,viewportSize:()=>({width:1440,height:1000})});
 Object.assign(browser,{isConnected:()=>connected,version:()=> '145.0.7632.6'});
 const diagnostics=createBrowserTransportDiagnostics(page,browser);
 return {page,context,browser,diagnostics,close(){closed=true;page.emit('close');},disconnect(){connected=false;browser.emit('disconnected');}};
}
const error=message=>new Error(message+'\nPRIVATE_URL_TOKEN');

test('known failures become closed categories without copying error data',()=>{
 for(const [message,category] of [
  ['page.screenshot: Protocol error (Page.captureScreenshot): Unable to capture screenshot','capture-unavailable'],
  ['response.body: Protocol error (Network.getResponseBody): No resource with given identifier found','body-resource-missing'],
  ['response.body: Protocol error (Network.getResponseBody): No data found for resource with given identifier','body-data-missing'],
  ['response.body: Protocol error (Network.getResponseBody): Request content was evicted from inspector cache','body-buffer-evicted'],
  ['response.body: Target page, context or browser has been closed','target-closed'],
  ['page.screenshot: Target crashed','target-crashed'],
  ['response.body: Protocol error (Network.getResponseBody): PRIVATE','body-protocol-other'],
  ['page.screenshot: Protocol error (Page.captureScreenshot): PRIVATE','capture-protocol-other'],
  ['PRIVATE_URL_TOKEN','other'],
 ])assert.equal(classifyTransportError(error(message)),category);
 assert.equal(classifyTransportError({name:'TimeoutError',message:'PRIVATE'}),'timeout');
 for(const input of [null,undefined,{},'PRIVATE',{message:5}])assert.equal(classifyTransportError(input),'other');
});

test('HTTP headers can precede a failed body; diagnose the exact request without rereading or replaying it',()=>{
 const {page,diagnostics}=fixture();let reads=0,failure=null;
 const request={failure:()=>failure},response={request:()=>request,status:()=>200,body:()=>{reads++;throw new Error('must not read');}};
 const caught=error('response.body: Protocol error (Network.getResponseBody): No resource with given identifier found');
 assert.equal(response.status(),200);
 assert.equal(diagnostics.capture('response-body',caught,{response}).requestState,'unobserved');
 failure={errorText:'net::ERR_ABORTED'};page.emit('requestfailed',request);
 const result=diagnostics.capture('response-body',caught,{response});
 assert.equal(result.requestState,'failed');assert.equal(result.requestFailure,'aborted');assert.equal(result.category,'body-resource-missing');assert.equal(reads,0);
 assert.equal(JSON.stringify(result).includes('PRIVATE'),false);diagnostics.dispose();
});

test('finished transport and missing DevTools bytes remain distinct from cancellation',()=>{
 const {page,diagnostics}=fixture(),request={failure:()=>null};
 page.emit('requestfinished',request);
 const result=diagnostics.capture('response-body',error('response.body: Protocol error (Network.getResponseBody): Request content was evicted from inspector cache'),{response:{request:()=>request}});
 assert.equal(result.requestState,'finished');assert.equal(result.requestFailure,'none');assert.equal(result.category,'body-buffer-evicted');diagnostics.dispose();
});

test('failure state is request-specific and unknown failure text never escapes',()=>{
 const {page,diagnostics}=fixture(),first={failure:()=>({errorText:'net::ERR_ABORTED'})},second={failure:()=>({errorText:'PRIVATE_URL_TOKEN'})};
 page.emit('requestfailed',first);page.emit('requestfinished',second);
 const result=diagnostics.capture('response-body',error('PRIVATE'),{response:{request:()=>second}});
 assert.equal(result.requestState,'finished');assert.equal(result.requestFailure,'other');assert.equal(JSON.stringify(result).includes('PRIVATE'),false);diagnostics.dispose();
});

test('all allowlisted network failures project to enums only',()=>{
 const {diagnostics}=fixture();
 for(const [input,expected] of [['net::ERR_CONNECTION_CLOSED','connection-closed'],['net::ERR_CONNECTION_RESET','connection-reset'],['net::ERR_CONNECTION_REFUSED','connection-refused'],['net::ERR_TIMED_OUT','timed-out'],['net::ERR_FAILED','failed'],['net::ERR_ABORTED PRIVATE','other']]){
  const result=diagnostics.capture('response-body',null,{response:{request:()=>({failure:()=>({errorText:input})})}});assert.equal(result.requestFailure,expected);
 }
 diagnostics.dispose();
});

test('snapshot occurs before cleanup and later close/crash events cannot rewrite it',()=>{
 const f=fixture();
 const before=f.diagnostics.capture('screenshot',error('page.screenshot: Protocol error (Page.captureScreenshot): Unable to capture screenshot'),{elapsedMs:12.34567});
 f.page.emit('crash');f.close();f.context.emit('close');f.disconnect();
 const after=f.diagnostics.capture('screenshot',error('PRIVATE'));
 for(const key of ['pageClosed','pageCrashed','contextClosed','browserDisconnected']){assert.equal(before[key],false);assert.equal(after[key],true);}
 assert.equal(before.browserConnected,true);assert.equal(after.browserConnected,false);assert.equal(before.elapsedMs,12.346);
 assert.equal(before.requestState,'not-applicable');assert.deepEqual(before.configuredViewport,{width:1440,height:1000});assert.equal(before.browserVersion,'145.0.7632.6');f.diagnostics.dispose();
});

test('only finite bounded geometry and numeric browser versions leave diagnostics',()=>{
 assert.deepEqual(sanitizeTransportLayout({viewportWidth:1440,viewportHeight:NaN,documentClientWidth:Infinity,documentClientHeight:-1,mainWidth:100001,mainHeight:12.34567,text:'PRIVATE'}),{viewportWidth:1440,mainHeight:12.346});
 for(const value of [null,[],{},'PRIVATE'])assert.equal(sanitizeTransportLayout(value),null);
 const f=fixture();f.page.viewportSize=()=>({width:Infinity,height:'PRIVATE'});f.browser.version=()=> 'PRIVATE';
 const result=f.diagnostics.capture('PRIVATE',error('PRIVATE'),{elapsedMs:Infinity,layout:{mainWidth:88,text:'PRIVATE'}});
 assert.equal(result.operation,'other');assert.equal(result.requestState,'not-page-response');assert.deepEqual(result.configuredViewport,{width:null,height:null});assert.equal(result.browserVersion,null);assert.equal(result.elapsedMs,null);assert.deepEqual(result.preCaptureLayout,{mainWidth:88});assert.equal(JSON.stringify(result).includes('PRIVATE'),false);f.diagnostics.dispose();
});

test('passive monitors detach all listeners and never perform page/API reads',()=>{
 const f=fixture();
 for(const target of [f.page,f.context,f.browser])assert.ok(target.eventNames().length>0);
 f.diagnostics.dispose();f.diagnostics.dispose();
 for(const target of [f.page,f.context,f.browser])assert.deepEqual(target.eventNames(),[]);
 const helper=fs.readFileSync(new URL('./browser-transport-diagnostics.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(helper,/\.evaluate\(|\.body\(|\.text\(|\.json\(|\.url\(|\.headers\(|\.allHeaders\(|\.postData|\.goto\(|\.reload\(|\.route\(|\.request\.(?:get|post)|\.send\(|setTimeout|setInterval|waitFor/);
});

test('both runners retain the original body/capture and rethrow before normal teardown',()=>{
 const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8');
 const body=read('./service-action-browser.mjs'),screen=read('./run.mjs');
 assert.match(body,/try\{bytes=await response\.body\(\);\}/);assert.match(body,/expect\(bytes.length\).toBeLessThanOrEqual\(32768\)/);assert.match(body,/JSON\.parse\(bytes.toString\('utf8'\)\)/);
 assert.match(body,/reportTransportFailure\(transportDiagnostics,'response-body',error,\{response,elapsedMs:performance.now\(\)-began\}\);\n  throw error;/);
 assert.match(screen,/page\.screenshot\(\{path:path.join\(out,`\$\{name\}\.png`\),fullPage,animations:'disabled'\}\)/);
 assert.match(screen,/reportTransportFailure\(transportDiagnostics.get\(page\),'screenshot',error,\{elapsedMs:performance.now\(\)-captureStarted,layout\}\);\n  throw error;/);
 assert.equal((body.match(/await response\.body\(\)/g)??[]).length,1);assert.equal((screen.match(/await page\.screenshot\(/g)??[]).length,1);
 assert.doesNotMatch(body,/response\.finished\(|received\.finished\(/);
});


test('diagnostic or output failures never mask the original operation error',()=>{
 const original=new Error('original operation failure'),saved=console.log,f=fixture();
 try{
  for(const diagnostics of [undefined,{capture(){throw new Error('PRIVATE');}},f.diagnostics]){
   console.log=()=>{throw new Error('PRIVATE_OUTPUT_FAILURE');};
   assert.throws(()=>{try{throw original;}catch(error){reportTransportFailure(diagnostics,'screenshot',error);throw error;}},caught=>caught===original);
  }
  const messages=[];console.log=value=>messages.push(value);
  reportTransportFailure(f.diagnostics,'screenshot',error('PRIVATE'));
  assert.equal(messages.length,1);assert.equal(messages[0].includes('PRIVATE'),false);
 }finally{console.log=saved;f.diagnostics.dispose();}
});
