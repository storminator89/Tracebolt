/** Inert fixture and assertion-source checks; no browser or host collection. */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {windowsBrowserFixture,windowsHealthBrowserDevice,windowsFixtureResponseTime} from './windows-inventory-browser.mjs';
import {requireWindowsHealthEvidence} from './windows-health-evidence.mjs';
const now='2026-10-08T18:00:00.000Z';
test('positive hosted Health fixture mirrors manager activation authority and original metric ages',()=>{
 const d=windowsHealthBrowserDevice(now),view=windowsBrowserFixture(now);
 assert.equal(d.id,view.deviceId);assert.equal(d.platform,'windows');assert.equal(d.source,'lan');assert.equal(d.synthetic,false);assert.equal(d.status,'unknown');
 assert.deepEqual(d.capabilities.map(({id,status})=>({id,status})),[{id:'agent_identity',status:'supported'}]);
 assert.equal(d.agentCertificate.source,'guided-enrollment');assert.equal(d.agentCertificate.checkedAt,now);assert.ok(Date.parse(d.agentCertificate.expiresAt)>Date.parse(now));
 assert.equal(d.disk.value,61);assert.equal(d.disk.unit,'%');assert.equal(d.disk.quality,'healthy');assert.match(d.disk.source,/Synthetic/);
 assert.equal(Date.parse(now)-Date.parse(d.disk.collectedAt),10000);assert.equal(d.lastSeen,d.disk.collectedAt);assert.equal(Date.parse(now)-Date.parse(view.receivedAt),1000);
});
test('missing-authority fixture changes no accepted readings or inventory to fabricate health',()=>{
 const positive=windowsHealthBrowserDevice(now),missing=windowsHealthBrowserDevice(now,'health-unverified');
 assert.deepEqual(missing.capabilities,[]);assert.deepEqual({...positive,capabilities:[]},missing);
 assert.deepEqual(windowsBrowserFixture(now,'health-unverified'),windowsBrowserFixture(now));
 assert.equal(windowsHealthBrowserDevice(now).capabilities.length,1,'a missing case cannot taint the next positive fixture');
});
test('hosted completion rejects skipped positive or authority-loss outputs without fake browser assertions',()=>{
 const sourceSha='a'.repeat(40),testName='Invented Windows case';
 const fixture=()=>['en','de'].flatMap(locale=>[1440,390].flatMap(width=>['current','unverified'].map(phase=>({file:`synthetic-windows-health-${phase}-${width}-${locale}.png`,sourceSha,test:testName,locale,viewport:{width,height:width===390?844:1000},publicSafe:true,fullPage:false}))));
 assert.deepEqual(requireWindowsHealthEvidence(fixture(),sourceSha,testName),{positive:4,authorityLoss:4});
 // An early-return/skipped helper produces no Health screenshots. Do not let
 // an otherwise successful surrounding inventory case count as Health proof.
 assert.throws(()=>requireWindowsHealthEvidence([],sourceSha,testName),/completion evidence/);
 for(let index=0;index<8;index++){
  const missing=fixture();missing.splice(index,1);assert.throws(()=>requireWindowsHealthEvidence(missing,sourceSha,testName),/completion evidence/);
  const duplicate=fixture();duplicate[index]={...duplicate[(index+1)%8]};assert.throws(()=>requireWindowsHealthEvidence(duplicate,sourceSha,testName),/completion evidence/);
 }
 for(const mutate of [item=>{item.sourceSha='b'.repeat(40);},item=>{item.test='Another case';},item=>{item.locale='de';},item=>{item.viewport.width=390;},item=>{item.viewport.height=844;},item=>{item.publicSafe=false;},item=>{item.fullPage=true;}]){
  const invalid=fixture();mutate(invalid[0]);assert.throws(()=>requireWindowsHealthEvidence(invalid,sourceSha,testName),/completion evidence/);
 }
 const unrelated=fixture();unrelated.push({file:'synthetic-unrelated.png'});assert.deepEqual(requireWindowsHealthEvidence(unrelated,sourceSha,testName),{positive:4,authorityLoss:4});
});

test('the real runner success boundary rejects a no-op Windows callback before reporting PASS',async()=>{
 const require=createRequire(new URL('../../web/package.json',import.meta.url)),ts=require('typescript'),vm=require('node:vm');
 const source=fs.readFileSync(new URL('./lan-browser.mjs',import.meta.url),'utf8');
 const parsed=ts.createSourceFile('lan-browser.mjs',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.JS);
 const check=parsed.statements.find(node=>ts.isFunctionDeclaration(node)&&node.name?.text==='check');assert.ok(check);
 // Execute only the actual success/failure wrapper. Its process/browser setup
 // and teardown are inert here; no Playwright assertion is mocked or replaced.
 const globals={Date,console:{log(){}},start:async()=>{},stop:async()=>{},context:null,currentTest:'',results:[],screenshots:[],sourceSha:'a'.repeat(40),requireWindowsHealthEvidence,windowsInventoryFailureStage:()=> 'fixture-before-completion'};
 for(const name of new Set([...check.getText(parsed).matchAll(/\b\w+CaseName\b/g)].map(match=>match[0])))globals[name]=name;
 const run=vm.runInNewContext('('+check.getText(parsed)+')',globals);
 await run(globals.windowsInventoryCaseName,async()=>{});
 assert.equal(globals.results.length,1);assert.equal(globals.results[0].status,'FAIL');assert.equal(globals.results[0].stage,'health-completion');
 globals.results.length=0;
 for(const locale of ['en','de'])for(const width of [1440,390])for(const phase of ['current','unverified'])globals.screenshots.push({file:`synthetic-windows-health-${phase}-${width}-${locale}.png`,sourceSha:globals.sourceSha,test:globals.windowsInventoryCaseName,locale,viewport:{width,height:width===390?844:1000},publicSafe:true,fullPage:false});
 await run(globals.windowsInventoryCaseName,async()=>{});
 assert.equal(globals.results[0].status,'PASS');
});

test('interleaved contact aging preserves the real Health watermark without poisoning the next viewport',async()=>{
 const require=createRequire(new URL('../../web/package.json',import.meta.url)),{build}=require('esbuild');
 const built=await build({stdin:{contents:"export {windowsHealthSummary} from './windows-health'; export {acceptWindowsHealthClock,windowsHealthElapsed} from './windows-health-clock'; export {abortProtectedRequests,getProtectedRequestEpoch} from './api';",resolveDir:fileURLToPath(new URL('../../web/src/',import.meta.url)),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,loader:{'.css':'empty'},logLevel:'silent'});
 const source=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text).toString('base64'));
 const originalDateNow=Object.getOwnPropertyDescriptor(Date,'now'),originalPerformance=Object.getOwnPropertyDescriptor(globalThis,'performance');
 const base=Date.parse(now),at=value=>new Date(base+value).toISOString();let local=0;
 try{
  Object.defineProperty(Date,'now',{value:()=>base+local,configurable:true,writable:true});
  Object.defineProperty(globalThis,'performance',{value:{now:()=>local},configurable:true});
  async function simulate(preincremented){
   source.abortProtectedRequests();const epoch=source.getProtectedRequestEpoch(),key='invented-health-device-session';local=0;let server=0,samples=0;
   const page={evaluate:async read=>{samples++;return read();}};
   const accept=()=>assert.equal(source.acceptWindowsHealthClock(key,epoch,at(server),0),true);
   accept();
   // The previous inventory remount is followed by 6s before Health. Its 15s
   // poll next runs 9s into the unchanged 121s contact-aging interval.
   for(local=9000;local<=121000;local+=15000){server=preincremented?121000:Date.parse(await windowsFixtureResponseTime(page))-base;accept();}
   local=121000;server=preincremented?121000:Date.parse(await windowsFixtureResponseTime(page))-base;accept();
   // Preserve the same device/session watermark through logs and the next
   // viewport: 15s polling +6s log expiry +500ms history +6s process +6s network.
   local+=33500;server=preincremented?local:Date.parse(await windowsFixtureResponseTime(page))-base;accept();
   const elapsed=source.windowsHealthElapsed(key,epoch,at(server),0),view=windowsBrowserFixture(at(server),'health-current'),device=windowsHealthBrowserDevice(at(server),'health-current');
   return {elapsed,samples,summary:source.windowsHealthSummary(device,{view,snapshot:view.snapshot,status:view.status,loading:false,error:null},elapsed,true)};
  }
  const broken=await simulate(true),fixed=await simulate(false);
  assert.equal(broken.elapsed,112000);assert.equal(broken.summary.reason,'available');assert.equal(broken.summary.contact,'recent');assert.equal(broken.summary.disk.state,'stale');assert.equal(broken.summary.disk.value,null);
  assert.equal(fixed.samples,10,'one bounded clock sample per modeled recognized response');assert.equal(fixed.elapsed,0);assert.equal(fixed.summary.reason,'available');assert.equal(fixed.summary.contact,'recent');assert.equal(fixed.summary.disk.state,'current');assert.equal(fixed.summary.disk.value,61);
 }finally{Object.defineProperty(Date,'now',originalDateNow);Object.defineProperty(globalThis,'performance',originalPerformance);}
});

test('only recognized synthetic GET responses sample the browser clock after request guards',async()=>{
 // Keep this deliberately interrupted setup's finite stage out of other source
 // tests that inspect the shared runner before its first actual browser case.
 const {windowsInventoryBrowserCase}=await import(new URL('./windows-inventory-browser.mjs?inert-clock-route-guards',import.meta.url).href);
 let handler,evaluations=0;
 const stop=new Error('inert setup complete'),base='http://fixture.invalid';
 const page={clock:{install:async()=>{},pauseAt:async()=>{}},route:async(_pattern,read)=>{handler=read;},evaluate:async()=>{evaluations++;return Date.parse(now);}};
 await assert.rejects(windowsInventoryBrowserCase({pageAt:async()=>page,login:async()=>{throw stop;},base}),error=>error===stop);
 const prefix='/api/devices/'+windowsHealthBrowserDevice(now).id;
 async function route(path,{method='GET',body=null,origin=base}={}){
  let result;
  await handler({request:()=>({url:()=>origin+path,method:()=>method,postData:()=>body}),abort:async reason=>{result={abort:reason};},continue:async()=>{result={continue:true};},fulfill:async value=>{result=value;}});
  return result;
 }
 assert.deepEqual(await route('/'),{continue:true});assert.deepEqual(await route('/api/auth/login',{method:'POST'}),{continue:true});
 assert.equal((await route(prefix+'/unrecognized')).status,404);assert.equal((await route(prefix,{method:'POST'})).abort,'blockedbyclient');assert.equal((await route(prefix,{origin:'https://outside.invalid'})).abort,'blockedbyclient');
 await assert.rejects(route(prefix+'/windows-inventory?unexpected=1'),/Unexpected Windows query/);await assert.rejects(route(prefix+'/windows-inventory',{body:'invented-body'}),/Unexpected Windows query/);
 assert.equal((await route(prefix+'/windows-contact?unexpected=1')).abort,'blockedbyclient');assert.equal((await route(prefix+'/windows-contact',{body:'invented-body'})).abort,'blockedbyclient');assert.equal(evaluations,0);
 const accepted=await route(prefix+'/windows-contact');assert.equal(accepted.status,200);assert.equal(JSON.parse(accepted.body).serverNow,now);assert.equal(evaluations,1);
});

test('an unusable synthetic browser clock never falls back to preadvanced host time',async()=>{
 for(const value of [NaN,Infinity,0,-1,1.5,undefined])await assert.rejects(windowsFixtureResponseTime({evaluate:async()=>value}),/Synthetic fixture clock unavailable/);
});
