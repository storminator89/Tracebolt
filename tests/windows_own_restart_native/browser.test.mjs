/** Portable parser/production-validator tests. Never launches Chromium or a
 * manager/controller/service; fixture values cannot produce native artifacts. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { resolve,dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { SCHEMA,OMISSIONS,Refusal,strictJSON,canonical,nanos,filetimeNanos,advancing,sample,selectIdentity,validateCompletion,loadValidators,budget,hash } from './browser.mjs';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'../..');
const dependencies=process.env.TRACEBOLT_BROWSER_TEST_DEPENDENCIES||resolve(root,'web');
const rejects=fn=>assert.throws(fn,Refusal);
const creation='134361504000000001';
const sampleA=()=>({sequence:2,generationId:'sample_a',collectedAt:'2026-10-11T00:00:00Z',receivedAt:'2026-10-11T00:00:10Z'});
const sampleB=()=>({sequence:9,generationId:'sample_b',collectedAt:'2026-10-11T00:00:02Z',receivedAt:'2026-10-11T00:00:11Z'});
test('strict JSON rejects duplicate keys at every depth, trailing objects and nonfinite numbers',()=>{
 for(const s of ['{"x":1,"x":2}','{"a":{"x":1,"x":2}}','{}{}','{"x":NaN}','{"x":1e999}','[1,]','{"x":01}','"unterminated'])rejects(()=>strictJSON(s));
 assert.equal(strictJSON('{"x":1,"a":[true,null]}').x,1);assert.equal(canonical({z:'ü',a:1}),'{"a":1,"z":"\\u00fc"}\n');
});
test('UTC and FILETIME retain submicrosecond precision without float conversion',()=>{
 assert.equal(nanos('2026-10-11T00:00:00.0000001Z'),filetimeNanos(creation));
 assert.equal(nanos('2026-10-11T00:00:00.0000002Z')-filetimeNanos(creation),100n);
 for(const s of ['2026-02-30T00:00:00Z','2026-10-11T00:00:60Z','2026-10-11T00:00:00+00:00','2026-10-11T00:00:00.1234567891Z'])rejects(()=>nanos(s));
 rejects(()=>filetimeNanos(Number(creation)));rejects(()=>filetimeNanos('0'+creation));
});
test('two advancing reports require sequence/generation/capture/manager original receipt, allow legitimate gaps',()=>{
 const a=sampleA(),b=sampleB();assert.equal(advancing(a,b,creation),true);
 for(const k of Object.keys(a))assert.equal(advancing(a,{...b,[k]:a[k]},creation),false);
 assert.equal(advancing(a,{...b,receivedAt:'2026-10-11T00:00:09Z'},creation),false);
});
test('fixed one-second Windows chronology margin rejects edge and one nanosecond below',()=>{
 const a=sampleA(),b=sampleB();
 for(const t of ['2026-10-11T00:00:01.000000099Z','2026-10-11T00:00:01.0000001Z'])assert.equal(advancing(a,{...b,collectedAt:t},creation),false);
 assert.equal(advancing(a,{...b,collectedAt:'2026-10-11T00:00:01.000000101Z'},creation),true);
});
test('expired real-clock budget fails closed',()=>rejects(budget(Math.floor(Date.now()/1000)-1)));
test('finite public completion rejects copied plan, missing checks, extra keys or fabricated full acceptance',()=>{
 const selected={deviceId:'agent_'+'ab'.repeat(16),certificateSHA256:hash('cert')};const p={runId:'portable-run-001',sources:{harness:hash('source')},selected,artifacts:{service:{sha256:hash('service')},controller:{sha256:hash('controller')}}};const s={plan:p,planSHA256:hash('plan'),bindingSHA256:hash('binding')},baseline=hash('baseline');
 const native={schema:'tracebolt.windows-own-restart-controller-result.v1',runId:p.runId,planSHA256:s.planSHA256,browserBaselineSHA256:baseline,status:'passed-native-subset',phase:'complete',fullAcceptance:false,installerContentionRefused:true,oldProcessExited:true,newRunningProcess:true,receiptPublicIdentityRetained:true,commandInvocations:2,oldExitCode:0,newProcessCreationFiletime:creation,newProcessCreationUTC:'2026-10-11T00:00:00.0000001Z',oldProcessGenerationSHA256:hash('old'),newProcessGenerationSHA256:hash('new'),deviceId:selected.deviceId,certificateSHA256:selected.certificateSHA256,installedSHA256:p.artifacts.service.sha256,controllerSHA256:p.artifacts.controller.sha256,windowStartFiletime:'134361504000000000',windowEndFiletime:'134361504100000000'};
 const c={schema:SCHEMA+'.completion',runId:p.runId,planSHA256:s.planSHA256,sources:p.sources,bindingSHA256:s.bindingSHA256,browserBaselineSHA256:baseline,native,fullAcceptance:false,omissions:OMISSIONS};validateCompletion(c,s,baseline);
 for(const key of ['installerContentionRefused','oldProcessExited','newRunningProcess','receiptPublicIdentityRetained'])rejects(()=>validateCompletion({...c,native:{...native,[key]:false}},s,baseline));
 for(const patch of [{fullAcceptance:true},{planSHA256:hash('other')},{manualPass:true}])rejects(()=>validateCompletion({...c,...patch},s,baseline));
 rejects(()=>validateCompletion({...c,native:{...native,newProcessCreationFiletime:'134361504000000002'}},s,baseline));
});
test('selected activated identity must retain exact certificate, invitation, issuer and validity',()=>{
 const p={selected:{deviceId:'agent_'+'ab'.repeat(16),certificateSHA256:hash('cert'),invitationIdSHA256:hash('invite')},tls:{managerInstanceId:'manager_123',operatorOrigin:'https://manager.test:8443',issuerFingerprint:hash('issuer')}};
 const now=Date.now(),r={state:'activated',approval:{deviceID:p.selected.deviceId},intent:{deviceID:p.selected.deviceId,notBefore:Math.floor(now/1000)-1,notAfter:Math.floor(now/1000)+10},issuance:{certificateHash:p.selected.certificateSHA256},invitationID:'invite',binding:{instanceID:p.tls.managerInstanceId,origin:p.tls.operatorOrigin,profile:'tls',collectionProfile:'windows-inventory-v1',issuerFingerprint:p.tls.issuerFingerprint}};
 const list={enabled:true,serverNow:new Date(now).toISOString(),items:[r]},validators={validEnrollmentList:()=>true};selectIdentity(list,p,validators,now);
 for(const state of ['created','revoked','expired'])rejects(()=>selectIdentity({...list,items:[{...r,state}]},p,validators,now));
 rejects(()=>selectIdentity({...list,items:[r,r]},p,validators,now));rejects(()=>selectIdentity({...list,items:[{...r,issuance:{certificateHash:hash('new')}}]},p,validators,now));
});
test('production Windows inventory validator sees complete bounded DTO before projection',async t=>{
 if(!existsSync(resolve(dependencies,'node_modules/esbuild'))){t.skip('locked web dependencies not present; source test only');return;}
 const validators=await loadValidators(root,dependencies);
 const section=rows=>({source:'Portable test only',scope:'Portable test only',quality:'healthy',observedCount:rows.length,countExact:true,complete:true,truncated:false,rows});
 const snapshot={schemaVersion:'tracebolt.windows-inventory.v1',collectionProfile:'windows-inventory-v1',generationId:'sample_'+'ab'.repeat(16),collectedAt:'2026-10-11T00:00:00Z',hostname:section([{value:'fixture'}]),processes:section([]),services:section([]),software:section([]),network:section([])};
 const view={schemaVersion:'tracebolt.windows-inventory-view.v1',collectionProfile:'windows-inventory-v1',deviceId:'agent_'+'12'.repeat(16),serverNow:'2026-10-11T00:00:10Z',maxAgeSeconds:120,status:'fresh',sequence:3,receivedAt:'2026-10-11T00:00:01Z',snapshot};
 const p={selected:{deviceId:view.deviceId,grantIds:{}}},now=Date.parse(view.serverNow);assert.equal(sample(view,p,validators,now).sequence,3);
 for(const patch of [{status:'stale'},{sequence:0},{receivedAt:'2026-10-10T23:00:00Z'},{snapshot:{...snapshot,unexpected:true}},{manualPass:true}])rejects(()=>sample({...view,...patch},p,validators,now));
 rejects(()=>sample(view,p,validators,now,120001));rejects(()=>sample(view,p,validators,now+31000));rejects(()=>sample(view,{selected:{...p.selected,grantIds:{events:'ab'.repeat(16)}}},validators,now));
});
test('native entry refuses CI=false, extra flags and malformed spec without browser launch',()=>{
 const script=fileURLToPath(new URL('./browser.mjs',import.meta.url));
 for(const args of [[],['--manual-pass']]){const r=spawnSync(process.execPath,[script,...args],{input:'{}\n',encoding:'utf8',env:{...process.env,CI:'false'},timeout:5000});assert.equal(r.status,2);assert.equal(r.stdout,'');}
});
test('source has no response routing, external-browser connection, fresh manager or manual success path',async()=>{
 const source=await readFile(new URL('./browser.mjs',import.meta.url),'utf8');
 for(const token of ['.route(','.fulfill(','.connectOverCDP(','.launchPersistentContext(','storageState:','ignoreHTTPSErrors:true','headless:true'])assert.equal(source.includes(token),false);
 assert.ok(source.includes('validWindowsInventoryView(view,p.selected.deviceId)'));assert.ok(source.includes("method:'GET'"));assert.ok(source.includes("cache:'no-store'"));assert.ok(source.includes('dashboardRendered:false'));
});

// Exercise the same private native coordinator body using an explicit source-only
// facade. Boundary IO is in-memory, outputs have rejected fixture schemas, and
// the private native-execution token is unavailable to tests or plan inputs.
import { observeSourceOnly,rejectCI } from './browser.mjs';
function sourceCase(mode,validators){
 const now=Date.now(),iso=n=>new Date(n).toISOString(),deviceId='agent_'+'12'.repeat(16);
 const p={runId:'source-only-run-001',notBeforeUnix:Math.floor(now/1000)-10,expiresUnix:Math.floor(now/1000)+60,sources:{harness:{commit:hash('source')}},targets:{linux:{workspace:'/never-written'}},selected:{deviceId,certificateSHA256:hash('certificate'),invitationIdSHA256:hash('invite_'+'34'.repeat(16)),grantIds:{}},tls:{operatorOrigin:'https://manager.test:8443',managerInstanceId:'manager_'+'56'.repeat(16),issuerFingerprint:hash('issuer')},artifacts:{chromium:{path:'/never-launched'},service:{sha256:hash('service')},controller:{sha256:hash('controller')}},handoff:{linuxCompletion:'/never-read'}};
 const spec={plan:p,planSHA256:hash('plan'),bindingSHA256:hash('binding'),baselinePath:'/never-written/baseline',resultPath:'/never-written/result'};
 if(mode==='spoof-token'){spec.nativeToken=Symbol('real pinned native observer');spec.nativeExecution=true;spec.schema=SCHEMA+'.browser-spec';}
 let baselineRecord,baselineHash,completionRaw,inv=0,enrollment=0,closes=0,guardCalls=0;
 const section=rows=>({source:'Source-only injected fixture',scope:'Source-only test',quality:'healthy',observedCount:rows.length,countExact:true,complete:true,truncated:false,rows});
 const view=index=>({schemaVersion:'tracebolt.windows-inventory-view.v1',collectionProfile:'windows-inventory-v1',deviceId,serverNow:iso(now),maxAgeSeconds:120,status:'fresh',sequence:[1,1,3,8][Math.min(index,3)],receivedAt:iso(now-[9000,9000,2500,1500][Math.min(index,3)]),snapshot:{schemaVersion:'tracebolt.windows-inventory.v1',collectionProfile:'windows-inventory-v1',generationId:'sample_'+['ab','ab','cd','ef'][Math.min(index,3)].repeat(16),collectedAt:iso(now-[10000,10000,3000,2000][Math.min(index,3)]),hostname:section([{value:'test-only'}]),processes:section([]),services:section([]),software:section([]),network:section([])}});
 const row={version:'tracebolt.enrollment-state.v2',invitationID:'invite_'+'34'.repeat(16),createRequestID:'request_test',platform:'windows',revision:4,state:'activated',createdAt:Math.floor(now/1000)-1000,deadlineAt:Math.floor(now/1000)+100,updatedAt:Math.floor(now/1000)-100,binding:{instanceID:p.tls.managerInstanceId,origin:p.tls.operatorOrigin,profile:'tls',collectionProfile:'windows-inventory-v1',issuerFingerprint:p.tls.issuerFingerprint},claim:{claimID:'test',keyFingerprint:hash('key'),comparisonCode:'ab'.repeat(16)},approval:{deviceID:deviceId},intent:{deviceID:deviceId,notBefore:Math.floor(now/1000)-100,notAfter:Math.floor(now/1000)+100},issuance:{certificateHash:p.selected.certificateSHA256},activation:{},termination:{}};
 const list={schemaVersion:'tracebolt.enrollment-operator.v2',enabled:true,serverNow:iso(now),platforms:['windows'],recordLimit:25,collectionProfile:'windows-inventory-v1',collectionPrivacy:'windows_inventory_metadata_may_be_sensitive',items:[row]};
 const page={isClosed:()=>false,url:()=>p.tls.operatorOrigin+'/#/devices',on(){},setDefaultTimeout(){},setDefaultNavigationTimeout(){},async goto(){},async evaluate(_fn,{path}){
  if(path==='/api/windows/enrollment'){enrollment++;if(enrollment===1)return {status:401,raw:''};if(mode==='session-loss'&&baselineRecord)return {status:401,raw:''};return {status:200,raw:JSON.stringify(list)};}
  let index=inv++;if(mode==='duplicate'&&index>0)index=0;const v=view(index);
  if(mode==='stale'&&inv>1)v.status='stale';if(mode==='grant-change'&&inv>1)p.selected.grantIds={events:'ab'.repeat(16)};
  return {status:200,raw:JSON.stringify(v)};
 }};
 const chromium={async launch(){return {async newContext(){return {async newPage(){return page;},on(){}};},async close(){closes++;if(mode==='cleanup-failure')throw new Error('injected');}};}};
 function boundary(){
  const ticks=n=>(BigInt(n)*10000n+116444736000000000n).toString();const made=now-5000;
  const native={schema:'tracebolt.windows-own-restart-controller-result.v1',runId:p.runId,planSHA256:spec.planSHA256,browserBaselineSHA256:baselineHash,status:'passed-native-subset',phase:'complete',fullAcceptance:false,installerContentionRefused:true,oldProcessExited:true,newRunningProcess:true,receiptPublicIdentityRetained:true,commandInvocations:2,oldExitCode:0,newProcessCreationFiletime:ticks(made),newProcessCreationUTC:iso(made),oldProcessGenerationSHA256:hash('old'),newProcessGenerationSHA256:hash('new'),deviceId,certificateSHA256:p.selected.certificateSHA256,installedSHA256:p.artifacts.service.sha256,controllerSHA256:p.artifacts.controller.sha256,windowStartFiletime:ticks(made-1),windowEndFiletime:ticks(made+1)};
  const c={schema:SCHEMA+'.completion',runId:p.runId,planSHA256:spec.planSHA256,sources:p.sources,bindingSHA256:spec.bindingSHA256,browserBaselineSHA256:baselineHash,native,fullAcceptance:false,omissions:OMISSIONS};
  if(mode==='manual-completion')c.manualPass=true;if(mode==='copied-baseline')c.browserBaselineSHA256=hash('other-baseline');return Buffer.from(canonical(c));
 }
 const io={async writeNew(_path,record){baselineRecord=record;baselineHash=hash(canonical(record));return baselineHash;},async privateRead(){return completionRaw;},async managerGuard(){guardCalls++;if((mode==='deadline'||mode==='duplicate')&&inv>2)throw new Refusal('deadline');},async pause(){},emit(){}};
 const getDigest=()=>{completionRaw=boundary();return hash(completionRaw);};
 return {async run(){return observeSourceOnly(spec,validators,chromium,getDigest,()=>false,io,Symbol('real pinned native observer'));},get baseline(){return baselineRecord;},get closes(){return closes;},get reads(){return inv;}};
}
test('actual coordinator source-only flow: human login, independent baseline, duplicate ignored, two advancing samples and cleanup',async t=>{
 if(!existsSync(resolve(dependencies,'node_modules/esbuild'))){t.skip('locked production validator dependencies absent');return;}
 const c=sourceCase('success',await loadValidators(root,dependencies)),report=await c.run();
 assert.equal(report.status,'source-only');assert.equal(report.schema,SCHEMA+'.source-only-browser-result');assert.equal(report.nativeExecution,false);assert.equal(report.fullAcceptance,false);assert.equal(report.samples.length,3);assert.deepEqual(report.samples.map(s=>s.sequence),[1,3,8]);assert.equal(c.reads,4);assert.equal(c.closes,1);assert.equal(c.baseline.schema,SCHEMA+'.source-only-baseline');assert.equal(report.checks.twoAdvancingSamples,true);assert.equal(report.checks.browserClosed,true);
 const spoof=sourceCase('spoof-token',await loadValidators(root,dependencies)),spoofReport=await spoof.run();assert.equal(spoofReport.nativeExecution,false);assert.equal(spoofReport.schema,SCHEMA+'.source-only-browser-result');assert.equal(spoof.baseline.schema,SCHEMA+'.source-only-baseline');
});
test('actual coordinator source-only flow rejects session loss, deadline, stale/grant change, copied/manual completion and missing cleanup',async t=>{
 if(!existsSync(resolve(dependencies,'node_modules/esbuild'))){t.skip('locked production validator dependencies absent');return;}
 const validators=await loadValidators(root,dependencies);
 for(const mode of ['session-loss','deadline','duplicate','stale','grant-change','manual-completion','copied-baseline','cleanup-failure']){
  const c=sourceCase(mode,validators),report=await c.run();assert.equal(report.status,'unknown',mode);assert.equal(report.nativeExecution,false,mode);assert.equal(report.schema,SCHEMA+'.source-only-browser-result',mode);assert.equal(c.closes,1,mode);assert.notEqual(report.reason,'complete',mode);
 }
});
test('every native CI marker is case-insensitive presence-based, including false/empty',()=>{
 for(const key of ['CI','ci','CONTINUOUS_INTEGRATION','BUILD_BUILDID','TF_BUILD','TEAMCITY_VERSION','JENKINS_URL','HUDSON_URL','GITHUB_ACTIONS','GITLAB_CI','CIRCLE_CI','BUILDKITE_JOB','TRAVIS_JOB','RUNNER_OS'])for(const value of ['false','', '0'])rejects(()=>rejectCI({[key]:value}));
 rejectCI({PATH:'/usr/bin'});
});
