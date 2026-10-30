import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import coordinates from './v3-browser-coordinates.json' with {type:'json'};
import {v3FailureCoordinates,v3Checkpoints} from './v3-browser-coordinates.mjs';
import {focusContrastStage} from './focus-contrast-browser.mjs';

const sha='a'.repeat(40), marker='PRIVATE_VALUE_MUST_NOT_ESCAPE';
const rows=()=>coordinates.cases.map(name=>({name,status:'PASS',durationMs:1}));
const input=(caseNumber=1,checkpoint=0)=>{
 const results=rows();results[caseNumber-1]={...results[caseNumber-1],status:'FAIL',stage:v3Checkpoints[checkpoint],error:marker};
 return {sourceSha:sha,results,setupFailure:false,runtimeErrorCount:0,stage:v3Checkpoints[0]};
};
const runner=await fs.readFile(new URL('./v3-mvp-browser.mjs',import.meta.url),'utf8');
const check=runner.slice(runner.indexOf('async function check(name,run)'),runner.indexOf('\ntry{',runner.indexOf('async function check(name,run)')));
const hook=runner.slice(runner.indexOf('if(!apiSmoke&&process.env.TRACEBOLT_V3_DIAGNOSTICS_PATH)'),runner.indexOf("\nawait fs.writeFile(path.join(out,apiSmoke?'v3-mvp-api-smoke.json'"));
const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;

test('registry exactly covers existing case and literal/helper/focus stage vocabulary',async()=>{
 assert.deepEqual([...runner.matchAll(/await check\('([^']+)'/g)].map(m=>m[1]),coordinates.cases);
 const diagnostic=await fs.readFile(new URL('./v3-failure-diagnostics.mjs',import.meta.url),'utf8');
 const expected=['setup',...[...runner.matchAll(/mark\('([^']+)'\)/g)].map(m=>m[1])];
 for(const [name,prefix] of [['freshSteps','fresh consent'],['mobileSteps','mobile socket']]){
  const text=diagnostic.match(new RegExp('const '+name+'=new Set\\((\\[[^\\]]+\\])\\)'))[1];
  expected.push(...[...text.matchAll(/'([^']+)'/g)].map(m=>`${prefix} / ${m[1]}`));
 }
 expected.push('v3 diagnostic / unknown','focus contrast unknown');
 assert.deepEqual([...new Set(expected)],coordinates.stages);
 const focus=await fs.readFile(new URL('./focus-contrast-browser.mjs',import.meta.url),'utf8');
 const phases=focus.match(/\|\| !(\['outline geometry read'.*?\])\.includes\(phase\)/)[1];
 assert.deepEqual([...phases.matchAll(/'([^']+)'/g)].map(m=>m[1]),coordinates.focus.phases);
 assert.equal(v3Checkpoints.length,995);assert.equal(new Set(v3Checkpoints).size,v3Checkpoints.length);
 for(const checkpoint of v3Checkpoints.slice(coordinates.stages.length))assert.notEqual(checkpoint,'focus contrast unknown');
});

test('all finite coordinates project numeric metadata only, with focus restricted to its actual case',()=>{
 for(let caseNumber=1;caseNumber<=coordinates.cases.length;caseNumber++)for(let checkpoint=0;checkpoint<v3Checkpoints.length;checkpoint++){
  const result=v3FailureCoordinates(input(caseNumber,checkpoint));
  if(checkpoint>=coordinates.stages.length&&caseNumber!==coordinates.focus.case){assert.equal(result,null);continue;}
  assert.deepEqual(result.failures,[{case:caseNumber,checkpoint}]);assert.equal(JSON.stringify(result).includes(marker),false);
 }
});

test('malformed, unknown, wrong-source-shaped and incomplete inputs stay withheld',()=>{
 for(const change of [{sourceSha:null},{sourceSha:'a'.repeat(40)+'\n'},{sourceSha:'A'.repeat(40)},{sourceSha:marker},
  {results:null},{results:rows().slice(1)},{results:[...rows(),rows()[0]]},{setupFailure:1},{runtimeErrorCount:NaN},
  {runtimeErrorCount:Infinity},{runtimeErrorCount:-1},{runtimeErrorCount:1.5},{runtimeErrorCount:true},{stage:marker}])assert.equal(v3FailureCoordinates({...input(),...change}),null);
 for(const change of [{name:marker},{status:marker},{stage:marker}]){const value=input();Object.assign(value.results[0],change);assert.equal(v3FailureCoordinates(value),null);}
 assert.equal(v3FailureCoordinates({...input(),results:rows()}),null);
 const source=input();source.sourceSha={toString(){throw Error(marker);}};assert.equal(v3FailureCoordinates(source),null);
});

test('setup/runtime flags are bounded and successful runs emit nothing',()=>{
 assert.deepEqual(v3FailureCoordinates({...input(),results:[],setupFailure:true,runtimeErrorCount:5}),{schemaVersion:'tracebolt.v3-browser-failure.v1',sourceSha:sha,failures:[],setupFailure:true,runtimeFailure:true,finalCheckpoint:0});
 assert.equal(v3FailureCoordinates({...input(),results:rows()}),null);
 assert.equal(v3FailureCoordinates({...input(),results:rows(),runtimeErrorCount:1}).runtimeFailure,true);
});

test('actual runner check retains failure, cleanup order and stage before the numeric projection',async()=>{
 const execute=new AsyncFunction('name','wantedStage','v3FailureCoordinates','sha','rows',`
  let results=[],stage='setup',currentTest='',failureSnapshot=null,failureEvents=null;
  const actions=[],mark=value=>{stage=value;},console={log(){}};
  let failureDiagnostics={dispose(){actions.push('dispose');}},context={async close(){actions.push('close');}};
  async function start(){actions.push('start');} async function stop(){actions.push('stop');}
  async function boundedFailure(){return '${marker}';}
  ${check}
  await check(name,async()=>{actions.push('run');mark(wantedStage);throw Error('${marker}');});
  return {results,actions,diagnostic:v3FailureCoordinates({sourceSha:sha,results:[...results,...rows().slice(1)],setupFailure:false,runtimeErrorCount:0,stage})};`);
 const result=await execute(coordinates.cases[0],coordinates.stages[5],v3FailureCoordinates,sha,rows);
 assert.equal(result.results[0].status,'FAIL');assert.equal(result.results[0].stage,coordinates.stages[5]);
 assert.deepEqual(result.actions,['start','run','dispose','close','stop']);assert.deepEqual(result.diagnostic.failures,[{case:1,checkpoint:5}]);
 assert.equal(JSON.stringify(result.diagnostic).includes(marker),false);
});

test('actual private writer is exclusive, mode-restricted, optional and best effort',async()=>{
 assert.ok(hook.startsWith('if('));
 const execute=new AsyncFunction('fs','process','apiSmoke','sourceSha','results','fatal','runtimeErrorCount','stage','v3FailureCoordinates',hook);
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'v3-coordinate-test-')),file=path.join(dir,'coordinates.json');
 const value=input();
 try{
  const invoke=(filesystem=fs,env={TRACEBOLT_V3_DIAGNOSTICS_PATH:file},api=false)=>execute(filesystem,{env},api,sha,value.results,false,0,value.stage,v3FailureCoordinates);
  await invoke();assert.equal((await fs.stat(file)).mode&0o777,0o600);assert.deepEqual(JSON.parse(await fs.readFile(file,'utf8')),v3FailureCoordinates(value));
  await fs.writeFile(file,marker);await invoke();assert.equal(await fs.readFile(file,'utf8'),marker);
  let calls=0;const failing={async writeFile(){calls++;throw Error(marker);}};
  await invoke(failing);assert.equal(calls,1);
  await invoke(failing,{});await invoke(failing,{TRACEBOLT_V3_DIAGNOSTICS_PATH:file},true);assert.equal(calls,1);
  await execute(failing,{env:{TRACEBOLT_V3_DIAGNOSTICS_PATH:file}},false,sha,rows(),false,0,value.stage,v3FailureCoordinates);assert.equal(calls,1);
 }finally{await fs.rm(dir,{recursive:true,force:true});}
});
