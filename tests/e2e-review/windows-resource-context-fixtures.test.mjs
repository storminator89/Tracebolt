import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {windowsResourceContextBrowserFixture,requireWindowsResourceContextEvidence,windowsResourceContextDisclosure} from './windows-resource-context-browser.mjs';
const serverNow='2026-10-07T12:00:10Z',capturedAt='2026-10-07T12:00:00Z';
test('resource cross-language fixture is the exact native canonical encoder artifact',()=>{
 assert.deepEqual(fs.readFileSync(new URL('../../web/src/windows-resource-context-go-fixture.json',import.meta.url)),fs.readFileSync(new URL('../../internal/windowsresourcecontext/testdata/snapshot.json',import.meta.url)));
});
test('resource fixtures preserve source truth, exact bytes and absent pagefiles',()=>{
 for(const phase of ['observed','no-pagefiles','denied-installed','unavailable-memory','partial-cpu','large-bytes']){
  const view=windowsResourceContextBrowserFixture({serverNow,capturedAt,phase}),s=view.resourceContext;
  assert.equal(s.collectedAt,capturedAt);assert.equal(s.generationId,view.snapshot.generationId);assert.equal(s.processors.rows[0].name.value,'Fixture CPU 12-Core');
  if(phase==='no-pagefiles'){assert.equal(s.pagefiles.count,0);assert.equal(s.pagefiles.totalBytes,'0');}
  if(phase==='denied-installed'){assert.equal(s.installedMemory.quality,'denied');assert.equal(s.memory.physicalTotalBytes,'33285996544');}
  if(phase==='unavailable-memory'){assert.equal(s.memory.commitTotalBytes,null);assert.equal(s.installedMemory.installedBytes,'34359738368');}
  if(phase==='partial-cpu'){assert.equal(s.processors.totalCores,null);assert.equal(s.processors.totalLogicalProcessors,null);}
  if(phase==='large-bytes'){assert.equal(s.pagefiles.totalBytes,'18446744073709551615');assert.equal(s.pagefiles.totalInUseBytes,'9007199254740993');}
 }
 for(const phase of ['legacy','revoked','unavailable-view'])assert.equal(windowsResourceContextBrowserFixture({serverNow,capturedAt,phase}).resourceContext,undefined);
 assert.equal(windowsResourceContextBrowserFixture({serverNow:'2026-10-08T12:00:00Z',capturedAt}).resourceContext,undefined);
});
test('resource retained fixtures keep original age and latest independent failure',()=>{
 const retainedCapturedAt='2026-10-07T11:00:00Z',fixture=at=>windowsResourceContextBrowserFixture({serverNow:at,capturedAt,phase:'retained',retainedCapturedAt});
 const view=fixture(serverNow),s=view.resourceContext,old=view.retainedContext.resourceContext;
 for(const key of ['processors','installedMemory','memory','pagefiles'])assert.equal(s[key].quality,'unavailable');
 assert.equal(old.collectedAt,retainedCapturedAt);assert.equal(s.collectedAt,capturedAt);assert.equal(old.grantId,s.grantId);assert.notEqual(old.generationId,s.generationId);
 assert.deepEqual(fixture('2026-10-07T12:01:00Z').retainedContext,view.retainedContext);assert.ok(fixture('2026-10-08T10:59:59Z').retainedContext);assert.equal(fixture('2026-10-08T11:00:00Z').retainedContext,undefined);
 for(const invalid of [undefined,'invalid',capturedAt,'2026-10-07T12:00:01Z'])assert.throws(()=>windowsResourceContextBrowserFixture({serverNow,capturedAt,phase:'retained',retainedCapturedAt:invalid}),/Invalid synthetic/);
});
test('shared stage and route initialize resource capture before retained reads in every walkthrough',async()=>{
 // Execute the real shared case and route, with inert page plumbing. Unrelated
 // display helpers and DOM matchers are stubs, not browser acceptance evidence.
 const entry=new URL('./windows-inventory-browser.mjs',import.meta.url),require=createRequire(new URL('../../web/package.json',import.meta.url));
 const {build}=require('esbuild');
 const built=await build({entryPoints:[fileURLToPath(entry)],bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent',define:{'import.meta.url':JSON.stringify(entry.href)},plugins:[{
  name:'inert-display-helpers',setup(builder){
   builder.onResolve({filter:/^\.\/.*-browser\.mjs$/},args=>({path:path.resolve(args.resolveDir,args.path),namespace:'inert-display'}));
   builder.onResolve({filter:/^file:/},args=>({path:args.path,external:true}));
   builder.onLoad({filter:/.*/,namespace:'inert-display'},async({path:file})=>{
    const url=pathToFileURL(file).href,exports=await import(url);
    const display=Object.keys(exports).filter(name=>(name.startsWith('exercise')||name==='windowsLogsBrowserCase')&&!file.endsWith('/windows-resource-context-browser.mjs'));
    return {contents:`export * from ${JSON.stringify(url)};\n${display.map(name=>`export async function ${name}(){}`).join('\n')}`,loader:'js'};
   });
  },
 }]});
 const {windowsInventoryBrowserCase,windowsInventoryFailureStage}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text+'\n//# sourceURL=windows-resource-context-shared-case.mjs\n').toString('base64'));
 const base='http://127.0.0.1:19886',reads=[],displayTimes=[];let routeHandler,inventoryPath,clock,locale,width;
 const read=async()=>{
  let result;
  await routeHandler({request:()=>({url:()=>base+inventoryPath,method:()=>'GET',postData:()=>null}),fulfill:async response=>{assert.equal(response.status,200);result=JSON.parse(response.body);},abort:()=>assert.fail('Unexpected abort'),continue:()=>assert.fail('Unexpected real request')});
  assert.ok(result);return result;
 };
 const locator=(role,name)=>({
  getByRole:(role,options={})=>locator(role,options.name),getByText:()=>locator(),getByLabel:()=>locator(),locator:()=>locator(),filter:()=>locator(),first:()=>locator(),nth:()=>locator(),all:async()=>[locator(),locator()],count:async()=>3,
  evaluate:async()=>({content:'',display:'',visibility:''}),scrollIntoViewIfNeeded:async()=>{},check:async()=>{},focus:async()=>{},fill:async()=>{},
  selectOption:async value=>{if(value==='en'||value==='de')locale=value;},
  click:async()=>{
   if(role!=='button'||!['Refresh Windows inventory','Windows-Inventar aktualisieren'].includes(name))return;
   const stage=windowsInventoryFailureStage();if(!stage.startsWith('resource-context'))return;
   const first=await read(),capture=first.resourceContext.collectedAt;
   reads.push({stage,locale,width,view:first});
   if(stage!=='resource-context-retained')return;
   const old=first.retainedContext.resourceContext,at=clock;
   assert.equal(Date.parse(capture)-Date.parse(old.collectedAt),3600000);
   for(const key of ['processors','installedMemory','memory','pagefiles'])assert.equal(first.resourceContext[key].reason,'windows_resource_context_budget_exhausted');
   assert.equal(old.processors.rows[0].name.value,'Fixture CPU 12-Core');assert.equal(old.memory.commitLimitBytes,'42949672960');
   try{
    // Rereads age the response only; the original retained expiry still wins.
    for(const next of [at+60000,Date.parse(old.collectedAt)+86400000-1]){clock=next;const repeat=await read();assert.equal(repeat.resourceContext.collectedAt,capture);assert.deepEqual(repeat.retainedContext,first.retainedContext);}
    clock=Date.parse(old.collectedAt)+86400000;const expired=await read();assert.equal(expired.retainedContext,undefined);assert.equal(expired.resourceContext.collectedAt,capture);assert.equal(expired.resourceContext.memory.quality,'unavailable');
   }finally{clock=at;}
  },
 });
 const page={...locator(),route:async(_,handler)=>{routeHandler=handler;},goto:async()=>{},setViewportSize:async value=>{width=value.width;},evaluate:async()=>clock,keyboard:{press:async()=>{}},clock:{install:async({time})=>{clock=+time;},pauseAt:async time=>{clock=+time;},runFor:async ms=>{clock+=ms;}},request:{get:async()=>({status:()=>200,json:async()=>({authenticated:true,serverNow:new Date(clock).toISOString(),expiresAt:new Date(clock+1200000).toISOString()}),dispose:async()=>{}})}};
 const matchers=new Proxy({},{get:(_,key)=>key==='not'?matchers:key==='toHaveAttribute'?(name,value)=>{if(name==='datetime'&&windowsInventoryFailureStage()==='resource-context-retained')displayTimes.push(value);}:()=>{}});
 const expect=()=>matchers;expect.poll=callback=>({toBe:async()=>{await callback();}});
 await windowsInventoryBrowserCase({base,pageAt:async pathname=>{inventoryPath='/api'+pathname+'/windows-inventory';return page;},login:async()=>{},expect,shot:async()=>{}});
 const stages=['resource-context','resource-context-no-pagefiles','resource-context-denied-installed','resource-context-unavailable-memory','resource-context-partial-cpu','resource-context-large-bytes','resource-context-retained'];
 assert.deepEqual(reads.map(({stage})=>stage),Array(4).fill(stages).flat());
 const retained=reads.filter(({stage})=>stage==='resource-context-retained');
 assert.deepEqual(retained.map(({locale,width})=>[locale,width]),[['en',1440],['en',390],['de',1440],['de',390]]);
 assert.deepEqual(displayTimes,retained.flatMap(({view})=>[view.resourceContext.collectedAt,view.retainedContext.resourceContext.collectedAt]));
 for(let index=0;index<reads.length;index+=stages.length){const group=reads.slice(index,index+stages.length);assert.ok(group.every(({view})=>view.resourceContext.collectedAt===group[0].view.resourceContext.collectedAt));assert.equal(Date.parse(group[0].view.serverNow)-Date.parse(group[0].view.resourceContext.collectedAt),2000);}
 assert.equal(new Set(retained.map(({view})=>view.retainedContext.resourceContext.collectedAt)).size,4,'each walkthrough initializes its own resource times');
});
test('resource completion requires each source-bound EN/DE desktop/mobile screenshot',()=>{
 const source='a'.repeat(40),name='synthetic',rows=[];for(const kind of ['summary','details','current-failure','retained-details'])for(const locale of ['en','de'])for(const width of [1440,390])rows.push({file:`synthetic-windows-resource-context-${kind}-${width}-${locale}.png`,sourceSha:source,test:name,locale,viewport:{width,height:width===390?844:1000},publicSafe:true,fullPage:false,fixtureDisclosure:windowsResourceContextDisclosure});
 assert.deepEqual(requireWindowsResourceContextEvidence(rows,source,name),{resourceSummary:4,resourceDetails:4,resourceCurrentFailure:4,resourceRetainedDetails:4});
 for(let index=0;index<rows.length;index++){
  assert.throws(()=>requireWindowsResourceContextEvidence(rows.filter((_,i)=>i!==index),source,name));assert.throws(()=>requireWindowsResourceContextEvidence([...rows,rows[index]],source,name));
  for(const change of [{sourceSha:'b'.repeat(40)},{test:'other'},{locale:'unsupported'},{viewport:{width:800,height:600}},{publicSafe:false},{fullPage:true},{fixtureDisclosure:'unverified'}])assert.throws(()=>requireWindowsResourceContextEvidence(rows.map((row,i)=>i===index?{...row,...change}:row),source,name));
 }
});
test('shared case wires reviewed resource assertions and gate without another browser or request',()=>{
 const flow=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8'),runner=fs.readFileSync(new URL('./lan-browser.mjs',import.meta.url),'utf8'),helper=fs.readFileSync(new URL('./windows-resource-context-browser.mjs',import.meta.url),'utf8');
 assert.match(flow,/mark\('resource-context'\);phase='resource-context'/);assert.match(flow,/exerciseWindowsResourceContext\(\{page,expect,locale,width,shot\}\)/);assert.match(flow,/exerciseWindowsResourceContextState\(/);assert.match(flow,/exerciseWindowsResourceRetainedContext\(/);assert.match(runner,/requireWindowsResourceContextEvidence\(screenshots,sourceSha,name\)/);
 assert.doesNotMatch(helper,/chromium\.launch|newContext\(|spawn\(|execFile|writeFile|ignoreHTTPSErrors|fetch\(|localStorage|sessionStorage|waitForTimeout|setDefaultTimeout|clock\.runFor/);
 const manifest=JSON.parse(fs.readFileSync(new URL('./inert-suites.json',import.meta.url),'utf8')),entry=fs.readFileSync(new URL('./windows-inventory-fixtures.test.mjs',import.meta.url),'utf8');assert.ok(manifest.imported.includes('windows-resource-context-fixtures.test.mjs'));assert.match(entry,/import '\.\/windows-resource-context-fixtures\.test\.mjs';/);
});
