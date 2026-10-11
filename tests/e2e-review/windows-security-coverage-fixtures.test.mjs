import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {windowsSecurityCoverageBrowserFixture,requireWindowsSecurityCoverageEvidence,windowsSecurityCoverageDisclosure} from './windows-security-coverage-browser.mjs';
const serverNow='2026-10-07T12:00:10Z',capturedAt='2026-10-07T12:00:00Z';
test('security coverage fixtures keep source quality, original time and unknowns independent',()=>{
 assert.match(windowsSecurityCoverageDisclosure,/UI-only fixture evidence/);
 for(const phase of ['observed','empty','not-found','unsupported-antivirus','denied-tpm','partial','bounded','unknown-only']){
  const view=windowsSecurityCoverageBrowserFixture({serverNow,capturedAt,phase}),s=view.securityCoverage;
  assert.equal(s.collectedAt,capturedAt);assert.equal(s.generationId,view.snapshot.generationId);assert.equal(view.securityPosture.defender.mode,'normal');assert.notEqual(s.grantId,view.securityPosture.grantId);
  if(phase==='empty'){assert.equal(s.antivirus.reportedCount,0);assert.equal(s.antivirus.quality,'observed');}
  if(phase==='not-found'){assert.equal(s.tpm.presence,'not-found');assert.equal(s.tpm.version,'unknown');}
  if(phase==='unsupported-antivirus'){assert.equal(s.antivirus.reportedCount,null);assert.equal(s.antivirus.reason,'windows_security_coverage_unsupported_platform');assert.equal(s.tpm.presence,'present');}
  if(phase==='denied-tpm'){assert.equal(s.tpm.quality,'denied');assert.equal(s.tpm.presence,'unknown');assert.equal(s.antivirus.rows.length,2);}
  if(phase==='bounded'){assert.equal(s.antivirus.reportedCount,40);assert.equal(s.antivirus.truncated,true);assert.equal(s.antivirus.rows.length,2);}
  if(phase==='unknown-only'){assert.equal(s.antivirus.rows[0].name,null);assert.equal(s.antivirus.rows[0].state,'unknown');assert.equal(s.tpm.presence,'unknown');}
 }
 for(const phase of ['legacy','revoked','unavailable-view'])assert.equal(windowsSecurityCoverageBrowserFixture({serverNow,capturedAt,phase}).securityCoverage,undefined);
 const expired=windowsSecurityCoverageBrowserFixture({serverNow:'2026-10-08T12:00:00Z',capturedAt});assert.equal(expired.securityCoverage,undefined);assert.equal(expired.status,'unavailable');
 const stale=windowsSecurityCoverageBrowserFixture({serverNow:'2026-10-07T12:05:00Z',capturedAt});assert.equal(stale.securityCoverage.collectedAt,capturedAt);assert.equal(stale.status,'stale');
});
test('retained coverage does not erase current failure or renew source time',()=>{
 const retainedCapturedAt='2026-10-07T11:00:00Z',fixture=at=>windowsSecurityCoverageBrowserFixture({serverNow:at,capturedAt,phase:'retained',retainedCapturedAt}),view=fixture(serverNow),old=view.retainedContext.securityCoverage;
 assert.equal(view.securityCoverage.antivirus.quality,'unavailable');assert.equal(view.securityCoverage.tpm.quality,'unavailable');assert.equal(old.collectedAt,retainedCapturedAt);assert.equal(old.grantId,view.securityCoverage.grantId);assert.notEqual(old.generationId,view.securityCoverage.generationId);
 assert.deepEqual(fixture('2026-10-07T12:01:00Z').retainedContext,view.retainedContext);assert.ok(fixture('2026-10-08T10:59:59Z').retainedContext);assert.equal(fixture('2026-10-08T11:00:00Z').retainedContext,undefined);
 for(const value of [undefined,'invalid',capturedAt,'2026-10-07T12:00:01Z'])assert.throws(()=>windowsSecurityCoverageBrowserFixture({serverNow,capturedAt,phase:'retained',retainedCapturedAt:value}),/Invalid synthetic/);
});
test('shared stage and route initialize coverage capture before retained reads in every walkthrough',async()=>{
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
    const display=Object.keys(exports).filter(name=>(name.startsWith('exercise')||name==='windowsLogsBrowserCase')&&!file.endsWith('/windows-security-coverage-browser.mjs'));
    return {contents:`export * from ${JSON.stringify(url)};\n${display.map(name=>`export async function ${name}(){}`).join('\n')}`,loader:'js'};
   });
  },
 }]});
 const {windowsInventoryBrowserCase,windowsInventoryFailureStage}=await import('data:text/javascript;base64,'+Buffer.from(built.outputFiles[0].text+'\n//# sourceURL=windows-security-coverage-shared-case.mjs\n').toString('base64'));
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
   const stage=windowsInventoryFailureStage();if(!stage.startsWith('security-coverage'))return;
   const first=await read(),capture=first.securityCoverage.collectedAt;
   reads.push({stage,locale,width,view:first});
   if(stage!=='security-coverage-retained')return;
   const old=first.retainedContext.securityCoverage,at=clock;
   assert.equal(Date.parse(capture)-Date.parse(old.collectedAt),3600000);
   assert.equal(first.securityCoverage.antivirus.reason,'windows_security_coverage_budget_exhausted');assert.equal(first.securityCoverage.tpm.reason,'windows_security_coverage_budget_exhausted');
   assert.equal(old.antivirus.rows[0].name,'Example Antivirus');assert.equal(old.tpm.version,'2.0');
   try{
    // Rereads age the response only; the original retained expiry still wins.
    for(const next of [at+60000,Date.parse(old.collectedAt)+86400000-1]){clock=next;const repeat=await read();assert.equal(repeat.securityCoverage.collectedAt,capture);assert.deepEqual(repeat.retainedContext,first.retainedContext);}
    clock=Date.parse(old.collectedAt)+86400000;const expired=await read();assert.equal(expired.retainedContext,undefined);assert.equal(expired.securityCoverage.collectedAt,capture);assert.equal(expired.securityCoverage.antivirus.quality,'unavailable');
   }finally{clock=at;}
  },
 });
 const page={...locator(),route:async(_,handler)=>{routeHandler=handler;},goto:async()=>{},setViewportSize:async value=>{width=value.width;},evaluate:async()=>clock,keyboard:{press:async()=>{}},clock:{install:async({time})=>{clock=+time;},pauseAt:async time=>{clock=+time;},runFor:async ms=>{clock+=ms;}},request:{get:async()=>({status:()=>200,json:async()=>({authenticated:true,serverNow:new Date(clock).toISOString(),expiresAt:new Date(clock+1200000).toISOString()}),dispose:async()=>{}})}};
 const matchers=new Proxy({},{get:(_,key)=>key==='not'?matchers:key==='toHaveAttribute'?(name,value)=>{if(name==='datetime'&&windowsInventoryFailureStage()==='security-coverage-retained')displayTimes.push(value);}:()=>{}});
 const expect=()=>matchers;expect.poll=callback=>({toBe:async()=>{await callback();}});
 await windowsInventoryBrowserCase({base,pageAt:async pathname=>{inventoryPath='/api'+pathname+'/windows-inventory';return page;},login:async()=>{},expect,shot:async()=>{}});
 const stages=['security-coverage','security-coverage-unsupported-antivirus','security-coverage-denied-tpm','security-coverage-not-found','security-coverage-empty','security-coverage-bounded','security-coverage-retained'];
 assert.deepEqual(reads.map(({stage})=>stage),Array(4).fill(stages).flat());
 const retained=reads.filter(({stage})=>stage==='security-coverage-retained');
 assert.deepEqual(retained.map(({locale,width})=>[locale,width]),[['en',1440],['en',390],['de',1440],['de',390]]);
 assert.deepEqual(displayTimes,retained.flatMap(({view})=>[view.securityCoverage.collectedAt,view.retainedContext.securityCoverage.collectedAt]));
 for(let index=0;index<reads.length;index+=stages.length){const group=reads.slice(index,index+stages.length);assert.ok(group.every(({view})=>view.securityCoverage.collectedAt===group[0].view.securityCoverage.collectedAt));assert.equal(Date.parse(group[0].view.serverNow)-Date.parse(group[0].view.securityCoverage.collectedAt),2000);}
 assert.equal(new Set(retained.map(({view})=>view.retainedContext.securityCoverage.collectedAt)).size,4,'each walkthrough initializes its own coverage times');
});
test('coverage completion requires each source-bound EN/DE desktop/mobile screenshot',()=>{
 const source='a'.repeat(40),name='synthetic',rows=[];for(const kind of ['summary','details','current-failure','retained-details'])for(const locale of ['en','de'])for(const width of [1440,390])rows.push({file:`synthetic-windows-coverage-${kind}-${width}-${locale}.png`,sourceSha:source,test:name,locale,viewport:{width,height:width===390?844:1000},publicSafe:true,fullPage:false,fixtureDisclosure:windowsSecurityCoverageDisclosure});
 assert.deepEqual(requireWindowsSecurityCoverageEvidence(rows,source,name),{coverageSummary:4,coverageDetails:4,coverageCurrentFailure:4,coverageRetainedDetails:4});
 for(let index=0;index<rows.length;index++){
  assert.throws(()=>requireWindowsSecurityCoverageEvidence(rows.filter((_,i)=>i!==index),source,name));assert.throws(()=>requireWindowsSecurityCoverageEvidence([...rows,rows[index]],source,name));
  for(const change of [{sourceSha:'b'.repeat(40)},{test:'other'},{locale:'unsupported'},{viewport:{width:800,height:600}},{publicSafe:false},{fullPage:true},{fixtureDisclosure:'unverified'}])assert.throws(()=>requireWindowsSecurityCoverageEvidence(rows.map((row,i)=>i===index?{...row,...change}:row),source,name));
 }
});
test('shared case wires reviewed coverage assertions and gate without another browser or request',()=>{
 const flow=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8'),runner=fs.readFileSync(new URL('./lan-browser.mjs',import.meta.url),'utf8'),helper=fs.readFileSync(new URL('./windows-security-coverage-browser.mjs',import.meta.url),'utf8');
 assert.match(flow,/mark\('security-coverage'\);phase='security-coverage'/);assert.match(flow,/exerciseWindowsSecurityCoverage\(\{page,expect,locale,width,shot\}\)/);assert.match(flow,/exerciseWindowsSecurityCoverageState\(/);assert.match(flow,/exerciseWindowsSecurityCoverageRetained\(/);assert.match(runner,/requireWindowsSecurityCoverageEvidence\(screenshots,sourceSha,name\)/);
 assert.doesNotMatch(helper,/chromium\.launch|newContext\(|spawn\(|execFile|writeFile|ignoreHTTPSErrors|fetch\(|localStorage|sessionStorage|waitForTimeout|setDefaultTimeout|clock\.runFor/);
 const manifest=JSON.parse(fs.readFileSync(new URL('./inert-suites.json',import.meta.url),'utf8')),entry=fs.readFileSync(new URL('./windows-inventory-fixtures.test.mjs',import.meta.url),'utf8');assert.ok(manifest.imported.includes('windows-security-coverage-fixtures.test.mjs'));assert.match(entry,/import '\.\/windows-security-coverage-fixtures\.test\.mjs';/);
});
