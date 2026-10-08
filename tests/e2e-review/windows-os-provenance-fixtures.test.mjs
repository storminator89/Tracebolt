/** Inert Node/production-renderer contracts. No browser, host read or grant. */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {windowsBrowserFixture,windowsHealthBrowserDevice,windowsInventoryFixtureDisclosure} from './windows-inventory-browser.mjs';
import {withWindowsOSProvenance,windowsOSProvenance,exerciseWindowsOSProvenance} from './windows-os-provenance-browser.mjs';
const require=createRequire(new URL('../../web/package.json',import.meta.url)),now='2026-10-08T18:00:00.000Z',originalAt='2026-10-08T17:59:50.000Z';
const built=await require('esbuild').build({stdin:{contents:"export {EvidenceCard} from './components'; export {DeviceTabs} from './device-tabs'; export {setLocale} from './i18n'; export {fullDate} from './utils'; export {windowsDevice,windowsNow} from './windows-inventory-fixture'; export {windowsHealthDevice} from './windows-health-fixture';",resolveDir:fileURLToPath(new URL('../../web/src/',import.meta.url)),loader:'tsx'},bundle:true,platform:'node',format:'cjs',jsx:'automatic',external:['react'],write:false,logLevel:'silent',loader:{'.css':'empty'}});
const mod={exports:{}};new Function('require','module','exports',built.outputFiles[0].text)(require,mod,mod.exports);
const {EvidenceCard,DeviceTabs,setLocale,fullDate,windowsDevice,windowsHealthDevice,windowsNow}=mod.exports;
function shifted(value,at){if(Array.isArray(value))return value.map(row=>shifted(row,at));if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([key,row])=>[key,shifted(row,at)]));return typeof value==='string'&&/^2026-\d\d-\d\dT/.test(value)?new Date(Date.parse(value)+Date.parse(at)-Date.parse(windowsNow)).toISOString():value;}

test('invented OS evidence mirrors exact collector provenance and retains its native-verification boundary',()=>{
 const collector=fs.readFileSync(new URL('../../internal/collector/native_windows_sample.go',import.meta.url),'utf8'),managed=fs.readFileSync(new URL('../../internal/windowsmanaged/os_provenance_test.go',import.meta.url),'utf8');
 assert.equal(windowsOSProvenance.source,collector.match(/windowsOSSource\s*= "([^"]+)"/)[1]);
 assert.equal(windowsOSProvenance.detail,collector.match(/windowsOSDetail\s*= "([^"]+)"/)[1]+' nativeVerification: target-acceptance-unverified.');
 for(const value of [windowsOSProvenance.id,windowsOSProvenance.title,windowsOSProvenance.source,windowsOSProvenance.value,windowsOSProvenance.detail])assert.ok(managed.includes(JSON.stringify(value)));
 const d=windowsHealthBrowserDevice(now);assert.equal(d.os,'Windows NT 10.0 (build 26100)');assert.deepEqual(d.evidence,[{...windowsOSProvenance,collectedAt:originalAt}]);
 assert.equal(d.evidence[0].quality,'healthy');assert.equal(d.evidence[0].synthetic,false);assert.match(windowsInventoryFixtureDisclosure,/invented Windows inventory/);assert.match(windowsInventoryFixtureDisclosure,/no native endpoint acceptance/);
});

test('hosted overlay preserves authority and unrelated DTO fields without changing bare or legacy absence',()=>{
 for(const phase of ['fresh','health-unverified','legacy']){
  const base=shifted(windowsHealthDevice(phase==='health-unverified'?'missing-identity':'activated'),now),before=structuredClone(base),overlay=withWindowsOSProvenance(base);
  assert.deepEqual({...overlay,os:base.os,evidence:base.evidence},base);assert.deepEqual(base,before);
  assert.deepEqual(windowsHealthBrowserDevice(now,phase),phase==='legacy'?base:overlay);assert.equal(overlay.evidence[0].collectedAt,base.lastSeen);
  assert.equal(overlay.source,'lan');assert.equal(overlay.synthetic,false);assert.equal(overlay.status,'unknown');
 }
 assert.equal(windowsDevice().os,'Windows fixture');assert.deepEqual(windowsDevice().evidence,[]);assert.deepEqual(windowsHealthDevice().evidence,[]);assert.equal(windowsHealthBrowserDevice(now,'legacy').os,'Windows fixture');assert.deepEqual(windowsHealthBrowserDevice(now,'legacy').evidence,[]);
 const legacy=windowsBrowserFixture(now,'legacy');for(const key of ['events','volumes','network','processMetrics','serviceStartup','osEvidence'])assert.equal(Object.hasOwn(legacy,key),false,key);
 const base=windowsDevice(),other={id:'unrelated-invented-evidence'};base.evidence=[other];const d=withWindowsOSProvenance(base,originalAt);
 assert.deepEqual(base.evidence,[other]);assert.deepEqual(d.evidence,[other,{...windowsOSProvenance,collectedAt:originalAt}]);
});

test('actual admitted device and Overview replies pin OS capture while later response clocks advance',async()=>{
 for(const first of ['device','overview']){
  const {windowsInventoryBrowserCase}=await import(new URL(`./windows-inventory-browser.mjs?inert-os-pin-${first}`,import.meta.url).href);
  let handler,sampled=Date.parse(now),evaluations=0;const stop=new Error('inert setup complete'),base='http://fixture.invalid',prefix='/api/devices/'+windowsDevice().id;
  const page={clock:{install:async()=>{},pauseAt:async()=>{}},route:async(_pattern,read)=>{handler=read;},evaluate:async()=>{evaluations++;return sampled;}};
  await assert.rejects(windowsInventoryBrowserCase({pageAt:async()=>page,login:async()=>{throw stop;},base}),error=>error===stop);
  async function route(pathname){let body;await handler({request:()=>({url:()=>base+pathname,method:()=> 'GET',postData:()=>null}),fulfill:async value=>{body=JSON.parse(value.body);}});return body;}
  // An inventory-only reply is not an admitted Device DTO and must not pin it.
  await route(prefix+'/windows-inventory');sampled+=500;
  const initial=first==='device'?await route(prefix):(await route('/api/overview')).devices[0],capture=initial.evidence[0].collectedAt;
  assert.equal(capture,initial.lastSeen);assert.equal(capture,new Date(Date.parse(originalAt)+500).toISOString());
  for(const elapsed of [500,121000,617000]){
   sampled=Date.parse(now)+elapsed+500;
   const device=await route(prefix),overview=(await route('/api/overview')).devices[0],inventory=await route(prefix+'/windows-inventory');
   for(const dto of [device,overview]){assert.equal(dto.evidence[0].collectedAt,capture);assert.notEqual(dto.lastSeen,capture);assert.deepEqual({...dto.evidence[0],collectedAt:capture},initial.evidence[0]);}
   assert.equal(inventory.serverNow,new Date(sampled).toISOString());assert.equal(device.agentCertificate.checkedAt,inventory.serverNow);
  }
  assert.equal(evaluations,11,'each recognized reply retains its existing one request-time clock sample');
 }
});

// Exercise the exact helper against real shared renderer markup and the pinned
// Playwright selector engine, with inert page/shot adapters. JSDOM cannot prove
// browser layout, viewport fit or actual pixels; those remain hosted gates.
function renderedPage(locale,{mutateEvidence=value=>value}={}){
 const {JSDOM,VirtualConsole}=require('jsdom'),React=require('react'),{renderToStaticMarkup}=require('react-dom/server');
 const playwrightRoot=path.dirname(require.resolve('playwright-core/package.json'));assert.equal(require(path.join(playwrightRoot,'package.json')).version,'1.58.2');
 const {source}=require(path.join(playwrightRoot,'lib/generated/injectedScriptSource.js'));
 const virtualConsole=new VirtualConsole();virtualConsole.on('jsdomError',error=>{if(!error.message.includes('getComputedStyle() method: with pseudo-elements'))throw error;});
 const dom=new JSDOM('',{runScripts:'outside-only',virtualConsole}),InjectedScript=dom.window.eval('var module={exports:{}};'+source+'\nInjectedScript');
 const injected=new InjectedScript(dom.window,{isUnderTest:true,sdkLanguage:'javascript',testIdAttributeName:'data-testid',customEngines:[],browserName:'chromium'}),checks=[],actions=[];let selected='overview';
 const names={overview:locale==='de'?'Übersicht':'Overview',inventory:locale==='de'?'Inventar':'Inventory',evidence:locale==='de'?'Belege':'Evidence'};
 function render(){setLocale(locale,false);dom.window.document.body.innerHTML=renderToStaticMarkup(React.createElement(React.Fragment,null,React.createElement(DeviceTabs,{tabs:Object.entries(names).map(([id,name])=>({id,name,icon:()=>null,...(id==='evidence'?{count:1}:{})})),selected,onSelect:()=>{}}),selected==='evidence'?React.createElement(EvidenceCard,{evidence:mutateEvidence({...windowsOSProvenance,collectedAt:originalAt}),index:0}):null));}render();
 const query=selector=>Array.from(injected.querySelectorAll(injected.parseSelector(selector),dom.window.document));
 function locator(selector){return {selector,all:()=>query(selector),one(){const found=query(selector);assert.equal(found.length,1,selector);return found[0];},locator:next=>locator(`${selector} >> ${next}`),getByText:(text,options)=>{assert.equal(options.exact,true);return locator(`${selector} >> internal:text=${JSON.stringify(text)}s`);},async click(){const el=this.one();actions.push(['click',selector]);if(el.matches('[role="tab"]')){selected=el.id.slice(4);render();}else {assert.equal(el.tagName,'SUMMARY');el.parentElement.toggleAttribute('open');}},async evaluate(read){return read(this.one());},async scrollIntoViewIfNeeded(){actions.push(['scroll',selector]);assert.equal(this.one().open,true);}};}
 const page={locator,getByRole:(role,options)=>{assert.equal(options.exact,true);return locator(`internal:role=${role}[name=${JSON.stringify(options.name)}s]`);},evaluate:async(read,args)=>{checks.push(['format',args]);return read(args);}};
 const normalized=value=>value.replace(/\s+/g,' ').trim();
 function expect(actual){function match(negate=false){return {
  toBe(value){checks.push(['toBe',actual,value]);assert.equal(actual,value);},
  toHaveText(value){checks.push(['toHaveText',actual.selector,value]);assert.equal(normalized(actual.one().textContent),normalized(value));},
  toHaveCount(value){checks.push(['toHaveCount',actual.selector,value]);assert.equal(actual.all().length,value);},
  toHaveAttribute(key,value){checks.push(['toHaveAttribute',actual.selector,key,value]);assert.equal(actual.one().getAttribute(key),value);},
  toContainText(value){checks.push([negate?'not.toContainText':'toContainText',actual.selector,String(value)]);assert.equal(value.test(actual.one().textContent),!negate);},
  toBeVisible(){checks.push(['toBeVisible',actual.selector]);const el=actual.one(),details=el.closest('details');assert.ok(!details||el===details||el.closest('summary')||details.open);},
  toBeInViewport(value){checks.push(['toBeInViewport',actual.selector,value]);assert.equal(actual.one().open,true);assert.deepEqual(value,{ratio:1});},
  get not(){return match(true);},
 };}return match();}
 return {page,expect,checks,actions,dom,get selected(){return selected;},query};
}

test('production EvidenceCard and exact tab selectors execute all four localized capture contracts',async()=>{
 const screenshots=[];
 for(const locale of ['en','de'])for(const width of [1440,390]){
  const mock=renderedPage(locale);
  try{
   await exerciseWindowsOSProvenance({page:mock.page,expect:mock.expect,locale,width,observedAt:originalAt,disclosure:windowsInventoryFixtureDisclosure,shot:async(page,name,disclosure)=>{
    assert.equal(page,mock.page);assert.equal(mock.selected,'evidence');assert.equal(mock.query('#evidence-local-windows-os[open]').length,1);assert.equal(disclosure,windowsInventoryFixtureDisclosure);screenshots.push(name);
   }});
   setLocale(locale,false);const texts=mock.checks.filter(row=>row[0]==='toHaveText').map(row=>row[2]);
   for(const value of ['1',windowsOSProvenance.title,locale==='de'?'Aktuell':'Current',windowsOSProvenance.value,windowsOSProvenance.detail,fullDate(originalAt),windowsOSProvenance.id])assert.ok(texts.includes(value),value);
   assert.ok(mock.checks.some(row=>row[0]==='toBeVisible'&&row[1].includes(windowsOSProvenance.source)));
   assert.ok(mock.checks.some(row=>row[0]==='not.toContainText'));assert.ok(mock.checks.some(row=>row[0]==='toBeInViewport'));
   assert.deepEqual(mock.checks.find(row=>row[0]==='format')[1],{locale,observedAt:originalAt});
   assert.equal(mock.selected,'evidence');
   // Match the caller's unchanged next step, with no extra Overview mount.
   await mock.page.getByRole('tab',{name:locale==='de'?'Inventar':'Inventory',exact:true}).click();assert.equal(mock.selected,'inventory');assert.equal(mock.query('#evidence-local-windows-os').length,0);
   assert.equal(mock.actions.filter(row=>row[0]==='click').length,3);
  }finally{mock.dom.window.close();}
 }
 assert.deepEqual(screenshots,['synthetic-windows-os-provenance-1440-en','synthetic-windows-os-provenance-390-en','synthetic-windows-os-provenance-1440-de','synthetic-windows-os-provenance-390-de']);assert.equal(new Set(screenshots).size,4);
});

test('hosted assertions reject changed source, quality, value, detail or original observation',async()=>{
 for(const change of [{source:'invented replacement'},{quality:'unknown'},{value:'Windows 11 Pro'},{detail:'target acceptance verified'},{collectedAt:now}]){
  const mock=renderedPage('en',{mutateEvidence:value=>({...value,...change})});let shots=0;
  try{await assert.rejects(exerciseWindowsOSProvenance({page:mock.page,expect:mock.expect,locale:'en',width:1440,observedAt:originalAt,shot:async()=>{shots++;},disclosure:windowsInventoryFixtureDisclosure}));assert.equal(shots,0);}finally{mock.dom.window.close();}
 }
});

test('observed-time assertion matches the production formatter in either browser timezone',async()=>{
 const previous=process.env.TZ;
 try{for(const zone of ['UTC','America/Los_Angeles']){process.env.TZ=zone;for(const locale of ['en','de']){const mock=renderedPage(locale);try{await exerciseWindowsOSProvenance({page:mock.page,expect:mock.expect,locale,width:390,observedAt:originalAt,shot:async()=>{},disclosure:windowsInventoryFixtureDisclosure});setLocale(locale,false);assert.ok(mock.checks.some(row=>row[0]==='toHaveText'&&row[1].endsWith('.evidence-foot > span')&&row[2]===fullDate(originalAt)));}finally{mock.dom.window.close();}}}}finally{if(previous===undefined)delete process.env.TZ;else process.env.TZ=previous;}
});

test('OS capture uses the existing four rounds and finite stage without a new clock, request or runner case',()=>{
 const helper=fs.readFileSync(new URL('./windows-os-provenance-browser.mjs',import.meta.url),'utf8'),runner=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8'),hosted=fs.readFileSync(new URL('./lan-browser.mjs',import.meta.url),'utf8'),gate=fs.readFileSync(new URL('./windows-inventory-fixtures.test.mjs',import.meta.url),'utf8');
 assert.match(runner,/for\(const locale of \['en','de'\]\)for\(const width of \[1440,390\]\)/);assert.match(runner,/'overview-history','os-provenance','inventory'/);
 assert.match(runner,/mark\('os-provenance'\);await exerciseWindowsOSProvenance\(\{page,expect,locale,width,shot,disclosure:windowsInventoryFixtureDisclosure,observedAt:osObservedAt\}\)/);
 assert.match(runner,/observedAt:osObservedAt\}\);\s*mark\('inventory'\);await page\.getByRole\('tab',\{name:locale==='de'\?'Inventar':'Inventory',exact:true\}\)\.click\(\)/);
 assert.match(gate,/import '\.\/windows-os-provenance-fixtures\.test\.mjs'/);assert.equal((hosted.match(/await check\(/g)||[]).length,26);assert.match(hosted,/check\(windowsInventoryCaseName,[^\n]+,'20m'\)/);
 assert.equal((runner.match(/page\.clock\.runFor\(/g)||[]).length,5);assert.equal((runner.match(/page\.clock\.install\(/g)||[]).length,1);assert.equal((runner.match(/page\.clock\.pauseAt\(/g)||[]).length,1);
 assert.match(runner,/at=await windowsFixtureResponseTime\(page\)/);assert.match(runner,/return reply\(windowsBrowserFixture\(at,phase,/);
 assert.doesNotMatch(helper.replace(/\/\/[^\n]*/g,''),/\.clock\b|clockNow|\badvance\s*\(|\brunFor\s*\(|\b(?:setTimeout|setInterval|waitForTimeout|setDefaultTimeout)\s*\(|Date\.now\s*\(|chromium\.launch|newContext\(|fetch\(|\.route\(|request\(|spawn\(|execFile|writeFile/);
 for(const counter of ['unexpected','writes','external'])assert.ok(runner.includes(`expect(${counter}).toEqual([])`));
 // The unchanged runner appends screenshots with the existing completion and
 // source/locale/viewport/disclosure metadata; no fixed capture count is widened.
 assert.match(hosted,/screenshots\.push\(\{file:`\$\{name\}\.png`,sourceSha,publicSafe:true,fullPage:false,viewport:page\.viewportSize\(\),locale:/);assert.match(hosted,/fixtureDisclosure,test:currentTest/);
});
