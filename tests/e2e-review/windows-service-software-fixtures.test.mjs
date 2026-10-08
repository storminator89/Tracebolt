/** Pure invented DTO/source checks. No hosted or local browser is started. */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {addWindowsServiceSoftwareControlsFixture} from './windows-service-software-browser.mjs';
import {windowsBrowserFixture} from './windows-inventory-browser.mjs';

const now='2026-10-07T12:00:10Z';

test('service/software control rows disclose captured and lower-bound observed counts independently',()=>{
 const view=addWindowsServiceSoftwareControlsFixture(windowsBrowserFixture(now));
 for(const key of ['services','software']){
  const section=view.snapshot[key];
  assert.equal(section.rows.length,61);assert.equal(section.observedCount,200);assert.equal(section.countExact,false);assert.equal(section.complete,false);assert.equal(section.truncated,true);assert.equal(section.quality,'partial');
  assert.match(section.source,/Synthetic/);assert.match(section.scope,/no native collection/);
 }
 assert.equal(Buffer.byteLength(JSON.stringify(view.snapshot))<48*1024,true);assert.equal(Buffer.byteLength(JSON.stringify(view))<74*1024,true);
});

test('invented control coverage leaves unrelated captures, grants and exact DTO row shape unchanged',()=>{
 const source=windowsBrowserFixture(now),before=structuredClone(source),view=addWindowsServiceSoftwareControlsFixture(source);
 assert.equal(view,source);for(const key of ['events','volumes','processMetrics','network'])assert.deepEqual(view[key],before[key]);
 assert.equal(Object.hasOwn(before,'serviceStartup'),false);assert.equal(Object.hasOwn(windowsBrowserFixture(now,'legacy'),'serviceStartup'),false);
 for(const key of ['hostname','processes','network'])assert.deepEqual(view.snapshot[key],before.snapshot[key]);
 for(const key of ['schemaVersion','collectionProfile','generationId','collectedAt'])assert.equal(view.snapshot[key],before.snapshot[key]);
 for(const key of ['schemaVersion','deviceId','collectionProfile','serverNow','maxAgeSeconds','status','sequence','receivedAt'])assert.equal(view[key],before[key]);
 for(const row of view.snapshot.services.rows)assert.deepEqual(Object.keys(row).sort(),['displayName','name','pid','state']);
 for(const row of view.snapshot.software.rows)assert.deepEqual(Object.keys(row).sort(),['name','publisher','registryView','version']);
 assert.deepEqual(windowsBrowserFixture(now),before,'new base fixtures must not inherit the controls overlay');
});

test('invented rows exercise literal, all-field, numeric PID and non-semantic version cases',()=>{
 const view=addWindowsServiceSoftwareControlsFixture(windowsBrowserFixture(now)),services=view.snapshot.services.rows,software=view.snapshot.software.rows;
 assert.equal(services[60].name,'synthetic-service-061');assert.equal(services[60].displayName,'Synthetic service label 061');assert.equal(services[60].pid,61);assert.equal(services[60].state,'start_pending');
 assert.deepEqual(services.slice(0,3).map(row=>row.pid),[2,10,3]);assert.equal(services[9].pid,1);assert.equal(new Set(services.map(row=>row.pid)).size,61);
 assert.equal(services[59].displayName,'Literal [.*] Service');assert.equal(software[59].version,'literal[.*]');
 assert.deepEqual(software.slice(0,2).map(row=>row.version),['2','10']);assert.deepEqual(software.slice(0,2).map(row=>row.publisher),['ZZZ Fixture Publisher','AAA Fixture Publisher']);
 assert.equal(software.filter(row=>row.registryView==='32').length,30);assert.equal(software.filter(row=>row.registryView==='64').length,31);
});

test('hosted service/software exercise covers both languages and sizes through the shared runner',()=>{
 const source=fs.readFileSync(new URL('./windows-service-software-browser.mjs',import.meta.url),'utf8');
 for(const fragment of ['Filter captured services','Erfasste Dienste filtern','Filter captured software','Erfasste Software filtern','Sort captured services','Erfasste Dienste sortieren','Sort captured software','Erfasste Software sortieren'])assert.ok(source.includes(fragment));
 for(const fragment of ['toHaveCount(25)','toHaveCount(11)','toHaveCount(1)','toHaveCount(5)','Rows 51–61 of 61 matching · 61 captured','Zeilen 51–61 von 61 Treffern · 61 erfasst','Rows 1–25 of 30 matching · 61 captured','Rows 0–0 of 0 matching · 61 captured'])assert.ok(source.includes(fragment));
 for(const fragment of ['SYNTHETIC-SERVICE-061','label 061','START_PENDING','WIRD GESTARTET','STARTING','SYNTHETIC-SOFTWARE-061','V061','Publisher 061',"filter.fill('32')","filter.fill('[.*]')"])assert.ok(source.includes(fragment));
 for(const fragment of ["'name-desc'","'name-asc'","selectOption('pid-asc')","selectOption('pid-desc')","selectOption('state-'+direction)","selectOption('version-asc')","selectOption('version-desc')","selectOption('publisher-asc')","selectOption('publisher-desc')"])assert.ok(source.includes(fragment));
 assert.match(source,/page\.keyboard\.press\('Enter'\)/);assert.match(source,/getComputedStyle\(el,'::before'\)/);assert.match(source,/thead th\[aria-sort\]/);assert.match(source,/thead input, thead select, thead button/);assert.match(source,/scrollWidth<=el\.clientWidth\+1/);
 assert.ok(source.includes('synthetic-windows-${kind}-controls-${width}-${locale}'));assert.match(source,/await expect\(filter\)\.toHaveValue\(''\)/);assert.match(source,/await expect\(sort\)\.toHaveValue\('name-asc'\)/);
 assert.doesNotMatch(source,/chromium\.launch|newContext\(|execFile|spawn\(|writeFile|ignoreHTTPSErrors|waitForTimeout|setDefaultTimeout|fetch\(|localStorage|sessionStorage/);
});

test('service/software overlay is admitted by the real validator in its isolated hosted phase',()=>{
 const view=windowsBrowserFixture(now,'service-software-controls');
 for(const key of ['services','software'])assert.equal(view.snapshot[key].rows.length,61);
 const source=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8'),gate=fs.readFileSync(new URL('./windows-inventory-fixtures.test.mjs',import.meta.url),'utf8');
 assert.match(source,/phase==='service-software-controls'\)addWindowsServiceSoftwareControlsFixture\(view\)/);
 assert.match(source,/mark\('service-software-controls'\);phase='service-software-controls'/);
 assert.match(source,/exerciseWindowsServiceSoftwareControls\(\{page,expect,locale,width,shot,disclosure:windowsInventoryFixtureDisclosure\}\)/);
 assert.match(source,/for\(const locale of \['en','de'\]\)for\(const width of \[1440,390\]\)/);
 assert.match(source,/expect\(unexpected\)\.toEqual\(\[\]\)/);assert.match(source,/expect\(writes\)\.toEqual\(\[\]\)/);assert.match(source,/expect\(external\)\.toEqual\(\[\]\)/);
 assert.match(gate,/import '\.\/windows-service-software-fixtures\.test\.mjs'/);
});

test('real table selector matches hosted EN/DE assertions without a DOM or source mutation',async()=>{
 const {createRequire}=await import('node:module'),require=createRequire(new URL('../../web/package.json',import.meta.url));
 const bundle=await require('esbuild').build({stdin:{contents:"export {capturedInventoryTableRows} from './windows-inventory-tables'; export {validWindowsInventoryView} from './windows-inventory-types'; export {windowsServicesDigest,windowsServicesCanonicalJSON} from './windows-service-startup-types';",resolveDir:new URL('../../web/src/',import.meta.url).pathname,loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent',loader:{'.css':'empty'}});
 const {capturedInventoryTableRows,validWindowsInventoryView,windowsServicesDigest,windowsServicesCanonicalJSON}=await import('data:text/javascript;base64,'+Buffer.from(bundle.outputFiles[0].text).toString('base64'));
 const view=windowsBrowserFixture(now,'service-software-controls');assert.equal(validWindowsInventoryView(view,view.deviceId),true);
 const invalid=structuredClone(view);invalid.snapshot.services.rows=Array.from({length:129},()=>invalid.snapshot.services.rows[0]);assert.equal(validWindowsInventoryView(invalid,invalid.deviceId),false);
 const snapshot=view.snapshot,before=structuredClone(snapshot);
 const startup=view.serviceStartup;
 assert.equal(startup.servicesSHA256,windowsServicesDigest(snapshot.services.rows));
 assert.equal(startup.servicesSHA256,createHash('sha256').update(windowsServicesCanonicalJSON(snapshot.services.rows),'utf8').digest('hex'));
 const vectors=JSON.parse(fs.readFileSync(new URL('../../web/src/windows-service-startup-go-fixture.json',import.meta.url),'utf8'));
 for(const vector of vectors){assert.equal(windowsServicesCanonicalJSON(vector.services),vector.canonicalJSON);assert.equal(windowsServicesDigest(vector.services),vector.sha256);assert.equal(createHash('sha256').update(vector.canonicalJSON,'utf8').digest('hex'),vector.sha256);}
 const wrong=structuredClone(view);wrong.snapshot.services.rows.reverse();assert.equal(validWindowsInventoryView(wrong,wrong.deviceId),false);

 const expected={services:{'name-asc':'001','name-desc':'061','pid-asc':'010','pid-desc':'061'},software:{'name-asc':'001','name-desc':'061','version-asc':'002','version-desc':'061','publisher-asc':'002','publisher-desc':'001'}};
 for(const locale of ['en','de']){
  for(const [kind,sorts] of Object.entries(expected))for(const [sort,suffix] of Object.entries(sorts))assert.equal(capturedInventoryTableRows(snapshot,kind,'',sort,locale,view.serviceStartup)[0].cells[0],`synthetic-${kind==='services'?'service':'software'}-${suffix}`,`${locale} ${kind} ${sort}`);
  for(const [sort,suffix] of [['state-asc',locale==='de'?'002':'001'],['state-desc',locale==='de'?'061':'002']])assert.equal(capturedInventoryTableRows(snapshot,'services','',sort,locale,view.serviceStartup)[0].cells[0],`synthetic-service-${suffix}`,`${locale} ${sort}`);
  for(const query of ['SYNTHETIC-SERVICE-061','label 061','61','START_PENDING',locale==='de'?'WIRD GESTARTET':'STARTING'])assert.deepEqual(capturedInventoryTableRows(snapshot,'services',query,'name-asc',locale,view.serviceStartup).map(row=>row.cells[0]),['synthetic-service-061'],`${locale} services ${query}`);
  for(const query of ['SYNTHETIC-SOFTWARE-061','V061','Publisher 061'])assert.deepEqual(capturedInventoryTableRows(snapshot,'software',query,'name-asc',locale,view.serviceStartup).map(row=>row.cells[0]),['synthetic-software-061'],`${locale} software ${query}`);
  for(const kind of ['services','software']){
   assert.deepEqual(capturedInventoryTableRows(snapshot,kind,'[.*]','name-asc',locale,view.serviceStartup).map(row=>row.cells[0]),[`synthetic-${kind==='services'?'service':'software'}-060`],`${locale} ${kind} literal`);
   assert.deepEqual(capturedInventoryTableRows(snapshot,kind,'absent-fixture','name-asc',locale,view.serviceStartup),[]);
  }
  const expectedStartup=locale==='de'?['Automatisch (verzögert)','Automatisch (nicht verzögert)','Manuell','Deaktiviert','Zugriff verweigert','Nicht verfügbar','Unbekannt','Automatisch · Verzögerungsstatus: Zugriff verweigert (teilweise)','Automatisch · Verzögerungsstatus: Nicht verfügbar (teilweise)','Automatisch · Verzögerungsstatus: Unbekannt (teilweise)']:['Automatic (delayed)','Automatic (not delayed)','Manual','Disabled','Access denied','Unavailable','Unknown','Automatic · delayed status: Access denied (partial)','Automatic · delayed status: Unavailable (partial)','Automatic · delayed status: Unknown (partial)'];
  const projected=capturedInventoryTableRows(snapshot,'services','','name-asc',locale,startup),base=capturedInventoryTableRows(snapshot,'services','','name-asc',locale);
  assert.deepEqual(projected.slice(0,10).map(row=>row.cells[4]),expectedStartup);assert.deepEqual(projected.map(row=>row.cells.slice(0,4)),base.map(row=>row.cells.slice(0,4)));
  assert.equal(projected[25].cells[4],locale==='de'?'Manuell':'Manual');assert.equal(projected[10].cells[4],locale==='de'?'Nicht erfasst (gekürzt)':'Not captured (trimmed)');
  for(const [query,indices] of [[locale==='de'?'Automatisch':'Automatic',[0,1,7,8,9]],[expectedStartup[0],[0]],[expectedStartup[1],[1]],[locale==='de'?'Manuell':'Manual',[2,25]],[locale==='de'?'Deaktiviert':'Disabled',[3]],[locale==='de'?'Zugriff verweigert':'Access denied',[4,7]],[locale==='de'?'Nicht verfügbar':'Unavailable',[5,8]],[locale==='de'?'Unbekannt':'Unknown',[6,9]],[locale==='de'?'teilweise':'partial',[7,8,9]]])assert.deepEqual(capturedInventoryTableRows(snapshot,'services',query,'name-asc',locale,startup).map(row=>row.index),indices);
  for(const [sort,indices] of [['startup-asc',[0,1,7,8,9,3,2,25]],['startup-desc',[2,25,3,0,1,7,8,9]]]){
   const sorted=capturedInventoryTableRows(snapshot,'services','',sort,locale,startup);assert.deepEqual(sorted.slice(0,8).map(row=>row.index),indices);
   for(const row of sorted)assert.equal(row.cells[4],projected[row.index].cells[4]);
   assert.equal(sorted.find(row=>row.index===10).cells[4],locale==='de'?'Nicht erfasst (gekürzt)':'Not captured (trimmed)');
  }
  const registry=capturedInventoryTableRows(snapshot,'software','32','name-asc',locale,view.serviceStartup);assert.equal(registry.length,30);assert.ok(registry.every(row=>row.cells[3]==='32-bit'));
  assert.deepEqual(capturedInventoryTableRows(snapshot,'services','','pid-asc',locale,view.serviceStartup).slice(0,3).map(row=>row.cells[0]),['synthetic-service-010','synthetic-service-001','synthetic-service-003']);
  assert.deepEqual(capturedInventoryTableRows(snapshot,'software','','version-asc',locale,view.serviceStartup).slice(0,2).map(row=>row.cells[0]),['synthetic-software-002','synthetic-software-001']);
 }
 assert.deepEqual(snapshot,before);
});

// Use the pinned Playwright selector implementation in an inert JSDOM. This
// checks engine label normalization on production markup, not browser layout.
test('actual Playwright exact label and role engines admit service/software sort controls without option text',async()=>{
 const {createRequire}=await import('node:module'),require=createRequire(new URL('../../web/package.json',import.meta.url));
 const path=require('node:path'),playwrightRoot=path.dirname(require.resolve('playwright-core/package.json'));
 assert.equal(require(path.join(playwrightRoot,'package.json')).version,'1.58.2');
 const {source}=require(path.join(playwrightRoot,'lib/generated/injectedScriptSource.js'));
 const {JSDOM,VirtualConsole}=require('jsdom'),React=require('react'),{renderToStaticMarkup}=require('react-dom/server');
 const bundle=await require('esbuild').build({stdin:{contents:"export {WindowsInventoryTable} from './windows-inventory-tables';",resolveDir:new URL('../../web/src/',import.meta.url).pathname,loader:'tsx'},bundle:true,platform:'node',format:'cjs',jsx:'automatic',external:['react'],write:false,logLevel:'silent',loader:{'.css':'empty'}});
 const mod={exports:{}};new Function('require','module','exports',bundle.outputFiles[0].text)(require,mod,mod.exports);
 const view=windowsBrowserFixture(now,'service-software-controls'),snapshot=view.snapshot;
 for(const locale of ['en','de'])for(const kind of ['services','software']){
  const name=kind==='services'?(locale==='de'?'Erfasste Dienste sortieren':'Sort captured services'):(locale==='de'?'Erfasste Software sortieren':'Sort captured software');
  const markup=renderToStaticMarkup(React.createElement(mod.exports.WindowsInventoryTable,{snapshot,serviceStartup:view.serviceStartup,kind,locale,controls:{query:'',sort:'name-asc',page:0},onChange:()=>{}}));
  const virtualConsole=new VirtualConsole();
  virtualConsole.on('jsdomError',error=>{if(!error.message.includes("getComputedStyle() method: with pseudo-elements"))throw error;});
  const dom=new JSDOM(markup,{runScripts:'outside-only',virtualConsole});
  try{
   const InjectedScript=dom.window.eval('var module={exports:{}};'+source+'\nInjectedScript');
   const injected=new InjectedScript(dom.window,{isUnderTest:true,sdkLanguage:'javascript',testIdAttributeName:'data-testid',customEngines:[],browserName:'chromium'});
   const query=selector=>Array.from(injected.querySelectorAll(injected.parseSelector(selector),dom.window.document));
   if(kind==='services'){const row=dom.window.document.querySelector('tbody tr'),cells=row.querySelectorAll('td');assert.equal(cells.length,5);assert.equal(cells[4].getAttribute('data-label'),locale==='de'?'Starttyp':'Startup mode');assert.equal(cells[4].textContent,locale==='de'?'Automatisch (verzögert)':'Automatic (delayed)');}
   const select=dom.window.document.querySelector('select'),label=dom.window.document.querySelector(`label[for="${select.id}"]`);
   assert.equal(select.closest('label'),null);assert.equal(label.textContent,name);assert.equal(label.control,select);
   assert.deepEqual(query(`internal:label=${JSON.stringify(name)}s`),[select]);
   assert.deepEqual(query(`internal:role=combobox[name=${JSON.stringify(name)}s]`),[select]);
   // Mutating only this synthetic DOM reproduces the old wrapping-label bug:
   // exact getByLabel includes options even though exact role naming succeeds.
   label.appendChild(select);
   assert.equal(query(`internal:label=${JSON.stringify(name)}s`).length,0);
   assert.deepEqual(query(`internal:role=combobox[name=${JSON.stringify(name)}s]`),[select]);
  }finally{dom.window.close();}
 }
});


test('startup fixture is a bounded optional projection only in the existing service/software phase',()=>{
 const view=windowsBrowserFixture(now,'service-software-controls'),startup=view.serviceStartup;
 assert.equal(startup.schemaVersion,'tracebolt.windows-service-startup.v1');assert.equal(startup.scope,'windows-service-startup-v1');assert.equal(startup.generationId,view.snapshot.generationId);assert.equal(startup.collectedAt,view.snapshot.collectedAt);assert.equal(startup.requestedCount,61);assert.equal(startup.truncated,true);
 assert.deepEqual(startup.rows.map(row=>row.serviceIndex),[0,1,2,3,4,5,6,7,8,9,25]);assert.ok(Buffer.byteLength(JSON.stringify(startup))<16*1024);
 assert.deepEqual(startup.rows.slice(0,2).map(row=>row.delayedAutoStart),[true,false]);assert.ok(startup.rows.slice(2).every(row=>row.delayedAutoStart===null));
 for(const phase of ['fresh','legacy','process-controls','metrics-stale','metrics-expiring','stale','network-stale','network-empty','network-denied','network-unavailable'])assert.equal(Object.hasOwn(windowsBrowserFixture(now,phase),'serviceStartup'),false,phase);
});

test('startup source adds exact localized display/search/sort checks without any clock or session budget change',()=>{
 const helper=fs.readFileSync(new URL('./windows-service-software-browser.mjs',import.meta.url),'utf8'),runner=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8'),hosted=fs.readFileSync(new URL('./lan-browser.mjs',import.meta.url),'utf8');
 for(const label of ['Startup mode','Starttyp','Automatic (delayed)','Automatic (not delayed)','Automatisch (verzögert)','Automatisch (nicht verzögert)','Manual','Manuell','Disabled','Deaktiviert','Access denied','Zugriff verweigert','Unavailable','Nicht verfügbar','Unknown','Unbekannt','Not captured (trimmed)','Nicht erfasst (gekürzt)'])assert.ok(helper.includes(label),label);
 assert.match(helper,/checkStartupModes/);assert.match(helper,/selectOption\('startup-'\+direction\)/);assert.match(helper,/locator\('thead th'\)\.nth\(4\)/);assert.match(helper,/createHash\('sha256'\)\.update\(canonical,'utf8'\)/);assert.doesNotMatch(helper,/servicesSHA256:\s*['"][a-f0-9]{64}['"]/);
 // Zero added virtual time preserves the composed 617-second fixture budget
 // within the existing 1200-second login session. No expiry exercise is added.
 assert.doesNotMatch(helper,/\.clock\b|clockNow|\badvance\s*\(|\brunFor\s*\(|\b(?:setTimeout|setInterval|waitForTimeout|setDefaultTimeout)\s*\(|Date\.now\s*\(/);
 assert.match(hosted,/check\(windowsInventoryCaseName,[^\n]+,'20m'\)/);
 assert.match(runner,/at=await windowsFixtureResponseTime\(page\)/);assert.match(runner,/return reply\(windowsBrowserFixture\(at,phase,/);
 const phase=runner.slice(runner.indexOf("mark('service-software-controls')"),runner.indexOf("mark('process-metrics-stale')"));
 assert.match(phase,/phase='service-software-controls'/);assert.match(phase,/exerciseWindowsServiceSoftwareControls/);assert.doesNotMatch(phase,/\.clock\b|clockNow|advance|timeout/i);
 assert.ok(helper.includes('synthetic-windows-${kind}-controls-${width}-${locale}'));
});
