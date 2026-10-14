/** Exact browser-selector/copy contracts. Pure source checks; no browser, server,
 * native collection, private endpoint data or network access is started. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';
const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8');
const conditional=read('./conditional-browser.mjs'),v3=read('./v3-mvp-browser.mjs');
function scenario(source,name){const begin=source.indexOf(`await check('${name}'`);assert.notEqual(begin,-1);const end=source.indexOf('await check(',begin+12);return source.slice(begin,end===-1?undefined:end);}
function firstCopy(source,key){const value=source.match(new RegExp(`\\b${key}: '([^']*)'`));assert.ok(value);return value[1];}
const coverage=scenario(conditional,'Device tabs and package/review disclosures issue only their lazy device-bound reads');
const compact=scenario(v3,'Compact Packages and Updates remain explicit about source, stale cache and unknown comparisons');
const sockets=scenario(v3,'Socket pages distinguish TCP listeners, connections, UDP bounds and unknown ownership');

test('held coverage retry asserts the current visible uncertainty warning, without relaxing cleared-state checks',()=>{
 const current=firstCopy(read('../../web/src/security-coverage.tsx'),'caution'),warning=current.slice(current.indexOf('Missing'));
 assert.ok(warning.includes('not zero vulnerabilities'));
 assert.ok(coverage.includes(`toContainText('${warning}')`),'held-view warning must match the actual current component copy');
 assert.ok(coverage.includes(".security-grid,.security-status-line,.security-gaps,.security-details')).toHaveCount(0)"));
 assert.ok(coverage.includes("expect(refreshCoverage).toBeDisabled()"));
});
test('compact gallery opens the actual accessible Security tab rather than its shorter visible label',()=>{
 const details=read('../../web/src/details.tsx'),match=details.match(/const securityTabLabel = locale === 'de' \? '[^']+' : '([^']+)'/);
 assert.ok(match);assert.equal(match[1],'Security coverage');
 assert.ok(compact.includes(`getByRole('tab',{name:'${match[1]}',exact:true}).click()`));
 assert.ok(!compact.includes("getByRole('tab',{name:'Security',exact:true})"));
 assert.ok(compact.includes("mark('select current Security coverage tab after package captures')"));
});
test('socket coverage locator and denial assertion match the real source note independently of table data',()=>{
 const note=firstCopy(read('../../web/src/system-inventory.tsx'),'network'),split=note.indexOf('“');assert.ok(split>0);
 const intro=note.slice(0,split).trim(),denial=note.slice(split);
 assert.ok(sockets.includes(`filter({hasText:'${intro}'})`),'attribution note must not be filtered out by obsolete wording');
 assert.ok(sockets.includes(`toContainText('${denial}')`),'denial remains an owner-field result, distinct from section failure');
 assert.ok(sockets.includes("toContainText('42 / qa-fixture-worker')"));
 assert.ok(sockets.includes("toContainText('Numeric endpoints may expose private topology; a listener does not establish external reachability.')"));
});
test('repairs preserve retry budgets, read-only evidence and safe fixed diagnostic fields',()=>{
 for(const text of ['},8000)','route.fetch({timeout:4000,maxRedirects:0,maxRetries:0})','{timeout:7000}',"expect(coverageStatuses).toEqual([429,200])",'expect(mutations).toBe(0)','expect(holdExpired).toBe(false)'])assert.ok(coverage.includes(text),text);
 assert.ok(coverage.includes('coverageStatuses.slice(0,3)'));assert.ok(coverage.includes("coverageStep='uncertainty warning retained'"));
 assert.doesNotMatch(coverage+compact+sockets,/\.skip\(|setDefaultTimeout|waitForTimeout|ignoreHTTPSErrors/);
 assert.ok(v3.includes("expect(text.includes(password))")||v3.includes("document.body.innerText.includes(p)||[...document.querySelectorAll('input')]"));
});

// Execute the exact hosted assertion against the value selected by production
// CSS at its existing 390px viewport. This is a source contract, not a browser.
test('overview typography accepts the narrow production rule and retains readable bounds and desktop sizing',()=>{
 const css=read('../../web/src/device-essentials.css');
 const narrow=css.match(/@media\(max-width:(\d+)px\)\{\.device-essential-card>\.device-essential-value\{font-size:clamp\((\d+)px,(\d+)vw,(\d+)px\)\}\}/);
 const normal=css.match(/\.device-essential-card>\.device-essential-value\{[^}]*font-size:(\d+)px/);
 assert.ok(narrow);assert.ok(normal);const viewport=390;assert.ok(viewport<=Number(narrow[1]));
 const computed=Math.min(Number(narrow[4]),Math.max(Number(narrow[2]),Number(narrow[3])*viewport/100));
 const body=v3.match(/ expect\(typography\)\.toHaveLength\(3\);[^\n]+/);assert.ok(body);
 const verify=(size,mobile)=>vm.runInNewContext(body[0],{mobile,typography:Array.from({length:3},()=>({size,margin:0,display:'block'})),expect:actual=>({
  toHaveLength:expected=>assert.equal(actual.length,expected),toBe:expected=>assert.equal(actual,expected),
  toBeGreaterThanOrEqual:expected=>assert.ok(actual>=expected),toBeLessThanOrEqual:expected=>assert.ok(actual<=expected),
 })});
 assert.doesNotThrow(()=>verify(computed,true));
 assert.doesNotThrow(()=>verify(Number(normal[1]),false));
 for(const unreadable of [12.99,16.01,18])assert.throws(()=>verify(unreadable,true));
 assert.throws(()=>verify(18,false));assert.throws(()=>verify(21.99,false));
});

// Authored hosted coverage remains distinct from executed browser proof.
test('read-first inventory captures use existing safe helpers with bilingual desktop/mobile and keyboard details',()=>{
 const helper=read('./inventory-read-first.mjs'),overview=read('./complete-overview-browser.mjs');
 for(const source of [v3,overview])assert.ok(source.includes("import {checkInventoryReadFirst} from './inventory-read-first.mjs'"));
 for(const selector of ['.complete-packages','.complete-overview'])assert.ok((v3+overview).includes(`selector:'${selector}'`));
 for(const value of ["['en','de']","[false,true]",'width:390,height:844','width:1440,height:1000',"press('Enter')","press('Space')",'toBeInViewport()',"getByText(fact,{exact:true})",'Node.DOCUMENT_POSITION_FOLLOWING'])assert.ok(helper.includes(value),value);
 assert.ok(helper.includes('await shot(page,'));assert.doesNotMatch(helper,/fetch\(|newContext|chromium|route\.fulfill|waitForTimeout|setDefaultTimeout/);
 for(const value of ['originalPackage.binding.generationId','originalPackage.manifest.collectedAt','originalPackage.retainedUntil'])assert.ok(compact.includes(value),value);
 for(const value of ['initial.processes.complete.binding.generationId','originalMount.binding.generationId','originalMount.manifest.captureStartedAt','originalMount.retainedUntil'])assert.ok(overview.includes(value),value);
});

test('capture-details focus keeps the opaque theme accent and contrast in light and dark palettes',()=>{
 const inventory=read('../../web/src/complete-packages.css'),styles=read('../../web/src/styles.css');
 const focus=inventory.match(/\.inventory-capture-details > summary:focus-visible\s*\{([^}]+)\}/);assert.ok(focus);
 assert.match(focus[1],/outline:\s*3px solid var\(--accent\)/);assert.match(focus[1],/outline-offset:\s*3px/);
 const luminance=hex=>{
  assert.match(hex,/^#(?:[0-9a-f]{3}|[0-9a-f]{6})$/i,'focus colors must be opaque source colors');
  const rgb=hex.length===4?hex.slice(1).split('').map(c=>c+c).join(''):hex.slice(1);
  const linear=rgb.match(/../g).map(c=>parseInt(c,16)/255).map(c=>c<=0.04045?c/12.92:((c+0.055)/1.055)**2.4);
  return linear.reduce((sum,c,i)=>sum+c*[0.2126,0.7152,0.0722][i],0);
 };
 for(const theme of ['light','dark']){
  const palette={};
  for(const [,selector,body] of styles.matchAll(/:root([^{}]*)\{([^{}]*)\}/g)){
   if(selector!==''&&selector!==(theme==='dark'?'[data-theme=dark]':':not([data-theme=dark])'))continue;
   for(const [,name,value] of body.matchAll(/--([a-z-]+):([^;}]+)/g))palette[name]=value.trim();
  }
  for(const surface of ['bg','panel']){
   const accent=luminance(palette.accent),background=luminance(palette[surface]);
   const contrast=(Math.max(accent,background)+0.05)/(Math.min(accent,background)+0.05);
   assert.ok(contrast>=3,`${theme} ${surface} focus contrast must remain at least 3:1`);
  }
 }
});
