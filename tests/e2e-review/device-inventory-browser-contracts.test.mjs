/** Exact browser-selector/copy contracts. Pure source checks; no browser, server,
 * native collection, private endpoint data or network access is started. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';
import { createHash } from 'node:crypto';
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

// Execute the exact callback chain without starting run.mjs (which owns a
// browser/manager). This proves capture positioning, never rendered pixels.
function keyboardCaptureHarness({ locale = 'en', size = 'desktop', dark = false, wrongHead = false, dirtySource = false, emptyFonts = false } = {}) {
 const gallery = read('./concise-shell-gallery.mjs'), runner = read('./run.mjs');
 const helper = gallery.slice(gallery.indexOf('async function inventoryKeyboardReview('), gallery.indexOf('export function conciseShellFixture('));
 const capture = gallery.match(/   const capture = async [\s\S]*?\n   };/)?.[0];
 const darkCallback = gallery.match(/capture: (\(name, section[^)]*\) => capture\(`\$\{name\}-dark`[^;]*?), locale, size/)?.[1];
 const shot = runner.slice(runner.indexOf('async function shot('), runner.indexOf('async function noOverflow('));
 assert.ok(helper && capture && darkCallback && shot);
 const calls = [], screenshots = [], pressed = [], phases = [], gitCalls = [], main = { scrollTop: 240, scrollTo: () => { calls.push('reset'); main.scrollTop = 0; }, getBoundingClientRect: () => ({ width: 1200, height: 940 }) };
 const labels = locale === 'de' ? ['Geräte durchsuchen', 'Nach Betriebssystem filtern', 'Nach Status filtern', 'Ansicht speichern', 'Geräte sortieren'] : ['Search devices', 'Filter by operating system', 'Filter by status', 'Save view', 'Sort devices'];
 let focused = 0, saved = false;
 const nodes = labels.map((name, index) => ({ name, index, matches: value => value === ':focus-visible', focus: async () => { focused = index; }, evaluate: async reader => reader(nodes[index]), locator: () => ({ hidden: size === 'mobile' }) }));
 const page = {
  keyboard: { press: async key => { pressed.push(key); if (key === 'Tab') focused++; else { assert.equal(key, 'Enter'); assert.equal(focused, 3); saved = true; } } },
  getByRole: (role, options) => role === 'dialog' ? { count: async () => 0 } : nodes.find(node => node.name === options.name),
  evaluate: async reader => reader.toString().includes('performance.getEntriesByType') ? emptyFonts ? [] : ['/assets/inert-font.woff2'] : reader(),
  locator: selector => selector === '.save-view' ? nodes[3] : selector === 'html' ? { getAttribute: async name => name === 'lang' ? locale : dark ? 'dark' : 'light' } : {
   evaluate: async reader => reader(selector === '.main-content' ? main : { scrollIntoView: () => { calls.push('align'); main.scrollTop = 620; } }),
  },
  viewportSize: () => size === 'mobile' ? { width: 390, height: 844 } : { width: 1440, height: 1000 },
  screenshot: async options => { assert.equal(options.fullPage, false); assert.equal(options.animations, 'disabled'); calls.push({ top: main.scrollTop, focused, file: options.path }); },
 };
 const expect = actual => ({
  toMatch: expected => assert.match(actual, expected), toBeGreaterThan: expected => assert.ok(actual > expected),
  toBe: expected => assert.equal(actual, expected), toEqual: expected => assert.equal(JSON.stringify(actual), JSON.stringify(expected)),
  toBeFocused: () => assert.equal(focused, actual.index), toBeInViewport: () => assert.ok(actual.index > 0),
  toHaveAccessibleName: expected => assert.equal(saved && actual.index === 3 ? locale === 'de' ? 'Gespeichert' : 'Saved' : actual.name, expected),
  toHaveAttribute: (name, expected) => { assert.equal(name, 'aria-label'); assert.equal(saved ? locale === 'de' ? 'Gespeichert' : 'Saved' : labels[3], expected); },
  toBeHidden: () => assert.equal(actual.hidden, true), toBeVisible: () => assert.equal(actual.hidden, false),
 });
 const context = { shellGalleryCheckpoint: phase => phases.push(phase), root: 'inert-source', createHash, browser: { version: () => 'inert-version' }, fs: { readFile: async () => Buffer.from('inert-source-bound-bytes') },
  execFileSync: (command, args) => { assert.equal(command, 'git'); gitCalls.push(args); if (args[0] === 'diff') { assert.deepEqual([...args], ['diff', '--quiet', 'a'.repeat(40), '--']); if (dirtySource) throw new Error('Dirty source'); return ''; } assert.equal(args[0], 'rev-parse'); return args[1] === 'HEAD' ? (wrongHead ? 'c' : 'a').repeat(40) : 'b'.repeat(40); },
  page, expect, locale, size, dark, screenshots, sourceSha: 'a'.repeat(40), currentTest: 'inert keyboard capture', out: 'inert-no-output', path: { join: (...parts) => parts.join('/') }, performance, transportDiagnostics: new Map(), reportTransportFailure: () => assert.fail('Unexpected screenshot failure'), innerWidth: 1440, innerHeight: 1000, document: { documentElement: { scrollWidth: 390, clientWidth: 1440, clientHeight: 1000 }, body: { scrollWidth: 390 } }, getComputedStyle: () => ({ outlineStyle: 'solid', outlineWidth: '2px', outlineOffset: '2px', outlineColor: '#17b8a6' }) };
 const chain = vm.runInNewContext(`${shot}\n${helper}\n${capture}\n({ run: () => inventoryKeyboardReview({ page, expect, capture: dark ? ${darkCallback} : capture, locale, size }), ordinary: () => shot(page, 'ordinary-inventory', '.inventory-meta'), numeric: (evidence, options) => capture('numeric-summary', '.summary-strip', evidence, options) })`, context);
 return { ...chain, calls, screenshots, pressed, phases, gitCalls };
}
test('every EN/DE light/dark desktop/mobile keyboard capture preserves the exact checked landing', async () => {
 for (const locale of ['en', 'de']) for (const size of ['desktop', 'mobile']) for (const dark of [false, true]) {
  const probe = keyboardCaptureHarness({ locale, size, dark }); await probe.run();
  assert.equal(probe.calls.length, 4, 'no reset or section alignment may run after keyboard assertions');
  assert.deepEqual(probe.calls.map(call => [call.top, call.focused]), [[240, 1], [240, 2], [240, 3], [240, 4]]);
  assert.deepEqual(probe.pressed, ['Tab', 'Tab', 'Tab', 'Enter', 'Tab']);
  assert.equal(probe.screenshots.length, 4); assert.equal(probe.gitCalls.length, 0);
  assert.ok(probe.screenshots.every(shot => !Object.hasOwn(shot, 'numericTypography')));
  for (const shot of probe.screenshots) { assert.equal(shot.sourceSha, 'a'.repeat(40)); assert.equal(shot.contentScrollTop, 240); assert.equal(shot.fullPage, false); assert.equal(shot.publicSafe, true); }
  assert.ok(probe.screenshots.at(-1).file.includes(`devices-sort-keyboard-focus${dark ? '-dark' : ''}-${size}-${locale}`));
 }
});
test('ordinary inventory captures retain their original top reset and explicit section alignment', async () => {
 const probe = keyboardCaptureHarness(); await probe.ordinary();
 assert.equal(probe.calls[0], 'reset'); assert.equal(probe.calls[1], 'align'); assert.equal(probe.calls[2].top, 620);
 assert.equal(probe.screenshots[0].section, '.inventory-meta'); assert.equal(probe.screenshots[0].contentScrollTop, 620);
});

test('numeric evidence and keyboard positioning retain separate argument slots through the real capture chain', async () => {
 for (const preserveScroll of [false, true]) {
  const probe = keyboardCaptureHarness(), evidence = { role: 'summary', synthetic: true };
  await probe.numeric(evidence, { preserveScroll });
  const shot = probe.screenshots[0]; assert.equal(shot.numericTypography, evidence);
  assert.equal(shot.contentScrollTop, preserveScroll ? 240 : 620); assert.equal(shot.sourceTree, 'b'.repeat(40));
  assert.equal(shot.fontAssets[0].asset, '/assets/inert-font.woff2');
  const digest = createHash('sha256').update('inert-source-bound-bytes').digest('hex');
  assert.equal(shot.fontAssets[0].sha256, digest); assert.equal(shot.sha256, digest); assert.equal(shot.browserVersion, 'inert-version');
  assert.match(shot.fixtureDisclosure, /temporary numeric-text shaping probe restored/);
  assert.equal(probe.gitCalls.length, 3); assert.ok(probe.phases.includes('source-clean')); assert.ok(probe.phases.includes('font-hashes'));
 }
});
test('numeric source-head, source-clean and loaded-font guards still reject before adding evidence', async () => {
 for (const options of [{ wrongHead: true }, { dirtySource: true }, { emptyFonts: true }]) {
  const probe = keyboardCaptureHarness(options);
  await assert.rejects(probe.numeric({ role: 'summary', synthetic: true }, { preserveScroll: true }));
  assert.equal(probe.screenshots.length, 0);
 }
});
