/** Inert source/diagnostic tests; no browser, listener or manager execution. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import test from 'node:test';
import vm from 'node:vm';
import contract from './shell-browser-cases.json' with { type: 'json' };
import { createShellFailureDiagnostic, shellFailureCategories } from './shell-browser-diagnostics.mjs';
import { routeLoadingDevelopmentCaseName } from './route-loading-browser.mjs';
const require = createRequire(new URL('../../web/package.json', import.meta.url)), ts = require('typescript');
const sourceFile = file => ts.createSourceFile(file, fs.readFileSync(new URL(file, import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);

// Read only literal loop domains and test-name expressions; never execute a
// callback, setup function, import side effect or arbitrary source expression.
function namesIn(source) {
    const names = [];
    function value(node, bindings) {
        if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
        if (ts.isIdentifier(node) && Object.hasOwn(bindings, node.text)) return bindings[node.text];
        if (ts.isTemplateExpression(node)) return node.head.text + node.templateSpans.map(span => value(span.expression, bindings) + span.literal.text).join('');
        throw new Error('Unreviewed test-name expression');
    }
    function scan(node, bindings) {
        if (ts.isForOfStatement(node)) {
            // Only loops containing registered test calls affect case IDs.
            let contains = false;
            function find(n) { if (ts.isCallExpression(n) && n.expression.getText(source) === 'test') contains = true; ts.forEachChild(n, find); }
            find(node.statement); if (!contains) return;
            assert.ok(ts.isArrayLiteralExpression(node.expression));
            const binding = node.initializer.declarations[0].name;
            for (const item of node.expression.elements) {
                const next = { ...bindings };
                if (ts.isIdentifier(binding)) next[binding.text] = value(item, bindings);
                else {
                    assert.ok(ts.isArrayBindingPattern(binding) && ts.isArrayLiteralExpression(item));
                    // Only literal label fields are consumed by case names.
                    binding.elements.forEach((element, i) => { if (ts.isStringLiteral(item.elements[i])) next[element.name.text] = item.elements[i].text; });
                }
                scan(node.statement, next);
            }
            return;
        }
        if (ts.isCallExpression(node) && node.expression.getText(source) === 'test') { names.push(value(node.arguments[0], bindings)); return; }
        ts.forEachChild(node, child => scan(child, bindings));
    }
    scan(source, { routeLoadingDevelopmentCaseName });
    return names;
}

test('numeric registry binds the exact ordered source cases including literal loop variants and AI', () => {
    assert.deepEqual(Object.keys(contract), ['schema', 'cases']); assert.equal(contract.schema, 1);
    assert.equal(contract.cases.length, 53); assert.equal(new Set(contract.cases).size, 53);
    const names = ['run.mjs', 'concise-shell-gallery.mjs', 'shell-scenarios.mjs', 'ai-scenarios.mjs', 'focus-contrast-shell.mjs'].flatMap(file => namesIn(sourceFile(file)));
    assert.deepEqual(contract.cases, names);
    assert.deepEqual(shellFailureCategories, ['assertion', 'timeout', 'other']);
    assert.ok(Object.isFrozen(shellFailureCategories));
});

test('failure projection emits only source IDs and closed categories, never error or name strings', () => {
    const diagnostic = createShellFailureDiagnostic(), marker = 'private-dynamic-marker';
    diagnostic.failure(contract.cases[3], { name: 'TimeoutError', message: marker });
    diagnostic.failure(contract.cases[1], { matcherResult: { actual: marker, expected: marker }, message: marker });
    diagnostic.failure(contract.cases[4], { name: marker, message: marker });
    diagnostic.failure(marker, new Error(marker));
    assert.deepEqual(diagnostic.report('a'.repeat(40)), { schema: 1, sourceSha: 'a'.repeat(40), failures: [
        { case: 2, category: 'assertion' }, { case: 4, category: 'timeout' }, { case: 5, category: 'other' },
    ], runtimeCases: [], unknownCase: true });
    const serialized = JSON.stringify(diagnostic.report('a'.repeat(40)));
    assert.equal(serialized.includes(marker), false);
    for (const name of contract.cases) assert.equal(serialized.includes(name), false);
});

test('runtime coordinates deduplicate and sort known IDs while withholding unknown names', () => {
    const diagnostic = createShellFailureDiagnostic();
    for (const name of [contract.cases[44], contract.cases[0], contract.cases[44], 'unregistered-private-marker']) diagnostic.runtime(name);
    assert.deepEqual(diagnostic.report('a'.repeat(40)).runtimeCases, [1, 45]);
    assert.equal(diagnostic.report('a'.repeat(40)).unknownCase, true);
});

test('diagnostic classification cannot replace an original failure even with hostile error getters', () => {
    const diagnostic = createShellFailureDiagnostic();
    diagnostic.failure(contract.cases[0], { get name() { throw new Error('private-marker'); } });
    assert.deepEqual(diagnostic.report('a'.repeat(40)).failures, [{ case: 1, category: 'other' }]);
});

test('actual shell test wrapper keeps failed results and cleanup after passive recording', async () => {
    const source = sourceFile('run.mjs'), wrapper = source.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'test');
    const diagnostic = createShellFailureDiagnostic(), closed = [], disposed = [];
    const globals = { currentTest: '', Date, results: [], console: { log() {} }, sanitize: value => value,
        shellDiagnostic: diagnostic, allPages: new Set([{ close: async () => closed.push(true) }]),
        transportDiagnostics: new Map([[1, { dispose: () => disposed.push(true) }]]) };
    const run = vm.runInNewContext('(' + wrapper.getText(source) + ')', globals);
    await run(contract.cases[1], async () => { throw Object.assign(new Error('inert-marker'), { matcherResult: {} }); });
    assert.equal(globals.results.length, 1); assert.equal(globals.results[0].status, 'FAIL');
    assert.equal(globals.results[0].error, 'inert-marker'); assert.equal(closed.length, 1); assert.equal(disposed.length, 1);
    assert.equal(globals.allPages.size, 0); assert.equal(globals.transportDiagnostics.size, 0);
    assert.deepEqual(diagnostic.report('a'.repeat(40)).failures, [{ case: 2, category: 'assertion' }]);
});

test('only case36 records its closed stage and other cases retain the existing shape', () => {
    const diagnostic = createShellFailureDiagnostic();
    diagnostic.failure(contract.cases[35], new Error('inert-marker'));
    diagnostic.failure(contract.cases[34], new Error('inert-marker'));
    assert.deepEqual(diagnostic.report('a'.repeat(40)).failures, [
        { case: 35, category: 'other' }, { case: 36, category: 'other', stage: 0 },
    ]);
});

test('actual case36 callback waits for both content assertions before its original keyboard sequence', async () => {
    const source = sourceFile('shell-scenarios.mjs');
    let callback;
    function find(node) {
        if (ts.isCallExpression(node) && node.expression.getText(source) === 'test' && node.arguments[0]?.text === contract.cases[35]) callback = node.arguments[1];
        ts.forEachChild(node, find);
    }
    find(source); assert.ok(callback);
    let releaseHeading, releaseNotes;
    const heading = new Promise(resolve => { releaseHeading = resolve; }), notes = new Promise(resolve => { releaseNotes = resolve; });
    const events = [], keys = [];
    const locator = selector => ({ selector, filter() { return this; }, click: async () => {}, scrollIntoViewIfNeeded: async () => {} });
    const page = { locator, getByRole: (_role, options) => locator(options.name), keyboard: { press: async key => keys.push(key) }, evaluate: async () => 'main-content' };
    const expect = target => ({
        toHaveText: async (title, options) => { assert.equal(target.selector, '.case-detail-header h1'); assert.equal(title, 'Synthetic title'); assert.equal(options.timeout, 10000); events.push('heading-wait'); await heading; },
        toBeVisible: async options => { if (target.selector === '.notes-panel') { assert.equal(options.timeout, 10000); events.push('notes-wait'); await notes; } },
        toBeFocused: async () => {}, toBe: value => assert.equal(target, value), not: { toHaveClass: async () => {} },
    });
    expect.poll = () => ({ toBeGreaterThan: async () => {} });
    const globals = { keyboardStage: 0, caseItem: { id: 'synthetic', title: 'Synthetic title' },
        pageAt: async (_route, viewport) => { assert.equal(viewport.width, 720); assert.equal(viewport.height, 500); return page; },
        loaded: async () => events.push('footer'), bounds: async () => events.push('bounds'), expect };
    const run = vm.runInNewContext('(' + callback.getText(source) + ')', globals);
    const pending = run(); await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(events, ['footer', 'heading-wait']); assert.deepEqual(keys, []); assert.equal(globals.keyboardStage, 1);
    releaseHeading(); await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(events, ['footer', 'heading-wait', 'notes-wait']); assert.deepEqual(keys, []);
    releaseNotes(); await pending;
    assert.deepEqual(keys, ['Tab', 'Enter', 'PageDown']); assert.equal(globals.keyboardStage, 9);
    assert.equal(events.filter(event => event === 'bounds').length, 3);
});

// The real helper and real failure collector are exercised with fabricated
// browser evidence. These are inert control-flow tests, never rendered proof.
import { numericTypographyReview, shellGalleryCheckpoint, shellGalleryFailureCoordinate, shellGallerySurfaces, shellGalleryPhases } from './concise-shell-gallery.mjs';
const { expect: browserExpect } = require('@playwright/test');
const numericEvidence = () => ({ role: 'summary', font: { weight: '600', style: 'normal', family: 'Inter, sans-serif', numeric: 'tabular-nums' }, loadedInter: true,
 originalText: '6', restoredText: '6', sameTextNode: true, restoredMarkup: true, restoredStyle: true, spans: [{ numeric: 'normal' }],
 frames: [0, 1].map(() => ({ number: { x: 0, width: 24 }, container: { x: 0, width: 80 }, spans: [{ x: 30, width: 12 }], sibling: { x: 90, width: 10 } })), proportionalControl: [15, 25] });

test('actual numeric assertions retain precise closed phases without changing failure identity', async () => {
 const failures = [
  ['font-role', e => { e.font.weight = '400'; }], ['font-role', e => { e.font.style = 'italic'; }],
  ['loaded-face', e => { e.loadedInter = false; }], ['font-family', e => { e.font.family = 'serif'; }],
  ['numeric-mode', e => { e.font.numeric = 'normal'; }], ['restoration-text', e => { e.restoredText = '7'; }],
  ['restoration-node', e => { e.sameTextNode = false; }], ['restoration-markup', e => { e.restoredMarkup = false; }], ['restoration-style', e => { e.restoredStyle = false; }],
  ['span-mode', e => { e.spans[0].numeric = 'tabular-nums'; }], ['text-geometry', e => { e.frames[1].number.width++; }], ['text-geometry', e => { e.frames[1].number.x++; }],
  ['container-geometry', e => { e.frames[1].container.width++; }], ['container-geometry', e => { e.frames[1].container.x++; }],
  ['span-geometry', e => { e.frames[1].spans[0].x++; }], ['span-geometry', e => { e.frames[1].spans[0].width++; }],
  ['sibling-geometry', e => { e.frames[1].sibling.x++; }], ['sibling-geometry', e => { e.frames[1].sibling.width++; }],
  ['proportional-control', e => { e.proportionalControl = [24, 24]; }],
 ];
 for (const [phase, mutate] of failures) {
  const evidence = numericEvidence(); mutate(evidence); let evaluations = 0, captured = false, original;
  const target = { first() { return this; }, async evaluate() { return ++evaluations === 1 ? undefined : evidence; } };
  const expect = value => value === target ? { async toBeVisible() {} } : new Proxy(browserExpect(value), { get(object, key) {
   const member = object[key]; return typeof member === 'function' ? (...args) => { try { return member(...args); } catch (error) { original = error; throw error; } } : member;
  } });
  await assert.rejects(numericTypographyReview({ page: { locator: () => target }, expect, capture: async () => { captured = true; }, name: 'summary', selector: '.summary-strip strong', section: '.summary-strip', locale: 'en' }), error => error === original);
  assert.equal(captured, false);
  const diagnostic = createShellFailureDiagnostic(); diagnostic.failure(contract.cases[27], original);
  assert.deepEqual(diagnostic.report('a'.repeat(40)).failures, [{ case: 28, category: 'assertion', surface: shellGallerySurfaces.indexOf('summary'), phase: shellGalleryPhases.indexOf(phase) }]);
 }
});

test('actual screenshot producer locates source and artifact boundaries and rethrows the original failure', async () => {
 const source = sourceFile('run.mjs'), shot = source.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'shot');
 assert.ok(shot);
 for (const phase of ['capture-position', 'screenshot', 'source-sha', 'source-head', 'source-clean', 'source-tree', 'font-resources', 'font-count', 'font-hashes', 'screenshot-hash', null]) {
  const original = new Error('Synthetic source-boundary failure'), screenshots = []; let observed;
  const locator = { evaluate: async () => ({}), getAttribute: async () => 'synthetic' };
  const page = { getByRole: () => ({ count: async () => { if (phase === 'capture-position') throw original; return 0; } }), locator: () => locator,
   screenshot: async () => { if (phase === 'screenshot') throw original; },
   evaluate: async () => { if (phase === 'font-resources') throw original; return phase === 'font-count' ? [] : ['/assets/inter.woff2']; }, viewportSize: () => ({ width: 1440, height: 1000 }) };
  const expect = value => new Proxy(browserExpect(value), { get(object, key) { const member = object[key]; return typeof member === 'function' ? (...args) => { try { return member(...args); } catch (error) { observed = error; throw error; } } : member; } });
  const globals = { shellGalleryCheckpoint, expect, performance, sourceSha: phase === 'source-sha' ? 'invalid' : 'a'.repeat(40), root: '/synthetic/repository', out: '/synthetic/review', currentTest: 'synthetic', screenshots,
   path: require('node:path'), createHash: require('node:crypto').createHash, browser: { version: () => '1.2.3' }, transportDiagnostics: new Map(), reportTransportFailure() {},
   fs: { readFile: async file => { if (phase === 'font-hashes' && file.includes('web/dist') || phase === 'screenshot-hash' && file.includes('/review/')) throw original; return Buffer.from('synthetic bytes'); } },
   execFileSync: (_command, args) => { if (args[0] === 'diff') { if (phase === 'source-clean') throw original; return ''; } if (args[1] === 'HEAD') return phase === 'source-head' ? 'b'.repeat(40) : 'a'.repeat(40); if (phase === 'source-tree') throw original; return 'c'.repeat(40); } };
  shellGalleryCheckpoint('original-scene', 'summary');
  const run = vm.runInNewContext('(' + shot.getText(source) + ')', globals);
  if (phase) {
   await assert.rejects(run(page, 'synthetic-concise-shell-numeric-summary-desktop-en', '.summary-strip', numericEvidence()), error => error === (observed ?? original));
   assert.equal(screenshots.length, 0); assert.equal(shellGalleryFailureCoordinate().phase, shellGalleryPhases.indexOf(phase));
  } else { await run(page, 'synthetic-concise-shell-numeric-summary-desktop-en', '.summary-strip', numericEvidence()); assert.equal(screenshots.length, 1); assert.equal(shellGalleryFailureCoordinate().phase, shellGalleryPhases.indexOf('manifest')); }
 }
});

test('gallery coordinates snapshot only cases 28–31 and invalid coordinate inputs never leak', () => {
 const diagnostic = createShellFailureDiagnostic(); shellGalleryCheckpoint('font-hashes', 'device-details');
 for (let id = 28; id <= 31; id++) diagnostic.failure(contract.cases[id - 1], { matcherResult: {} });
 shellGalleryCheckpoint('private-phase', 'private-surface');
 diagnostic.failure(contract.cases[31], { matcherResult: {} });
 const report = diagnostic.report('a'.repeat(40));
 for (const row of report.failures.slice(0, 4)) assert.deepEqual(row, { case: row.case, category: 'assertion', surface: shellGallerySurfaces.indexOf('device-details'), phase: shellGalleryPhases.indexOf('font-hashes') });
 assert.deepEqual(report.failures[4], { case: 32, category: 'assertion' });
 assert.equal(JSON.stringify(report).includes('private-'), false);
 assert.deepEqual(shellGalleryFailureCoordinate(), { surface: -1, phase: -1 });
});

test('target, font-load and in-page measurement failures retain their original error and phase', async () => {
 for (const phase of ['target-visible', 'font-load', 'measure']) {
  const original = new Error('Synthetic early probe failure'); let count = 0;
  const target = { first() { return this; }, async evaluate() { count++; if (count === (phase === 'font-load' ? 1 : 2)) throw original; } };
  const expect = value => { assert.equal(value, target); return { async toBeVisible() { if (phase === 'target-visible') throw original; } }; };
  await assert.rejects(numericTypographyReview({ page: { locator: () => target }, expect, capture: async () => assert.fail('Unexpected capture'), name: 'summary', selector: '.summary-strip strong', section: '.summary-strip', locale: 'en' }), error => error === original);
  assert.deepEqual(shellGalleryFailureCoordinate(), { surface: shellGallerySurfaces.indexOf('summary'), phase: shellGalleryPhases.indexOf(phase) });
 }
});


test('restoration subphase names only the first failed invariant and preserves the combined guard', async () => {
 const fields = ['sameTextNode', 'restoredMarkup', 'restoredStyle'], phases = ['restoration-node', 'restoration-markup', 'restoration-style'];
 for (let mask = 1; mask < 8; mask++) {
  const evidence = numericEvidence(); let evaluations = 0, captured = false;
  fields.forEach((field, index) => { if (mask & (1 << index)) evidence[field] = false; });
  const target = { first() { return this; }, async evaluate() { return ++evaluations === 1 ? undefined : evidence; } };
  const expect = value => value === target ? { async toBeVisible() {} } : browserExpect(value);
  await assert.rejects(numericTypographyReview({ page: { locator: () => target }, expect, capture: async () => { captured = true; }, name: 'summary', selector: '.summary-strip strong', section: '.summary-strip', locale: 'en' }));
  assert.equal(captured, false);
  const first = fields.findIndex(field => !evidence[field]);
  assert.equal(shellGalleryFailureCoordinate().phase, shellGalleryPhases.indexOf(phases[first]));
 }
 const source = fs.readFileSync(new URL('concise-shell-gallery.mjs', import.meta.url), 'utf8');
 assert.ok(source.includes('expect(evidence.sameTextNode && evidence.restoredMarkup && evidence.restoredStyle).toBe(true)'));
});

// Source-grounded model of Blink's lazy style-attribute storage, not a browser
// implementation or rendered proof. Chromium 145.0.7632.6 element.cc:
// RemoveAttributeHinted, RemoveAllInlineStyleProperties, InlineStyleChanged,
// InvalidateStyleAttribute, SynchronizeStyleAttributeInternal, GetAttributeHinted.
// https://raw.githubusercontent.com/chromium/chromium/145.0.7632.6/third_party/blink/renderer/core/dom/element.cc
function modelLazyStyleAttribute(element) {
 const get = element.getAttribute.bind(element), set = element.setAttribute.bind(element), remove = element.removeAttribute.bind(element);
 const declaration = element.ownerDocument.createElement('div').style;
 declaration.cssText = get('style') ?? '';
 let dirty = false;
 Object.defineProperty(element, 'style', { value: new Proxy(declaration, {
  set(target, key, value) { Reflect.set(target, key, value, target); dirty = true; return true; },
 }) });
 element.getAttribute = name => {
  if (name === 'style' && dirty) { set(name, declaration.cssText); dirty = false; }
  return get(name);
 };
 element.setAttribute = (name, value) => {
  set(name, value);
  if (name === 'style') { declaration.cssText = value; dirty = false; }
 };
 element.removeAttribute = name => {
  if (name !== 'style') return remove(name);
  if (get(name) === null) {
   if (dirty) declaration.cssText = ''; // Clearing declarations leaves it dirty.
   return;
  }
  remove(name); declaration.cssText = ''; dirty = false;
 };
}

test('lazy-style model distinguishes absent from empty and requires synchronization before removal', () => {
 const { JSDOM } = require('jsdom'), dom = new JSDOM('<strong>6</strong>');
 try {
  const element = dom.window.document.querySelector('strong'); modelLazyStyleAttribute(element);
  assert.equal(element.getAttribute('style'), null);
  element.style.fontVariantNumeric = 'normal'; element.removeAttribute('style');
  assert.equal(element.getAttribute('style'), ''); // The old finally path fails exact null equality.
  element.removeAttribute('style'); assert.equal(element.getAttribute('style'), null);
  element.style.fontVariantNumeric = 'normal'; element.getAttribute('style'); element.removeAttribute('style');
  assert.equal(element.getAttribute('style'), null);
 } finally { dom.window.close(); }
});

function assertSameChildNodes(element, originalNodes) {
 const restoredNodes = [...element.childNodes];
 assert.equal(restoredNodes.length, originalNodes.length);
 restoredNodes.forEach((node, index) => assert.equal(node, originalNodes[index]));
}

test('restoration fixture rejects cloned numeric, unit and quality nodes', () => {
 const { JSDOM } = require('jsdom'), dom = new JSDOM('<div>6<span>MiB</span><span>Stale</span></div>');
 try {
  const element = dom.window.document.querySelector('div'), nodes = [...element.childNodes];
  for (const node of nodes) {
   const clone = node.cloneNode(true); element.replaceChild(clone, node);
   assert.throws(() => assertSameChildNodes(element, nodes));
   element.replaceChild(node, clone); assertSameChildNodes(element, nodes);
  }
 } finally { dom.window.close(); }
});

test('actual numeric probe restores exact DOM bytes and failure identity with eager and lazy inline styles', async () => {
 const { JSDOM } = require('jsdom');
 const globals = ['document', 'Node', 'getComputedStyle'].map(key => [key, Object.getOwnPropertyDescriptor(globalThis, key)]);
 let count = 0;
 try {
  for (const lazy of [false, true]) for (const role of ['summary', 'compact', 'expanded']) for (const locale of ['en', 'de'])
   for (const originalStyle of [null, '', ' color : red; --original:  3 !important; ']) for (const failure of [null, 2, 3, 'capture']) {
    const dom = new JSDOM('<!doctype html><body></body>');
    try {
     const d = dom.window.document, holder = d.createElement('div');
     holder.className = role === 'summary' ? 'summary-strip' : `metric ${role === 'compact' ? 'compact' : ''}`;
     const element = d.createElement(role === 'summary' ? 'strong' : 'div'); element.className = 'metric-value'; holder.append(element); d.body.append(holder);
     const number = d.createTextNode(locale === 'de' ? ' 1.234,5 ' : ' 1,234.5 '); element.append(number);
     if (role !== 'summary') { const unit = d.createElement('span'); unit.textContent = 'MiB / s'; element.append(unit); }
     if (role === 'expanded') { const quality = d.createElement('span'); quality.textContent = locale === 'de' ? 'Veraltet' : 'Stale'; element.append(quality); }
     const sibling = d.createElement('span'); sibling.textContent = 'Synthetic subtitle'; holder.append(sibling);
     if (originalStyle !== null) element.setAttribute('style', originalStyle);
     if (lazy) modelLazyStyleAttribute(element);
     const originalText = number.data, html = element.innerHTML, outer = holder.innerHTML, nodes = [...element.childNodes];
     const restored = () => {
      assert.equal(number.data, originalText); assert.equal(number.parentNode, element);
      assert.equal(element.getAttribute('style'), originalStyle); assert.equal(element.innerHTML, html);
      assertSameChildNodes(element, nodes); assert.equal(holder.innerHTML, outer);
     };
     const weight = { summary: '600', compact: '400', expanded: '500' }[role];
     // All font/geometry values below are fabricated control-flow fixtures.
     const computed = node => ({ fontFamily: 'Inter, sans-serif', fontWeight: weight, fontStyle: 'normal', fontSize: '24px', letterSpacing: '0px',
      fontVariantNumeric: node === element ? element.style.fontVariantNumeric || 'tabular-nums' : 'normal', fontFeatureSettings: 'normal' });
     const width = () => [...number.data].reduce((sum, character) => sum + (/[0-9]/.test(character) ? (computed(element).fontVariantNumeric === 'tabular-nums' ? 8 : character === '1' ? 5 : 9) : 3), 0);
     element.getBoundingClientRect = () => ({ x: 20, width: width() + 50 });
     for (const span of element.children) span.getBoundingClientRect = () => ({ x: 20 + width(), width: 20 });
     sibling.getBoundingClientRect = () => ({ x: 20 + width() + 50, width: 30 });
     const originalFailure = new Error('Injected synthetic probe failure'); let measurements = 0, captured = false;
     d.createRange = () => ({ selectNodeContents: node => assert.equal(node, number), getBoundingClientRect() {
      if (++measurements === failure) throw originalFailure; return { x: 20, width: width() };
     } });
     const fonts = [{ family: 'Inter', weight, status: 'loaded' }]; fonts.load = async () => {}; fonts.ready = Promise.resolve();
     Object.defineProperty(d, 'fonts', { value: fonts }); globalThis.document = d; globalThis.Node = dom.window.Node; globalThis.getComputedStyle = computed;
     const target = { first() { return this; }, evaluate: (callback, argument) => callback(element, argument) };
     const expect = value => value === target ? { async toBeVisible() {} } : browserExpect(value);
     const capture = async (_name, _section, evidence) => {
      captured = true; restored(); assert.equal(evidence.restoredStyle, true); assert.equal(evidence.role, role);
      assert.deepEqual(evidence.claims, { liveReactUpdate: false, cls: false, loadingImprovement: false, nativeZoom: false });
      if (failure === 'capture') throw originalFailure;
     };
     const task = numericTypographyReview({ page: { locator: () => target }, expect, capture, name: role, selector: '.metric-value', section: '.metric', locale, decimal: role === 'expanded' });
     if (failure === null) await task; else await assert.rejects(task, error => error === originalFailure);
     restored(); assert.equal(captured, failure === null || failure === 'capture'); count++;
    } finally { dom.window.close(); }
   }
 } finally {
  for (const [key, descriptor] of globals) { if (descriptor) Object.defineProperty(globalThis, key, descriptor); else delete globalThis[key]; }
 }
 assert.equal(count, 144);
});

// Newly integrated contrast cases keep original diagnostic IDs stable.
test('all eight contrast scenarios are source-bound diagnostics without raw text', () => {
 const diagnostic = createShellFailureDiagnostic();
 for (const name of contract.cases.slice(45)) diagnostic.failure(name, { matcherResult: {} });
 const report = diagnostic.report('a'.repeat(40));
 assert.deepEqual(report.failures, Array.from({length: 8}, (_, i) => ({case: 46+i, category: 'assertion'})));
 assert.equal(report.unknownCase, false);
});
