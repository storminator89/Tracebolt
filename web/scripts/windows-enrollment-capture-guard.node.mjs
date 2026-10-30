/** Inert DOM/event/animation adapters. Never starts a browser or reads a host. */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createCaptureGuard } from './windows-enrollment-capture-guard.mjs';
function guardHarness(options = {}) {
 const callbacks = new Map(), frames = new Map(); let observer, id = 0, now = 0;
 const eventTarget = () => ({
  addEventListener(name, callback) { callbacks.set(this.kind + name, callback); },
  removeEventListener(name) { callbacks.delete(this.kind + name); },
 });
 const fonts = { ...eventTarget(), kind: 'fonts', status: 'loaded' };
 const sheet = { disabled: false, media: { mediaText: '' }, cssRules: [{ cssText: 'p { color: black; }' }] };
 const document = { ...eventTarget(), kind: 'document', visibilityState: 'visible', fonts, adoptedStyleSheets: [], styleSheets: [sheet], getAnimations: () => options.animations ?? [] };
 const window = { ...eventTarget(), kind: 'window' };
 const root = { isConnected: true, ownerDocument: document, getRootNode: () => document };
 const MutationObserver = class {
  constructor(callback) { observer = this; this.callback = callback; this.records = []; this.disconnected = false; }
  observe(target, options) { assert.equal(target, document); assert.deepEqual(options, { subtree: true, childList: true, attributes: true, characterData: true }); }
  takeRecords() { return this.records.splice(0); }
  disconnect() { this.disconnected = true; this.records = []; }
 };
 const requestAnimationFrame = callback => { frames.set(++id, callback); return id; };
 const cancelAnimationFrame = key => frames.delete(key);
 const run = new Function('document', 'window', 'MutationObserver', 'requestAnimationFrame', 'cancelAnimationFrame', 'performance', `return (${createCaptureGuard.toString()});`)(document, window, options.noObserver ? undefined : MutationObserver, requestAnimationFrame, cancelAnimationFrame, { now: () => now });
 return { create: () => run(root), document, root, sheet, options,
  event(name, target = 'document') { callbacks.get(target + name)?.(); },
  mutation(deliver = true) { if (deliver) observer.callback([{ type: 'attributes' }]); else observer.records.push({ type: 'attributes' }); },
  tick() { const current = [...frames.values()]; frames.clear(); current.forEach(callback => callback()); },
  time(value) { now = value; }, clean: () => observer?.disconnected && frames.size === 0 && callbacks.size === 0,
 };
}
test('capture guard accepts unchanged static state, returns only a boolean and cleans up idempotently', () => {
 const h = guardHarness(), guard = h.create(); assert.equal(guard.check(), true); h.tick(); assert.equal(guard.check(), true);
 guard.dispose(); guard.dispose(); assert(h.clean()); assert.equal(guard.check(), false);
});
test('any mutation including an open-then-close reversal dirties the whole capture interval', () => {
 for (const deliver of [false, true]) {
  const h = guardHarness(), guard = h.create(); h.mutation(deliver); h.mutation(deliver);
  assert.equal(guard.check(), false); assert.equal(guard.check(), false); guard.dispose(); assert(h.clean());
 }
});
test('active paused pending and unknown animation states fail closed before capture', () => {
 for (const animation of [{ pending: false, playState: 'running' }, { pending: false, playState: 'paused' }, { pending: true, playState: 'finished' }, { pending: false, playState: 'unknown' }, { playState: 'finished' }]) {
  const h = guardHarness({ animations: [animation] }); assert.throws(() => h.create(), /Unsupported synthetic capture guard/); assert(h.clean());
 }
 for (const playState of ['finished', 'idle']) { const h = guardHarness({ animations: [{ pending: false, playState }] }), guard = h.create(); assert(guard.check()); guard.dispose(); }
});
test('CSS animation and transition events and per-frame WAAPI checks cover transient interval changes', () => {
 for (const name of ['animationstart', 'animationiteration', 'animationend', 'animationcancel', 'transitionrun', 'transitionstart', 'transitionend', 'transitioncancel']) {
  const h = guardHarness(), guard = h.create(); h.event(name); assert.equal(guard.check(), false); guard.dispose();
 }
 const h = guardHarness(), guard = h.create(); h.options.animations = [{ pending: false, playState: 'running' }]; h.tick(); h.options.animations = []; assert.equal(guard.check(), false); guard.dispose();
});
test('stylesheet source identity disabled state media rules and adopted sheets are rechecked', () => {
 for (const change of [h => { h.sheet.disabled = true; }, h => { h.sheet.media.mediaText = 'print'; }, h => { h.sheet.cssRules[0].cssText = 'p { display: none; }'; }, h => { h.document.styleSheets = [{ ...h.sheet }]; }, h => { h.document.styleSheets = []; }, h => { h.document.adoptedStyleSheets = [{}]; }]) {
  const h = guardHarness(), guard = h.create(); change(h); assert.equal(guard.check(), false); guard.dispose();
 }
 const h = guardHarness(), guard = h.create(); h.sheet.disabled = true; h.tick(); h.sheet.disabled = false; assert.equal(guard.check(), false); guard.dispose();
});
test('guard fails closed on detached roots lifecycle events fonts errors and bounded resource limits', () => {
 for (const change of [h => { h.root.isConnected = false; }, h => { h.root.ownerDocument = {}; }, h => { h.root.getRootNode = () => ({}); }, h => { h.document.visibilityState = 'hidden'; }, h => { h.document.fonts.status = 'loading'; }, h => { h.time(10001); }, h => { h.time(NaN); }, h => { h.time(-1); }, h => { h.document.styleSheets = Array(33).fill(h.sheet); }, h => { h.sheet.cssRules = Array(8193).fill({ cssText: 'x' }); }, h => { h.sheet.cssRules = [{ cssText: 'x'.repeat((1 << 20) + 1) }]; }, h => { h.options.animations = Array(257).fill({ pending: false, playState: 'idle' }); }, h => { h.document.getAnimations = () => { throw new Error('private'); }; }, h => { Object.defineProperty(h.sheet, 'cssRules', { get() { throw new Error('private'); } }); }]) {
  const h = guardHarness(), guard = h.create(); change(h); assert.equal(guard.check(), false); guard.dispose(); assert(h.clean());
 }
 for (const [name, target] of [['visibilitychange', 'document'], ['pagehide', 'window'], ['loading', 'fonts'], ['loadingdone', 'fonts'], ['loadingerror', 'fonts']]) { const h = guardHarness(), guard = h.create(); h.event(name, target); assert.equal(guard.check(), false); guard.dispose(); }
 const h = guardHarness(), guard = h.create(); for (let n = 0; n < 601; n++) h.tick(); assert.equal(guard.check(), false); guard.dispose();
 assert.throws(() => guardHarness({ noObserver: true }).create(), /Unsupported synthetic capture guard/);
});
