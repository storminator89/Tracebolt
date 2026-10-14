/** Failure-only observations of fixed synthetic fixtures. Never capture evidence.
 * The original controls and production privacy predicate remain authoritative. */
import assert from 'node:assert/strict';
import { publicSafeFailures, requireHosted, visibilityControlCases, visibilityControlPrivacyStages, visibilityControlStage } from './windows-enrollment-contract.mjs';
import { controlRoute, controlURL, runVisibilityControls as originalControls } from './windows-enrollment-visibility-controls.mjs';

export const geometryDiagnosticBudgetMs = 15000;
const schema = 'synthetic-visibility-geometry.v1';
const signals = new WeakMap(), results = new WeakMap();
const geometryKinds = ['positive', 'empty', 'error'];
const unavailableReasons = ['budget', 'setup', 'measurement', 'privacy', 'runtime', 'route', 'cleanup'];
const rowKeys = ['name', 'initialElementRange', 'ownBox', 'textNodeRange', 'repeatElementRange', 'native', 'privacy', 'privacyLast'];
const sorted = values => [...values].sort();
const unavailable = reason => ({ schema, status: 'unavailable', reason });

export function registerVisibilityDiagnosticSignal(browser, signal) {
 assert(signal && typeof signal.aborted === 'boolean' && typeof signal.addEventListener === 'function');
 signals.set(browser, signal); results.delete(browser);
}
export function validateVisibilityDiagnostic(value) {
 assert(value && typeof value === 'object' && !Array.isArray(value));
 assert.equal(value.schema, schema);
 if (value.status === 'unavailable') {
  assert.deepEqual(sorted(Object.keys(value)), sorted(['schema', 'status', 'reason']));
  assert(unavailableReasons.includes(value.reason)); return value;
 }
 assert.equal(value.status, 'complete');
 assert.deepEqual(sorted(Object.keys(value)), sorted(['schema', 'status', 'probes', 'contexts', 'documents', 'screenshots', 'exceptionPath']));
 assert.equal(value.contexts, 15); assert.equal(value.documents, 15); assert.equal(value.screenshots, 0);
 assert.equal(value.exceptionPath, 'not-observed');
 assert(Array.isArray(value.probes)); assert.equal(value.probes.length, 15);
 for (const [index, row] of value.probes.entries()) {
  assert(row && typeof row === 'object' && !Array.isArray(row));
  assert.deepEqual(sorted(Object.keys(row)), sorted(rowKeys)); assert.equal(row.name, visibilityControlCases[index]);
  for (const field of ['initialElementRange', 'ownBox', 'textNodeRange', 'repeatElementRange']) assert(geometryKinds.includes(row[field]));
  assert(['true', 'false', 'error'].includes(row.native)); assert(['accepted', 'rejected', 'error'].includes(row.privacy));
  assert(['none', 'invalid', ...visibilityControlPrivacyStages].includes(row.privacyLast));
  if (row.privacy === 'accepted') assert.equal(row.privacyLast, 'public-safe-inspection');
  if (row.privacy === 'rejected') assert(publicSafeFailures.includes(row.privacyLast));
 }
 return value;
}
export function visibilityDiagnosticFor(browser) {
 const value = results.get(browser);
 return value ? validateVisibilityDiagnostic(structuredClone(value)) : null;
}

/** Executed only on a fresh synthetic page. No values or rectangle data leave it. */
export function measureControlGeometry(element) {
 const rectKind = read => {
  try {
   const rects = [...read()];
   if (rects.length > 64 || rects.some(rect => ![rect.x, rect.y, rect.width, rect.height].every(Number.isFinite) || rect.width < 0 || rect.height < 0)) return 'error';
   return rects.some(rect => rect.width > 0 && rect.height > 0) ? 'positive' : 'empty';
  } catch { return 'error'; }
 };
 const rangeKind = node => rectKind(() => { const range = document.createRange(); range.selectNodeContents(node); return range.getClientRects(); });
 const initialElementRange = rangeKind(element);
 const ownBox = rectKind(() => Element.prototype.getClientRects.call(element));
 const textNodeRange = element.childNodes.length === 1 && element.firstChild.nodeType === 3 ? rangeKind(element.firstChild) : 'error';
 const repeatElementRange = rangeKind(element);
 let native = 'error';
 try { const value = Element.prototype.checkVisibility.call(element); if (value === true || value === false) native = value ? 'true' : 'false'; } catch {}
 return { initialElementRange, ownBox, textNodeRange, repeatElementRange, native };
}

// Fresh context AND document per probe prevents cross-probe layout priming.
// Geometry order within a probe is intentional; these are sequential observations,
// not a claim that any reading or a later privacy inspection was simultaneous.
export async function collectVisibilityDiagnostic({ browser, expect, assertPublicSafe, signal, now = Date.now }) {
 requireHosted();
 const deadline = now() + geometryDiagnosticBudgetMs, probes = [];
 let phase = 'setup', stopped = false, current = null, interrupt;
 const interrupted = new Promise(resolve => { interrupt = resolve; });
 const close = record => record.promise ??= Promise.resolve().then(() => record.context.close());
 const stop = reason => {
  stopped = true;
  if (current) void close(current).catch(() => {});
  interrupt(reason === 'budget' ? unavailable('budget') : null);
 };
 const onAbort = () => stop('cancelled');
 signal.addEventListener('abort', onAbort, { once: true });
 const timer = setTimeout(() => stop('budget'), geometryDiagnosticBudgetMs);
 const active = () => {
  if (stopped || signal.aborted || !browser.isConnected()) { stopped = true; throw new Error('Diagnostic stopped'); }
  if (now() >= deadline) { phase = 'budget'; stopped = true; throw new Error('Diagnostic budget'); }
 };
 const run = async () => { try {
  for (const name of visibilityControlCases) {
   phase = 'setup'; active();
   let context, closed = false, runtimeErrors = 0;
   const state = { documents: 0, blocked: 0 };
   try {
    context = await browser.newContext({ viewport: { width: 800, height: 600 }, locale: 'en-US', reducedMotion: 'reduce', serviceWorkers: 'block' }); current = { context, promise: null }; active();
    context.setDefaultTimeout(Math.max(1, Math.min(1000, deadline - now())));
    await context.route('**/*', controlRoute(state)); active();
    const page = await context.newPage(); active(); assert.equal(page.url(), 'about:blank');
    page.on('pageerror', () => { runtimeErrors++; });
    await page.goto(controlURL, { timeout: Math.max(1, Math.min(1000, deadline - now())) }); active();
    const region = page.locator(`#${name}`), probe = region.locator('[data-probe]');
    phase = 'measurement'; const observed = await probe.evaluate(measureControlGeometry); active();
    assert.deepEqual(sorted(Object.keys(observed)), sorted(['initialElementRange', 'ownBox', 'textNodeRange', 'repeatElementRange', 'native']));
    for (const field of ['initialElementRange', 'ownBox', 'textNodeRange', 'repeatElementRange']) assert(geometryKinds.includes(observed[field]));
    assert(['true', 'false', 'error'].includes(observed.native));
    const stages = []; let threw = false, overflow = false;
    phase = 'privacy';
    try { await assertPublicSafe(page, region, expect, stage => { if (stages.length < 3) stages.push(visibilityControlPrivacyStages.includes(stage) ? stage : 'invalid'); else overflow = true; }); } catch { threw = true; }
    active();
    const privacyLast = overflow ? 'invalid' : stages.at(-1) ?? 'none';
    const prefix = stages[0] === 'public-safe-elements' && stages[1] === 'public-safe-inspection';
    const privacy = !overflow && prefix && !threw && stages.length === 2 ? 'accepted' : !overflow && prefix && threw && stages.length === 3 && publicSafeFailures.includes(privacyLast) ? 'rejected' : 'error';
    const row = { name, ...observed, privacy, privacyLast };
    phase = 'runtime'; assert.equal(runtimeErrors, 0); active();
    phase = 'route'; assert.deepEqual(state, { documents: 1, blocked: 0 }); active();
    probes.push(row);
   } finally {
    if (context) {
     const prior = phase; phase = 'cleanup'; await close(current); closed = true; current = null; phase = prior;
    }
   }
   assert(closed); active();
   phase = 'runtime'; assert.equal(runtimeErrors, 0); active();
   phase = 'route'; assert.deepEqual(state, { documents: 1, blocked: 0 }); active();
  }
  phase = 'measurement';
  return validateVisibilityDiagnostic({ schema, status: 'complete', probes, contexts: 15, documents: 15, screenshots: 0, exceptionPath: 'not-observed' });
 } catch {
  // Cancellation/disconnection has no observational report at all. The runner's
  // original failure remains authoritative, including when cleanup is uncertain.
  if (signal.aborted || !browser.isConnected()) return null;
  return validateVisibilityDiagnostic(unavailable(unavailableReasons.includes(phase) ? phase : 'measurement'));
 } };
 try { if (signal.aborted) return null; return await Promise.race([run(), interrupted]); }
 finally { clearTimeout(timer); signal.removeEventListener('abort', onAbort); }
}

/** Same success call/result; only a confirmed, closed Range-assertion failure
 * can begin diagnostics. Browser setup, timeout and cleanup errors cannot. */
export async function runVisibilityControls(options) {
 const { browser, mark = () => {} } = options;
 let lastStage = null, originalClosed = false;
 results.delete(browser);
 const trackedBrowser = { newContext: async configuration => {
  const context = await browser.newContext(configuration);
  return {
   route: (...args) => context.route(...args), newPage: (...args) => context.newPage(...args),
   close: async () => { await context.close(); originalClosed = true; },
  };
 } };
 try {
  return await originalControls({ ...options, browser: trackedBrowser, mark: stage => { lastStage = stage; mark(stage); } });
 } catch (error) {
  const signal = signals.get(browser);
  const eligible = visibilityControlCases.some(name => ['positive', 'empty'].some(kind => lastStage === visibilityControlStage(name, `range-${kind}`)));
  try { if (error?.code === 'ERR_ASSERTION' && eligible && originalClosed && signal && !signal.aborted && browser.isConnected()) {
   const value = await collectVisibilityDiagnostic({ ...options, signal });
   if (value && !signal.aborted && browser.isConnected()) results.set(browser, validateVisibilityDiagnostic(value));
  } } catch {} // Diagnostics can never replace the original assertion.
  throw error;
 }
}
