/** Known synthetic DOM in one isolated hosted context. Never a production page. */
import assert from 'node:assert/strict';
import { origin, requireHosted } from './windows-enrollment-contract.mjs';
import { invitation, secret } from './windows-enrollment-fixtures.mjs';
export const controlURL = origin + '/visibility-control';
export const controlHTML = `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><link rel="icon" href="data:,"><title>Synthetic visibility controls only</title></head><body>
<section id="clear"><p data-probe>Known safe control text</p></section>
<section id="visible"><p data-probe>${secret}</p></section>
<section id="closed-body"><details><summary>Closed control</summary><dl><div><dt>Invented ID</dt><dd data-probe>${invitation}</dd></div></dl></details></section>
<section id="closed-summary"><details><summary data-probe>${invitation}</summary><p>Closed safe body</p></details></section>
<section id="open-body"><details open><summary>Open control</summary><p data-probe>${invitation}</p></details></section>
<section id="contents"><p data-probe style="display:contents">${secret}</p></section>
</body></html>`;
export function controlRoute(state) {
 return async route => {
  const request = route.request(), headers = request.headers();
  if (request.url() !== controlURL || request.method() !== 'GET' || request.postData() !== null || headers.cookie || headers.authorization || state.documents !== 0) {
   state.blocked++; return route.abort('blockedbyclient');
  }
  state.documents++; return route.fulfill({ status: 200, contentType: 'text/html', headers: { 'cache-control': 'no-store' }, body: controlHTML });
 };
}
export async function runVisibilityControls({ browser, expect, assertPublicSafe, mark = () => {} }) {
 requireHosted(); mark('visibility-control-context');
 const context = await browser.newContext({ viewport: { width: 800, height: 600 }, locale: 'en-US', reducedMotion: 'reduce', serviceWorkers: 'block' });
 let completed = false, closedBodyRange = null, runtimeErrors = 0; const state = { documents: 0, blocked: 0 };
 try {
  await context.route('**/*', controlRoute(state));
  const page = await context.newPage(); assert.equal(page.url(), 'about:blank'); page.on('pageerror', () => { runtimeErrors++; });
  mark('visibility-control-document'); await page.goto(controlURL);
  for (const name of ['clear', 'visible', 'closed-body', 'closed-summary', 'open-body', 'contents']) {
   mark(`visibility-control-${name}`);
   const region = page.locator(`#${name}`), probe = region.locator('[data-probe]');
   // Geometry and default native box visibility are deliberately separate.
   const observed = await probe.evaluate(element => {
    const range = document.createRange(); range.selectNodeContents(element);
    const positiveRange = [...range.getClientRects()].some(rect => rect.width > 0 && rect.height > 0);
    const native = Element.prototype.checkVisibility.call(element);
    return { positiveRange, native };
   });
   assert.deepEqual(Object.keys(observed).sort(), ['native', 'positiveRange']); assert.equal(typeof observed.positiveRange, 'boolean');
   assert.equal(observed.native, name !== 'closed-body' && name !== 'contents');
   if (name === 'closed-body') { await expect(probe).toBeHidden(); closedBodyRange = observed.positiveRange ? 'positive' : 'empty'; }
   else { assert.equal(observed.positiveRange, true); await expect(probe).toBeVisible(); }
   const expected = name === 'clear' || name === 'closed-body' && !observed.positiveRange ? null : name === 'closed-body' ? 'public-safe-text-closed-details-native-false' : 'public-safe-text';
   const stages = []; let rejected = false;
   try { await assertPublicSafe(page, region, expect, stage => { stages.push(stage); }); } catch { rejected = true; }
   assert.equal(rejected, expected !== null, 'Synthetic privacy control mismatch');
   assert.deepEqual(stages, ['public-safe-elements', 'public-safe-inspection', ...(expected === null ? [] : [expected])]);
  }
  assert.equal(runtimeErrors, 0); assert.deepEqual(state, { documents: 1, blocked: 0 }); completed = true;
  return { contexts: 1, cases: 6, passed: true, closedBodyRange, screenshots: 0, syntheticDocumentRequests: 1, requestsToRealAPI: 0, actualMutationRequests: 0 };
 } finally { if (completed) mark('visibility-control-close'); await context.close(); }
}
