/** Known synthetic DOM in one isolated hosted context. Never a production page. */
import assert from 'node:assert/strict';
import { origin, requireHosted, visibilityControlCases, visibilityControlPrivacyStages, visibilityControlStage } from './windows-enrollment-contract.mjs';
import { invitation, secret } from './windows-enrollment-fixtures.mjs';
export const controlURL = origin + '/visibility-control';
export const controlHTML = `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><link rel="icon" href="data:,"><title>Synthetic visibility controls only</title><style>
#override-body details::details-content { content-visibility:visible; }
#override-contents details::details-content { display:contents; }
#override-inline details::details-content { display:inline; }
</style></head><body>
<section id="clear"><p data-probe>Known safe control text</p></section>
<section id="visible"><p data-probe>${secret}</p></section>
<section id="closed-body"><details><summary>Closed control</summary><dl><div><dt>Invented ID</dt><dd data-probe>${invitation}</dd></div></dl></details></section>
<section id="closed-summary"><details><summary data-probe>${invitation}</summary><p>Closed safe body</p></details></section>
<section id="open-body"><details open><summary>Open control</summary><p data-probe>${invitation}</p></details></section>
<section id="contents"><p data-probe style="display:contents">${secret}</p></section>
<section id="closed-secret"><details><summary>Closed secret control</summary><p data-probe>${secret}</p></details></section>
<section id="second-summary"><details><summary>First safe summary</summary><summary data-probe>${invitation}</summary></details></section>
<section id="outer-body"><details><summary>Outer safe summary</summary><details open><summary data-probe>${invitation}</summary></details></details></section>
<section id="inner-body"><details><summary>Outer safe summary<details><summary>Inner safe summary</summary><p data-probe>${invitation}</p></details></summary></details></section>
<section id="body-contents"><details><summary>Closed contents control</summary><p data-probe style="display:contents">${invitation}</p></details></section>
<section id="closed-then-visible"><details><summary>Closed safe summary</summary><p data-probe>${invitation}</p></details><p>${invitation}</p></section>
<section id="override-body"><details><summary>Overridden content visibility</summary><p data-probe>${invitation}</p></details></section>
<section id="override-contents"><details><summary>Overridden contents display</summary><p data-probe>${invitation}</p></details></section>
<section id="override-inline"><details><summary>Overridden inline display</summary><p data-probe>${invitation}</p></details></section>
</body></html>`;
// Each fixture must exercise its intended geometry, never an unknown/optional
// Range path. The closed secret is a negative control even with empty text Range.
export const controlRangeExpectations = Object.freeze({
 clear: true,
 visible: true,
 'closed-body': true,
 'closed-summary': true,
 'open-body': true,
 contents: true,
 'closed-secret': false,
 'second-summary': true,
 'outer-body': true,
 'inner-body': true,
 'body-contents': true,
 'closed-then-visible': true,
 'override-body': true,
 'override-contents': true,
 'override-inline': true,
});
export const hiddenControlCases = Object.freeze(['closed-body', 'closed-secret', 'second-summary', 'outer-body', 'inner-body', 'body-contents', 'closed-then-visible']);
export const acceptedControlCases = Object.freeze(['clear', 'closed-body', 'second-summary', 'outer-body', 'inner-body']);
export function controlFailure(name) {
 if (acceptedControlCases.includes(name)) return null;
 if (name === 'body-contents') return 'public-safe-text-closed-details-native-false';
 if (name.startsWith('override-')) return 'public-safe-text-closed-details-native-true';
 return 'public-safe-text';
}
export function controlRoute(state) {
 return async route => {
  const request = route.request(), headers = request.headers();
  if (request.url() !== controlURL || request.method() !== 'GET' || request.postData() !== null || headers.cookie || headers.authorization || state.documents !== 0) {
   state.blocked++; return route.abort('blockedbyclient');
  }
  state.documents++; return route.fulfill({ status: 200, contentType: 'text/html', headers: { 'cache-control': 'no-store' }, body: controlHTML });
 };
}
// Closed disclosure descendants may have lazy Range layout in Chromium. Prime
// only the synthetic identifier controls whose positive Range path is required.
// Closed-secret remains Range-first, preserving the empty-Range negative control.
export function measureVisibilityControl(element, primeIdentifierLayout) {
 if (primeIdentifierLayout) Element.prototype.getClientRects.call(element);
 const range = document.createRange(); range.selectNodeContents(element);
 const positiveRange = [...range.getClientRects()].some(rect => rect.width > 0 && rect.height > 0);
 const positiveBox = [...Element.prototype.getClientRects.call(element)].some(rect => [rect.x, rect.y, rect.width, rect.height].every(Number.isFinite) && rect.width > 0 && rect.height > 0);
 const native = Element.prototype.checkVisibility.call(element);
 return { positiveRange, positiveBox, native };
}
export async function runVisibilityControls({ browser, expect, assertPublicSafe, mark = () => {} }) {
 requireHosted(); mark('visibility-control-context');
 const context = await browser.newContext({ viewport: { width: 800, height: 600 }, locale: 'en-US', reducedMotion: 'reduce', serviceWorkers: 'block' });
 let completed = false, runtimeErrors = 0; const state = { documents: 0, blocked: 0 };
 try {
  mark('visibility-control-route'); await context.route('**/*', controlRoute(state));
  mark('visibility-control-page'); const page = await context.newPage();
  mark('visibility-control-blank'); assert.equal(page.url(), 'about:blank'); page.on('pageerror', () => { runtimeErrors++; });
  mark('visibility-control-document'); await page.goto(controlURL);
  for (const name of visibilityControlCases) {
   const checkpoint = phase => mark(visibilityControlStage(name, phase));
   mark(`visibility-control-${name}`);
   const region = page.locator(`#${name}`), probe = region.locator('[data-probe]');
   // Geometry and default native box visibility are deliberately separate.
   checkpoint('measure');
   const observed = await probe.evaluate(measureVisibilityControl, (acceptedControlCases.includes(name) && name !== 'clear') || name === 'closed-then-visible');
   checkpoint('observation-shape'); assert.deepEqual(Object.keys(observed).sort(), ['native', 'positiveBox', 'positiveRange']);
   checkpoint('range-type'); assert.equal(typeof observed.positiveRange, 'boolean');
   checkpoint('box-type'); assert.equal(typeof observed.positiveBox, 'boolean');
   checkpoint(observed.positiveBox ? 'box-positive' : 'box-empty'); assert.equal(observed.positiveBox, name !== 'contents' && name !== 'body-contents');
   const rangeKind = observed.positiveRange ? 'positive' : 'empty';
   const nativeKind = observed.native === true ? 'true' : observed.native === false ? 'false' : 'invalid';
   checkpoint(`native-${nativeKind}-range-${rangeKind}`); assert.equal(observed.native, !hiddenControlCases.includes(name) && name !== 'contents');
   // Identifier exceptions still require positive Range evidence. Only the exact
   // closed-secret negative requires empty Range before unconditional rejection.
   checkpoint(`range-${rangeKind}`); assert.equal(observed.positiveRange, controlRangeExpectations[name]);
   if (hiddenControlCases.includes(name) && name !== 'body-contents') { checkpoint(`playwright-hidden-range-${rangeKind}`); await expect(probe).toBeHidden(); }
   else { checkpoint('playwright-visible'); await expect(probe).toBeVisible(); }
   // Playwright's display:contents visibility also uses Range geometry. Its
   // visible result there is not independent proof of painted visibility.
   const expected = controlFailure(name);
   const stages = []; let rejected = false;
   // Never interpolate an inspected value or exception into a public checkpoint.
   const lastStage = () => stages.length === 0 ? 'none' : visibilityControlPrivacyStages.includes(stages.at(-1)) ? stages.at(-1) : 'invalid';
   checkpoint(`privacy-check-range-${rangeKind}`);
   try { await assertPublicSafe(page, region, expect, stage => { stages.push(stage); checkpoint(`privacy-check-${lastStage()}-range-${rangeKind}`); }); } catch { rejected = true; }
   checkpoint(`privacy-${rejected ? 'rejected' : 'accepted'}-last-${lastStage()}-range-${rangeKind}`);
   assert.equal(rejected, expected !== null, 'Synthetic privacy control mismatch');
   checkpoint(`privacy-sequence-last-${lastStage()}-range-${rangeKind}`);
   assert.deepEqual(stages, ['public-safe-elements', 'public-safe-inspection', ...(expected === null ? [] : [expected])]);
  }
  mark('visibility-control-runtime-errors'); assert.equal(runtimeErrors, 0);
  mark('visibility-control-route-boundary'); assert.deepEqual(state, { documents: 1, blocked: 0 }); completed = true;
  return { contexts: 1, cases: visibilityControlCases.length, passed: true, closedBodyRange: 'positive', closedBodyBox: 'positive', screenshots: 0, syntheticDocumentRequests: 1, requestsToRealAPI: 0, actualMutationRequests: 0 };
 } finally { if (completed) mark('visibility-control-close'); await context.close(); }
}
