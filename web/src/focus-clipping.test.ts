import { describe, expect, it, vi } from 'vitest';
const { readFileSync } = await vi.importActual<{ readFileSync(path: string, encoding: 'utf8'): string }>('node:fs');
const { createRequire } = await vi.importActual<{ createRequire(path: string): (name: string) => unknown }>('node:module');
type Rect = { left: number; top: number; right: number; bottom: number };
type Input = { bounds: Rect; outlineWidth: number; outlineOffset: number; viewport: Rect; clips?: { bounds: Rect; x: boolean; y: boolean; kind?: unknown; fractionalRight?: number; fractionalWidth?: number; fractionalGuard?: boolean }[]; headers?: Rect[]; allowTallBottom?: boolean };
type Result = { accepted: boolean; clipped: { left: boolean; top: boolean; right: boolean; bottom: boolean }; tallBottomCrop: boolean; headerOverlap: boolean; topBandVisible: boolean };
const { focusVisibility, rightFocusClipReason, enterFocusByTab, measureFocusVisibility, focusContrastStage } = createRequire(import.meta.url)('../../tests/e2e-review/focus-contrast-browser.mjs') as {
 focusVisibility(input: Input): Result;
 rightFocusClipReason(input: Input, result: Result): string;
 focusContrastStage(name: unknown, size: unknown, locale: unknown, theme: unknown, phase: unknown): string;
 measureFocusVisibility(control: { evaluate(fn: (element: HTMLElement, value?: unknown) => unknown, value?: unknown): Promise<unknown> }): Promise<Result & { hitTests: Record<string, boolean>; rightClipReason: string }>;
 enterFocusByTab(options: Record<string, unknown>): Promise<{ method: string; from: string; path: string[] }>;
};
const viewport = { left: 0, top: 0, right: 390, bottom: 844 };
const scrollport = { left: 35, top: 150, right: 355, bottom: 844 };
const summary: Input = { bounds: { left: 277, top: 211, right: 355, bottom: 276 }, outlineWidth: 3, outlineOffset: -3, viewport,
 clips: [{ bounds: scrollport, x: true, y: true }], headers: [{ left: 0, top: 55, right: 390, bottom: 150 }] };

describe('bounded outline clipping and protected-header contract', () => {
 it('rejects the legacy outside ring at a horizontal scroll edge', () => {
  const result = focusVisibility({ ...summary, outlineOffset: 3 });
  expect(result.clipped.right).toBe(true); expect(result.accepted).toBe(false);
 });
 it('accepts an inset summary only when its complete border box is exposed', () => {
  expect(focusVisibility(summary).accepted).toBe(true);
  const clipped = focusVisibility({ ...summary, bounds: { ...summary.bounds, right: 361 } });
  expect(clipped.clipped.right).toBe(true); expect(clipped.accepted).toBe(false);
 });
 it('never grants the tall-table bottom exemption to a small summary', () => {
  const result = focusVisibility({ ...summary, bounds: { ...summary.bounds, top: 820, bottom: 875 }, allowTallBottom: true });
  expect(result.clipped.bottom).toBe(true); expect(result.tallBottomCrop).toBe(false); expect(result.accepted).toBe(false);
 });
 for (const top of [103, 150]) {
  const table: Input = { bounds: { left: 35, top, right: 355, bottom: 4000 }, outlineWidth: 3, outlineOffset: -3, viewport,
   clips: [{ bounds: { left: 20, top, right: 370, bottom: 844 }, x: true, y: true }],
   headers: [{ left: 0, top: 55, right: 390, bottom: top }], allowTallBottom: true };
  it(`rejects the outside top ring at the ${top}px LAN-chrome boundary despite allowed bottom crop`, () => {
   const result = focusVisibility({ ...table, outlineOffset: 3 });
   expect(result.clipped.top).toBe(true); expect(result.headerOverlap).toBe(true); expect(result.tallBottomCrop).toBe(true); expect(result.accepted).toBe(false);
  });
  it(`accepts the exposed inset top/sides at ${top}px while labelling long-table bottom cropping`, () => {
   const result = focusVisibility(table);
   expect(result.clipped.top).toBe(false); expect(result.headerOverlap).toBe(false); expect(result.tallBottomCrop).toBe(true); expect(result.accepted).toBe(true);
  });
 }
 it('rejects fixed-header overlap independently of overflow ancestry', () => {
  const result = focusVisibility({ ...summary, bounds: { ...summary.bounds, top: 120, bottom: 180 }, clips: [] });
  expect(result.clipped.top).toBe(false); expect(result.headerOverlap).toBe(true); expect(result.accepted).toBe(false);
 });
 it('does not waive top clipping when a tall region begins above the scrollport', () => {
  const result = focusVisibility({ ...summary, bounds: { left: 35, top: 149, right: 355, bottom: 4000 }, allowTallBottom: true });
  expect(result.clipped.top).toBe(true); expect(result.accepted).toBe(false);
 });
 it('requires an actual visible top band, not one intersecting sliver', () => {
  const result = focusVisibility({ ...summary, bounds: { left: 35, top: 843, right: 355, bottom: 4000 }, allowTallBottom: true });
  expect(result.topBandVisible).toBe(false); expect(result.accepted).toBe(false);
 });
 it('rejects clipping by an inner ancestor even when an outer scrollport fits', () => {
  const result = focusVisibility({ ...summary, clips: [...summary.clips!, { bounds: { left: 35, top: 210, right: 350, bottom: 844 }, x: true, y: false }] });
  expect(result.clipped.right).toBe(true); expect(result.accepted).toBe(false);
 });
 it('rejects unsupported deeply inset geometry rather than measuring a smaller safe rectangle', () => {
  expect(() => focusVisibility({ ...summary, outlineOffset: -4 })).toThrow('Invalid focus geometry');
 });
 it('rejects bad measurements instead of turning them into passing geometry', () => {
  expect(() => focusVisibility({ ...summary, outlineWidth: NaN })).toThrow();
  expect(() => focusVisibility({ ...summary, bounds: { ...summary.bounds, right: Infinity } })).toThrow();
  expect(() => focusVisibility({ ...summary, clips: Array.from({ length: 33 }, () => ({ bounds: scrollport, x: true, y: true })) })).toThrow();
 });
});

describe('fixed right-edge cause labels preserve every original clipping failure', () => {
 const table = (right = 355.75, fractionalRight = 355, fractionalGuard = true): Input => ({ ...summary, bounds: { ...summary.bounds, right },
  clips: [{ bounds: scrollport, x: true, y: true, kind: 'table', fractionalRight, fractionalWidth: 320, fractionalGuard }] });
 const cases: [string, Input][] = [
  ['none', summary],
  ['unclassified', { ...summary, bounds: { ...summary.bounds, right: 356 } }],
  ['viewport', { ...summary, clips: [], bounds: { ...summary.bounds, right: 391 } }],
  ['ancestor', { ...table(), clips: [{ bounds: scrollport, x: true, y: true, kind: 'ancestor' }] }],
  ['mixed', table(391)],
  ['mixed', { ...table(), clips: [...table().clips!, { bounds: scrollport, x: true, y: true, kind: 'ancestor' }] }],
  ['table wider', { ...table(357), bounds: { ...summary.bounds, left: 35, right: 357 } }],
  ['table fractional', table(355.75, 355.875)],
  ['table fractional', table(355.75, 355.75)],
  ['table subpixel', table()],
  ['table subpixel', table(356)],
  ['table overflow', table(356.01)],
  ['table unverified subpixel', table(355.75, 355.875, false)],
  ['table unverified overflow', table(357, 358, false)],
  ['table unverified subpixel', table(355.75, NaN)],
  ['table unverified overflow', { ...table(357), bounds: { ...summary.bounds, left: 35, right: 357 }, clips: [{ ...table(357).clips![0], fractionalGuard: false }] }],
  ['table unverified subpixel', { ...table(), clips: [{ ...table().clips![0], fractionalWidth: NaN }] }],
  ['table fractional', { ...table(355.75, 355.875), bounds: { ...summary.bounds, left: 35.25, right: 355.75 }, clips: [{ ...table(355.75, 355.875).clips![0], fractionalWidth: 320.875 }] }],
  ['table subpixel', { ...table(355.75, 355.875), clips: [...table(355.75, 355.875).clips!, ...table().clips!] }],
  ['unclassified', { ...table(), clips: [{ ...table().clips![0], kind: { toString() { throw new Error('PRIVATE_VALUE'); } } }] }],
 ];
 for (const [index, [reason, geometry]] of cases.entries()) it(`classifies fixed scenario ${index} as ${reason} without changing acceptance`, () => {
  const before = focusVisibility(geometry), frozen = JSON.stringify(before);
  expect(rightFocusClipReason(geometry, before)).toBe(reason);
  expect(JSON.stringify(before)).toBe(frozen);
  expect(before.accepted).toBe(reason === 'none');
 });
 it('does not treat a small physical overhang as a rounding discrepancy', () => {
  const geometry = table(355.75, 355.74);
  expect(rightFocusClipReason(geometry, focusVisibility(geometry))).toBe('table subpixel');
  expect(focusVisibility(geometry).accepted).toBe(false);
 });
});

// Exercise the browser-side ownership callback without launching a browser.
// Geometry is a fixed synthetic input; these are not rendered pixel results.
describe('inset ring ownership samples', () => {
 for (const covered of [false, true]) it(covered ? 'rejects a covering sibling even when the rectangle fits' : 'accepts target descendants at every sampled inset edge', async () => {
  const target = document.createElement('summary'), child = document.createElement('span'), overlay = document.createElement('div');
  target.style.outlineWidth = '3px'; target.append(child); document.body.append(target, overlay);
  const original = Object.getOwnPropertyDescriptor(document, 'elementFromPoint');
  const hit = vi.fn(() => covered ? overlay : child);
  Object.defineProperty(document, 'elementFromPoint', { configurable: true, value: hit });
  try {
   const result = await measureFocusVisibility({ async evaluate(fn, value) { return value === undefined ? summary : fn(target, value); } });
   expect(result.accepted).toBe(!covered);
   expect(result.hitTests).toEqual({ top: !covered, left: !covered, right: !covered, bottom: !covered });
   expect(hit).toHaveBeenCalledTimes(4);
  } finally {
   target.remove(); overlay.remove();
   if (original) Object.defineProperty(document, 'elementFromPoint', original);
   else Reflect.deleteProperty(document, 'elementFromPoint');
  }
 });
});

// Run the actual browser geometry callback against inert DOM objects. These
// synthetic CSSOM values model edge/rounding guards, not measured browser pixels.
describe('actual geometry reader keeps fractional comparison guarded and private', () => {
 const scenarios = ['supported', 'vertical-overflow', 'forced-scrollbar', 'reserved-gutter', 'ancestor-transform', 'target-transform', 'ancestor-zoom', 'ancestor-scale', 'scaled-wide-target', 'supported-wide-target', 'rtl', 'vertical-writing', 'unknown-style'] as const;
 for (const scenario of scenarios) it(`uses a fixed diagnostic with ${scenario}`, async () => {
  const wrapper = document.createElement('div'), target = document.createElement('summary');
  wrapper.className = 'package-table-scroll'; wrapper.append(target); document.body.append(wrapper);
  const bounds = { left: scenario.endsWith('wide-target') ? 35 : 277, top: 211, right: scenario === 'scaled-wide-target' ? 235 : scenario === 'supported-wide-target' ? 357 : 355.75, bottom: 276 };
  target.getBoundingClientRect = () => ({ ...bounds, x: bounds.left, y: bounds.top, width: bounds.right - bounds.left, height: bounds.bottom - bounds.top, toJSON() {} });
  wrapper.getBoundingClientRect = () => scenario === 'scaled-wide-target'
   ? { left: 35, top: 150, right: 235, bottom: 550, x: 35, y: 150, width: 200, height: 400, toJSON() {} }
   : { left: 34, top: 149, right: 356.8, bottom: 845, x: 34, y: 149, width: 322.8, height: 696, toJSON() {} };
  Object.defineProperties(wrapper, { clientLeft: { value: scenario === 'scaled-wide-target' ? 0 : 1 }, clientTop: { value: scenario === 'scaled-wide-target' ? 0 : 1 }, clientWidth: { value: scenario === 'scaled-wide-target' ? 100 : 320 }, clientHeight: { value: scenario === 'scaled-wide-target' ? 200 : 694 }, scrollHeight: { value: scenario === 'scaled-wide-target' ? 200 : scenario === 'vertical-overflow' ? 695 : 694 } });
  const basic = { transform: 'none', perspective: 'none', translate: 'none', rotate: 'none', scale: 'none', zoom: '1', overflowX: 'visible', overflowY: 'visible', outlineWidth: '3px', outlineOffset: '-3px' };
  const styles = vi.spyOn(window, 'getComputedStyle').mockImplementation(node => {
   const style: Record<string, string> = { ...basic };
   if (node === wrapper) Object.assign(style, { overflowX: 'auto', overflowY: 'auto', borderLeftWidth: '1.4px', borderRightWidth: '1px', direction: 'ltr', writingMode: 'horizontal-tb', scrollbarGutter: 'auto' });
   if (node === wrapper && scenario === 'forced-scrollbar') style.overflowY = 'scroll';
   if (node === wrapper && scenario === 'reserved-gutter') style.scrollbarGutter = 'stable';
   if (node === wrapper && scenario === 'rtl') style.direction = 'rtl';
   if (node === wrapper && scenario === 'vertical-writing') style.writingMode = 'vertical-rl';
   if (node === document.body && scenario === 'ancestor-transform') style.transform = 'matrix(2,0,0,2,0,0)';
   if (node === wrapper && scenario === 'scaled-wide-target') Object.assign(style, { transform: 'matrix(2,0,0,2,0,0)', borderLeftWidth: '0px', borderRightWidth: '0px' });
   if (node === target && scenario === 'target-transform') style.translate = '1px';
   if (node === document.body && scenario === 'ancestor-zoom') style.zoom = '1.25';
   if (node === document.body && scenario === 'ancestor-scale') style.scale = '2';
   if (node === document.body && scenario === 'unknown-style') delete style.zoom;
   return style as unknown as CSSStyleDeclaration;
  });
  const point = Object.getOwnPropertyDescriptor(document, 'elementFromPoint');
  Object.defineProperty(document, 'elementFromPoint', { configurable: true, value: () => target });
  try {
   const result = await measureFocusVisibility({ async evaluate(fn, value) { return fn(target, value); } });
   expect(result.rightClipReason).toBe(scenario === 'supported' ? 'table fractional'
    : scenario === 'supported-wide-target' ? 'table wider' : scenario === 'scaled-wide-target' ? 'table unverified overflow' : 'table unverified subpixel');
   expect(result.clipped.right).toBe(true); expect(result.accepted).toBe(false);
   if (scenario === 'scaled-wide-target') expect(target.getBoundingClientRect().width).toBe(wrapper.getBoundingClientRect().width);
   expect(result).not.toHaveProperty('fractionalRight'); expect(result).not.toHaveProperty('fractionalGuard'); expect(result).not.toHaveProperty('fractionalWidth');
  } finally {
   styles.mockRestore(); wrapper.remove();
   if (point) Object.defineProperty(document, 'elementFromPoint', point); else Reflect.deleteProperty(document, 'elementFromPoint');
  }
 });
});

function keyboardHarness(actualPath = ['region', 'summary']) {
 const actions: string[] = []; let focused = ''; let index = 0;
 const locator = (selector: string) => ({ selector, first() { return this; }, async scrollIntoViewIfNeeded() { actions.push(`scroll:${selector}`); }, async focus() { actions.push(`focus:${selector}`); focused = selector; } });
 return { actions, page: { locator, keyboard: { async press(key: string) { actions.push(key); focused = actualPath[index++]; } } },
  expect: (control: ReturnType<typeof locator>) => ({ async toBeFocused() { expect(focused).toBe(control.selector); } }) };
}
describe('genuine bounded forward entry without target prepositioning', () => {
 it('reaches region then first mapping summary only through actual Tab steps', async () => {
  const harness = keyboardHarness();
  expect(await enterFocusByTab({ ...harness, selector: 'summary', keyboardEntry: { from: 'refresh', path: ['region', 'summary'] } })).toEqual({ method: 'forward-tab', from: 'refresh', path: ['region', 'summary'] });
  expect(harness.actions).toEqual(['scroll:refresh', 'focus:refresh', 'Tab', 'Tab']);
 });
 it('fails on an intervening control instead of skipping focus until the screenshot looks right', async () => {
  const harness = keyboardHarness(['unexpected', 'summary']);
  await expect(enterFocusByTab({ ...harness, selector: 'summary', keyboardEntry: { from: 'refresh', path: ['region', 'summary'] } })).rejects.toThrow();
  expect(harness.actions).toEqual(['scroll:refresh', 'focus:refresh', 'Tab']);
 });
 it('rejects direct-target anchors and unbounded or mismatched traversal', async () => {
  for (const keyboardEntry of [{ from: 'summary', path: ['summary'] }, { from: 'refresh', path: [] }, { from: 'refresh', path: ['region', 'wrong'] }, { from: 'refresh', path: ['a', 'b', 'summary'] }]) {
   const harness = keyboardHarness();
   await expect(enterFocusByTab({ ...harness, selector: 'summary', keyboardEntry })).rejects.toThrow('Invalid bounded keyboard entry');
   expect(harness.actions).toEqual([]);
  }
 });
 it('wires real preceding controls and samples ring ownership without scrolling the focused target', () => {
  const conditional = readFileSync('../tests/e2e-review/conditional-browser.mjs', 'utf8');
  const complete = readFileSync('../tests/e2e-review/v3-mvp-browser.mjs', 'utf8');
  expect(conditional).toContain("keyboardEntry:{from:'.package-observations > .package-heading button',path:['.package-observations .package-table-scroll','.package-observations .package-row-details summary']}");
  expect(complete).toContain("keyboardEntry:{from:'.complete-packages .inventory-capture-details > summary',path:['.complete-packages .package-table-scroll','.complete-packages .package-row-details summary']}");
  const helper = readFileSync('../tests/e2e-review/focus-contrast-browser.mjs', 'utf8');
  expect(helper).toContain('document.elementFromPoint(x, y)'); expect(helper).toContain(".main-shell > .topbar, .main-shell > .transport-warning");
  expect(helper).toContain("element.matches('.package-table-scroll[tabindex=\"0\"]')");
  expect(helper).not.toMatch(/scrollTop\s*=|scrollLeft\s*=|scrollBy\(|addStyleTag|setContent/);
 });
});

describe('closed focus diagnostic coordinates', () => {
 it('covers every current producer target and exact check phase', () => {
  const sources = ['conditional-browser.mjs', 'v3-mvp-browser.mjs'].map(file => readFileSync(`../tests/e2e-review/${file}`, 'utf8')).join('\n');
  const names = [...sources.matchAll(/name:'([^']+)',selector:/g)].map(match => match[1]);
  expect(names).toEqual(['legacy-package-table', 'legacy-package-details', 'advisory-toggle', 'inventory-source-tab', 'complete-package-search', 'complete-package-table', 'complete-package-details']);
  const helper = readFileSync('../tests/e2e-review/focus-contrast-browser.mjs', 'utf8');
  const phases = [...helper.matchAll(/stage\('([^']+)'\)/g)].map(match => match[1]);
  expect(phases).toEqual(['outline geometry read', 'outline geometry classify', 'outline hit-test read', 'keyboard entry', 'computed contrast', 'outline exposure', 'outline left edge', 'outline right edge', 'outline right viewport', 'outline right ancestor', 'outline right mixed', 'outline right table wider', 'outline right table fractional', 'outline right table subpixel', 'outline right table overflow', 'outline right table unverified subpixel', 'outline right table unverified overflow', 'outline top edge', 'outline top band', 'outline header', 'outline bottom edge', 'outline hit top', 'outline hit left', 'outline hit right', 'outline hit bottom', 'outline accepted', 'synthetic capture']);
  for (const name of names) for (const size of ['desktop', 'mobile']) for (const locale of ['en', 'de']) for (const theme of ['light', 'dark']) for (const phase of phases)
   expect(focusContrastStage(name, size, locale, theme, phase)).toBe(`focus contrast ${name} ${size} ${locale} ${theme}: ${phase}`);
 });
 it('never coerces or echoes unknown diagnostic coordinates', () => {
  const hostile = { toString() { throw new Error('PRIVATE_VALUE'); } };
  for (let index = 0; index < 5; index++) for (const value of ['PRIVATE_VALUE', hostile, null, undefined, 390]) {
   const args: unknown[] = ['complete-package-table', 'mobile', 'de', 'dark', 'outline exposure']; args[index] = value;
   expect(focusContrastStage(args[0], args[1], args[2], args[3], args[4])).toBe('focus contrast unknown');
  }
 });
});
