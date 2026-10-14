import { describe, expect, it, vi } from 'vitest';
const { readFileSync } = await vi.importActual<{ readFileSync(path: string, encoding: 'utf8'): string }>('node:fs');
const { createRequire } = await vi.importActual<{ createRequire(path: string): (name: string) => unknown }>('node:module');
type Color = number[];
const { rgba, composite, contrast, measureContrast } = createRequire(import.meta.url)('../../tests/e2e-review/focus-contrast-browser.mjs') as {
 rgba(value: string): Color; composite(foreground: Color, background: Color): Color; contrast(foreground: Color, background: Color): number;
 measureContrast(locator: { evaluate: () => Promise<unknown> }, kind?: string): Promise<{ ratio: number; effectiveBackground: Color }>;
};
const css = readFileSync('src/styles.css', 'utf8');
const blocks = (selector: string) => [...css.matchAll(/([^{}]+)\{([^{}]*)\}/g)].filter(m => m[1].trim().replace(/\/\*[\s\S]*?\*\//g, '').trim() === selector).map(m => m[2]);
const declarations = (source: string) => Object.fromEntries(source.split(';').filter(x => x.includes(':')).map(x => { const i = x.indexOf(':'); return [x.slice(0, i).trim(), x.slice(i + 1).trim()]; }));
const tokens = (theme: string, sidebar = false) => {
 const values: Record<string, string> = Object.assign({}, ...blocks(':root').map(declarations), ...blocks(theme === 'dark' ? ':root[data-theme=dark]' : ':root:not([data-theme=dark])').map(declarations), ...(sidebar ? blocks('.sidebar').map(declarations) : []));
 const resolve = (value: string): string => value.replace(/var\((--[\w-]+)\)/g, (_, key) => resolve(values[key]));
 return Object.fromEntries(Object.entries(values).filter(([key]) => key.startsWith('--')).map(([key, value]) => [key, resolve(value)]));
};
describe('S03/S04 exact solid-color contrast regression', () => {
 it('uses unrounded sRGB alpha composition before WCAG luminance', () => {
  expect(rgba('#3aab9877')[3]).toBe(119 / 255);
  expect(composite(rgba('#3aab9877'), rgba('#fff'))[0]).toBeCloseTo(0.6394771241830065, 14);
  expect(contrast(rgba('#3aab9877'), rgba('#fff'))).toBeCloseTo(1.5836001460249807, 12);
  expect(contrast(rgba('#3aab9877'), rgba('#17242c'))).toBeCloseTo(2.2905906750859906, 12);
  expect(contrast(rgba('#000'), rgba('#fff'))).toBe(21);
 });
 it('rejects unsupported or non-opaque backing colors', () => {
  expect(() => rgba('color(display-p3 1 0 0)')).toThrow();
  expect(() => rgba('rgba(0, 0, 0, 2)')).toThrow();
  expect(() => composite(rgba('#fff'), rgba('#00000077'))).toThrow();
 });
 for (const theme of ['light', 'dark']) {
  it(`${theme}: opaque focus clears 3:1 against panel, soft panel, and workspace`, () => {
   const t = tokens(theme); expect(rgba(t['--focus-ring'])[3]).toBe(1);
   for (const background of ['--panel', '--panel-soft', '--bg']) expect(contrast(rgba(t['--focus-ring']), rgba(t[background]))).toBeGreaterThanOrEqual(3);
  });
  it(`${theme}: sidebar focus clears 3:1 at rest, hover and selected backgrounds`, () => {
   const t = tokens(theme, true); const backgrounds = [rgba(t['--sidebar']), composite(rgba('#ffffff07'), rgba(t['--sidebar'])), rgba('#24413f')];
   for (const background of backgrounds) expect(contrast(rgba(t['--focus-ring']), background)).toBeGreaterThanOrEqual(3);
  });
  it(`${theme}: section label and exact error-banner foreground clear 4.5:1`, () => {
   const t = tokens(theme);
   expect(contrast(rgba(t['--sidebar-secondary']), rgba(t['--sidebar']))).toBeGreaterThanOrEqual(4.5);
   expect(contrast(rgba(t['--error-text']), rgba(t['--danger-soft']))).toBeGreaterThanOrEqual(4.5);
  });
 }
 it('keeps general danger tokens and banner background unchanged', () => {
  expect(tokens('light')['--danger']).toBe('#ba4f47'); expect(tokens('dark')['--danger']).toBe('#ee9c90');
  expect(tokens('light')['--danger-soft']).toBe('#fff0ed'); expect(tokens('dark')['--danger-soft']).toBe('#3e2c2e');
  expect(blocks('.error-banner').map(declarations).find(d => d.color)?.color).toBe('var(--error-text)');
  expect(blocks('.nav-label').map(declarations).find(d => d.color)?.color).toBe('var(--sidebar-secondary)');
 });
 for (const [file, selectors, offsets] of [
  ['advisory-review.css', ['.advisory-review-toggle:focus-visible'], ['-3px']],
  ['package-observations.css', ['.package-table-scroll:focus-visible', '.package-row-details summary:focus-visible'], ['3px', '3px']],
  ['complete-packages.css', ['.complete-package-search input:focus-visible', '.inventory-source-tabs button:focus-visible'], ['2px', '2px']],
 ] as const) it(`${file}: removes each demonstrated alpha override, preserving ring geometry`, () => {
  const source = readFileSync(`src/${file}`, 'utf8'); expect(source).not.toContain('#3aab9877');
  selectors.forEach((selector, index) => {
   const block = [...source.matchAll(/([^{}]+)\{([^{}]*)\}/g)].find(m => m[1].trim() === selector);
   expect(block).toBeDefined(); const rule = declarations(block![2]);
   expect(rule.outline).toBe('3px solid var(--focus-ring)'); expect(rule['outline-offset']).toBe(offsets[index]);
  });
 });
 it('shared button/link/summary and form focus inherit the semantic surface token', () => {
  for (const selector of ['button:focus-visible,a:focus-visible,summary:focus-visible', 'input:focus-visible,textarea:focus-visible,select:focus-visible']) {
   const rule = Object.assign({}, ...blocks(selector).map(declarations));
   expect(rule.outline).toContain('var(--focus-ring)');
   if (rule['outline-color']) expect(rule['outline-color']).toBe('var(--focus-ring)');
  }
  expect(css).not.toContain('#3aab9877');
 });
});


describe('hosted computed-color recipe contracts without launching a browser', () => {
 const paint = { theme: 'light', backgrounds: ['rgb(246, 248, 249)', 'rgba(0, 0, 0, 0)', 'rgb(255, 255, 255)', 'rgb(5, 117, 106)'], foreground: 'rgb(5, 117, 106)', focusVisible: true, outlineStyle: 'solid', outlineWidth: '3px', outlineOffset: '3px' };
 it('outside outlines use the painted parent, not the control fill', async () => {
  const value = await measureContrast({ evaluate: async () => paint });
  expect(value.effectiveBackground).toEqual([1, 1, 1, 1]); expect(value.ratio).toBeCloseTo(5.5864578335715, 12);
 });
 it('inset outlines and text use the element fill', async () => {
  const value = await measureContrast({ evaluate: async () => ({ ...paint, outlineOffset: '-3px' }) });
  expect(value.ratio).toBe(1);
  expect((await measureContrast({ evaluate: async () => paint }, 'text')).ratio).toBe(1);
 });
 it('unknown canvas cannot silently become a passing white canvas', async () => {
  await expect(measureContrast({ evaluate: async () => ({ ...paint, backgrounds: ['rgba(0, 0, 0, 0)'] }) })).rejects.toThrow('Opaque root canvas required');
 });
 it('shell and package checks are wired through existing synthetic hosted gates', () => {
  const runner = (name: string) => readFileSync(`../tests/e2e-review/${name}`, 'utf8');
  expect(runner('run.mjs')).toContain('await focusContrastShellGallery(');
  expect(runner('conditional-browser.mjs')).toContain("name:'advisory-toggle'");
  expect(runner('conditional-browser.mjs')).toContain("name:'legacy-package-details'");
  expect(runner('v3-mvp-browser.mjs')).toContain("name:'inventory-source-tab'");
  expect(runner('v3-mvp-browser.mjs')).toContain("name:'complete-package-search'");
  const helper = runner('focus-contrast-browser.mjs');
  expect(helper).toContain("await page.keyboard.press('Tab'); await page.keyboard.press('Shift+Tab')");
  expect(helper).toContain("for (const theme of ['light', 'dark'])");
  expect(helper).not.toMatch(/chromium\.launch|setContent|addStyleTag/);
 });
});
