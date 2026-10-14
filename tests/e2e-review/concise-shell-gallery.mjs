/** Page-by-page rendered copy review. Overview rows are restricted to the
 * disposable manager's built-in synthetic fixtures before any public capture. */
import { assertDesktopNavigation, assertMobileDrawerClosed, shellDrawerKeyboardReview } from './shell-scenarios.mjs';

/** Steady-state shaping probe on the actual rendered synthetic component. It
 * temporarily substitutes only its numeric text, measures a DOM Range, then
 * restores it before capture. This is not a React-update, CLS or loading test. */
export async function numericTypographyReview({ page, expect, capture, name, selector, section, locale, decimal = false }) {
 const target = page.locator(selector).first();
 await expect(target).toBeVisible();
 const samples = decimal ? locale === 'de' ? ['11,1', '88,8'] : ['11.1', '88.8'] : ['111', '888'];
 await target.evaluate(async element => {
  const style = getComputedStyle(element);
  await document.fonts.load(`${style.fontWeight} ${style.fontSize} Inter`, '0123456789');
  await document.fonts.ready;
 });
 const evidence = await target.evaluate((element, samples) => {
  const number = [...element.childNodes].find(node => node.nodeType === Node.TEXT_NODE && /[0-9]/.test(node.data));
  if (!number) throw new Error('Synthetic numeric text is not a direct child');
  const style = getComputedStyle(element), original = number.data, originalStyle = element.getAttribute('style'), originalHTML = element.innerHTML;
  const rect = node => { const bounds = node.getBoundingClientRect(); return { x: bounds.x, width: bounds.width }; };
  const spans = [...element.children].map(child => ({ text: child.textContent, numeric: getComputedStyle(child).fontVariantNumeric }));
  const sibling = element.nextElementSibling;
  const measure = () => {
   const range = document.createRange(); range.selectNodeContents(number);
   return { number: rect(range), container: rect(element), spans: [...element.children].map(rect), sibling: sibling ? rect(sibling) : null };
  };
  const role = element.matches('.summary-strip strong') ? 'summary' : element.closest('.metric.compact') ? 'compact' : 'expanded';
  const font = { family: style.fontFamily, weight: style.fontWeight, style: style.fontStyle, size: style.fontSize, letterSpacing: style.letterSpacing, numeric: style.fontVariantNumeric, features: style.fontFeatureSettings };
  const loadedInter = [...document.fonts].some(face => face.family.replace(/["']/g, '') === 'Inter' && face.weight === font.weight && face.status === 'loaded');
  const frames = [], proportionalControl = [];
  try {
   for (const text of samples) { number.data = text; frames.push({ text, ...measure() }); }
   // The same font and DOM with its former shaping must actually differ. A
   // computed family name alone cannot establish that tnum affected the glyphs.
   element.style.fontVariantNumeric = 'normal';
   for (const text of samples) { number.data = text; proportionalControl.push(measure().number.width); }
  } finally {
   number.data = original;
   if (originalStyle === null) element.removeAttribute('style'); else element.setAttribute('style', originalStyle);
  }
  return { kind: 'restored-synthetic-DOM-shaping-probe', role, font, loadedInter, spans, frames, proportionalControl, restoredText: number.data, originalText: original, sameTextNode: number.parentNode === element, restoredMarkup: element.innerHTML === originalHTML, restoredStyle: element.getAttribute('style') === originalStyle,
   claims: { liveReactUpdate: false, cls: false, loadingImprovement: false, nativeZoom: false } };
 }, samples);
 // These existing styles.css weights are source-checked by the focused suite.
 const weights = { summary: '600', compact: '400', expanded: '500' };
 expect(evidence.font.weight).toBe(weights[evidence.role]); expect(evidence.font.style).toBe('normal');
 expect(evidence.loadedInter).toBe(true); expect(evidence.font.family).toMatch(/^\"?Inter\"?(?:,|$)/);
 expect(evidence.font.numeric).toBe('tabular-nums'); expect(evidence.restoredText).toBe(evidence.originalText);
 expect(evidence.sameTextNode && evidence.restoredMarkup && evidence.restoredStyle).toBe(true);
 for (const span of evidence.spans) expect(span.numeric).toBe('normal');
 const [first, second] = evidence.frames;
 const stable = (a, b) => expect(Math.abs(a - b)).toBeLessThanOrEqual(0.1);
 stable(first.number.width, second.number.width); stable(first.number.x, second.number.x);
 stable(first.container.width, second.container.width); stable(first.container.x, second.container.x);
 for (let i = 0; i < first.spans.length; i++) { stable(first.spans[i].x, second.spans[i].x); stable(first.spans[i].width, second.spans[i].width); }
 if (first.sibling) { stable(first.sibling.x, second.sibling.x); stable(first.sibling.width, second.sibling.width); }
 expect(Math.abs(evidence.proportionalControl[0] - evidence.proportionalControl[1])).toBeGreaterThan(0.1);
 await capture(`numeric-${name}`, section, evidence);
}

async function inventoryKeyboardReview({ page, expect, capture, locale, size }) {
 const labels = locale === 'de'
  ? { search: 'Geräte durchsuchen', platform: 'Nach Betriebssystem filtern', status: 'Nach Status filtern', sort: 'Geräte sortieren', save: 'Ansicht speichern', saved: 'Gespeichert' }
  : { search: 'Search devices', platform: 'Filter by operating system', status: 'Filter by status', sort: 'Sort devices', save: 'Save view', saved: 'Saved' };
 const save = page.locator('.save-view');
 // The second theme pass starts only after the existing temporary Saved notice
 // resets; keep the runner's assertion deadline and avoid a fixed delay.
 await expect(save).toHaveAccessibleName(labels.save);
 const focusSelect = async (name, screenshot, section) => {
  await page.keyboard.press('Tab');
  const select = page.getByRole('combobox', { name, exact: true });
  await expect(select).toBeFocused(); await expect(select).toBeInViewport();
  // Test computed cascade and true keyboard focus, rather than matching a
  // stylesheet rule that a later selector could silently override.
  expect(await select.evaluate(element => {
   const style = getComputedStyle(element);
   return { visible: element.matches(':focus-visible'), style: style.outlineStyle, width: style.outlineWidth, offset: style.outlineOffset,
    colored: style.outlineColor !== 'transparent' && style.outlineColor !== 'rgba(0, 0, 0, 0)' };
  })).toEqual({ visible: true, style: 'solid', width: '2px', offset: '2px', colored: true });
  await capture(screenshot, section);
 };
 await page.getByRole('textbox', { name: labels.search, exact: true }).focus();
 await focusSelect(labels.platform, 'devices-platform-keyboard-focus', '.filter-toolbar');
 await focusSelect(labels.status, 'devices-status-keyboard-focus', '.filter-toolbar');
 await page.keyboard.press('Tab');
 await expect(save).toBeFocused(); await expect(save).toHaveAccessibleName(labels.save);
 await expect(save).toHaveAttribute('aria-label', labels.save);
 if (size === 'mobile') await expect(save.locator('span')).toBeHidden();
 else await expect(save.locator('span')).toBeVisible();
 await capture('devices-save-view-keyboard-name', '.filter-toolbar');
 await page.keyboard.press('Enter');
 await expect(save).toHaveAccessibleName(labels.saved); await expect(save).toHaveAttribute('aria-label', labels.saved);
 await focusSelect(labels.sort, 'devices-sort-keyboard-focus', '.inventory-meta');
}

export function conciseShellFixture(data) {
 const devices = data.devices.filter(item => item.synthetic === true && item.id.startsWith('demo-'));
 const deviceIds = new Set(devices.map(item => item.id));
 const cases = data.cases.filter(item => item.synthetic === true && item.id.startsWith('case-demo-') && deviceIds.has(item.deviceId));
 const caseIds = new Set(cases.map(item => item.id));
 return { product: 'Tracebolt synthetic gallery', mode: 'local-development', generatedAt: data.generatedAt, devices, cases,
  activity: data.activity.filter(item => (deviceIds.has(item.deviceId) || caseIds.has(item.caseId)) && (!item.deviceId || deviceIds.has(item.deviceId)) && (!item.caseId || caseIds.has(item.caseId))),
  stats: { totalDevices: devices.length, healthyDevices: devices.filter(item => item.status === 'healthy').length,
   attentionDevices: devices.filter(item => ['attention', 'critical'].includes(item.status)).length,
   unknownDevices: devices.filter(item => item.status === 'unknown').length,
   openCases: cases.filter(item => item.status !== 'resolved').length,
   criticalCases: cases.filter(item => item.status !== 'resolved' && item.severity === 'critical').length,
  },
 };
}
export function conciseShellTargets(data) {
 const fixture = conciseShellFixture(data);
 const device = fixture.devices.find(item => item.id === 'demo-win-01' && item.platform === 'windows');
 const statusDevice = fixture.devices.find(item => item.id === 'demo-linux-01' && item.platform === 'linux');
 const selectedCase = fixture.cases.find(item => item.deviceId === device?.id);
 if (!device || !statusDevice || !selectedCase) throw new Error('Required synthetic platform gallery fixtures are unavailable.');
 return { fixture, device, statusDevice, selectedCase };
}
export async function conciseShellGallery({ test, pageAt, loaded, shot, expect, data }) {
 const { fixture, device, statusDevice, selectedCase } = conciseShellTargets(data);
 for (const locale of ['en', 'de']) for (const [size, viewport] of [['desktop', { width: 1440, height: 1000 }], ['mobile', { width: 390, height: 844 }]]) {
  await test(`Concise shell every-page synthetic gallery ${size} ${locale}`, async () => {
   const page = await pageAt('/overview', viewport, { reviewLocale: locale });
   await page.route('**/api/overview', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fixture) }));
   await page.reload(); await loaded(page);
   const capture = async (name, section, numericTypography) => {
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1 && document.body.scrollWidth <= innerWidth + 1)).toBe(true);
    await shot(page, `synthetic-concise-shell-${name}-${size}-${locale}`, section, numericTypography);
   };
   await expect(page.locator('.fleet-panel .device-table .source.real')).toHaveCount(0);
   if (size === 'desktop') await assertDesktopNavigation({ page, expect });
   await numericTypographyReview({ page, expect, capture, locale, name: 'summary', selector: '.summary-strip strong', section: '.summary-strip' });
   await expect(page.locator('.fleet-panel .device-table .source.real')).toHaveCount(0);
   await capture('overview');
   for (const route of ['devices', 'cases', 'settings']) {
    await page.goto(new URL(`#/${route}`, page.url()).href); await loaded(page);
    if (route === 'devices') await expect(page.locator('.device-table .source.real')).toHaveCount(0);
    if (route === 'devices' && size === 'desktop') {
     // Compact fleet metrics are intentionally hidden at the mobile breakpoint.
     await numericTypographyReview({ page, expect, capture, locale, name: 'compact', selector: '.device-table .metric-value:not(:has(.unavailable)):visible', section: '.device-table' });
    }
    if (route === 'devices') await expect(page.locator('.device-table .source.real')).toHaveCount(0);
    await capture(route);
    if (route === 'devices') {
     await inventoryKeyboardReview({ page, expect, capture, locale, size });
     await page.getByRole('button', { name: locale === 'de' ? 'Dunkles Design aktivieren' : 'Switch to dark theme', exact: true }).click();
     await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
     await inventoryKeyboardReview({ page, expect, capture: (name, section) => capture(`${name}-dark`, section), locale, size });
     await page.getByRole('button', { name: locale === 'de' ? 'Helles Design aktivieren' : 'Switch to light theme', exact: true }).click();
     await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
     if (size === 'mobile') await shellDrawerKeyboardReview({ page, expect, capture, locale, viewport });
    }
    if (route === 'settings') await capture('settings-runtime', '.settings-grid');
   }
   await page.goto(new URL(`#/devices/${device.id}`, page.url()).href);
   await expect(page.locator('.device-page h1')).toHaveText(device.name);
   if (size === 'mobile') {
    const deviceRoute = page.url();
    await page.locator('.mobile-menu').focus(); await page.keyboard.press('Enter');
    await expect(page.locator('.sidebar')).toHaveClass(/is-open/);
    await page.keyboard.press('Escape'); await assertMobileDrawerClosed({ page, expect, returnFocus: true });
    // Drawer Escape must not leak to DeviceDetail's existing Back shortcut.
    await expect(page).toHaveURL(deviceRoute); await capture('device-drawer-escape');
   }
   for (const [key, name] of [['overview', locale === 'de' ? 'Übersicht' : 'Overview'], ['details', 'Details'], ['evidence', locale === 'de' ? 'Belege' : 'Evidence']]) {
    await page.getByRole('tab', { name, exact: true }).click();
    if (key === 'overview' || key === 'details') await numericTypographyReview({ page, expect, capture, locale, name: `device-${key}`, selector: '.device-metrics .metric-value:not(:has(.unavailable)):visible', section: '.device-metrics', decimal: key === 'overview' });
    await expect(page.locator('.device-page h1')).toHaveText(device.name);
    await capture(`device-${key}`);
   }
   if (locale === 'de') {
    // Windows has its own overview. Exercise the original three-card contract
    // on a separately whitelisted Linux demo, without dropping Windows views.
    await page.goto(new URL(`#/devices/${statusDevice.id}`, page.url()).href);
    await expect(page.locator('.device-page h1')).toHaveText(statusDevice.name);
    await page.getByRole('tab', { name: 'Übersicht', exact: true }).click();
    // Real layout assertion: the two unknown status values must remain intact
    // at 390px, while desktop typography and the three-card structure stay put.
    await page.evaluate(async () => { await document.fonts.ready; });
    await expect(page.locator('.device-essential-card')).toHaveCount(3);
    const unknown = page.locator('.device-essential-value').filter({ hasText: /^Unbekannt$/ });
    await expect(unknown).toHaveCount(2);
    const geometry = await unknown.evaluateAll(values => values.map(value => {
     const range = document.createRange(); range.selectNodeContents(value);
     const lines = [...range.getClientRects()], card = value.closest('.device-essential-card');
     const bounds = card.getBoundingClientRect(), style = getComputedStyle(card);
     return { text: value.textContent, lines: lines.length,
      contained: lines.every(line => line.left >= bounds.left + parseFloat(style.paddingLeft) - 1 && line.right <= bounds.right - parseFloat(style.paddingRight) + 1),
      fontSize: parseFloat(getComputedStyle(value).fontSize) };
    }));
    for (const value of geometry) {
     expect(value.text).toBe('Unbekannt'); expect(value.lines).toBe(1); expect(value.contained).toBe(true);
     if (size === 'desktop') expect(value.fontSize).toBe(22);
     else { expect(value.fontSize).toBeGreaterThanOrEqual(13); expect(value.fontSize).toBeLessThanOrEqual(16); }
    }
    await capture('linux-device-overview');
   }
   await page.goto(new URL(`#/cases/${selectedCase.id}`, page.url()).href);
   await expect(page.locator('.case-detail-header h1')).toHaveText(selectedCase.title);
   await capture('case'); await capture('case-steps', '.next-steps-panel');
   await page.keyboard.press('?');
   await expect(page.getByRole('dialog', { name: locale === 'de' ? 'Tastenkürzel' : 'Keyboard shortcuts', exact: true })).toBeVisible();
   await capture('shortcuts'); await page.keyboard.press('Escape');
  });
 }
}
