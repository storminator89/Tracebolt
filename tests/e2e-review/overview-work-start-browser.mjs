/** Read-only overview composition checks. All captures use the existing
 * synthetic-only gallery projection; no real local/device row is eligible. */
export const overviewWorkStartWidths = Object.freeze([320, 375, 414, 720, 768]);
export const overviewWorkStartOrder = Object.freeze(['.overview-context', '.attention-panel', '.summary-strip', '.fleet-panel .device-table', '.activity-panel']);

export function overviewNoOpenWork(fixture) {
 if (!fixture.devices.length || fixture.devices.some(row => row.synthetic !== true || !row.id.startsWith('demo-')) || fixture.cases.some(row => row.synthetic !== true || !row.id.startsWith('case-demo-'))) throw new Error('Synthetic populated overview required.');
 // Keep the exact device and evidence snapshots. No open case is not healthy.
 return { ...fixture, cases: [], activity: [], stats: { ...fixture.stats, openCases: 0, criticalCases: 0 } };
}

export async function assertOverviewWorkStart({ page, expect, empty = false }) {
 const selectors = empty ? ['.overview-context', '.first-device-panel', '.attention-panel', '.activity-panel'] : overviewWorkStartOrder;
 await expect(page.locator('.overview-workspace')).toBeVisible();
 expect(await page.evaluate(selectors => {
  const elements = selectors.map(selector => document.querySelector(selector));
  return elements.every(Boolean) && elements.every((element, index) => index === 0 || Boolean(elements[index - 1].compareDocumentPosition(element) & Node.DOCUMENT_POSITION_FOLLOWING));
 }, selectors)).toBe(true);
 if (empty) {
  await expect(page.locator('.summary-strip,.fleet-panel')).toHaveCount(0);
  expect(await page.locator('.first-device-panel .empty-state').evaluate(node => getComputedStyle(node).textAlign)).toBe('left');
 } else {
  await expect(page.locator('.first-device-panel')).toHaveCount(0);
  // Original report timestamps stay present in the narrow-screen row, even
  // when the desktop Last seen column is hidden. This is not fresh reachability.
  expect(await page.locator('.overview-device-report').evaluateAll(nodes => nodes.every(node => node.querySelector('.source') && node.querySelector('time')?.getAttribute('datetime') === node.closest('tr')?.querySelector('td.hide-mobile time')?.getAttribute('datetime')))).toBe(true);
  const width = page.viewportSize().width;
  if (width <= 760) await expect(page.locator('.overview-device-report').first()).toBeVisible();
  else await expect(page.locator('.overview-device-report').first()).toBeHidden();
 }
 expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1 && document.body.scrollWidth <= innerWidth + 1)).toBe(true);
}

export function contrastRatio(first, second) {
 const luminance = color => {
  const match = /^rgb\((\d+), (\d+), (\d+)\)$/.exec(color);
  if (!match) throw new Error('Expected opaque computed RGB color.');
  const values = match.slice(1).map(value => Number(value) / 255).map(value => value <= .04045 ? value / 12.92 : ((value + .055) / 1.055) ** 2.4);
  return values[0] * .2126 + values[1] * .7152 + values[2] * .0722;
 };
 const a = luminance(first), b = luminance(second);
 return (Math.max(a, b) + .05) / (Math.min(a, b) + .05);
}

async function focusReview({ page, expect }) {
 // Start at the first work section and traverse into its first actual item.
 // This verifies DOM order without moving focus by click or testing a CSS rule.
 const all = page.locator('.attention-panel .section-head button');
 await all.focus(); await page.keyboard.press('Tab');
 const first = page.locator('.attention-panel .case-row').first();
 await expect(first).toBeFocused(); await expect(first).toBeInViewport();
 expect(await first.evaluate(node => {
  const css = getComputedStyle(node);
  return node.matches(':focus-visible') && css.outlineStyle === 'solid' && parseFloat(css.outlineWidth) >= 2 && parseFloat(css.outlineOffset) <= 0;
 })).toBe(true);
 const colors = await first.evaluate(node => {
  const color = getComputedStyle(node).outlineColor;
  for (let current = node; current; current = current.parentElement) {
   const background = getComputedStyle(current).backgroundColor;
   if (background !== 'transparent' && background !== 'rgba(0, 0, 0, 0)') return { color, background };
  }
  throw new Error('No opaque focus background found.');
 });
 expect(contrastRatio(colors.color, colors.background)).toBeGreaterThanOrEqual(3);
}

export async function reviewOverviewWorkStart({ page, expect, capture, locale, size, viewport, fixture }) {
 overviewNoOpenWork(fixture); // Privacy assertion before creating any capture.
 const initialTheme = await page.locator('html').getAttribute('data-theme');
 const themeButton = dark => page.getByRole('button', { name: locale === 'de' ? dark ? 'Dunkles Design aktivieren' : 'Helles Design aktivieren' : dark ? 'Switch to dark theme' : 'Switch to light theme', exact: true });
 const top = () => page.locator('#main-content').evaluate(node => { node.scrollTop = 0; });
 await assertOverviewWorkStart({ page, expect });
 for (const theme of ['light', 'dark']) {
  if (await page.locator('html').getAttribute('data-theme') !== theme) await themeButton(theme === 'dark').click();
  await focusReview({ page, expect }); await capture(`overview-work-focus-${theme}`, '.attention-panel');
  await top(); await capture(`overview-work-start-${theme}`);
  if (size === 'desktop') for (const width of overviewWorkStartWidths) {
   await page.setViewportSize({ width, height: width === 720 ? 500 : 844 });
   await top(); await assertOverviewWorkStart({ page, expect });
   await capture(`overview-reflow-${width}-${theme}`);
   await capture(`overview-fleet-${width}-${theme}`, '.fleet-panel');
  }
  await page.setViewportSize(viewport);
 }
 if (await page.locator('html').getAttribute('data-theme') !== initialTheme) await themeButton(initialTheme === 'dark').click();
 // A separate populated/no-open-work fixture cannot be confused with first setup.
 const noWork = overviewNoOpenWork(fixture);
 let state = 'no-work', release = null;
 const handler = async route => {
  if (state === 'held') await new Promise(resolve => { release = resolve; });
  if (state === 'error') return route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: { message: 'Synthetic overview unavailable' } }) });
  return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(state === 'no-work' ? noWork : fixture) });
 };
 await page.route('**/api/overview', handler);
 try {
  await page.reload(); await expect(page.locator('.attention-panel .empty-state')).toBeVisible();
  await assertOverviewWorkStart({ page, expect });
  await expect(page.locator('.fleet-panel tbody tr')).toHaveCount(Math.min(6, fixture.devices.length));
  await capture('overview-populated-no-open-work');
  state = 'held'; await page.locator('.page-footer button').click();
  await expect(page.locator('.overview-context-notice')).toContainText(locale === 'de' ? 'Vorheriger Stand' : 'Previous snapshot');
  await capture('overview-refreshing');
  await expect.poll(() => Boolean(release)).toBe(true);
  state = 'error'; release(); release = null;
  await expect(page.locator('.error-banner')).toBeVisible();
  await expect(page.locator('.overview-context-notice')).toContainText(locale === 'de' ? 'Aktualisierung nicht verfügbar' : 'Refresh unavailable');
  await expect(page.locator('.overview-context time')).toHaveAttribute('datetime', fixture.generatedAt);
  await capture('overview-retained-fetch-error');
  state = 'held'; await page.reload({ waitUntil: 'domcontentloaded' });
  await expect(page.locator('.initial-loading')).toBeVisible();
  await expect(page.locator('.overview-workspace,.first-device-panel')).toHaveCount(0);
  await capture('overview-initial-loading');
  await expect.poll(() => Boolean(release)).toBe(true);
  state = 'error'; release(); release = null;
  await expect(page.locator('.error-banner')).toBeVisible();
  await expect(page.locator('.overview-workspace,.first-device-panel')).toHaveCount(0);
  await capture('overview-initial-fetch-error');
 } finally {
  state = 'ready'; release?.(); await page.unroute('**/api/overview', handler);
  await page.reload(); await expect(page.locator('.overview-workspace')).toBeVisible(); await top();
 }
}
