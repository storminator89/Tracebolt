import { conciseShellFixture } from './concise-shell-gallery.mjs';
import { assertKeyboardContrast, measureContrast, setContrastTheme } from './focus-contrast-browser.mjs';

/** Existing disposable synthetic shell, with one deterministic read failure.
 * Every image is filtered to built-in synthetic rows before capture. */
export async function focusContrastShellGallery({ test, pageAt, loaded, shot, expect, data, record }) {
 const fixture = conciseShellFixture(data);
 for (const locale of ['en', 'de']) for (const [size, viewport] of [['desktop', { width: 1440, height: 1000 }], ['mobile', { width: 390, height: 844 }]]) for (const theme of ['light', 'dark']) {
  await test(`S03/S04 shell solid-color contrast ${size} ${locale} ${theme}`, async () => {
   const page = await pageAt('/overview', viewport, { reviewLocale: locale });
   await page.route('**/api/overview', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fixture) }));
   await page.reload(); await loaded(page); await expect(page.locator('.fleet-panel .source.real')).toHaveCount(0);
   await setContrastTheme(page, expect, theme);
   if (size === 'mobile') {
    await page.locator('.mobile-menu').focus(); await page.keyboard.press('Enter');
    await expect(page.locator('.sidebar')).toHaveClass(/is-open/);
   }
   const label = await measureContrast(page.locator('.sidebar .nav-label').first(), 'text');
   expect(label.ratio).toBeGreaterThanOrEqual(4.5);
   for (const [state, selector] of [['selected', '.sidebar .nav-item.active'], ['unselected', '.sidebar .nav-item:not(.active)']]) {
    const measurement = await assertKeyboardContrast({ page, expect, selector });
    await shot(page, `synthetic-focus-contrast-sidebar-${state}-${size}-${locale}-${theme}`);
    record({ focus: measurement, secondaryText: label });
   }
   if (size === 'mobile') { await page.keyboard.press('Escape'); await expect(page.locator('.sidebar')).not.toHaveClass(/is-open/); }
   // Fail only this disposable overview read, retaining the already-filtered rows.
   await page.unroute('**/api/overview');
   await page.route('**/api/overview', route => route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: { code: 'synthetic_unavailable', message: 'Synthetic review read unavailable' } }) }));
   await page.getByRole('button', { name: locale === 'de' ? 'Aktualisieren' : 'Refresh', exact: true }).click();
   await expect(page.locator('.error-banner')).toBeVisible();
   await expect(page.locator('.fleet-panel .source.real')).toHaveCount(0);
   const heading = await measureContrast(page.locator('.error-banner strong'), 'text');
   const body = await measureContrast(page.locator('.error-banner p'), 'text');
   expect(heading.ratio).toBeGreaterThanOrEqual(4.5); expect(body.ratio).toBeGreaterThanOrEqual(4.5);
   await shot(page, `synthetic-focus-contrast-error-${size}-${locale}-${theme}`, '.error-banner');
   record({ heading, body });
  });
 }
}
