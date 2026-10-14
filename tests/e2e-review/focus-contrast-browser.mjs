/** Narrow computed-color evidence for real controls in existing synthetic runners.
 * No browser launch, fixture grants, DOM replacement, or stylesheet injection.
 * Ratios describe solid authored colors, not antialiased pixels or whole-app WCAG.
 */
export function rgba(value) {
 const hex = /^#([\da-f]{3}|[\da-f]{6}|[\da-f]{8})$/i.exec(value);
 if (hex) {
  const s = hex[1].length === 3 ? [...hex[1]].map(c => c + c).join('') : hex[1];
  return [0, 2, 4].map(i => parseInt(s.slice(i, i + 2), 16) / 255).concat(s.length === 8 ? parseInt(s.slice(6), 16) / 255 : 1);
 }
 const match = /^rgba?\(\s*([\d.]+)[, ]+([\d.]+)[, ]+([\d.]+)(?:\s*[,/]\s*([\d.]+))?\s*\)$/.exec(value);
 if (!match) throw new Error('Unsupported solid color syntax');
 const color = match.slice(1, 4).map(Number).map(n => n / 255).concat(match[4] === undefined ? 1 : Number(match[4]));
 if (color.some(n => !Number.isFinite(n) || n < 0 || n > 1)) throw new Error('Invalid solid color range');
 return color;
}
export function composite(foreground, background) {
 if (background[3] !== 1) throw new Error('Opaque backing color required');
 return foreground.slice(0, 3).map((n, i) => n * foreground[3] + background[i] * (1 - foreground[3])).concat(1);
}
export function contrast(foreground, background) {
 const luminance = color => color.slice(0, 3).map(n => n <= 0.04045 ? n / 12.92 : ((n + 0.055) / 1.055) ** 2.4).reduce((sum, n, i) => sum + n * [0.2126, 0.7152, 0.0722][i], 0);
 const a = luminance(composite(foreground, background)), b = luminance(background);
 return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}
export async function measureContrast(locator, kind = 'focus') {
 const paint = await locator.evaluate((element, kind) => {
  const styles = [];
  for (let node = element; node; node = node.parentElement) {
   const style = getComputedStyle(node);
   // Solid-color arithmetic would be misleading for images/opacity/filter layers.
   if (style.backgroundImage !== 'none' || Number(style.opacity) !== 1 || style.filter !== 'none') throw new Error('Unsupported painted background');
   styles.push(style.backgroundColor);
  }
  const style = getComputedStyle(element);
  return { theme: document.documentElement.dataset.theme, backgrounds: styles.reverse(), foreground: kind === 'focus' ? style.outlineColor : style.color,
   focusVisible: element.matches(':focus-visible'), outlineStyle: style.outlineStyle, outlineWidth: style.outlineWidth, outlineOffset: style.outlineOffset };
 }, kind);
 // The root must provide an opaque canvas; never silently assume white.
 if (rgba(paint.backgrounds[0])[3] !== 1) throw new Error('Opaque root canvas required');
 let backing = rgba(paint.backgrounds[0]);
 const backgrounds = paint.backgrounds.slice(1);
 if (kind === 'focus' && parseFloat(paint.outlineOffset) >= 0) backgrounds.pop();
 for (const color of backgrounds) backing = composite(rgba(color), backing);
 return { ...paint, effectiveBackground: backing, ratio: contrast(rgba(paint.foreground), backing) };
}
export async function assertKeyboardContrast({ page, expect, selector }) {
 const control = page.locator(selector).first();
 await control.scrollIntoViewIfNeeded(); await control.focus();
 // Finish with real keyboard traversal so :focus-visible is genuinely active.
 await page.keyboard.press('Tab'); await page.keyboard.press('Shift+Tab');
 await expect(control).toBeFocused(); await expect(control).toBeInViewport();
 const measurement = await measureContrast(control);
 expect(measurement.focusVisible).toBe(true); expect(measurement.outlineStyle).toBe('solid');
 expect(parseFloat(measurement.outlineWidth)).toBeGreaterThanOrEqual(2);
 expect(measurement.ratio).toBeGreaterThanOrEqual(3);
 return measurement;
}
export async function setContrastTheme(page, expect, theme) {
 if (await page.locator('html').getAttribute('data-theme') === theme) return;
 const name = theme === 'dark' ? /^(Switch to dark theme|Dunkles Design aktivieren)$/ : /^(Switch to light theme|Helles Design aktivieren)$/;
 await page.getByRole('button', { name, exact: true }).click();
 await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
}
export async function captureFocusMatrix({ page, expect, targets, capture }) {
 const originalViewport = page.viewportSize(), originalTheme = await page.locator('html').getAttribute('data-theme'), originalLocale = await page.locator('html').getAttribute('lang');
 try {
  for (const locale of ['en', 'de']) for (const [size, viewport] of [['desktop', { width: 1440, height: 1000 }], ['mobile', { width: 390, height: 844 }]]) for (const theme of ['light', 'dark']) {
   await page.setViewportSize(viewport); await page.getByLabel(/^(Language|Sprache)$/).selectOption(locale); await setContrastTheme(page, expect, theme);
   for (const { name, selector } of targets) {
    const measurement = await assertKeyboardContrast({ page, expect, selector });
    await capture(`synthetic-focus-contrast-${name}-${size}-${locale}-${theme}`, measurement);
   }
  }
 } finally {
  await page.setViewportSize(originalViewport); await page.getByLabel(/^(Language|Sprache)$/).selectOption(originalLocale); await setContrastTheme(page, expect, originalTheme || 'light');
 }
}
