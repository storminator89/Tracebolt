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
/** Geometry only: classify bounded edge clipping, not whole-page accessibility.
 * Long table bottoms may extend past the viewport; their top and both sides may not.
 */
export function focusVisibility({ bounds, outlineWidth, outlineOffset, viewport, clips = [], headers = [], allowTallBottom = false }) {
 const validRect = rect => rect && ['left', 'top', 'right', 'bottom'].every(key => Number.isFinite(rect[key])) && rect.right > rect.left && rect.bottom > rect.top;
 if (!validRect(bounds) || !validRect(viewport) || !Number.isFinite(outlineWidth) || outlineWidth <= 0 || !Number.isFinite(outlineOffset) || outlineOffset < -outlineWidth || clips.length > 32 || headers.length > 2) throw new Error('Invalid focus geometry');
 const clip = { ...viewport };
 for (const layer of clips) {
  if (!validRect(layer.bounds) || typeof layer.x !== 'boolean' || typeof layer.y !== 'boolean') throw new Error('Invalid clipping layer');
  if (layer.x) { clip.left = Math.max(clip.left, layer.bounds.left); clip.right = Math.min(clip.right, layer.bounds.right); }
  if (layer.y) { clip.top = Math.max(clip.top, layer.bounds.top); clip.bottom = Math.min(clip.bottom, layer.bounds.bottom); }
 }
 if (!validRect(clip)) throw new Error('No visible focus scrollport');
 const extent = outlineWidth + outlineOffset;
 const outline = { left: bounds.left - extent, top: bounds.top - extent, right: bounds.right + extent, bottom: bounds.bottom + extent };
 if (!validRect(outline)) throw new Error('Invalid outline bounds');
 const epsilon = 0.5;
 const clipped = { left: outline.left < clip.left - epsilon, right: outline.right > clip.right + epsilon,
  top: outline.top < clip.top - epsilon, bottom: outline.bottom > clip.bottom + epsilon };
 const topBandVisible = outline.top + outlineWidth <= clip.bottom + epsilon;
 const tallBottomCrop = allowTallBottom && bounds.bottom - bounds.top > clip.bottom - clip.top && clipped.bottom;
 const headerOverlap = headers.some(header => {
  if (!validRect(header)) throw new Error('Invalid protected header');
  return Math.min(outline.right, header.right) - Math.max(outline.left, header.left) > epsilon && Math.min(outline.bottom, header.bottom) - Math.max(outline.top, header.top) > epsilon;
 });
 return { outlineBounds: outline, clipBounds: clip, clipped, topBandVisible, tallBottomCrop, headerOverlap,
  accepted: !clipped.left && !clipped.right && !clipped.top && (!clipped.bottom || tallBottomCrop) && topBandVisible && !headerOverlap };
}
/** Fixed diagnostic only; never changes the clipping decision or its tolerance.
 * A fractional-client discrepancy is not evidence that painted pixels are clear.
 */
export function rightFocusClipReason(geometry, visibility) {
 if (!visibility.clipped.right) return 'none';
 const right = visibility.outlineBounds.right;
 const viewport = right > geometry.viewport.right + 0.5;
 const layers = (geometry.clips ?? []).filter(layer => layer.x && right > layer.bounds.right + 0.5);
 if (layers.some(layer => !['table', 'ancestor'].includes(layer.kind))) return 'unclassified';
 const table = layers.filter(layer => layer.kind === 'table');
 const ancestor = layers.some(layer => layer.kind !== 'table');
 if (Number(viewport) + Number(table.length > 0) + Number(ancestor) > 1) return 'mixed';
 if (viewport) return 'viewport';
 if (ancestor) return 'ancestor';
 if (!table.length) return 'unclassified';
 // This independent edge is diagnostic-only and requires every offending table
 // to pass the unscaled/no-gutter/no-vertical-overflow guard. Unknown is explicit.
 const fractional = table.every(layer => layer.fractionalGuard === true && Number.isFinite(layer.fractionalRight)
  && Number.isFinite(layer.fractionalWidth) && layer.fractionalWidth > 0);
 const small = right - visibility.clipBounds.right <= 1;
 if (!fractional) return small ? 'table unverified subpixel' : 'table unverified overflow';
 if (table.some(layer => geometry.bounds.right - geometry.bounds.left > layer.fractionalWidth)) return 'table wider';
 if (table.every(layer => right <= layer.fractionalRight)) return 'table fractional';
 return small ? 'table subpixel' : 'table overflow';
}
export async function measureFocusVisibility(control, stage = () => {}) {
 stage('outline geometry read');
 const geometry = await control.evaluate(element => {
  const rect = node => { const r = node.getBoundingClientRect(); return { left: r.left, top: r.top, right: r.right, bottom: r.bottom }; };
  const style = getComputedStyle(element), clips = [];
  const unscaled = s => s.transform === 'none' && s.perspective === 'none'
   && s.translate === 'none' && s.rotate === 'none' && s.scale === 'none' && (s.zoom === '1' || s.zoom === 'normal');
  let allUnscaled = unscaled(style);
  for (let node = element.parentElement; node; node = node.parentElement) {
   const s = getComputedStyle(node), x = /^(auto|scroll|hidden|clip)$/.test(s.overflowX), y = /^(auto|scroll|hidden|clip)$/.test(s.overflowY);
   allUnscaled = allUnscaled && unscaled(s);
   if (x || y) {
    const r = node.getBoundingClientRect(), left = r.left + node.clientLeft, top = r.top + node.clientTop;
    clips.push({ x, y, bounds: { left, top, right: left + node.clientWidth, bottom: top + node.clientHeight },
     kind: node.matches('.package-table-scroll') ? 'table' : 'ancestor',
     fractionalRight: r.right - parseFloat(s.borderRightWidth),
     fractionalWidth: r.right - r.left - parseFloat(s.borderLeftWidth) - parseFloat(s.borderRightWidth),
     fractionalGuard: s.direction === 'ltr' && s.writingMode === 'horizontal-tb' && s.scrollbarGutter === 'auto'
      && /^(auto|hidden|clip)$/.test(s.overflowY) && node.scrollHeight <= node.clientHeight });
   }
  }
  for (const layer of clips) layer.fractionalGuard = layer.fractionalGuard && allUnscaled;
  const headers = [...document.querySelectorAll('.main-shell > .topbar, .main-shell > .transport-warning')].map(rect).filter(r => r.right > r.left && r.bottom > r.top);
  return { bounds: rect(element), outlineWidth: parseFloat(style.outlineWidth), outlineOffset: parseFloat(style.outlineOffset),
   viewport: { left: 0, top: 0, right: innerWidth, bottom: innerHeight }, clips, headers,
   allowTallBottom: element.matches('.package-table-scroll[tabindex="0"]') };
 });
 stage('outline geometry classify');
 const visibility = focusVisibility(geometry);
 // Inset ring samples are inside the target border box, away from rounded
 // corners. Hit testing rejects a covering fixed header/overlay without moving it.
 stage('outline hit-test read');
 const hitTests = await control.evaluate((element, v) => {
  const ring = v.outlineBounds, width = parseFloat(getComputedStyle(element).outlineWidth);
  const centerX = (ring.left + ring.right) / 2;
  const middleY = (Math.max(ring.top, v.clipBounds.top) + Math.min(ring.bottom, v.clipBounds.bottom)) / 2;
  const points = { top: [centerX, ring.top + width / 2], left: [ring.left + width / 2, middleY], right: [ring.right - width / 2, middleY] };
  if (!v.tallBottomCrop) points.bottom = [centerX, ring.bottom - width / 2];
  return Object.fromEntries(Object.entries(points).map(([edge, [x, y]]) => {
   const hit = document.elementFromPoint(x, y);
   return [edge, !!hit && (hit === element || element.contains(hit))];
  }));
 }, visibility);
 return { ...visibility, rightClipReason: rightFocusClipReason(geometry, visibility), hitTests, accepted: visibility.accepted && Object.values(hitTests).every(Boolean) };
}
/** Preposition only a real predecessor. The target and intermediate region are
 * reached exclusively by forward Tab, with no target focus/scroll correction. */
export async function enterFocusByTab({ page, expect, selector, keyboardEntry }) {
 if (!keyboardEntry || typeof keyboardEntry.from !== 'string' || keyboardEntry.from === selector || !Array.isArray(keyboardEntry.path)
  || keyboardEntry.path.length < 1 || keyboardEntry.path.length > 2 || keyboardEntry.path.at(-1) !== selector
  || keyboardEntry.path.some(step => typeof step !== 'string' || !step)) throw new Error('Invalid bounded keyboard entry');
 const predecessor = page.locator(keyboardEntry.from).first();
 await predecessor.scrollIntoViewIfNeeded(); await predecessor.focus(); await expect(predecessor).toBeFocused();
 for (const step of keyboardEntry.path) {
  await page.keyboard.press('Tab'); await expect(page.locator(step).first()).toBeFocused();
 }
 return { method: 'forward-tab', from: keyboardEntry.from, path: keyboardEntry.path };
}
export async function assertKeyboardContrast({ page, expect, selector, keyboardEntry, stage = () => {} }) {
 const control = page.locator(selector).first();
 stage('keyboard entry');
 let entry;
 if (keyboardEntry) entry = await enterFocusByTab({ page, expect, selector, keyboardEntry });
 else {
  await control.scrollIntoViewIfNeeded(); await control.focus();
  // Existing unaffected captures retain their keyboard-return evidence.
  await page.keyboard.press('Tab'); await page.keyboard.press('Shift+Tab');
  entry = { method: 'target-return' };
 }
 await expect(control).toBeFocused(); await expect(control).toBeInViewport();
 stage('computed contrast');
 const measurement = await measureContrast(control);
 expect(measurement.focusVisible).toBe(true); expect(measurement.outlineStyle).toBe('solid');
 expect(parseFloat(measurement.outlineWidth)).toBeGreaterThanOrEqual(2);
 expect(measurement.ratio).toBeGreaterThanOrEqual(3);
 if (keyboardEntry) {
  stage('outline exposure');
  const visibility = await measureFocusVisibility(control, stage);
  stage('outline left edge'); expect(visibility.clipped.left).toBe(false);
  stage('outline right edge');
  if (visibility.clipped.right) {
   if (visibility.rightClipReason === 'viewport') stage('outline right viewport');
   else if (visibility.rightClipReason === 'ancestor') stage('outline right ancestor');
   else if (visibility.rightClipReason === 'mixed') stage('outline right mixed');
   else if (visibility.rightClipReason === 'table wider') stage('outline right table wider');
   else if (visibility.rightClipReason === 'table fractional') stage('outline right table fractional');
   else if (visibility.rightClipReason === 'table subpixel') stage('outline right table subpixel');
   else if (visibility.rightClipReason === 'table overflow') stage('outline right table overflow');
   else if (visibility.rightClipReason === 'table unverified subpixel') stage('outline right table unverified subpixel');
   else if (visibility.rightClipReason === 'table unverified overflow') stage('outline right table unverified overflow');
  }
  expect(visibility.clipped.right).toBe(false);
  stage('outline top edge'); expect(visibility.clipped.top).toBe(false);
  stage('outline top band'); expect(visibility.topBandVisible).toBe(true);
  stage('outline header'); expect(visibility.headerOverlap).toBe(false);
  // Explain the unchanged aggregate assertion using only fixed labels for its
  // existing booleans. No coordinate, DOM content or measurement is released.
  if (visibility.clipped.bottom && !visibility.tallBottomCrop) stage('outline bottom edge');
  else if (visibility.hitTests.top === false) stage('outline hit top');
  else if (visibility.hitTests.left === false) stage('outline hit left');
  else if (visibility.hitTests.right === false) stage('outline hit right');
  else if (visibility.hitTests.bottom === false) stage('outline hit bottom');
  else stage('outline accepted');
  expect(visibility.accepted).toBe(true);
  return { ...measurement, entry, visibility };
 }
 return { ...measurement, entry };
}
export async function setContrastTheme(page, expect, theme) {
 if (await page.locator('html').getAttribute('data-theme') === theme) return;
 const name = theme === 'dark' ? /^(Switch to dark theme|Dunkles Design aktivieren)$/ : /^(Switch to light theme|Helles Design aktivieren)$/;
 await page.getByRole('button', { name, exact: true }).click();
 await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
}
// Closed diagnostic vocabulary; never interpolate unknown page/caller values.
export function focusContrastStage(name, size, locale, theme, phase) {
 if (!['legacy-package-table', 'legacy-package-details', 'advisory-toggle', 'inventory-source-tab', 'complete-package-search', 'complete-package-table', 'complete-package-details'].includes(name)
  || !['desktop', 'mobile'].includes(size) || !['en', 'de'].includes(locale) || !['light', 'dark'].includes(theme)
  || !['outline geometry read', 'outline geometry classify', 'outline hit-test read', 'keyboard entry', 'computed contrast', 'outline exposure', 'outline left edge', 'outline right edge', 'outline right viewport', 'outline right ancestor', 'outline right mixed', 'outline right table wider', 'outline right table fractional', 'outline right table subpixel', 'outline right table overflow', 'outline right table unverified subpixel', 'outline right table unverified overflow', 'outline top edge', 'outline top band', 'outline header', 'outline bottom edge', 'outline hit top', 'outline hit left', 'outline hit right', 'outline hit bottom', 'outline accepted', 'synthetic capture'].includes(phase)) return 'focus contrast unknown';
 return `focus contrast ${name} ${size} ${locale} ${theme}: ${phase}`;
}
export async function captureFocusMatrix({ page, expect, targets, capture, mark = () => {} }) {
 const originalViewport = page.viewportSize(), originalTheme = await page.locator('html').getAttribute('data-theme'), originalLocale = await page.locator('html').getAttribute('lang');
 try {
  for (const locale of ['en', 'de']) for (const [size, viewport] of [['desktop', { width: 1440, height: 1000 }], ['mobile', { width: 390, height: 844 }]]) for (const theme of ['light', 'dark']) {
   await page.setViewportSize(viewport); await page.getByLabel(/^(Language|Sprache)$/).selectOption(locale); await setContrastTheme(page, expect, theme);
   for (const { name, selector, keyboardEntry } of targets) {
    const stage = phase => mark(focusContrastStage(name, size, locale, theme, phase));
    const measurement = await assertKeyboardContrast({ page, expect, selector, keyboardEntry, stage });
    stage('synthetic capture');
    await capture(`synthetic-focus-contrast-${name}-${size}-${locale}-${theme}`, measurement);
   }
  }
 } finally {
  await page.setViewportSize(originalViewport); await page.getByLabel(/^(Language|Sprache)$/).selectOption(originalLocale); await setContrastTheme(page, expect, originalTheme || 'light');
 }
}
