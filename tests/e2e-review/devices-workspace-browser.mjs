/** Source-bound composition checks for the existing synthetic shell gallery and
 * disposable enrollment runner. No browser launch, requests or fixture writes. */
export const devicesWorkspaceOrder = Object.freeze(['.devices-workspace-index', '.devices-inventory-section', '.devices-setup-section', '.devices-tools-section']);
export const devicesWorkspaceWidths = Object.freeze([320, 375, 414, 768]);
export const devicesWorkspaceCaptureMatrix = Object.freeze([
 { locale: 'en', size: 'desktop', theme: 'light', destination: 'setup' }, { locale: 'en', size: 'desktop', theme: 'light', destination: 'tools' },
 { locale: 'de', size: 'mobile', theme: 'dark', destination: 'setup' }, { locale: 'de', size: 'mobile', theme: 'dark', destination: 'tools' },
]);
export async function assertDevicesWorkspace({ page, expect, locale = 'en', tools = false, jump = true }) {
 const labels = locale === 'de' ? ['Inventar', 'Einrichten', 'Flottentools'] : ['Inventory', 'Setup', 'Fleet tools'];
 const index = page.locator('.devices-workspace-index');
 await expect(index).toBeVisible(); await expect(index.locator('button')).toHaveCount(3);
 await expect(index.locator('a,[role=tab],[aria-selected],[aria-expanded]')).toHaveCount(0);
 expect(await page.evaluate(selectors => {
  const elements = selectors.map(selector => document.querySelector(selector));
  return elements.every(Boolean) && elements.every((element, i) => (!i || elements[i - 1].compareDocumentPosition(element) & Node.DOCUMENT_POSITION_FOLLOWING) && !element.hidden && !element.inert && getComputedStyle(element).display !== 'none');
 }, devicesWorkspaceOrder)).toBe(true);
 if (tools) await expect(page.locator('.devices-tools-section > section')).toHaveCount(6);
 const before = await page.evaluate(() => ({ hash: location.hash, length: history.length }));
 if (jump) {
  for (const name of [labels[2], labels[0], labels[1]]) {
   const button = index.getByRole('button', { name, exact: true });
   await button.focus(); await page.keyboard.press('Enter');
   const heading = page.getByRole('heading', { name, exact: true });
   await expect(heading).toBeFocused(); await expect(heading).toBeInViewport();
   expect(await heading.evaluate(node => { const css = getComputedStyle(node); return css.outlineStyle === 'solid' && parseFloat(css.outlineWidth) >= 2; })).toBe(true);
   expect(await page.evaluate(() => ({ hash: location.hash, length: history.length }))).toEqual(before);
  }
 }
 expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1 && document.body.scrollWidth <= innerWidth + 1)).toBe(true);
}
export async function reviewDevicesWorkspace({ page, expect, capture, locale, size, viewport }) {
 const reviewTheme = locale === 'de' ? 'dark' : 'light';
 const initial = await page.locator('html').getAttribute('data-theme');
 const theme = dark => page.getByRole('button', { name: locale === 'de' ? dark ? 'Dunkles Design aktivieren' : 'Helles Design aktivieren' : dark ? 'Switch to dark theme' : 'Switch to light theme', exact: true });
 const top = () => page.locator('#main-content').evaluate(node => { node.scrollTop = 0; });
 if (initial !== reviewTheme) await theme(reviewTheme === 'dark').click();
 try {
  await assertDevicesWorkspace({ page, expect, locale }); await top();
  // The existing route capture already covers the index. The four core images
  // now show actual LAN Setup/Tools destinations in the enrollment runner.
  // Assertions cover all required reflow widths without multiplying screenshots.
  if (size === 'desktop') for (const width of devicesWorkspaceWidths) {
   await page.setViewportSize({ width, height: 844 }); await assertDevicesWorkspace({ page, expect, locale });
   if (locale === 'en' && width === 320) { await top(); await capture('devices-workspaces-reflow-320'); }
  }
  if (size === 'desktop' && locale === 'de') {
   await page.setViewportSize({ width: 320, height: 844 });
   // Deliberately a 200% text-resize fixture for the new navigation/status/
   // section text. This is not native browser zoom or a whole-app zoom claim.
   const style = await page.addStyleTag({ content: '.devices-workspace-index button{font-size:28px}.devices-setup-attention,.devices-workspace-heading p,.devices-workspace-unavailable{font-size:24px}.devices-workspace-heading h2{font-size:36px}' });
   try { await assertDevicesWorkspace({ page, expect, locale }); await top(); await capture('devices-workspaces-text-resize-200-percent-320'); }
   finally { await style.evaluate(node => node.remove()); }
  }
 } finally {
  await page.setViewportSize(viewport);
  if (await page.locator('html').getAttribute('data-theme') !== initial) await theme(initial === 'dark').click();
  await top();
 }
}

export async function captureDevicesWorkspaceDestinations({ page, expect, shot, locale, mobile }) {
 const size = mobile ? 'mobile' : 'desktop';
 const cases = devicesWorkspaceCaptureMatrix.filter(row => row.locale === locale && row.size === size);
 if (!cases.length) return;
 const initial = await page.locator('html').getAttribute('data-theme');
 const themeButton = dark => page.getByRole('button', { name: locale === 'de' ? dark ? 'Dunkles Design aktivieren' : 'Helles Design aktivieren' : dark ? 'Switch to dark theme' : 'Switch to light theme', exact: true });
 if (initial !== cases[0].theme) await themeButton(cases[0].theme === 'dark').click();
 try {
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await assertDevicesWorkspace({ page, expect, locale, tools: true, jump: false });
  for (const item of cases) {
   const name = item.destination === 'setup' ? locale === 'de' ? 'Einrichten' : 'Setup' : locale === 'de' ? 'Flottentools' : 'Fleet tools';
   const before = await page.evaluate(() => ({ hash: location.hash, length: history.length }));
   await page.locator('.devices-workspace-index').getByRole('button', { name, exact: true }).focus();
   await page.keyboard.press('Enter');
   const heading = page.getByRole('heading', { name, exact: true });
   await expect(heading).toBeFocused(); await expect(heading).toBeInViewport();
   const section = page.locator(item.destination === 'setup' ? '.devices-setup-section' : '.devices-tools-section');
   await expect(section.getByRole('button').first()).toBeInViewport();
   expect(await page.evaluate(() => ({ hash: location.hash, length: history.length }))).toEqual(before);
   // Capture where the actual jump landed. Never reset scroll, collapse tools,
   // hide controls, or rewrite styles in order to obtain a clean image.
   await shot(page, `synthetic-devices-${item.destination}-${size}-${locale}-${item.theme}`);
  }
 } finally {
  if (await page.locator('html').getAttribute('data-theme') !== initial) await themeButton(initial === 'dark').click();
 }
}

export async function reviewSelectedSetupAttention({ page, expect, shot, state }) {
 if (!['pending-review', 'unconfirmed'].includes(state)) throw new Error('Unsupported selected setup state.');
 // Run only after the existing scenario has closed its original dialog. Keep
 // the runner's stricter secret/comparison/fingerprint capture guard unchanged.
 await expect(page.getByRole('dialog')).toHaveCount(0);
 await expect(page.locator('.devices-setup-attention')).toHaveAttribute('data-state', state);
 await assertDevicesWorkspace({ page, expect, tools: true });
 // The assertion's final real jump leaves Setup focused and in view. Capture
 // the original retained rows/uncertainty notice before the separate index shot.
 await expect(page.locator('#devices-setup-heading')).toBeFocused();
 await expect(page.locator('.enrollment-panel')).toBeInViewport();
 const detail = state === 'pending-review' ? page.locator('.enrollment-history .enrollment-row').first() : page.locator('.enrollment-panel > .enrollment-message[role=status]').first();
 await expect(detail).toBeInViewport();
 await shot(page, `synthetic-devices-setup-${state}-destination`);
 await page.locator('#main-content').evaluate(node => { node.scrollTop = 0; });
 await shot(page, `synthetic-devices-setup-${state}`);
}
