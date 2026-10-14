/** English/German state continuity and viewport-owned scrolling, real app/API. */
import { installWorkspaceContinuity } from './workspace-navigation-browser.mjs';

/** Browser-only assertions. Captures are supplied only by the whitelisted
 * synthetic gallery; these helpers neither read nor retain response contents. */
export async function assertMobileDrawerClosed({ page, expect, returnFocus = false }) {
 const sidebar = page.locator('.sidebar'), trigger = page.locator('.mobile-menu');
 await expect(sidebar).not.toHaveClass(/is-open/);
 await expect(sidebar).toHaveAttribute('aria-hidden', 'true');
 await expect.poll(() => sidebar.evaluate(element => element.inert)).toBe(true);
 await expect.poll(() => page.locator('.main-shell').evaluate(element => element.inert)).toBe(false);
 await expect(page.locator('.mobile-scrim')).toHaveCount(0);
 await expect(trigger).toHaveAttribute('aria-expanded', 'false');
 await expect(page.getByRole('dialog')).toHaveCount(0);
 await expect(sidebar.getByRole('button')).toHaveCount(0);
 if (returnFocus) await expect(trigger).toBeFocused();
}

export async function assertDesktopNavigation({ page, expect }) {
 const sidebar = page.locator('.sidebar');
 await expect.poll(() => sidebar.evaluate(element => element.inert)).toBe(false);
 await expect(sidebar).not.toHaveAttribute('aria-hidden', 'true');
 await expect(sidebar).not.toHaveAttribute('role', 'dialog');
 await expect(sidebar).not.toHaveAttribute('aria-modal', 'true');
 await expect.poll(() => page.locator('.main-shell').evaluate(element => element.inert)).toBe(false);
 await expect(page.locator('.mobile-scrim')).toHaveCount(0);
 await expect(page.locator('.mobile-menu')).toBeHidden();
 await expect(page.locator('.mobile-nav-close')).toBeHidden();
 await sidebar.locator('.brand').focus();
 await page.keyboard.press('Tab');
 await expect(sidebar.locator('nav .nav-item').first()).toBeFocused();
}

export async function shellDrawerKeyboardReview({ page, expect, capture, locale, viewport }) {
 const sidebar = page.locator('.sidebar'), trigger = page.locator('.mobile-menu');
 const continuity = await page.evaluateHandle(installWorkspaceContinuity);
 const stable = async () => {
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  expect(await continuity.evaluate(probe => probe.read())).toEqual({ sameDocument: true,
   identity: { shell: true, sidebar: true, topbar: true, main: true },
   removedAnchors: { shell: 0, sidebar: 0, topbar: 0, main: 0 }, initialLoadingInsertions: 0, pageHides: 0 });
 };
 const closed = async () => { await assertMobileDrawerClosed({ page, expect, returnFocus: true }); await stable(); };
 const open = async () => {
  await trigger.focus(); await page.keyboard.press('Enter');
  await expect(sidebar).toHaveClass(/is-open/);
  await expect(sidebar).toHaveAttribute('role', 'dialog');
  await expect(sidebar).toHaveAttribute('aria-modal', 'true');
  await expect(sidebar).not.toHaveAttribute('aria-hidden', 'true');
  await expect.poll(() => sidebar.evaluate(element => element.inert)).toBe(false);
  await expect.poll(() => page.locator('.main-shell').evaluate(element => element.inert)).toBe(true);
  await expect(trigger).toHaveAttribute('aria-expanded', 'true');
  const controlledId = await trigger.getAttribute('aria-controls');
  expect(controlledId).toBeTruthy(); expect(controlledId).toBe(await sidebar.getAttribute('id'));
  await expect(page.locator('.mobile-nav-close')).toBeInViewport();
  await expect.poll(() => sidebar.evaluate(element => element.contains(document.activeElement))).toBe(true);
  await stable();
 };
 try {
  await assertMobileDrawerClosed({ page, expect });
  // A complete forward/reverse document tab cycle must never enter the
  // translated-offscreen drawer, even though its DOM remains mounted.
  await trigger.focus();
  await sidebar.locator('.brand').evaluate(element => element.focus());
  await expect(trigger).toBeFocused();
  const stops = await page.evaluate(() => [...document.querySelectorAll('button, a[href], input, select, textarea, [tabindex]')]
   .filter(element => element.tabIndex >= 0 && !element.matches(':disabled') && !element.closest('[inert]') && element.getClientRects().length && getComputedStyle(element).visibility !== 'hidden').length);
  for (const key of ['Tab', 'Shift+Tab']) for (let index = 0; index < stops + 2; index++) {
   await page.keyboard.press(key);
   expect(await sidebar.evaluate(element => element.contains(document.activeElement))).toBe(false);
  }
  await trigger.focus(); await capture('drawer-closed-keyboard');
  await open();
  const controls = sidebar.locator('button:enabled:visible, a[href]:visible, input:enabled:visible, select:enabled:visible, textarea:enabled:visible, [tabindex="0"]:visible');
  expect(await controls.count()).toBeGreaterThan(1);
  await controls.first().focus(); await page.keyboard.press('Shift+Tab'); await expect(controls.last()).toBeFocused();
  await page.keyboard.press('Tab'); await expect(controls.first()).toBeFocused();
  for (let index = 0; index < await controls.count(); index++) {
   await page.keyboard.press('Tab');
   expect(await sidebar.evaluate(element => element.contains(document.activeElement))).toBe(true);
  }
  await expect(controls.first()).toBeFocused();
  await capture('drawer-open-keyboard');
  await page.keyboard.press('Escape'); await closed();
  await open(); await page.locator('.mobile-nav-close').focus(); await page.keyboard.press('Enter'); await closed();
  await open(); await page.locator('.mobile-scrim').click({ position: { x: viewport.width - 10, y: 150 } }); await closed();

  // Help dismisses the drawer first, so its own dialog owns Escape.
  await open(); await sidebar.locator('.sidebar-help').focus(); await page.keyboard.press('Enter');
  const help = page.getByRole('dialog', { name: locale === 'de' ? 'Tastenkürzel' : 'Keyboard shortcuts', exact: true });
  await expect(help).toBeVisible(); await expect(sidebar).not.toHaveClass(/is-open/);
  await expect(sidebar).toHaveAttribute('aria-hidden', 'true');
  await expect.poll(() => sidebar.evaluate(element => element.inert)).toBe(true);
  await expect(page.getByRole('dialog')).toHaveCount(1); await capture('drawer-help');
  await page.keyboard.press('Escape'); await expect(help).toHaveCount(0);
  await closed();

  // A Help opener can become hidden at the breakpoint. Keep focus in Help
  // during each resize, then return to the now-visible navigation control.
  await open(); await sidebar.locator('.sidebar-help').focus(); await page.keyboard.press('Enter');
  await expect(help).toBeVisible(); await expect(sidebar).not.toHaveClass(/is-open/);
  await expect.poll(() => help.evaluate(element => element.contains(document.activeElement))).toBe(true);
  await page.setViewportSize({ width: 761, height: viewport.height });
  await expect(help).toBeVisible();
  await expect.poll(() => help.evaluate(element => element.contains(document.activeElement))).toBe(true); await stable();
  await page.keyboard.press('Escape'); await expect(help).toHaveCount(0);
  await expect(sidebar.locator('[aria-current="page"]')).toBeFocused(); await stable();
  await sidebar.locator('.sidebar-help').focus(); await page.keyboard.press('Enter');
  await expect(help).toBeVisible();
  await expect.poll(() => help.evaluate(element => element.contains(document.activeElement))).toBe(true);
  await page.setViewportSize({ width: 760, height: viewport.height });
  await expect(help).toBeVisible();
  await expect.poll(() => help.evaluate(element => element.contains(document.activeElement))).toBe(true); await stable();
  await page.keyboard.press('Escape'); await expect(help).toHaveCount(0); await closed();
  await page.setViewportSize(viewport); await closed();

  await open();
  await sidebar.locator('nav .nav-item').filter({ hasText: locale === 'de' ? /^Übersicht$/ : /^Overview$/ }).focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { name: locale === 'de' ? 'Übersicht' : 'Overview', exact: true, level: 1 })).toBeVisible();
  await closed(); await capture('drawer-route-dismissed');
  await open(); await page.evaluate(() => { window.location.hash = '/devices'; });
  await expect(page.getByRole('heading', { name: locale === 'de' ? 'Geräte' : 'Devices', exact: true, level: 1 })).toBeVisible();
  await closed();

  // Exercise both sides of the exact media-query boundary without reloading.
  await page.setViewportSize({ width: 760, height: viewport.height }); await assertMobileDrawerClosed({ page, expect });
  await open(); await capture('drawer-open-760px');
  await page.setViewportSize({ width: 761, height: viewport.height });
  await expect.poll(() => page.evaluate(() => {
   const active = document.activeElement;
   return active instanceof HTMLElement && Boolean(active.closest('.sidebar')) && !active.closest('[inert]') && active.getClientRects().length > 0 && getComputedStyle(active).visibility !== 'hidden';
  })).toBe(true);
  await assertDesktopNavigation({ page, expect }); await stable(); await capture('drawer-desktop-761px');
  await page.setViewportSize({ width: 760, height: viewport.height });
  await closed(); await capture('drawer-closed-760px');
  await page.setViewportSize(viewport); await closed();
 } finally {
  try { await continuity.evaluate(probe => probe.stop()); } catch { /* A lost document already fails the probe. */ }
  await continuity.dispose();
 }
}

export async function runShellReview({test,pageAt,loaded,shot,expect,caseItem,cleanCase}) {
 async function bounds(page) {
  const value=await page.evaluate(()=>({width:innerWidth,height:innerHeight,scrollY,bodyH:document.body.scrollHeight,docH:document.documentElement.scrollHeight,bodyW:document.body.scrollWidth,docW:document.documentElement.scrollWidth,header:document.querySelector('.topbar')?.getBoundingClientRect().toJSON(),main:document.querySelector('.main-content')?.getBoundingClientRect().toJSON()}));
  const geometry=JSON.stringify(value);
  expect(value.scrollY,'window.scrollY; '+geometry).toBe(0);expect(value.bodyH,'body.scrollHeight; '+geometry).toBeLessThanOrEqual(value.height+1);expect(value.docH,'documentElement.scrollHeight; '+geometry).toBeLessThanOrEqual(value.height+1);expect(value.bodyW,'body.scrollWidth; '+geometry).toBeLessThanOrEqual(value.width+1);expect(value.docW,'documentElement.scrollWidth; '+geometry).toBeLessThanOrEqual(value.width+1);expect(value.header.top,'topbar top; '+geometry).toBeGreaterThanOrEqual(0);expect(value.main.bottom,'main bottom; '+geometry).toBeLessThanOrEqual(value.height+1);
  return value;
 }
 async function scrollMain(page,selector) {
  await page.locator(selector).evaluate(el=>el.scrollIntoView({block:'start',behavior:'instant'}));
  await expect.poll(()=>page.locator('.main-content').evaluate(el=>el.scrollTop)).toBeGreaterThan(0);
  await bounds(page);
 }
 await test('Fresh English default and live German switch preserve route, filter, theme and note draft',async()=>{
  const page=await pageAt('/devices',{width:1440,height:1000},{reviewLocale:null});await loaded(page);
  await expect(page.locator('html')).toHaveAttribute('lang','en');await expect(page.getByRole('heading',{name:'Devices',exact:true,level:1})).toBeVisible();await expect(page.getByLabel('Language')).toHaveValue('en');
  await page.getByLabel('Search devices').fill('BER');await page.getByLabel('Filter by operating system').selectOption('windows');await page.getByRole('button',{name:'Switch to dark theme'}).click();
  const before=page.url();await page.getByLabel('Language').selectOption('de');await expect(page.getByRole('heading',{name:'Geräte',exact:true,level:1})).toBeVisible();expect(page.url()).toBe(before);await expect(page.getByLabel('Geräte durchsuchen')).toHaveValue('BER');await expect(page.getByLabel('Nach Betriebssystem filtern')).toHaveValue('windows');await expect(page.locator('html')).toHaveAttribute('data-theme','dark');
  await page.reload();await loaded(page);await expect(page.getByLabel('Sprache')).toHaveValue('de');await page.goto(new URL(`#/cases/${caseItem.id}`,page.url()).href);await page.getByLabel('Notiz zur Untersuchung').fill('UNSAVED_LANGUAGE_REVIEW');await page.getByLabel('Sprache').selectOption('en');await expect(page.getByLabel('Investigation note')).toHaveValue('UNSAVED_LANGUAGE_REVIEW');await expect(page.locator('.case-detail-header h1')).toHaveText(caseItem.title);await expect(page.locator('html')).toHaveAttribute('lang','en');
 });
 for(const [name,route,section] of [['case',`/cases/${cleanCase.id}`,'.notes-panel'],['settings','/settings','.settings-capabilities']]) await test(`Long ${name} scrolls inside main while desktop navigation and topbar stay reachable`,async()=>{
  const page=await pageAt(route);await loaded(page);const initial=await bounds(page);const sidebar=await page.locator('.sidebar').boundingBox();await scrollMain(page,section);const after=await bounds(page);expect(after.header.y).toBe(initial.header.y);expect(after.header.height).toBe(initial.header.height);expect(await page.locator('.sidebar').boundingBox()).toEqual(sidebar);
  await expect(page.locator('.sidebar .nav-item').filter({hasText:'Geräte'})).toBeInViewport();
  if(name==='case') await shot(page,'synthetic-case-scrolled-desktop-light',section);
  await page.locator('.sidebar .nav-item').filter({hasText:'Geräte'}).click();await expect(page.getByRole('heading',{name:'Geräte',exact:true,level:1})).toBeVisible();await expect.poll(()=>page.locator('.main-content').evaluate(el=>el.scrollTop)).toBe(0);
 });
 await test('Short desktop window keeps independently scrollable sidebar controls reachable',async()=>{
  const page=await pageAt(`/cases/${caseItem.id}`,{width:1024,height:420});await loaded(page);await scrollMain(page,'.notes-panel');
  const settings=page.locator('.sidebar .nav-item').filter({hasText:'Einstellungen'});await settings.scrollIntoViewIfNeeded();await expect(settings).toBeInViewport();await settings.click();await expect(page.getByRole('heading',{name:'Einstellungen',exact:true,level:1})).toBeVisible();await bounds(page);
 });
 await test('200 percent equivalent CSS viewport keeps keyboard navigation and content usable',async()=>{
  // 720x500 CSS pixels is the space available from a 1440x1000 display at 200%.
  // This is responsive/keyboard coverage, not an OS/browser zoom certification.
  const page=await pageAt(`/cases/${caseItem.id}`,{width:720,height:500});await loaded(page);await bounds(page);await page.keyboard.press('Tab');await expect(page.getByRole('link',{name:'Zum Inhalt'})).toBeFocused();await page.keyboard.press('Enter');expect(await page.evaluate(()=>document.activeElement?.id)).toBe('main-content');await page.keyboard.press('PageDown');await expect.poll(()=>page.locator('.main-content').evaluate(el=>el.scrollTop)).toBeGreaterThan(0);await bounds(page);
  await page.getByRole('button',{name:'Menü öffnen'}).click();const settings=page.locator('.sidebar .nav-item').filter({hasText:'Einstellungen'});await settings.scrollIntoViewIfNeeded();await settings.click();await expect(page.getByRole('heading',{name:'Einstellungen',exact:true,level:1})).toBeVisible();await expect(page.locator('.sidebar')).not.toHaveClass(/is-open/);await bounds(page);
 });
 await test('Mobile shell has no desktop gutter and navigation survives long content and dismissals',async()=>{
  const page=await pageAt(`/cases/${caseItem.id}`,{width:390,height:844},{isMobile:true,hasTouch:true});await loaded(page);await scrollMain(page,'.notes-panel');const main=await page.locator('.main-shell').boundingBox();expect(main.x).toBe(0);expect(main.width).toBe(390);
  await assertMobileDrawerClosed({page,expect});
  await page.getByRole('button',{name:'Menü öffnen'}).click();await expect(page.locator('.sidebar')).toHaveClass(/is-open/);await page.locator('.mobile-scrim').click({position:{x:380,y:200}});await assertMobileDrawerClosed({page,expect,returnFocus:true});await bounds(page);
  await page.getByRole('button',{name:'Menü öffnen'}).click();await page.keyboard.press('Escape');await assertMobileDrawerClosed({page,expect,returnFocus:true});await expect(page).toHaveURL(new RegExp(caseItem.id));
 });
}
