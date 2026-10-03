/** English/German state continuity and viewport-owned scrolling, real app/API. */
export async function runShellReview({test,pageAt,loaded,shot,expect,caseItem,cleanCase}) {
 async function bounds(page) {
  const value=await page.evaluate(()=>({width:innerWidth,height:innerHeight,scrollY,bodyH:document.body.scrollHeight,docH:document.documentElement.scrollHeight,bodyW:document.body.scrollWidth,docW:document.documentElement.scrollWidth,header:document.querySelector('.topbar')?.getBoundingClientRect().toJSON(),main:document.querySelector('.main-content')?.getBoundingClientRect().toJSON()}));
  expect(value.scrollY).toBe(0);expect(value.bodyH).toBeLessThanOrEqual(value.height+1);expect(value.docH).toBeLessThanOrEqual(value.height+1);expect(value.bodyW).toBeLessThanOrEqual(value.width+1);expect(value.docW).toBeLessThanOrEqual(value.width+1);expect(value.header.top).toBeGreaterThanOrEqual(0);expect(value.main.bottom).toBeLessThanOrEqual(value.height+1);
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
  await page.getByRole('button',{name:'Menü öffnen'}).click();await expect(page.locator('.sidebar')).toHaveClass(/is-open/);await page.getByRole('button',{name:'Menü schließen',exact:true}).click({position:{x:380,y:200}});await expect(page.locator('.sidebar')).not.toHaveClass(/is-open/);await bounds(page);
  await page.getByRole('button',{name:'Menü öffnen'}).click();await page.keyboard.press('Escape');await expect(page.locator('.sidebar')).not.toHaveClass(/is-open/);await expect(page).toHaveURL(new RegExp(caseItem.id));
 });
}
