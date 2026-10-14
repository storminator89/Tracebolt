/** Presentation checks for existing invented complete-inventory fixtures.
 * The caller owns the authenticated fixture, safe screenshot helper and manifest.
 * This helper performs no requests, collection, setup or workflow changes. */
export async function checkInventoryReadFirst(page,{expect,selector,stem,shot,facts}){
 const panel=page.locator(selector),details=panel.locator('.inventory-capture-details'),summary=details.locator(':scope > summary');
 for(const locale of ['en','de'])for(const mobile of [false,true]){
  await page.setViewportSize(mobile?{width:390,height:844}:{width:1440,height:1000});
  await page.getByLabel(/^(Language|Sprache)$/).selectOption(locale);
  await expect(details).toHaveCount(1);await expect(details).not.toHaveAttribute('open');
  await expect(summary).toHaveText(locale==='de'?'Erfassungsdetails':'Capture details');
  await expect(panel.locator('.inventory-summary').first()).toBeVisible();
  await expect(panel.locator('.complete-package-search')).toBeVisible();
  await expect(panel.locator('tbody tr').first()).toBeVisible();
  expect(await panel.evaluate(el=>{
   const search=el.querySelector('.complete-package-search'),table=el.querySelector('.package-table-scroll'),details=el.querySelector('.inventory-capture-details');
   return Boolean(search&&table&&details&&(search.compareDocumentPosition(details)&Node.DOCUMENT_POSITION_FOLLOWING)&&(details.compareDocumentPosition(table)&Node.DOCUMENT_POSITION_FOLLOWING)&&details.previousElementSibling?.tagName==='DL'&&details.nextElementSibling===table);
  })).toBe(true);
  for(const fact of facts){const value=details.getByText(fact,{exact:true});await expect(value.first()).toHaveText(fact);await expect(value.first()).toBeHidden();}
  await panel.locator('.package-heading').evaluate(el=>el.scrollIntoView({block:'start'}));
  await shot(page,`${stem}-summary-${mobile?'mobile':'desktop'}-${locale}`);
  await panel.locator('.complete-package-search').evaluate(el=>el.scrollIntoView({block:'start'}));
  await expect(panel.locator('tbody tr').first()).toBeInViewport();
  await shot(page,`${stem}-results-${mobile?'mobile':'desktop'}-${locale}`);
  await summary.focus();await page.keyboard.press('Enter');await expect(details).toHaveAttribute('open','');
  for(const fact of facts)await expect(details.getByText(fact,{exact:true}).first()).toBeVisible();
  await details.evaluate(el=>el.scrollIntoView({block:'start'}));
  await shot(page,`${stem}-details-${mobile?'mobile':'desktop'}-${locale}`);
  await summary.focus();await page.keyboard.press('Space');await expect(details).not.toHaveAttribute('open');await expect(summary).toBeFocused();
 }
 await page.getByLabel(/^(Language|Sprache)$/).selectOption('en');await page.setViewportSize({width:1440,height:1000});
}
