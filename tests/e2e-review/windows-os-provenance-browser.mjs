/** Invented OS provenance for the existing hosted Windows DTO only. The LAN
 * shape mirrors admitted metadata; it is not native collection or acceptance. */
export const windowsOSProvenance=Object.freeze({
 id:'local-windows-os',title:'Windows NT version',
 source:'ntdll.RtlGetVersion; numeric NT version and build',quality:'healthy',
 value:'Windows NT 10.0 (build 26100)',
 detail:'NT major/minor/build only, without inferring a marketing release or edition. Application compatibility can affect RtlGetVersion. nativeVerification: target-acceptance-unverified.',
 synthetic:false,
});
export function withWindowsOSProvenance(device,collectedAt=device.lastSeen){
 return {...device,os:windowsOSProvenance.value,evidence:[...device.evidence,{...windowsOSProvenance,collectedAt}]};
}
export async function exerciseWindowsOSProvenance({page,expect,locale,width,shot,disclosure,observedAt}){
 const de=locale==='de',tab=page.getByRole('tab',{name:de?'Belege':'Evidence',exact:true});
 // Use the original admitted DTO capture in the browser's own timezone, never
 // Date.now() or the later clock after overview charts have settled.
 expect(typeof observedAt).toBe('string');
 const observed=await page.evaluate(({locale,observedAt})=>new Intl.DateTimeFormat(locale==='de'?'de-DE':'en-GB',{dateStyle:'medium',timeStyle:'medium'}).format(new Date(observedAt)),{locale,observedAt});
 await expect(tab.locator('span')).toHaveText('1');await tab.click();await expect(tab).toHaveAttribute('aria-selected','true');
 const card=page.locator('#evidence-local-windows-os');
 await expect(card).toBeVisible();await expect(card.locator('.evidence-heading strong')).toHaveText(windowsOSProvenance.title);
 await expect(card.getByText(windowsOSProvenance.source,{exact:true})).toBeVisible();
 await expect(card.locator('.quality-healthy')).toHaveText(de?'Aktuell':'Current');await expect(card.locator('.quality-healthy')).toBeVisible();
 await card.locator('summary').click();await expect(card).toHaveAttribute('open','');
 await expect(card.locator('.evidence-value > code')).toHaveText(windowsOSProvenance.value);await expect(card.locator('.evidence-value > code')).toBeVisible();
 await expect(card.locator('.evidence-content > p')).toHaveText(windowsOSProvenance.detail);await expect(card.locator('.evidence-content > p')).toBeVisible();
 await expect(card.locator('.evidence-foot > span')).toHaveText(observed);await expect(card.locator('.evidence-foot > span')).toBeVisible();
 await expect(card.locator('.evidence-foot > code')).toHaveText(windowsOSProvenance.id);
 await expect(card).not.toContainText(/\bWindows (?:10|11|Server)\b|\b(?:Home|Pro|Enterprise|Education)\b/);
 expect(await card.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
 await card.scrollIntoViewIfNeeded();await expect(card).toBeInViewport({ratio:1});
 await shot(page,`synthetic-windows-os-provenance-${width}-${locale}`,disclosure);
 // The caller's existing Inventory step resumes immediately. Do not revisit
 // Overview here: that would remount its resource-history reader.
}
