/** Additive assertions for the existing journal cancellation case. The runner's
 * original 407 assertion ASTs and closed case/checkpoint coordinates stay intact.
 * No browser launch, content read, new capture or changed runner is introduced. */
export async function assertJournalCancellationNavigation({ page, expect, panel, rows, tally, queriesBeforeCancel, statusReads, releaseStatus }) {
 await page.getByRole('tab',{name:'Details',exact:true}).click();await expect(panel(page)).toHaveCount(0);
 const beforeRemountStatus=statusReads();await page.getByRole('tab',{name:'Logs',exact:true}).click();await expect.poll(statusReads).toBeGreaterThan(beforeRemountStatus);await expect(panel(page)).toHaveAttribute('aria-busy','false');
 await expect(panel(page).getByText('The last action could not be confirmed. Refresh status before issuing another action.',{exact:true})).toBeVisible();await expect(rows(page)).toHaveCount(0);expect(tally.query).toBe(queriesBeforeCancel);expect(tally.cancel).toBe(1);expect(tally.create).toBe(1);
 await releaseStatus();await page.getByRole('button',{name:'Refresh status',exact:true}).click();
}
