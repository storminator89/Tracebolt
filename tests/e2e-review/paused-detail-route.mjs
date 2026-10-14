/** Synchronize a cold detail route while the presentation fixture clock is
 * paused. Pinned React 19 delays a resolved Suspense retry until 300 ms after
 * its fallback committed. Observe that fallback (or an already-ready route)
 * before advancing: a pre-navigation tick can miss the eventual commit timer.
 *
 * Advance at most once, by that exact bounded interval. Do not resume the clock,
 * drain all timers, poll simulated time, change fixture timestamps or extend
 * assertion deadlines. The existing route-ready assertion still must pass.
 */
export const pausedDetailCommitMs = 300;
export async function settlePausedDetailRoute(page, expect, ready) {
    const fallback = page.getByText(/^(Loading view …|Ansicht wird geladen …)$/);
    await expect(ready.or(fallback).first()).toBeVisible();
    if (await fallback.isVisible()) await page.clock.runFor(pausedDetailCommitMs);
    await expect(ready).toBeVisible();
}
