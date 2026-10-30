import type { FocusEvent } from 'react';

/** A complete table can be taller than its viewport: nearest may leave its top
 * clipped. Reveal the region's start only when the region itself indicates focus;
 * row focus keeps its own nearest reveal and ordinary pointer focus stays put.
 */
export function revealCompletePackageRegion(event: FocusEvent<HTMLElement>): void {
    const region = event.currentTarget;
    if (event.target !== region || region.ownerDocument.activeElement !== region || !region.matches(':focus-visible')) return;
    region.scrollIntoView?.({ block: 'start', inline: 'nearest', behavior: 'instant' });
}
