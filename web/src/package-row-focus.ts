import type { FocusEvent } from 'react';

/** Native focus can leave a partly visible summary clipped horizontally.
 * Reveal the focused row control, without changing focus or disclosure state.
 */
export function revealPackageRowSummary(event: FocusEvent<HTMLElement>): void {
    const summary = event.currentTarget;
    if (event.target !== summary || summary.ownerDocument.activeElement !== summary) return;
    summary.scrollIntoView?.({ block: 'nearest', inline: 'nearest', behavior: 'instant' });
}
