import { windowsView } from './windows-inventory-fixture';
import type { WindowsUpdates } from './windows-updates-types';
/** Invented metadata only. No native WUA read or endpoint consent. */
export function windowsUpdates(count = 4): WindowsUpdates {
    const snapshot = windowsView().snapshot!;
    return { schemaVersion: 'tracebolt.windows-update-inspection.v1', scope: 'windows-cached-update-inspection-v1', grantId: '9'.repeat(32), generationId: snapshot.generationId, collectedAt: snapshot.collectedAt, source: 'wua-cache', cacheFreshness: 'unknown', quality: 'observed', reason: '', countExact: true, observedCount: count, truncated: false,
        rows: Array.from({ length: count }, (_, i) => ({ updateId: `00000001-0000-0000-0000-${String(i + 1).padStart(12, '0')}`, revision: i === 0 ? 10 : i, title: `Synthetic cached update ${String(i + 1).padStart(3, '0')}`, kbArticleIds: i === 2 ? [] : [`KB${1000000 + i}`], severity: (['critical', 'important', 'unspecified', 'low', 'moderate'] as const)[i % 5], downloaded: i % 2 === 0, metadataTruncated: i === 1 })) };
}
export const windowsUpdatesView = (count = 4) => ({ ...windowsView(), updates: windowsUpdates(count) });
