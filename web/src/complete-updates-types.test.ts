import { describe, expect, it } from 'vitest';
import { completeUpdatesGenerationVisible, completeUpdatesTransferExpired, validCompleteUpdateManifest, validCompleteUpdatePage, validCompleteUpdateView } from './complete-updates-types';
import { updateDevice, updatePage, updateRows, updateView } from './complete-updates-fixtures';
describe('complete update operator contract', () => {
    it('accepts 1,213 rows and exact known-empty metadata', () => { const view = updateView(); expect(validCompleteUpdateView(view, updateDevice)).toBe(true); expect(validCompleteUpdatePage(updatePage(view, updateRows()), updateDevice, view.complete!, '', '')).toBe(true); expect(validCompleteUpdateView(updateView(0), updateDevice)).toBe(true); });
    it('keeps unknown comparisons partial even when all known rows are complete', () => { const m = updateView().complete!.manifest; m.unknownCount = 1; m.checkedCount--; expect(validCompleteUpdateManifest(m)).toBe(false); m.comparisonCoverage = 'partial'; m.comparisonReason = 'candidate_unknown'; expect(validCompleteUpdateManifest(m)).toBe(true); });
    it('rejects overflow, unsupported OS, fresh-source invention and extra security fields', () => { const m = updateView().complete!.manifest; for (const bad of [{ ...m, checkedCount: 4294967295, unknownCount: 1217 }, { ...m, release: { ...m.release, id: 'linuxmint' } }, { ...m, metadata: { ...m.metadata, freshness: 'fresh' } }, { ...m, cveCount: 0 }, { ...m, candidateCount: 20000 }, { ...m, rowsSha256: '' }]) expect(validCompleteUpdateManifest(bad)).toBe(false); });
    it('requires matching generation, row ordering and complete source identity on pages', () => { const v = updateView(), p = updatePage(v, updateRows()); for (const bad of [{ ...p, binding: { ...p.binding, generationId: `sample_${'f'.repeat(32)}` } }, { ...p, collectedAt: '2026-10-05T04:00:01Z' }, { ...p, items: [...p.items].reverse() }, { ...p, items: Array(101).fill(p.items[0]) }, { ...p, totalRows: 16 }, { ...p, items: [{ ...p.items[0], candidateVersion: '0.1' }] }]) expect(validCompleteUpdatePage(bad, updateDevice, v.complete!, '', '')).toBe(false); });
    it('does not extend capture retention when view is reread', () => { const v = updateView(); expect(completeUpdatesGenerationVisible(v, 0)).toBe(true); expect(completeUpdatesGenerationVisible(v, 86400000)).toBe(false); expect(completeUpdatesGenerationVisible(v, Infinity)).toBe(false); });
});

import goFixture from './complete-updates-go-fixture.json';
it('accepts the exact Go-encoded manifest/view/page including nanos, holds and partial comparisons', () => {
    const value: unknown = goFixture.view;
    expect(validCompleteUpdateView(value, goFixture.view.deviceId)).toBe(true);
    if (!validCompleteUpdateView(value, goFixture.view.deviceId) || !value.complete) throw new Error('invalid Go fixture');
    expect(validCompleteUpdatePage(goFixture.page, value.deviceId, value.complete, '', '')).toBe(true);
    expect(value.complete.manifest.comparisonCoverage).toBe('partial');
    expect(value.complete.manifest.metadata.freshness).toBe('stale');
});

it('derives only pending transfer expiry from both original deadlines', () => {
    const view = updateView();
    view.transfer = { binding: view.complete!.binding, state: 'pending', declaredRows: 1213, acceptedRows: 128, expectedChunks: 10, acceptedChunks: 1, collectedAt: '2026-10-05T04:00:00Z', startedAt: '2026-10-05T04:00:05Z', expiresAt: '2026-10-05T04:15:05Z' };
    expect(completeUpdatesTransferExpired(view, 894999)).toBe(false); expect(completeUpdatesTransferExpired(view, 895000)).toBe(true);
    view.transfer.collectedAt = '2026-10-04T04:00:11Z';
    expect(completeUpdatesTransferExpired(view, 999)).toBe(false); expect(completeUpdatesTransferExpired(view, 1000)).toBe(true);
    for (const elapsed of [-1, Infinity, NaN]) expect(completeUpdatesTransferExpired(view, elapsed)).toBe(false);
    for (const state of ['complete', 'failed', 'expired'] as const) { view.transfer.state = state; expect(completeUpdatesTransferExpired(view, 900000)).toBe(false); }
    view.transfer = null; expect(completeUpdatesTransferExpired(view, 900000)).toBe(false);
});
