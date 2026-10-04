import { describe, expect, it } from 'vitest';
import { completeGenerationVisible, inventorySequence, validCompletePackagePage, validCompletePackageView } from './complete-packages-types';
import { completeDevice, completePage, completeRows, completeView } from './complete-packages-fixtures';

describe('complete generation operator contracts', () => {
    it('preserves canonical MaxInt64 sequences without JavaScript numeric rounding', () => {
        for (const value of ['1', '9007199254740993', '9223372036854775807']) expect(inventorySequence(value)).toBe(true);
        for (const value of [1, '0', '-1', '+1', '01', '1.0', '1e3', '9223372036854775808', '10000000000000000000']) expect(inventorySequence(value)).toBe(false);
        expect(validCompletePackageView(completeView(), completeDevice)).toBe(true);
    });
    it('accepts the server empty-profile not-configured shape and pending / failed attempts without erasing the complete generation', () => {
        expect(validCompletePackageView({ ...completeView(), collectionProfile: '', status: 'not_configured', complete: null }, completeDevice)).toBe(true);
        const view = completeView(); view.complete!.binding.sequence = '1';
        view.transfer = { binding: { sequence: '2', generationId: `sample_${'d'.repeat(32)}`, manifestHash: 'e'.repeat(64) }, state: 'pending', declaredRows: 350, acceptedRows: 128, expectedChunks: 3, acceptedChunks: 1, collectedAt: '2026-10-04T00:00:06Z', startedAt: '2026-10-04T00:00:07Z', expiresAt: '2026-10-04T00:15:07Z' };
        view.failure = { sequence: '3', generationId: `sample_${'f'.repeat(32)}`, attemptedAt: '2026-10-04T00:00:08Z', receivedAt: '2026-10-04T00:00:09Z', reason: 'source_changed' };
        expect(validCompletePackageView(view, completeDevice)).toBe(true);
        expect(completeGenerationVisible(view, 1000)).toBe(true);
    });
    it('keeps expired complete metadata historical, including an originally zero-row generation', () => {
        for (const count of [0, 350]) {
            const view = completeView(count); view.serverNow = '2026-10-05T00:00:00Z'; view.complete!.state = 'expired';
            expect(validCompletePackageView(view, completeDevice)).toBe(true); expect(completeGenerationVisible(view, 0)).toBe(false);
        }
    });
    it('rejects unknown fields, profiles, manifest identity drift, unknown failure strings and unsafe row counts', () => {
        const view = completeView();
        for (const bad of [{ ...view, extra: true }, { ...view, deviceId: 'agent_other' }, { ...view, collectionProfile: 'managed-operations-v9' }, { ...view, complete: { ...view.complete, manifest: { ...view.complete!.manifest, generationId: `sample_${'d'.repeat(32)}` } } }, { ...view, complete: { ...view.complete, manifest: { ...view.complete!.manifest, observedCount: 100001 } } }, { ...view, failure: { sequence: '1', generationId: `sample_${'a'.repeat(32)}`, attemptedAt: view.serverNow, receivedAt: view.serverNow, reason: '<untrusted raw error>' } }]) expect(validCompletePackageView(bad, completeDevice)).toBe(false);
    });
    it('accepts bounded pages beyond row 256 and empty search scan windows', () => {
        const view = completeView(), rows = completeRows();
        expect(validCompletePackagePage(completePage(view, rows, JSON.stringify({ cursor: 'cursor_300', search: '', limit: 100 })), completeDevice, view.complete!, '', 'cursor_300')).toBe(true);
        const large = completeView(2300), scan = completePage(large, completeRows(2300), JSON.stringify({ cursor: '', search: 'fixture-002299', limit: 100 }));
        expect(scan.items).toEqual([]); expect(scan.exhausted).toBe(false); expect(validCompletePackagePage(scan, completeDevice, large.complete!, 'fixture-002299', '')).toBe(true);
    });
    it('rejects page binding mismatches, numeric sequences, duplicate rows, oversized pages, false exhaustion and expired cursor clocks', () => {
        const view = completeView(), page = completePage(view, completeRows());
        for (const bad of [{ ...page, binding: { ...page.binding, sequence: 1 } }, { ...page, binding: { ...page.binding, manifestHash: 'f'.repeat(64) } }, { ...page, items: [page.items[0], page.items[0]] }, { ...page, items: completeRows(101) }, { ...page, scannedRows: 2049 }, { ...page, exhausted: true }, { ...page, cursorExpiresAt: page.serverNow }, { ...page, nextCursor: 'x'.repeat(1025) }, { ...page, totalRows: 300 }, { ...page, searchIncomplete: true }]) expect(validCompletePackagePage(bad, completeDevice, view.complete!, '', '')).toBe(false);
    });
    it('uses monotonic elapsed time and exact nanosecond expiry boundaries', () => {
        const view = completeView(); expect(completeGenerationVisible(view, 86389999)).toBe(true); expect(completeGenerationVisible(view, 86390000)).toBe(false);
        expect(completeGenerationVisible(view, -1)).toBe(false); expect(completeGenerationVisible(view, Infinity)).toBe(false);
        view.serverNow = '2026-10-05T00:00:00.000000001Z'; expect(validCompletePackageView(view, completeDevice)).toBe(false);
    });
});
