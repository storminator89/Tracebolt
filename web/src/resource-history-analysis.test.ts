import { describe, expect, it } from 'vitest';
import { historyIntervals, inHistoryInterval, summarizeResource } from './resource-history-analysis';
import { historyFixture } from './resource-history-fixture';

describe('original-snapshot resource investigation', () => {
    it('anchors equal intervals to original manager time, with one shared boundary owner', () => {
        const view = historyFixture(), { current, previous } = historyIntervals(view, 12);
        expect(current.end).toBe(view.serverNow);
        expect(Date.parse(current.end) - Date.parse(current.start)).toBe(12 * 3600000);
        expect(Date.parse(previous!.end) - Date.parse(previous!.start)).toBe(Date.parse(current.end) - Date.parse(current.start));
        expect(previous!.start).toBe(view.windowStart);
        expect(inHistoryInterval(current.start, current)).toBe(true);
        expect(inHistoryInterval(current.start, previous!)).toBe(false);
        expect(historyIntervals(view, 24).previous).toBeNull();
        expect(view.windowStart).toBe('2026-10-06T12:00:00Z');
    });
    it('keeps actual zero, nearest-rank p95, even median, report gaps and minute buckets', () => {
        const view = historyFixture(), { current } = historyIntervals(view, 1);
        const summary = summarizeResource(view, 'cpu', current);
        expect(summary).toEqual({ reports: 4, usable: 4, unavailable: 0, repeated: 0, conflicts: 0, minuteBuckets: 4, expectedBuckets: 61, minimum: 0, median: 36.5, p95: 38, maximum: 38, longestGapMs: 55 * 60000 });
        expect(summarizeResource(view, 'disk', current).median).toBe(26);
    });
    it('does not convert missing, stale, denied or unknown evidence into zero', () => {
        const view = historyFixture();
        view.points[0].cpu = { ...view.points[0].cpu, quality: 'unknown', value: null };
        view.points[1].cpu = { ...view.points[1].cpu, quality: 'denied', value: null };
        view.points[2].cpu.quality = 'stale';
        const { current, previous } = historyIntervals(view, 1);
        const summary = summarizeResource(view, 'cpu', current);
        expect(summary.usable).toBe(1); expect(summary.minimum).toBe(38); expect(summary.unavailable).toBe(3);
        const missing = summarizeResource(view, 'cpu', previous!);
        expect(missing.usable).toBe(0); expect(missing.minimum).toBeNull(); expect(missing.median).toBeNull(); expect(missing.p95).toBeNull(); expect(missing.maximum).toBeNull();
        expect(missing.longestGapMs).toBe(3600000);
    });
    it('ignores repeated original metric times and withholds contradictory values', () => {
        const view = historyFixture([-180, -120, -60, 0]);
        view.points[1].cpu = { ...view.points[0].cpu };
        const current = historyIntervals(view, 1).current;
        expect(summarizeResource(view, 'cpu', current)).toMatchObject({ usable: 3, repeated: 1, conflicts: 0, minimum: 0 });
        view.points[1].cpu.value = 99;
        expect(summarizeResource(view, 'cpu', current)).toMatchObject({ usable: 2, repeated: 1, conflicts: 1, minimum: 37 });
    });
    it('assigns measurements by original metric time, not later report delivery', () => {
        const view = historyFixture([-3600, -3540, 0]);
        const { current, previous } = historyIntervals(view, 1);
        view.points[0].cpu.collectedAt = new Date(Date.parse(current.start) - 1000).toISOString();
        view.points[1].cpu.collectedAt = new Date(current.start).toISOString();
        expect(summarizeResource(view, 'cpu', previous!)).toMatchObject({ reports: 0, usable: 1, minimum: 0 });
        expect(summarizeResource(view, 'cpu', current)).toMatchObject({ reports: 3, usable: 2, minimum: 36 });
    });
    it('distinguishes partial edge minute buckets, exact end and empty history', () => {
        const view = historyFixture([]), { current, previous } = historyIntervals(view, 1);
        expect(summarizeResource(view, 'cpu', current).expectedBuckets).toBe(61);
        expect(summarizeResource(view, 'cpu', previous!).expectedBuckets).toBe(60);
        const partial = { ...current, start: new Date(Date.parse(current.start) + 20000).toISOString(), end: new Date(Date.parse(current.end) - 20000).toISOString() };
        expect(summarizeResource(view, 'cpu', partial).expectedBuckets).toBe(60);
        expect(summarizeResource(view, 'cpu', partial).median).toBeNull();
    });
    it('computes sample percentiles without interpolation or duration weighting', () => {
        const view = historyFixture(Array.from({ length: 20 }, (_, i) => -1200 + i * 60));
        view.points.forEach((point, index) => { point.cpu.value = index * 5; });
        expect(summarizeResource(view, 'cpu', historyIntervals(view, 1).current)).toMatchObject({ median: 47.5, p95: 90, maximum: 95 });
    });
    it('retains sub-millisecond interval boundaries and distinct original sample times', () => {
        const view = historyFixture([-3600, -3540, 0]);
        view.serverNow = '2026-10-07T12:00:00.000000200Z';
        view.windowStart = '2026-10-06T12:00:00.000000200Z';
        const { current, previous } = historyIntervals(view, 1);
        expect(current.start).toBe('2026-10-07T11:00:00.000000200Z');
        expect(current.end).toBe(view.serverNow);
        expect(inHistoryInterval('2026-10-07T11:00:00.000000100Z', current)).toBe(false);
        expect(inHistoryInterval('2026-10-07T11:00:00.000000100Z', previous!)).toBe(true);
        expect(inHistoryInterval(current.start, current)).toBe(true);
        expect(inHistoryInterval(current.start, previous!)).toBe(false);
        view.points[0].cpu.collectedAt = '2026-10-07T10:59:59.999000100Z';
        view.points[1].cpu.collectedAt = '2026-10-07T10:59:59.999000200Z';
        expect(summarizeResource(view, 'cpu', previous!)).toMatchObject({ usable: 2, repeated: 0, conflicts: 0, median: 18 });
        expect(historyIntervals(view, 12).previous!.start).toBe(view.windowStart);
    });
    it('deduplicates equivalent fractional spellings as the same original instant', () => {
        const view = historyFixture([-180, -120, 0]);
        view.points[0].cpu.collectedAt = '2026-10-07T11:56:59.1Z';
        view.points[1].cpu = { ...view.points[0].cpu, collectedAt: '2026-10-07T11:56:59.100000000Z' };
        expect(summarizeResource(view, 'cpu', historyIntervals(view, 1).current)).toMatchObject({ usable: 2, repeated: 1, conflicts: 0, minimum: 0 });
        view.points[1].cpu.value = 99;
        expect(summarizeResource(view, 'cpu', historyIntervals(view, 1).current)).toMatchObject({ usable: 1, repeated: 1, conflicts: 1 });
    });
});
