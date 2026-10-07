import { describe, expect, it } from 'vitest';
import { historyDevice, historyFixture } from './resource-history-fixture';
import { mergeResourceHistoryReply, type ResourceHistory } from './resource-history-types';
const delta = (base: ResourceHistory, offsets: number[], count: number, seconds = 60) => {
    const points = historyFixture(offsets).points.map((point, index) => ({ ...point, sequence: String(BigInt(base.points.at(-1)!.sequence) + BigInt(index + 1)) }));
    return { ...base, schemaVersion: 'tracebolt.resource-history-delta.v1', serverNow: new Date(Date.parse(base.serverNow) + seconds * 1000).toISOString(), windowStart: new Date(Date.parse(base.windowStart) + seconds * 1000).toISOString(), points, baseSequence: base.points.at(-1)!.sequence, lastSequence: points.at(-1)?.sequence ?? base.points.at(-1)!.sequence, pointCount: count };
};
describe('session-local history delta verification', () => {
    it('retains every older sample and replaces only a newer sample in the same minute', () => {
        const base = historyFixture(); base.points[0].cpu.value = 99.9;
        const reply = delta(base, [30, 60], 5), merged = mergeResourceHistoryReply(reply, historyDevice, base, '4');
        expect(merged?.points.map(point => point.sequence)).toEqual(['1', '2', '3', '5', '6']);
        expect(merged?.points[0]).toEqual(base.points[0]); expect(merged?.points[0].cpu.value).toBe(99.9);
        expect(base.points.map(point => point.sequence)).toEqual(['1', '2', '3', '4']);
    });
    it('accepts unchanged deltas without sending retained points again', () => {
        const base = historyFixture(), reply = delta(base, [], 4, 30);
        expect(mergeResourceHistoryReply(reply, historyDevice, base, '4')?.points).toEqual(base.points);
    });
    it('expires by returned server time and preserves real unknown-quality gaps', () => {
        const base = historyFixture([-86400, -60, 0]); base.points[1].cpu = { ...base.points[1].cpu, quality: 'unknown', value: null };
        const merged = mergeResourceHistoryReply(delta(base, [], 2, 30), historyDevice, base, '3');
        expect(merged?.points).toEqual(base.points.slice(1)); expect(merged?.points[0].cpu.quality).toBe('unknown');
    });
    it('does not admit a delta without its exact device and sequence baseline', () => {
        const base = historyFixture(), reply = delta(base, [60], 5);
        expect(mergeResourceHistoryReply(reply, historyDevice)).toBeNull();
        expect(mergeResourceHistoryReply(reply, historyDevice, base, '3')).toBeNull();
        expect(mergeResourceHistoryReply({ ...reply, baseSequence: '3' }, historyDevice, base, '4')).toBeNull();
        expect(mergeResourceHistoryReply(reply, 'agent_22222222222222222222222222222222', base, '4')).toBeNull();
    });
    it('rejects missing/extra points, sequence regression, wrong latest sequence, and clock rollback', () => {
        const base = historyFixture(), reply = delta(base, [60], 5);
        for (const corrupt of [{ ...reply, pointCount: 4 }, { ...reply, pointCount: 6 }, { ...reply, lastSequence: '4' }, { ...reply, lastSequence: '9223372036854775808' }, { ...reply, points: [{ ...reply.points[0], sequence: '4' }] }, { ...reply, serverNow: '2026-10-07T11:59:00Z', windowStart: '2026-10-06T11:59:00Z' }, { ...reply, points: [] }]) expect(mergeResourceHistoryReply(corrupt, historyDevice, base, '4')).toBeNull();
    });
    it('keeps full bootstrap/fallback and terminal clearing compatible', () => {
        const base = historyFixture(); expect(mergeResourceHistoryReply(base, historyDevice)).toEqual(base);
        const revoked: ResourceHistory = { ...historyFixture([]), status: 'revoked' };
        expect(mergeResourceHistoryReply(revoked, historyDevice, base, '4')?.points).toEqual([]);
        expect(mergeResourceHistoryReply({ ...delta(base, [], 4), status: 'revoked' }, historyDevice, base, '4')).toBeNull();
    });
});
