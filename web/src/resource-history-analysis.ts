import type { ResourceHistory, ResourceKey } from './resource-history-types';

export const historyHours = [1, 6, 12, 24] as const;
export type HistoryHours = typeof historyHours[number];
export type HistoryInterval = { start: string; end: string; endInclusive: boolean };
export type ResourceSummary = {
    reports: number;
    usable: number;
    unavailable: number;
    repeated: number;
    conflicts: number;
    minuteBuckets: number;
    expectedBuckets: number;
    minimum: number | null;
    median: number | null;
    p95: number | null;
    maximum: number | null;
    longestGapMs: number;
};

/** Both periods use the original manager snapshot, never a browser clock.
 * The shared boundary belongs only to the current interval. */
function originalNanoseconds(at: string): bigint {
    const [whole, fraction = ''] = at.slice(0, -1).split('.');
    return BigInt(Date.parse(`${whole}Z`)) * 1000000n + BigInt(fraction.padEnd(9, '0'));
}

// Subtracting whole hours preserves the exact original fractional second.
function beforeHours(at: string, hours: number): string {
    const fraction = at.match(/\.\d+Z$/)?.[0] ?? 'Z';
    return new Date(Date.parse(at) - hours * 3600000).toISOString().replace(/\.\d{3}Z$/, fraction);
}

export function historyIntervals(history: ResourceHistory, hours: HistoryHours) {
    const current: HistoryInterval = { start: beforeHours(history.serverNow, hours), end: history.serverNow, endInclusive: true };
    const precedingStart = beforeHours(current.start, hours);
    const previous: HistoryInterval | null = originalNanoseconds(precedingStart) >= originalNanoseconds(history.windowStart)
        ? { start: precedingStart, end: current.start, endInclusive: false } : null;
    return { current, previous };
}

export function inHistoryInterval(at: string, interval: HistoryInterval): boolean {
    const instant = originalNanoseconds(at), start = originalNanoseconds(interval.start), end = originalNanoseconds(interval.end);
    return instant >= start && (interval.endInclusive ? instant <= end : instant < end);
}

/** A sample distribution, not a time-weighted load or a health assessment.
 * Repeated metric timestamps count once. Contradictory values at one original
 * timestamp are withheld, rather than choosing a favorable value. */
export function summarizeResource(history: ResourceHistory, key: ResourceKey, interval: HistoryInterval): ResourceSummary {
    const observations = new Map<bigint, { value: number | null; conflict: boolean }>();
    let reports = 0, unavailable = 0, repeated = 0;
    for (const point of history.points) {
        if (inHistoryInterval(point.collectedAt, interval)) reports++;
        const metric = point[key], at = originalNanoseconds(metric.collectedAt);
        if (!inHistoryInterval(metric.collectedAt, interval)) continue;
        if (metric.quality !== 'healthy' || metric.value === null) { unavailable++; continue; }
        const existing = observations.get(at);
        if (existing) {
            repeated++;
            if (existing.value !== metric.value) existing.conflict = true;
        } else observations.set(at, { value: metric.value, conflict: false });
    }
    const samples = [...observations].filter(([, item]) => !item.conflict).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
    const values = samples.map(([, item]) => item.value!).sort((a, b) => a - b);
    const count = values.length;
    const start = originalNanoseconds(interval.start), end = originalNanoseconds(interval.end), minute = 60000000000n;
    let previous = start, longestGap = 0n;
    for (const [at] of samples) { if (at - previous > longestGap) longestGap = at - previous; previous = at; }
    if (end - previous > longestGap) longestGap = end - previous;
    return {
        reports, usable: count, unavailable, repeated, conflicts: observations.size - count,
        minuteBuckets: new Set(samples.map(([at]) => at / minute)).size,
        expectedBuckets: Number((interval.endInclusive ? end / minute + 1n : (end + minute - 1n) / minute) - start / minute),
        minimum: count ? values[0] : null,
        median: count ? count % 2 ? values[(count - 1) / 2] : (values[count / 2 - 1] + values[count / 2]) / 2 : null,
        p95: count ? values[Math.ceil(count * .95) - 1] : null,
        maximum: count ? values[count - 1] : null,
        longestGapMs: Number(longestGap) / 1000000,
    };
}
