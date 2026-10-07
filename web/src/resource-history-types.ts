export type ResourceMetric = { value: number | null; quality: 'healthy' | 'stale' | 'unknown' | 'denied'; collectedAt: string };
export type ResourcePoint = { sequence: string; collectedAt: string; receivedAt: string; cpu: ResourceMetric; memory: ResourceMetric; disk: ResourceMetric };
export type ResourceHistory = { schemaVersion: 'tracebolt.resource-history.v1'; deviceId: string; serverNow: string; windowStart: string; status: 'available' | 'awaiting' | 'revoked' | 'expired' | 'not_configured'; resolutionSeconds: 60; gapAfterSeconds: 120; points: ResourcePoint[] };
export type ResourceKey = 'cpu' | 'memory' | 'disk';
export const HISTORY_WINDOW_MS = 86400000;
const object = (value: unknown): value is Record<string, unknown> => Boolean(value && typeof value === 'object' && !Array.isArray(value));
const time = (value: unknown): number => typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value) ? Date.parse(value) : NaN;
export function validResourceHistory(value: unknown, id: string): value is ResourceHistory {
    if (!object(value) || value.schemaVersion !== 'tracebolt.resource-history.v1' || value.deviceId !== id || value.resolutionSeconds !== 60 || value.gapAfterSeconds !== 120 || !['available', 'awaiting', 'revoked', 'expired', 'not_configured'].includes(String(value.status)) || !Array.isArray(value.points) || value.points.length > 1441) return false;
    const now = time(value.serverNow), start = time(value.windowStart);
    if (!Number.isFinite(now) || !Number.isFinite(start) || now - start !== HISTORY_WINDOW_MS || (value.status === 'available') !== (value.points.length > 0)) return false;
    let sequence = 0n, previous = -Infinity, previousBucket = -Infinity;
    for (const point of value.points) {
        if (!object(point) || typeof point.sequence !== 'string' || !/^[1-9][0-9]{0,18}$/.test(point.sequence)) return false;
        const seq = BigInt(point.sequence), collected = time(point.collectedAt), received = time(point.receivedAt), bucket = Math.floor(collected / 60000);
        if (seq <= sequence || seq > 9223372036854775807n || !Number.isFinite(collected) || collected < start || collected > now || collected <= previous || bucket <= previousBucket || !Number.isFinite(received) || received > now || collected - received > 30000 || received - collected > 120000) return false;
        for (const key of ['cpu', 'memory', 'disk'] as const) {
            const metric = point[key];
            if (!object(metric) || !['healthy', 'stale', 'unknown', 'denied'].includes(String(metric.quality))) return false;
            const at = time(metric.collectedAt);
            if (!Number.isFinite(at) || at > collected || collected - at > 150000 || metric.value !== null && (typeof metric.value !== 'number' || !Number.isFinite(metric.value) || metric.value < 0 || metric.value > 100) || metric.quality === 'healthy' && metric.value === null || ['unknown', 'denied'].includes(String(metric.quality)) && metric.value !== null) return false;
        }
        sequence = seq; previous = collected; previousBucket = bucket;
    }
    return true;
}
/** Historical healthy means a valid observation at capture, not current health.
 * Keep reported unavailable samples and long report gaps as actual gaps. */
export function resourceSegments(history: ResourceHistory, key: ResourceKey): ResourceMetric[][] {
    const result: ResourceMetric[][] = []; let current: ResourceMetric[] = [];
    const flush = () => { if (current.length) result.push(current); current = []; };
    const start = Date.parse(history.windowStart), end = Date.parse(history.serverNow);
    for (const point of history.points) {
        const metric = point[key], at = Date.parse(metric.collectedAt), previous = current.at(-1);
        if (metric.quality !== 'healthy' || metric.value === null || at < start || at > end) { flush(); continue; }
        if (previous && (at <= Date.parse(previous.collectedAt) || at - Date.parse(previous.collectedAt) > history.gapAfterSeconds * 1000)) flush();
        current.push(metric);
    }
    flush(); return result;
}

/** Merge only into the exact verified view used to request this delta. The
 * caller owns device/session/epoch scoping and clears it on access uncertainty. */
export function mergeResourceHistoryReply(value: unknown, id: string, baseline?: ResourceHistory, after?: string): ResourceHistory | null {
    if (validResourceHistory(value, id)) return value;
    if (!object(value) || value.schemaVersion !== 'tracebolt.resource-history-delta.v1' || value.status !== 'available' || !baseline || !validResourceHistory(baseline, id) || !after || baseline.points.at(-1)?.sequence !== after || value.baseSequence !== after || typeof value.lastSequence !== 'string' || !/^[1-9][0-9]{0,18}$/.test(value.lastSequence) || !Number.isInteger(value.pointCount) || Number(value.pointCount) < 1 || Number(value.pointCount) > 1441 || !Array.isArray(value.points) || value.points.length > 1441) return null;
    const base = BigInt(after), last = BigInt(value.lastSequence), start = time(value.windowStart), now = time(value.serverNow);
    if (last < base || last > 9223372036854775807n || !Number.isFinite(start) || !Number.isFinite(now) || now < time(baseline.serverNow)) return null;
    // Validate incoming rows independently before using their fields as keys.
    const subset = { ...value, schemaVersion: 'tracebolt.resource-history.v1', status: value.points.length ? 'available' : 'awaiting' };
    if (!validResourceHistory(subset, id) || subset.points.some(point => BigInt(point.sequence) <= base || BigInt(point.sequence) > last || time(point.collectedAt) <= time(baseline.points.at(-1)!.collectedAt))) return null;
    const buckets = new Map<number, ResourcePoint>();
    for (const point of baseline.points) if (time(point.collectedAt) >= start) buckets.set(Math.floor(time(point.collectedAt) / 60000), point);
    for (const point of subset.points) buckets.set(Math.floor(time(point.collectedAt) / 60000), point);
    const points = [...buckets.values()].sort((a,b) => time(a.collectedAt) - time(b.collectedAt));
    const merged = { ...value, schemaVersion: 'tracebolt.resource-history.v1', points };
    return points.length === value.pointCount && points.at(-1)?.sequence === value.lastSequence && validResourceHistory(merged, id) ? merged : null;
}
