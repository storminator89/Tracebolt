import { effectiveOperationalStatus } from './operational-types';
import type { OperationalMeta, OperationalNetwork, OperationalView } from './operational-types';

/** One deliberately selected, bounded in-memory observation. No retained fallback. */
export interface NetworkObservation {
    deviceId: string;
    sequence: number;
    generationId: string;
    observedAt: string;
    receivedAt: string;
    serverNow: string;
    coverage: Pick<OperationalMeta, 'complete' | 'truncated' | 'countExact' | 'observedCount' | 'reason' | 'itemLimit'>;
    rows: OperationalNetwork[];
}
export const MAX_NETWORK_INTERVAL_SECONDS = 3600;
export const NETWORK_COUNTERS = ['rxBytes', 'txBytes', 'rxErrors', 'txErrors'] as const;
export type NetworkCounter = typeof NETWORK_COUNTERS[number];
export type NetworkIntervalStatus = 'waiting' | 'advanced' | 'too_short' | 'expired' | 'changed';
export interface NetworkIntervalRow {
    name: string;
    before: OperationalNetwork | null;
    after: OperationalNetwork | null;
    status: 'matched' | 'baseline_only' | 'current_only' | 'decreased' | 'context_changed';
    differences: Record<NetworkCounter, number | null>;
}
export interface NetworkInterval {
    status: NetworkIntervalStatus;
    seconds: number | null;
    rows: NetworkIntervalRow[];
}

/** Millisecond Date parsing alone would collapse distinct original timestamps. */
function nanos(value: string): bigint {
    const fraction = value.match(/\.(\d{1,9})Z$/)?.[1] ?? '';
    return BigInt(Date.parse(`${value.slice(0, 19)}Z`)) * 1000000n + BigInt(fraction.padEnd(9, '0') || '0');
}

/** Called only for a strict-parsed view. Healthy rows may have partial source coverage (address counts are not
 * collected by the native provider). Never infer absence from the bounded rows. */
export function networkObservation(view: OperationalView | null, elapsedMs: number): NetworkObservation | null {
    if (!view || effectiveOperationalStatus(view, elapsedMs) !== 'fresh' || !Number.isFinite(elapsedMs) || elapsedMs < 0 || !view.snapshot || view.sequence === null || !view.receivedAt) return null;
    const section = view.snapshot.sections.network;
    const elapsedNanos = Math.ceil(elapsedMs * 1e6);
    if (!Number.isSafeInteger(elapsedNanos)) return null;
    const now = nanos(view.serverNow) + BigInt(elapsedNanos), maxAge = BigInt(view.maxAgeSeconds) * 1000000000n;
    if (nanos(section.meta.observedAt) > nanos(view.serverNow) || nanos(view.receivedAt) > nanos(view.serverNow) || now - nanos(section.meta.observedAt) > maxAge || now - nanos(view.receivedAt) > maxAge) return null;
    if (section.meta.quality !== 'healthy' || new Set(section.items.map(row => row.name)).size !== section.items.length) return null;
    const { complete, truncated, countExact, observedCount, reason, itemLimit } = section.meta;
    return { deviceId: view.deviceId, sequence: view.sequence, generationId: section.meta.generationId, observedAt: section.meta.observedAt, receivedAt: view.receivedAt, serverNow: view.serverNow, coverage: { complete, truncated, countExact, observedCount, reason, itemLimit }, rows: section.items.map(row => ({ ...row })) };
}

/** The manager supplies no boot ID or immutable interface ID. Matching by name
 * is explicit; even positive arithmetic changes do not prove identity continuity. */
export function compareNetworkObservations(before: NetworkObservation, after: NetworkObservation): NetworkInterval {
    const unavailable = (status: NetworkIntervalStatus): NetworkInterval => ({ status, seconds: null, rows: [] });
    if (before.deviceId !== after.deviceId || nanos(after.serverNow) < nanos(before.serverNow)) return unavailable('changed');
    if (before.sequence === after.sequence && before.generationId === after.generationId && before.observedAt === after.observedAt && before.receivedAt === after.receivedAt && JSON.stringify(before.rows) === JSON.stringify(after.rows) && JSON.stringify(before.coverage) === JSON.stringify(after.coverage)) return unavailable('waiting');
    if (after.sequence <= before.sequence || before.generationId === after.generationId || nanos(after.observedAt) <= nanos(before.observedAt) || nanos(after.receivedAt) <= nanos(before.receivedAt)) return unavailable('changed');
    const duration = nanos(after.observedAt) - nanos(before.observedAt);
    if (duration < 1000000000n) return unavailable('too_short');
    if (duration > BigInt(MAX_NETWORK_INTERVAL_SECONDS) * 1000000000n) return unavailable('expired');
    const first = new Map(before.rows.map(row => [row.name, row]));
    const second = new Map(after.rows.map(row => [row.name, row]));
    const rows: NetworkIntervalRow[] = [...new Set([...first.keys(), ...second.keys()])].sort().map(name => {
        const previous = first.get(name) ?? null, current = second.get(name) ?? null;
        const differences: Record<NetworkCounter, number | null> = { rxBytes: null, txBytes: null, rxErrors: null, txErrors: null };
        if (!previous || !current) return { name, before: previous, after: current, status: previous ? 'baseline_only' : 'current_only', differences };
        const decreased = NETWORK_COUNTERS.some(key => previous[key] !== null && current[key] !== null && current[key]! < previous[key]!);
        // A changed MTU is additional evidence of changed interface context. State
        // changes are shown independently; they do not establish interval uptime.
        const contextChanged = previous.mtu !== current.mtu;
        if (!decreased && !contextChanged) for (const key of NETWORK_COUNTERS) {
            if (previous[key] !== null && current[key] !== null) differences[key] = current[key]! - previous[key]!;
        }
        return { name, before: previous, after: current, status: decreased ? 'decreased' : contextChanged ? 'context_changed' : 'matched', differences };
    });
    return { status: 'advanced', seconds: Number(duration) / 1e9, rows };
}

/** A new successful but incompatible source cannot silently replace a baseline. */
export function retainNetworkBaseline(before: NetworkObservation | null, after: NetworkObservation | null): NetworkObservation | null {
    if (!before || !after) return null;
    const status = compareNetworkObservations(before, after).status;
    return status === 'changed' || status === 'expired' ? null : before;
}

/** Conservative manager-time floor across successful reads in this mounted
 * session. Unchanged serverNow cannot refresh old evidence indefinitely. */
export interface NetworkReadClock { floor: bigint; serverNow: string; monotonicAt: number }
export function advanceNetworkReadClock(previous: NetworkReadClock | null, serverNow: string, readStarted: number, monotonicNow: number): { clock: NetworkReadClock; elapsedMs: number } | null {
    const latency = monotonicNow - readStarted;
    if (!Number.isFinite(monotonicNow) || !Number.isFinite(readStarted) || latency < 0 || !Number.isSafeInteger(Math.ceil(latency * 1e6))) return null;
    let floor = nanos(serverNow) + BigInt(Math.ceil(latency * 1e6));
    if (previous) {
        const elapsed = monotonicNow - previous.monotonicAt;
        if (!Number.isFinite(elapsed) || elapsed < 0 || !Number.isSafeInteger(Math.ceil(elapsed * 1e6)) || nanos(serverNow) < nanos(previous.serverNow)) return null;
        const previousFloor = previous.floor + BigInt(Math.ceil(elapsed * 1e6));
        if (previousFloor > floor) floor = previousFloor;
    }
    const elapsedMs = Number(floor - nanos(serverNow)) / 1e6;
    return { clock: { floor, serverNow, monotonicAt: monotonicNow }, elapsedMs };
}
