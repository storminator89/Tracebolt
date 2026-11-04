import { describe, expect, it } from 'vitest';
import { advanceNetworkReadClock, compareNetworkObservations, networkObservation, retainNetworkBaseline } from './network-interval-model';
import { networkRow, networkView } from './network-interval-fixture';
import { validOperationalView } from './operational-types';
const before = () => networkObservation(networkView(), 0)!;
const after = () => networkObservation(networkView(2, '2026-10-03T12:01:00Z', [networkRow('fixture0', 1600, 3200)]), 0)!;

describe('network observation admission', () => {
    it('uses native-reachable partial latest data, preserving all coverage and null address fields', () => {
        const view = networkView(); expect(validOperationalView(view, 'agent_fixture')).toBe(true);
        const observation = networkObservation(view, 0)!;
        expect(observation.coverage).toEqual({ complete: false, truncated: false, countExact: true, observedCount: 1, reason: 'not_implemented', itemLimit: 32 });
        expect(observation.rows[0].ipv4Count).toBeNull();
        observation.rows[0].rxBytes = 1; expect(view.snapshot!.sections.network.items[0].rxBytes).toBe(1000);
    });
    it.each(['stale', 'revoked', 'awaiting', 'unavailable', 'not_configured'] as const)('withholds %s source without retained fallback', status => {
        const view = networkView(); view.status = status; view.lastGood.network = structuredClone(view.snapshot!.sections.network);
        expect(networkObservation(view, 0)).toBeNull();
    });
    it.each(['unknown', 'denied', 'stale'] as const)('withholds latest %s section even with lastGood', quality => {
        const view = networkView(); view.lastGood.network = structuredClone(view.snapshot!.sections.network); view.snapshot!.sections.network.meta.quality = quality;
        expect(networkObservation(view, 0)).toBeNull();
    });
    it('rejects duplicate names rather than silently joining them', () => {
        const view = networkView(1, undefined, [networkRow(), networkRow()]); expect(networkObservation(view, 0)).toBeNull();
    });
    it('accepts bounded truncated rows without absence or source-wide totals', () => {
        const view = networkView(); Object.assign(view.snapshot!.sections.network.meta, { reason: 'item_limit', truncated: true, countExact: false, observedCount: 100 });
        expect(validOperationalView(view, 'agent_fixture')).toBe(true);
        expect(networkObservation(view, 0)?.coverage).toMatchObject({ truncated: true, observedCount: 100, countExact: false });
    });
    it('retains nanosecond freshness and includes read age at the exact boundary', () => {
        const view = networkView(1, '2026-10-03T12:00:00.000000001Z'); view.serverNow = '2026-10-03T12:02:00.000000001Z';
        expect(networkObservation(view, 0)).not.toBeNull();
        expect(networkObservation(view, 0.000001)).toBeNull();
        view.serverNow = '2026-10-03T12:01:59Z'; expect(networkObservation(view, 999)).not.toBeNull(); expect(networkObservation(view, 1001)).toBeNull();
        view.serverNow = '2026-10-03T12:00:00Z'; expect(networkObservation(view, 0)).toBeNull();
    });
    it.each([NaN, Infinity, -1, Number.MAX_VALUE])('rejects invalid elapsed %s', elapsed => { expect(networkObservation(networkView(), elapsed)).toBeNull(); });
});

describe('name-qualified network counter arithmetic', () => {
    it('computes exact zero and positive counter differences, without changing source rows', () => {
        const first = before(), second = after(); const bytes = JSON.stringify([first, second]);
        const result = compareNetworkObservations(first, second);
        expect(result).toMatchObject({ status: 'advanced', seconds: 60, rows: [{ name: 'fixture0', status: 'matched', differences: { rxBytes: 600, txBytes: 1200, rxErrors: 0, txErrors: 0 } }] });
        expect(result.rows[0].differences.rxBytes! / result.seconds!).toBe(10); expect(JSON.stringify([first, second])).toBe(bytes);
    });
    it('keeps missing counters unknown and withholds the entire row on any counter decrease', () => {
        const first = before(), second = after(); second.rows[0].rxErrors = null;
        expect(compareNetworkObservations(first, second).rows[0].differences).toMatchObject({ rxErrors: null, rxBytes: 600 });
        second.rows[0].txErrors = 0; first.rows[0].txErrors = 1;
        expect(compareNetworkObservations(first, second).rows[0]).toMatchObject({ status: 'decreased', differences: { rxBytes: null, txBytes: null, rxErrors: null, txErrors: null } });
    });
    it('withholds changed MTU context; never claims interval uptime from up/down samples', () => {
        const second = after(); second.rows[0].state = 'down'; expect(compareNetworkObservations(before(), second).rows[0].status).toBe('matched');
        second.rows[0].mtu = null; expect(compareNetworkObservations(before(), second).rows[0]).toMatchObject({ status: 'context_changed', differences: { rxBytes: null } });
    });
    it('preserves bounded names only in one observation without inferring additions or removals', () => {
        const first = before(), second = after(); first.rows.push(networkRow('old')); second.rows.push(networkRow('new'));
        expect(compareNetworkObservations(first, second).rows.map(row => [row.name, row.status])).toEqual([['fixture0', 'matched'], ['new', 'current_only'], ['old', 'baseline_only']]);
    });
    it('waits only for byte-identical original sample references, never conflicting same-sequence data', () => {
        expect(compareNetworkObservations(before(), before()).status).toBe('waiting');
        const second = before(); second.serverNow = '2026-10-03T12:00:30Z'; expect(compareNetworkObservations(before(), second).status).toBe('waiting');
        second.rows[0].rxBytes = 1111; expect(compareNetworkObservations(before(), second).status).toBe('changed');
    });
    it.each(['deviceId', 'sequence', 'generationId', 'observedAt', 'receivedAt', 'serverNow'] as const)('rejects nonadvancing or changed %s', key => {
        const first = before(), second = after();
        if (key === 'deviceId') second.deviceId = 'agent_other';
        else if (key === 'serverNow') second.serverNow = '2026-10-03T11:59:59Z';
        else (second as unknown as Record<string, unknown>)[key] = first[key];
        expect(compareNetworkObservations(first, second).status).toBe('changed'); expect(retainNetworkBaseline(first, second)).toBeNull();
    });
    it('preserves submillisecond original order, withholds tiny intervals, bounds one hour exactly', () => {
        const first = networkObservation(networkView(1, '2026-10-03T12:00:00.999999999Z'), 0)!;
        const tiny = networkObservation(networkView(2, '2026-10-03T12:00:01Z'), 0)!;
        expect(compareNetworkObservations(first, tiny).status).toBe('too_short');
        const exact = networkObservation(networkView(2, '2026-10-03T12:00:01.999999999Z'), 0)!;
        expect(compareNetworkObservations(first, exact).seconds).toBe(1);
        const hour = networkObservation(networkView(2, '2026-10-03T13:00:00.999999999Z'), 0)!;
        expect(compareNetworkObservations(first, hour).seconds).toBe(3600);
        hour.observedAt = '2026-10-03T13:00:01Z'; expect(compareNetworkObservations(first, hour).status).toBe('expired'); expect(retainNetworkBaseline(first, hour)).toBeNull();
    });
    it('clears lost source and keeps an advancing compatible baseline only in memory', () => {
        const first = before(); expect(retainNetworkBaseline(first, null)).toBeNull(); expect(retainNetworkBaseline(first, after())).toBe(first); expect(retainNetworkBaseline(first, before())).toBe(first);
    });
});

describe('session-local conservative network read clock', () => {
    it('includes request age and advances across frozen repeated reads', () => {
        const first = advanceNetworkReadClock(null, '2026-10-03T12:00:00Z', 0, 1000)!; expect(first.elapsedMs).toBe(1000);
        const next = advanceNetworkReadClock(first.clock, '2026-10-03T12:00:00Z', 120000, 121000)!;
        expect(next.elapsedMs).toBe(121000); expect(networkObservation(networkView(), next.elapsedMs)).toBeNull();
        const progressed = advanceNetworkReadClock(next.clock, '2026-10-03T12:02:00Z', 121000, 122000)!;
        expect(progressed.elapsedMs).toBe(2000);
    });
    it('rejects clock rollback and invalid monotonic values instead of renewing source confidence', () => {
        const first = advanceNetworkReadClock(null, '2026-10-03T12:00:00.000000001Z', 0, 1)!;
        expect(advanceNetworkReadClock(first.clock, '2026-10-03T12:00:00Z', 1, 2)).toBeNull();
        expect(advanceNetworkReadClock(first.clock, first.clock.serverNow, 0, 0)).toBeNull();
        expect(advanceNetworkReadClock(null, first.clock.serverNow, 2, 1)).toBeNull();
        expect(advanceNetworkReadClock(null, first.clock.serverNow, 1, NaN)).toBeNull();
    });
});
