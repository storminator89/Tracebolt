import { describe, expect, it } from 'vitest';
import { applicationObservationAge, projectApplicationCheck, validApplicationChecksView } from './application-checks-types';
import type { ApplicationCheckV2 } from './application-checks-types';
import { applicationNow, applicationRow, applicationView } from './application-checks-fixtures';
import { applicationDNSRow, applicationHTTPRow, applicationTCPRow, applicationViewV2, disabledApplicationViewV2 } from './application-checks-v2-fixtures';

const valid = validApplicationChecksView;
const validRow = (row: unknown) => valid({ ...applicationViewV2([]), maxAgeSeconds: 70, items: [row] });
const networkRows = () => [applicationDNSRow(), applicationTCPRow()];
const networkKeys = ['kind', 'id', 'state', 'reason', 'observedAt'].sort();
const reasons = ['http_2xx', 'http_status', 'redirect_blocked', 'dns_resolved', 'tcp_connected', 'dns_failed', 'timeout', 'tcp_failed', 'request_failed', 'tls_verification_failed', 'tls_handshake_failed', 'not_checked', 'invalid_configuration', 'cancelled', 'destination_blocked', 'stale', 'raw socket error', '', null];

describe('strict tagged v2 retained observation contract', () => {
    it('accepts mixed HTTP, HTTPS, DNS and TCP with the unchanged envelope and bound', () => {
        const plain = applicationHTTPRow({ id: 'fixture-plain', targetScheme: 'http', tls: { state: 'not_applicable', expiresAt: null } });
        expect(valid(applicationViewV2([...applicationViewV2().items, plain]))).toBe(true);
        for (const count of [1, 8]) for (const intervalSeconds of [60, 3600]) {
            const items = Array.from({ length: count }, (_, index) => ({ ...applicationViewV2().items[index % 3], id: `fixture-${index}` }));
            expect(valid({ ...applicationViewV2(items), intervalSeconds, maxAgeSeconds: intervalSeconds + (count + 1) * 5 })).toBe(true);
        }
        expect(valid(applicationViewV2([]))).toBe(false);
        expect(valid(applicationViewV2(Array.from({ length: 9 }, (_, index) => ({ ...applicationDNSRow(), id: `fixture-${index}` }))))).toBe(false);
        expect(valid({ ...applicationViewV2(), maxAgeSeconds: 75 })).toBe(false);
        for (const intervalSeconds of [59, 3601, 60.5, '60', null]) expect(valid({ ...applicationViewV2(), intervalSeconds })).toBe(false);
    });

    it('accepts v2 disabled only with an empty zero-cadence envelope', () => {
        const disabled = disabledApplicationViewV2();
        expect(valid(disabled)).toBe(true);
        expect(disabled.schemaVersion).toBe('tracebolt.application-checks.v2');
        for (const patch of [{ intervalSeconds: 60 }, { maxAgeSeconds: 70 }, { items: [applicationDNSRow()] }, { serverNow: null }, { enabled: 'false' }, { vantage: 'browser' }]) expect(valid({ ...disabled, ...patch })).toBe(false);
    });

    it('keeps exact legacy rows accepted only in v1 and requires tags in v2', () => {
        expect(valid(applicationView())).toBe(true);
        expect(valid({ ...applicationViewV2(), items: applicationView().items, maxAgeSeconds: 70 })).toBe(false);
        for (const row of applicationViewV2().items) expect(valid({ ...applicationView(), items: [row] })).toBe(false);
        for (const schemaVersion of ['tracebolt.application-checks.v0', 'tracebolt.application-checks.v3', 'v2', 2, null]) expect(valid({ ...applicationViewV2(), schemaVersion })).toBe(false);
        expect(validRow(applicationRow())).toBe(false);
    });

    it('requires exact own keys and rejects kind confusion, destination and cross-kind fields', () => {
        for (const original of applicationViewV2().items) {
            for (const key of Object.keys(original)) {
                const row = { ...original } as Record<string, unknown>;
                delete row[key];
                expect(validRow(row), `${original.kind}: missing ${key}`).toBe(false);
            }
            for (const [key, value] of Object.entries({ host: 'do-not-render', hostname: 'do-not-render', port: 443, address: 'do-not-render', addresses: [], url: 'do-not-render', destination: {}, responseBody: 'do-not-render', rawError: 'do-not-render' })) {
                expect(validRow({ ...original, [key]: value }), `${original.kind}: extra ${key}`).toBe(false);
            }
            for (const kind of ['https', 'DNS', 'udp', '', null]) expect(validRow({ ...original, kind })).toBe(false);
            const inherited: Record<string, unknown> = Object.assign(Object.create({ kind: original.kind }) as Record<string, unknown>, original);
            delete inherited.kind;
            expect(validRow(inherited)).toBe(false);
        }
        for (const original of networkRows()) {
            for (const patch of [{ targetScheme: 'http' }, { targetScheme: 'https' }, { httpStatus: null }, { httpStatus: 200 }, { tls: null }, { tls: { state: 'not_applicable', expiresAt: null } }, { tls: { state: 'valid', expiresAt: '2027-01-01T00:00:00Z' } }]) expect(validRow({ ...original, ...patch })).toBe(false);
        }
        for (const value of [null, false, 0, 'dns', [], {}]) expect(validRow(value)).toBe(false);
        const envelope = applicationViewV2();
        for (const key of Object.keys(envelope)) { const value = { ...envelope } as Record<string, unknown>; delete value[key]; expect(valid(value)).toBe(false); }
        expect(valid({ ...envelope, destination: 'do-not-render' })).toBe(false);
    });

    it('keeps unique safe IDs across all kinds', () => {
        expect(valid(applicationViewV2([applicationDNSRow(), { ...applicationTCPRow(), id: 'fixture-dns' }]))).toBe(false);
        expect(valid(applicationViewV2([applicationHTTPRow(), { ...applicationDNSRow(), id: 'fixture-app' }]))).toBe(false);
        for (const original of networkRows()) {
            for (const id of ['x', '-', '_', 'a'.repeat(48)]) expect(validRow({ ...original, id })).toBe(true);
            for (const id of ['', 'a'.repeat(49), 'two words', 'Upper', 'x\n', 'x.y', '/', null, 7]) expect(validRow({ ...original, id })).toBe(false);
        }
    });

    it.each(['dns', 'tcp'] as const)('accepts only the exact %s state/reason combinations', kind => {
        const original = kind === 'dns' ? applicationDNSRow() : applicationTCPRow();
        for (const state of ['ok', 'network_error', 'unknown', 'http_error', 'tls_error', 'healthy', '', null]) {
            for (const reason of reasons) for (const observedAt of [applicationNow, null]) {
                const success = state === 'ok' && reason === (kind === 'dns' ? 'dns_resolved' : 'tcp_connected') && observedAt !== null;
                const failure = state === 'network_error' && (reason === 'dns_failed' || reason === 'timeout' || kind === 'tcp' && reason === 'tcp_failed') && observedAt !== null;
                const unknown = state === 'unknown' && (reason === 'not_checked' ? observedAt === null : ['invalid_configuration', 'cancelled', 'destination_blocked', 'stale'].includes(String(reason)) && observedAt !== null);
                expect(validRow({ ...original, state, reason, observedAt }), `${kind}/${state}/${reason}/${observedAt}`).toBe(success || failure || unknown);
            }
        }
    });

    it('does not weaken HTTP or verified certificate rules when a row is tagged', () => {
        const http = applicationHTTPRow();
        expect(validRow(http)).toBe(true);
        for (const patch of [{ reason: 'dns_resolved' }, { reason: 'tcp_connected' }, { reason: 'tcp_failed' }, { httpStatus: null }, { observedAt: null }, { tls: { state: 'unknown', expiresAt: null } }, { tls: { ...http.tls, state: 'valid' } }, { tls: { ...http.tls, address: 'do-not-render' } }]) expect(validRow({ ...http, ...patch })).toBe(false);
        for (const httpStatus of [200, 204, 299, 302, 404, 503]) {
            const state = httpStatus < 300 ? 'ok' : 'http_error';
            const reason = httpStatus < 300 ? 'http_2xx' : httpStatus < 400 ? 'redirect_blocked' : 'http_status';
            expect(validRow({ ...http, state, reason, httpStatus })).toBe(true);
        }
        const expired = applicationHTTPRow({ observedAt: '2026-10-06T11:59:50Z', tls: { state: 'expired', expiresAt: '2026-10-06T11:59:55Z' } });
        expect(validRow(expired)).toBe(true);
        expect(validRow({ ...expired, tls: { state: 'expired', expiresAt: expired.observedAt } })).toBe(false);
    });

    it('uses the same strict UTC timestamp grammar for DNS/TCP evidence', () => {
        for (const row of networkRows()) {
            for (const observedAt of ['', '2026-10-06', '2026-02-30T12:00:00Z', '2026-10-06T12:00:00+00:00', '2026-10-06T12:00:00.1234567890Z', '1969-12-31T23:59:59Z', 1, undefined]) expect(validRow({ ...row, observedAt })).toBe(false);
            for (const observedAt of ['1970-01-01T00:00:00Z', '2026-10-06T12:00:00.000000001Z', '2026-10-06T12:00:00.123456789Z']) expect(validRow({ ...row, observedAt })).toBe(true);
        }
    });
});

describe('kind-preserving retained v2 projection', () => {
    it('keeps fresh DNS/TCP evidence exact and projects stale results without HTTP or TLS fields', () => {
        for (const row of networkRows()) {
            const view = applicationViewV2([row]), original = structuredClone(row);
            expect(projectApplicationCheck(view, row, 70000)).toEqual(row);
            for (const elapsed of [70000.000001, 71000, Infinity, NaN, -1]) {
                const projected = projectApplicationCheck(view, row, elapsed);
                expect(projected).toEqual({ ...row, state: 'unknown', reason: 'stale' });
                expect(Object.keys(projected).sort()).toEqual(networkKeys);
            }
            expect(row).toEqual(original);
        }
    });

    it('preserves all three tags while clearing old mixed evidence together', () => {
        const view = applicationViewV2();
        for (const row of view.items) {
            const projected = projectApplicationCheck(view, row, 80001);
            expect(projected.kind).toBe(row.kind);
            expect(projected.state).toBe('unknown'); expect(projected.reason).toBe('stale');
            expect(projected.observedAt).toBe(row.observedAt);
            if (projected.kind === 'http') { expect(projected.httpStatus).toBeNull(); expect(projected.tls).toEqual({ state: 'unknown', expiresAt: null }); }
            else expect(Object.keys(projected).sort()).toEqual(networkKeys);
        }
    });

    it('cannot heal just-future DNS/TCP evidence with local waiting', () => {
        for (const original of networkRows()) {
            const row = { ...original, observedAt: '2026-10-06T12:00:00.000000001Z' }, view = applicationViewV2();
            expect(validRow(row)).toBe(true);
            for (const elapsed of [0, 0.000001, 1000, 60000, 100000]) {
                expect(applicationObservationAge(view, row, elapsed)).toBeNull();
                expect(projectApplicationCheck(view, row, elapsed)).toEqual({ ...row, state: 'unknown', reason: 'stale' });
            }
        }
    });

    it('retains unchecked and observed unknown states without creating a certificate claim', () => {
        for (const base of networkRows()) {
            const unchecked: ApplicationCheckV2 = { kind: base.kind, id: base.id, state: 'unknown', reason: 'not_checked', observedAt: null };
            expect(projectApplicationCheck(applicationViewV2(), unchecked, 5000)).toEqual(unchecked);
            for (const reason of ['invalid_configuration', 'cancelled', 'destination_blocked', 'stale'] as const) {
                const row: ApplicationCheckV2 = { kind: base.kind, id: base.id, state: 'unknown', reason, observedAt: applicationNow };
                expect(validRow(row)).toBe(true);
                expect(projectApplicationCheck(applicationViewV2(), row, 1000)).toEqual(row);
            }
        }
    });
});
