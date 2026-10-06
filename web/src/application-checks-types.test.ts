import { describe, expect, it } from 'vitest';
import { APPLICATION_CHECKS_BYTES, applicationObservationAge, projectApplicationCheck, validApplicationChecksView } from './application-checks-types';
import type { ApplicationCheck, ApplicationChecksView, ApplicationTLSState } from './application-checks-types';

// Invented retained observations only. These tests do not resolve or contact a target.
const now = '2026-10-06T12:00:00.123456789Z';
const observedAt = '2026-10-06T11:59:50.123456789Z';
const expiresAt = '2026-12-06T12:00:00.123456789Z';
function row(changes: Partial<ApplicationCheck> = {}): ApplicationCheck {
    return { id: 'fixture-app', targetScheme: 'https', state: 'ok', reason: 'http_2xx', observedAt, httpStatus: 200, tls: { state: 'valid', expiresAt }, ...changes };
}
function view(items: ApplicationCheck[] = [row()]): ApplicationChecksView {
    return { schemaVersion: 'tracebolt.application-checks.v1', enabled: true, vantage: 'management_server', serverNow: now, intervalSeconds: 60, maxAgeSeconds: 60 + (items.length + 1) * 5, items };
}
function plaintext(changes: Partial<ApplicationCheck> = {}): ApplicationCheck {
    return row({ targetScheme: 'http', tls: { state: 'not_applicable', expiresAt: null }, ...changes });
}
function disabled(): ApplicationChecksView {
    return { ...view([]), enabled: false, intervalSeconds: 0, maxAgeSeconds: 0 };
}
function unknown(changes: Partial<ApplicationCheck> = {}): ApplicationCheck {
    return row({ state: 'unknown', reason: 'not_checked', observedAt: null, httpStatus: null, tls: { state: 'unknown', expiresAt: null }, ...changes });
}
function network(reason: 'dns_failed' | 'timeout' | 'request_failed', changes: Partial<ApplicationCheck> = {}): ApplicationCheck {
    return row({ state: 'network_error', reason, httpStatus: null, tls: { state: 'unknown', expiresAt: null }, ...changes });
}
const valid = (value: unknown) => validApplicationChecksView(value);
const validRow = (value: unknown) => valid({ ...view(), items: [value] });
const malformedTimes: unknown[] = [
    undefined, 0, {}, '', 'not-a-time', '2026-10-06', '2026-10-06T12:00:00',
    '2026-10-06t12:00:00z', '2026-10-06T12:00:00+00:00', '2026-10-06T12:00:00.1234567890Z',
    '2026-10-06T12:00:00.Z', '2026-10-06T12:00:00Z\n', '2026-02-29T12:00:00Z',
    '2026-02-31T12:00:00Z', '2026-13-06T12:00:00Z', '2026-10-00T12:00:00Z',
    '2026-10-06T24:00:00Z', '2026-10-06T12:60:00Z', '2026-10-06T12:00:60Z',
    '1969-12-31T23:59:59Z', '0000-01-01T00:00:00Z', '+010000-01-01T00:00:00Z',
];

describe('strict retained application-check contract', () => {
    it('accepts the exact disabled shape and bounded enabled generations', () => {
        expect(valid(disabled())).toBe(true);
        expect(APPLICATION_CHECKS_BYTES).toBe(16384);
        for (const count of [1, 8]) for (const intervalSeconds of [60, 3600]) {
            const value = view(Array.from({ length: count }, (_, index) => row({ id: `fixture-${index}` })));
            value.intervalSeconds = intervalSeconds;
            value.maxAgeSeconds = intervalSeconds + (count + 1) * 5;
            expect(valid(value)).toBe(true);
        }
        expect(valid(view([unknown(), plaintext({ id: 'fixture-plain' })]))).toBe(true);
    });

    it('requires an object and exact own keys at every JSON boundary', () => {
        const selectors = [(value: ApplicationChecksView) => value, (value: ApplicationChecksView) => value.items[0], (value: ApplicationChecksView) => value.items[0].tls];
        for (const select of selectors) {
            for (const key of Object.keys(select(view()))) {
                const value = view(), target = select(value) as unknown as Record<string, unknown>;
                delete target[key];
                expect(valid(value), `missing ${key}`).toBe(false);
            }
            for (const extra of ['url', 'responseBody', 'rawError', 'headers', 'externalUrl']) {
                const value = view();
                Object.assign(select(value), { [extra]: 'unexpected' });
                expect(valid(value), `extra ${extra}`).toBe(false);
            }
        }
        for (const value of [null, undefined, false, 1, 'view', []]) {
            expect(valid(value)).toBe(false);
            expect(validRow(value)).toBe(false);
            expect(validRow({ ...row(), tls: value })).toBe(false);
        }
        const own = view();
        const inherited: Record<string, unknown> = Object.assign(Object.create({ vantage: own.vantage }) as Record<string, unknown>, own);
        delete inherited.vantage;
        expect(valid(inherited)).toBe(false);
    });

    it('rejects wrong schema, vantage, enablement types and item containers', () => {
        for (const changes of [
            { schemaVersion: 'tracebolt.application-checks.v2' }, { schemaVersion: null },
            { vantage: 'endpoint' }, { vantage: 'browser' }, { enabled: 1 }, { enabled: 'true' },
            { enabled: null }, { items: null }, { items: {} }, { items: '[]' },
        ]) expect(valid({ ...view(), ...changes }), JSON.stringify(changes)).toBe(false);
    });

    it('does not accept enabled evidence in a disabled or empty generation', () => {
        for (const changes of [{ intervalSeconds: 60 }, { maxAgeSeconds: 70 }, { items: [row()] }]) expect(valid({ ...disabled(), ...changes })).toBe(false);
        expect(valid(view([]))).toBe(false);
        expect(valid(view(Array.from({ length: 9 }, (_, index) => row({ id: `fixture-${index}` }))))).toBe(false);
    });

    it('bounds the interval and derives max age from the exact configured item count', () => {
        for (const intervalSeconds of [0, 59, 3601, 60.5, -1, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '60', null]) {
            expect(valid({ ...view(), intervalSeconds })).toBe(false);
        }
        for (const maxAgeSeconds of [0, 69, 71, 70.5, -1, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '70', null]) {
            expect(valid({ ...view(), maxAgeSeconds })).toBe(false);
        }
        const value = view([row(), row({ id: 'fixture-second' })]);
        expect(valid(value)).toBe(true);
        value.maxAgeSeconds = 70;
        expect(valid(value)).toBe(false);
    });

    it('bounds safe IDs and rejects duplicate configured IDs without requiring sort order', () => {
        for (const id of ['a', '0', '_', '-', 'a'.repeat(48), 'fixture_app-2']) expect(validRow(row({ id }))).toBe(true);
        for (const id of ['', 'a'.repeat(49), 'Fixture', 'fixture.app', 'fixture/app', 'two apps', 'app\n', '<script>', 'ä', 1, null]) {
            expect(validRow({ ...row(), id }), String(id)).toBe(false);
        }
        expect(valid(view([row({ id: 'z-app' }), row({ id: 'a-app' })]))).toBe(true);
        expect(valid(view([row(), row()]))).toBe(false);
        expect(valid(view([row(), plaintext({ id: row().id })]))).toBe(false);
        for (const targetScheme of ['HTTPS', 'ftp', '', null]) expect(validRow({ ...row(), targetScheme })).toBe(false);
    });

    it('accepts canonical UTC timestamps with zero through nine fractional digits', () => {
        for (const serverNow of ['1970-01-01T00:00:00Z', '2024-02-29T12:00:00Z', '9999-12-31T23:59:59Z', ...Array.from({ length: 9 }, (_, index) => `2026-10-06T12:00:00.${'1'.repeat(index + 1)}Z`)]) {
            expect(valid({ ...disabled(), serverNow }), serverNow).toBe(true);
        }
        expect(validRow(row({ observedAt: '2026-10-06T11:59:50Z', tls: { state: 'valid', expiresAt: '2026-12-06T12:00:00Z' } }))).toBe(true);
    });

    it('rejects malformed, normalized, non-UTC or over-precise timestamps at every boundary', () => {
        for (const time of [null, ...malformedTimes]) {
            expect(valid({ ...view(), serverNow: time }), `server ${String(time)}`).toBe(false);
            expect(validRow({ ...row(), observedAt: time }), `observation ${String(time)}`).toBe(false);
            expect(validRow({ ...row(), tls: { state: 'valid', expiresAt: time } }), `expiry ${String(time)}`).toBe(false);
        }
    });

    it.each([100, 199, 200, 204, 299, 300, 301, 399, 400, 500, 599, 999])('maps HTTP %i to its exact state and reason for both schemes', httpStatus => {
        const ok = httpStatus >= 200 && httpStatus < 300;
        const state = ok ? 'ok' : 'http_error';
        const reason = ok ? 'http_2xx' : httpStatus >= 300 && httpStatus < 400 ? 'redirect_blocked' : 'http_status';
        for (const original of [row(), plaintext()]) {
            const value = { ...original, state, reason, httpStatus };
            expect(validRow(value)).toBe(true);
            expect(validRow({ ...value, state: ok ? 'http_error' : 'ok' })).toBe(false);
            for (const wrongReason of ['http_2xx', 'http_status', 'redirect_blocked', 'timeout', 'not_checked', 'success'].filter(candidate => candidate !== reason)) {
                expect(validRow({ ...value, reason: wrongReason }), wrongReason).toBe(false);
            }
            expect(validRow({ ...value, observedAt: null })).toBe(false);
        }
    });

    it('rejects absent, nonintegral, out-of-range and forged HTTP status evidence', () => {
        for (const httpStatus of [null, undefined, 0, 99, 1000, 200.1, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '200']) {
            expect(validRow({ ...row(), httpStatus })).toBe(false);
        }
        for (const state of ['healthy', 'success', '', null]) expect(validRow({ ...row(), state })).toBe(false);
        expect(validRow(row({ tls: { state: 'unknown', expiresAt: null } }))).toBe(false);
        expect(validRow(row({ state: 'http_error', reason: 'http_status', httpStatus: 503, tls: { state: 'unknown', expiresAt: null } }))).toBe(false);
    });

    it('distinguishes never checked from an observed unknown result', () => {
        for (const targetScheme of ['http', 'https'] as const) {
            const empty = unknown({ targetScheme, tls: { state: targetScheme === 'http' ? 'not_applicable' : 'unknown', expiresAt: null } });
            expect(validRow(empty)).toBe(true);
            expect(validRow({ ...empty, observedAt })).toBe(false);
            for (const reason of ['invalid_configuration', 'cancelled', 'destination_blocked', 'stale'] as const) {
                expect(validRow({ ...empty, reason, observedAt })).toBe(true);
                expect(validRow({ ...empty, reason })).toBe(false);
                expect(validRow({ ...empty, reason, observedAt, httpStatus: 200 })).toBe(false);
            }
            for (const reason of ['http_2xx', 'http_status', 'timeout', 'tls_handshake_failed', 'untrusted raw error']) expect(validRow({ ...empty, reason })).toBe(false);
        }
        expect(validRow(unknown({ reason: 'stale', observedAt, tls: row().tls }))).toBe(false);
    });

    it('allows only bounded network reasons and preserves independently verified TLS after an HTTP timeout', () => {
        for (const reason of ['dns_failed', 'timeout', 'request_failed'] as const) {
            const value = network(reason);
            expect(validRow(value)).toBe(true);
            expect(validRow({ ...value, targetScheme: 'http', tls: plaintext().tls })).toBe(true);
            expect(validRow({ ...value, observedAt: null })).toBe(false);
            expect(validRow({ ...value, httpStatus: 503 })).toBe(false);
            expect(validRow({ ...value, tls: row().tls })).toBe(reason !== 'dns_failed');
        }
        for (const reason of ['http_status', 'tls_verification_failed', 'not_checked', 'connection to private target failed']) expect(validRow({ ...network('timeout'), reason })).toBe(false);
    });

    it('requires HTTPS, an observed attempt and unknown certificate evidence for TLS errors', () => {
        for (const reason of ['tls_verification_failed', 'tls_handshake_failed'] as const) {
            const value = row({ state: 'tls_error', reason, httpStatus: null, tls: { state: 'unknown', expiresAt: null } });
            expect(validRow(value)).toBe(true);
            expect(validRow({ ...value, observedAt: null })).toBe(false);
            expect(validRow({ ...value, httpStatus: 200 })).toBe(false);
            expect(validRow({ ...value, targetScheme: 'http', tls: plaintext().tls })).toBe(false);
            expect(validRow({ ...value, tls: row().tls })).toBe(false);
        }
        for (const reason of ['http_status', 'dns_failed', 'timeout', 'stale']) expect(validRow({ ...network('timeout'), state: 'tls_error', reason })).toBe(false);
    });

    it('permits not_applicable only for plaintext and unknown only without a claimed expiry', () => {
        expect(validRow(plaintext())).toBe(true);
        for (const state of ['valid', 'expiring', 'expired', 'unknown', 'secure', null]) {
            for (const expiry of [null, expiresAt]) expect(validRow({ ...plaintext(), tls: { state, expiresAt: expiry } })).toBe(false);
        }
        expect(validRow({ ...plaintext(), tls: { state: 'not_applicable', expiresAt } })).toBe(false);
        for (const state of ['not_applicable', 'secure', '', null]) {
            for (const expiry of [null, expiresAt]) expect(validRow({ ...row(), tls: { state, expiresAt: expiry } })).toBe(false);
        }
        expect(validRow(network('timeout', { tls: { state: 'unknown', expiresAt } }))).toBe(false);
    });

    it.each([
        ['valid', '2026-11-05T12:00:00.123456790Z'],
        ['expiring', '2026-11-05T12:00:00.123456789Z'],
        ['expiring', '2026-10-06T12:00:00.123456790Z'],
        ['expired', '2026-10-06T12:00:00.123456789Z'],
        ['expired', '2026-10-06T11:59:59.123456789Z'],
    ] as const)('classifies retained TLS as %s at the exact server-clock boundary %s', (state, expiry) => {
        for (const outcome of [row(), row({ state: 'http_error', reason: 'http_status', httpStatus: 503 }), network('timeout'), network('request_failed')]) {
            const value = { ...outcome, tls: { state, expiresAt: expiry } };
            expect(validRow(value)).toBe(true);
            for (const incorrect of (['valid', 'expiring', 'expired'] as const).filter(candidate => candidate !== state)) {
                expect(validRow({ ...value, tls: { ...value.tls, state: incorrect } })).toBe(false);
            }
        }
    });

    it('does not invent a verified certificate that already expired at the original observation', () => {
        for (const expiry of [observedAt, '2026-10-06T11:59:50.123456788Z']) {
            expect(validRow(row({ tls: { state: 'expired', expiresAt: expiry } }))).toBe(false);
        }
        expect(validRow(row({ tls: { state: 'expired', expiresAt: '2026-10-06T11:59:50.123456790Z' } }))).toBe(true);
    });
});

describe('retained observation age and local projection', () => {
    it('measures original server-clock age plus monotonic elapsed time without rounding timestamps to milliseconds', () => {
        const value = view(), original = row({ observedAt: '2026-10-06T11:59:50.123456788Z' });
        expect(applicationObservationAge(value, original, 0)).toBe(10000.000001);
        expect(applicationObservationAge(value, original, 2.5)).toBe(10002.500001);
        const equal = row({ observedAt: now });
        expect(applicationObservationAge(value, equal, 0)).toBe(0);
        expect(applicationObservationAge(value, row({ observedAt: '2026-10-06T12:00:00.123456788Z' }), 0)).toBe(0.000001);
        const reread = { ...value, serverNow: '2026-10-06T12:00:05.123456789Z' };
        expect(applicationObservationAge(reread, original, 0)).toBe(15000.000001);
        expect(original.observedAt).toBe('2026-10-06T11:59:50.123456788Z');
    });

    it('never heals a just-future observation because the browser waited', () => {
        const value = view(), future = row({ observedAt: '2026-10-06T12:00:00.123456790Z' });
        expect(valid(view([future]))).toBe(true);
        for (const elapsed of [0, 0.000001, 1000, 60000]) {
            expect(applicationObservationAge(value, future, elapsed)).toBeNull();
            expect(projectApplicationCheck(value, future, elapsed)).toEqual({ ...future, state: 'unknown', reason: 'stale', httpStatus: null, tls: { state: 'unknown', expiresAt: null } });
        }
    });

    it('fails closed for malformed source clocks and invalid elapsed time', () => {
        for (const elapsed of [-1, -0.000001, NaN, Infinity, -Infinity]) {
            expect(applicationObservationAge(view(), row(), elapsed)).toBeNull();
            expect(projectApplicationCheck(view(), row(), elapsed)).toEqual({ ...row(), state: 'unknown', reason: 'stale', httpStatus: null, tls: { state: 'unknown', expiresAt: null } });
        }
        for (const time of malformedTimes.filter((value): value is string => typeof value === 'string')) {
            const value = { ...view(), serverNow: time }, badRow = row({ observedAt: time });
            expect(applicationObservationAge(value, row(), 0)).toBeNull();
            expect(applicationObservationAge(view(), badRow, 0)).toBeNull();
            for (const result of [projectApplicationCheck(value, row(), 0), projectApplicationCheck(view(), badRow, 0)]) {
                expect(result.state).toBe('unknown'); expect(result.reason).toBe('stale'); expect(result.httpStatus).toBeNull(); expect(result.tls).toEqual({ state: 'unknown', expiresAt: null });
            }
        }
        expect(applicationObservationAge(view(), unknown(), 0)).toBeNull();
        expect(projectApplicationCheck(view(), unknown(), 0)).toEqual(unknown());
    });

    it('keeps the exact max-age boundary fresh and clears both HTTP and TLS one nanosecond later', () => {
        const value = view(), edge = row({ observedAt: '2026-10-06T11:58:50.123456789Z' });
        expect(applicationObservationAge(value, edge, 0)).toBe(70000);
        expect(projectApplicationCheck(value, edge, 0)).toEqual(edge);
        for (const [original, elapsed] of [[edge, 0.000001], [row({ observedAt: '2026-10-06T11:58:50.123456788Z' }), 0]] as const) {
            expect(projectApplicationCheck(value, original, elapsed)).toEqual({ ...original, state: 'unknown', reason: 'stale', httpStatus: null, tls: { state: 'unknown', expiresAt: null } });
        }
        const latest = row();
        expect(projectApplicationCheck(value, latest, 60000)).toEqual(latest);
        expect(projectApplicationCheck(value, latest, 60000.000001).state).toBe('unknown');
    });

    it('ages verified TLS and every HTTP outcome together while keeping plaintext explicitly not applicable', () => {
        const originals = [row(), row({ state: 'http_error', reason: 'http_status', httpStatus: 503 }), network('timeout', { tls: row().tls }), plaintext()];
        for (const original of originals) {
            const snapshot = structuredClone(original);
            const projected = projectApplicationCheck(view(), original, 60001);
            expect(projected).toEqual({ ...original, state: 'unknown', reason: 'stale', httpStatus: null, tls: { state: original.targetScheme === 'http' ? 'not_applicable' : 'unknown', expiresAt: null } });
            expect(original).toEqual(snapshot);
            expect(projected.observedAt).toBe(original.observedAt);
            expect(projected.id).toBe(original.id);
            expect(projected.targetScheme).toBe(original.targetScheme);
        }
        const futurePlain = plaintext({ observedAt: '2026-10-06T12:00:00.123456790Z' });
        expect(projectApplicationCheck(view(), futurePlain, 1000).tls).toEqual({ state: 'not_applicable', expiresAt: null });
        const uncheckedPlain = plaintext({ state: 'unknown', reason: 'not_checked', observedAt: null, httpStatus: null });
        expect(projectApplicationCheck(view(), uncheckedPlain, 1000)).toEqual(uncheckedPlain);
    });

    it('projects valid to expiring at the exact 30-day threshold without rewriting HTTP or timestamps', () => {
        const original = row({ tls: { state: 'valid', expiresAt: '2026-11-05T12:00:01.123456789Z' } });
        const snapshot = structuredClone(original), value = view([original]);
        expect(valid(value)).toBe(true);
        expect(projectApplicationCheck(value, original, 999.999999).tls.state).toBe('valid');
        const projected = projectApplicationCheck(value, original, 1000);
        expect(projected).toEqual({ ...original, tls: { ...original.tls, state: 'expiring' } });
        expect(original).toEqual(snapshot);
        expect(projected.observedAt).toBe(observedAt);
        expect(projected.tls.expiresAt).toBe(original.tls.expiresAt);
        expect(value.serverNow).toBe(now);
    });

    it.each(['ok', 'http_error', 'network_error'] as const)('projects a retained certificate to expired independently from %s', state => {
        const original = state === 'network_error' ? network('timeout') : row({ state, reason: state === 'ok' ? 'http_2xx' : 'http_status', httpStatus: state === 'ok' ? 200 : 503 });
        original.tls = { state: 'expiring', expiresAt: '2026-10-06T12:00:01.123456789Z' };
        const value = view([original]);
        expect(valid(value)).toBe(true);
        expect(projectApplicationCheck(value, original, 999.999999).tls.state).toBe('expiring');
        expect(projectApplicationCheck(value, original, 1000)).toEqual({ ...original, tls: { ...original.tls, state: 'expired' } });
        expect(projectApplicationCheck(value, original, 60000).tls.state).toBe('expired');
        expect(projectApplicationCheck(value, original, 60000.000001)).toEqual({ ...original, state: 'unknown', reason: 'stale', httpStatus: null, tls: { state: 'unknown', expiresAt: null } });
    });

    it('uses nanosecond expiry ordering for local sub-millisecond transitions', () => {
        for (const [initial, expiry, expected] of [
            ['valid', '2026-11-05T12:00:00.123456790Z', 'expiring'],
            ['expiring', '2026-10-06T12:00:00.123456790Z', 'expired'],
        ] satisfies [ApplicationTLSState, string, ApplicationTLSState][]) {
            const original = row({ tls: { state: initial, expiresAt: expiry } });
            expect(valid(view([original]))).toBe(true);
            expect(projectApplicationCheck(view(), original, 0).tls.state).toBe(initial);
            expect(projectApplicationCheck(view(), original, 0.000001).tls.state).toBe(expected);
            expect(original.tls).toEqual({ state: initial, expiresAt: expiry });
        }
    });

    it('preserves fresh unknown, TLS-failed and plaintext evidence without fabricating a certificate', () => {
        const originals = [
            unknown({ reason: 'cancelled', observedAt }),
            network('dns_failed'), network('timeout'),
            row({ state: 'tls_error', reason: 'tls_verification_failed', httpStatus: null, tls: { state: 'unknown', expiresAt: null } }),
            plaintext(), plaintext({ state: 'http_error', reason: 'redirect_blocked', httpStatus: 302 }),
        ];
        for (const original of originals) {
            expect(validRow(original)).toBe(true);
            expect(projectApplicationCheck(view(), original, 1000)).toEqual(original);
        }
    });
});
