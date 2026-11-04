import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, getProtectedRequestEpoch } from './api';
import { acceptWindowsHealthClock, windowsHealthElapsed } from './windows-health-clock';
import {
    MANAGER_CERTIFICATE_ROLES, MANAGER_READINESS_COMPONENTS, MANAGER_READINESS_UNASSESSED,
    managerCertificateState, managerComponentState, managerReadinessStatus,
    validManagerReadinessTimestamp, validManagerReadinessView,
} from './manager-readiness-model';
import type { ManagerCertificateLifetime, ManagerReadinessComponent, ManagerReadinessView } from './manager-readiness-model';

const now = '2026-11-04T00:00:00Z';
function fixture(): ManagerReadinessView {
    return {
        schemaVersion: 'tracebolt.manager-readiness.v1', scope: 'core_reads_and_last_worker_steps', status: 'ready', serverNow: now,
        components: MANAGER_READINESS_COMPONENTS.map(component => ['state_boundary', 'operator_store', 'trust_store'].includes(component)
            ? { component, state: 'ready', checkedAt: now } : { component, state: 'not_configured' }),
        unassessed: [...MANAGER_READINESS_UNASSESSED],
    };
}
function replace(view: ManagerReadinessView, row: ManagerReadinessComponent) { view.components = view.components.map(item => item.component === row.component ? row : item); }
function withCertificates(): ManagerReadinessView {
    const view = fixture();
    view.certificateLifetimes = MANAGER_CERTIFICATE_ROLES.map(role => ({ role, state: 'not_configured' }));
    return view;
}
function certificateView(from: string, until: string, state: ManagerCertificateLifetime['state']): ManagerReadinessView {
    const view = withCertificates();
    view.certificateLifetimes![0] = { role: 'server_chain', state, validFrom: from, validUntil: until };
    const failed = state === 'expired' || state === 'not_yet_valid';
    replace(view, { component: 'server_certificate', state: failed ? 'failed' : 'ready', checkedAt: now });
    if (failed) view.status = 'unavailable';
    return view;
}

describe('manager readiness closed wire contract', () => {
    it('accepts only the complete positive runtime roster and matching HTTP status', () => {
        const view = fixture(), before = JSON.stringify(view);
        expect(validManagerReadinessView(view, 200)).toBe(true);
        expect(validManagerReadinessView(view)).toBe(true);
        expect(validManagerReadinessView(view, 503)).toBe(false);
        expect(validManagerReadinessView(view, 201)).toBe(false);
        expect(validManagerReadinessView({ ...view, components: view.components.slice(0, 3) })).toBe(false);
        expect(validManagerReadinessView({ ...view, status: 'unavailable' }, 503)).toBe(false);
        expect(JSON.stringify(view)).toBe(before);
    });
    it('retains 503 evidence, fallback unknowns and timeout without empty success', () => {
        for (const components of [[], [{ component: 'runtime', state: 'unknown' }], [{ component: 'probe', state: 'busy' }]]) {
            const value = { ...fixture(), status: 'unavailable', components };
            expect(validManagerReadinessView(value, 503)).toBe(true);
            expect(validManagerReadinessView({ ...value, status: 'ready' }, 200)).toBe(false);
            expect(validManagerReadinessView({ ...value, certificateLifetimes: [] }, 503)).toBe(false);
        }
        const value = withCertificates(); value.status = 'unavailable';
        value.components.push({ component: 'probe', state: 'timeout' });
        expect(validManagerReadinessView(value, 503)).toBe(true);
        expect(validManagerReadinessView(value, 200)).toBe(false);
        expect(validManagerReadinessView({ ...value, components: [{ component: 'probe', state: 'timeout' }] }, 503)).toBe(false);
    });
    it('rejects unknown labels, duplicates, missing fields, extra detail and malformed arrays', () => {
        const view = withCertificates();
        for (const value of [
            null, [], { ...view, schemaVersion: 'tracebolt.manager-readiness.v2' }, { ...view, scope: 'all_manager_health' },
            { ...view, status: 'healthy' }, { ...view, privatePath: '/private/state' }, { ...view, serverNow: undefined },
            { ...view, components: null }, { ...view, components: new Array(1) },
            { ...view, components: [...view.components, view.components[0]] },
            { ...view, components: [{ ...view.components[0], component: 'provider' }, ...view.components.slice(1)] },
            { ...view, components: [{ ...view.components[0], error: 'private SQL error' }, ...view.components.slice(1)] },
            { ...view, components: [{ ...view.components[0], state: 'healthy' }, ...view.components.slice(1)] },
            { ...view, unassessed: [...view.unassessed, view.unassessed[0]] },
            { ...view, unassessed: [view.unassessed[0], ...view.unassessed.slice(0, 4)] },
            { ...view, unassessed: ['unknown_scope', ...view.unassessed.slice(1)] },
            { ...view, certificateLifetimes: null }, { ...view, certificateLifetimes: [] },
            { ...view, certificateLifetimes: [view.certificateLifetimes![0], view.certificateLifetimes![0], view.certificateLifetimes![2]] },
            { ...view, certificateLifetimes: [{ role: 'endpoint', state: 'valid' }, ...view.certificateLifetimes!.slice(1)] },
            { ...view, certificateLifetimes: [{ ...view.certificateLifetimes![0], fingerprint: 'private identity' }, ...view.certificateLifetimes!.slice(1)] },
        ]) expect(validManagerReadinessView(value)).toBe(false);
    });
    it('accepts optional-store absence but never disabled core tables or invented observation times', () => {
        const view = fixture();
        replace(view, { component: 'operator_store', state: 'not_configured' });
        expect(validManagerReadinessView(view)).toBe(false);
        replace(view, { component: 'operator_store', state: 'ready' });
        expect(validManagerReadinessView(view)).toBe(false);
        replace(view, { component: 'operator_store', state: 'ready', checkedAt: '2026-11-04T00:00:00.000000001Z' });
        expect(validManagerReadinessView(view)).toBe(false);
        replace(view, { component: 'operator_store', state: 'unknown' }); view.status = 'unavailable';
        expect(validManagerReadinessView(view, 503)).toBe(true);
        replace(view, { component: 'linux_inventory_step', state: 'starting', checkedAt: now });
        expect(validManagerReadinessView(view)).toBe(false);
    });
    it('keeps inventory step success distinct and validates original worker freshness', () => {
        const view = fixture();
        replace(view, { component: 'linux_inventory_step', state: 'succeeded', checkedAt: '2026-11-03T23:59:55Z' });
        expect(validManagerReadinessView(view)).toBe(true);
        replace(view, { component: 'linux_inventory_step', state: 'ready', checkedAt: now });
        expect(validManagerReadinessView(view)).toBe(false);
        replace(view, { component: 'linux_inventory_step', state: 'succeeded', checkedAt: '2026-11-03T23:59:54.999999999Z' });
        expect(validManagerReadinessView(view)).toBe(false);
        replace(view, { component: 'linux_inventory_step', state: 'stale', checkedAt: '2026-11-04T00:00:00.000000001Z' }); view.status = 'unavailable';
        expect(validManagerReadinessView(view, 503)).toBe(true);
        replace(view, { component: 'linux_inventory_step', state: 'stale', checkedAt: now });
        expect(validManagerReadinessView(view)).toBe(false);
        replace(view, { component: 'linux_inventory_step', state: 'stopped' });
        expect(validManagerReadinessView(view)).toBe(true);
        replace(view, { component: 'linux_inventory_step', state: 'stopped', checkedAt: now });
        expect(validManagerReadinessView(view)).toBe(true);
    });
    it('validates UTC calendar instants without truncating nanosecond or old public certificate dates', () => {
        for (const value of [now, '2026-11-04T00:00:00.000000001Z', '9999-12-31T23:59:59.999999999Z']) expect(validManagerReadinessTimestamp(value)).toBe(true);
        for (const value of ['2026-02-29T00:00:00Z', '2026-11-04T24:00:00Z', '2026-11-04T00:00:60Z', '2026-11-04T00:00:00+00:00', '2026-11-04T00:00:00.1234567890Z', '0000-01-01T00:00:00Z', '1969-12-31T23:59:59Z', '', Infinity]) expect(validManagerReadinessTimestamp(value)).toBe(false);
        expect(validManagerReadinessTimestamp('0001-01-01T00:00:00Z', true)).toBe(true);
        expect(validManagerReadinessTimestamp('0000-01-01T00:00:00Z', true)).toBe(false);
    });
});

describe('manager certificate lifetime contract', () => {
    it.each([
        ['2026-12-04T00:00:00.000000001Z', 'valid'], ['2026-12-04T00:00:00Z', 'within_30_days'],
        ['2026-11-11T00:00:00.000000001Z', 'within_30_days'], ['2026-11-11T00:00:00Z', 'within_7_days'],
        ['2026-11-04T00:00:00.000000001Z', 'within_7_days'], [now, 'expired'],
    ] as const)('preserves exact deadline %s as %s', (until, state) => {
        const view = certificateView('0001-01-01T00:00:00Z', until, state);
        expect(validManagerReadinessView(view, state === 'expired' ? 503 : 200)).toBe(true);
        expect(view.certificateLifetimes![0].validUntil).toBe(until);
        expect(validManagerReadinessView({ ...view, certificateLifetimes: [{ ...view.certificateLifetimes![0], state: state === 'valid' ? 'within_30_days' : 'valid' }, ...view.certificateLifetimes!.slice(1)] })).toBe(false);
    });
    it('requires complete original windows, does not infer missing report and rejects dates for absent material', () => {
        expect(validManagerReadinessView(fixture())).toBe(true);
        const view = certificateView('2026-11-04T00:00:00.000000001Z', '2027-11-04T00:00:00Z', 'not_yet_valid');
        expect(validManagerReadinessView(view)).toBe(true);
        for (const row of [
            { role: 'server_chain', state: 'valid', validUntil: '2027-11-04T00:00:00Z' },
            { role: 'server_chain', state: 'valid', validFrom: now, validUntil: now },
            { role: 'server_chain', state: 'valid', validFrom: '2027-11-04T00:00:00Z', validUntil: now },
            { role: 'server_chain', state: 'not_configured', validFrom: now, validUntil: '2027-11-04T00:00:00Z' },
            { role: 'server_chain', state: 'unavailable', validFrom: now },
            { role: 'server_chain', state: 'valid', validFrom: null, validUntil: null },
        ]) expect(validManagerReadinessView({ ...view, certificateLifetimes: [row, ...view.certificateLifetimes!.slice(1)] })).toBe(false);
    });
    it('keeps useful independent lifetime warnings on an unavailable response', () => {
        const view = certificateView('2026-11-01T00:00:00Z', '2026-11-05T00:00:00Z', 'within_7_days');
        replace(view, { component: 'server_certificate', state: 'failed', checkedAt: now }); view.status = 'unavailable';
        expect(validManagerReadinessView(view, 503)).toBe(true);
        expect(managerReadinessStatus(view, 0)).toBe('unavailable');
        expect(managerCertificateState(view.certificateLifetimes![0], now, 0)).toBe('within_7_days');
    });
    it('rejects contradictory expired/future success and disabled configuration without promoting valid dates', () => {
        for (const [from, until, state] of [
            ['2026-11-01T00:00:00Z', now, 'expired'],
            ['2026-11-05T00:00:00Z', '2027-11-04T00:00:00Z', 'not_yet_valid'],
        ] as const) {
            const view = certificateView(from, until, state);
            expect(validManagerReadinessView(view, 503)).toBe(true);
            replace(view, { component: 'server_certificate', state: 'ready', checkedAt: now }); view.status = 'ready';
            expect(validManagerReadinessView(view, 200)).toBe(false);
        }
        const view = certificateView('2026-11-01T00:00:00Z', '2027-11-04T00:00:00Z', 'valid');
        replace(view, { component: 'server_certificate', state: 'not_configured' });
        expect(validManagerReadinessView(view)).toBe(false);
        const disabled = withCertificates();
        replace(disabled, { component: 'enrollment_issuer', state: 'ready', checkedAt: now });
        expect(validManagerReadinessView(disabled)).toBe(false);
        disabled.certificateLifetimes![1] = { role: 'enrollment_issuer', state: 'valid', validFrom: '2026-11-01T00:00:00Z', validUntil: '2027-11-04T00:00:00Z' };
        disabled.certificateLifetimes![2] = { role: 'enrollment_root', state: 'expired', validFrom: '2026-11-01T00:00:00Z', validUntil: now };
        expect(validManagerReadinessView(disabled)).toBe(false);
        replace(disabled, { component: 'enrollment_issuer', state: 'failed', checkedAt: now }); disabled.status = 'unavailable';
        expect(validManagerReadinessView(disabled, 503)).toBe(true);
    });
});

describe('manager readiness ages without renewing or upgrading evidence', () => {
    it('expires snapshot confidence and worker evidence at their original precise bounds', () => {
        const view = fixture();
        expect(managerReadinessStatus(view, 5000)).toBe('ready');
        expect(managerReadinessStatus(view, 5000.000001)).toBe('stale');
        for (const [component, state, checkedAt] of [
            ['linux_inventory_step', 'succeeded', '2026-11-03T23:59:56Z'],
            ['macos_inventory_step', 'succeeded', '2026-11-03T23:58:01Z'],
            ['windows_health_worker', 'ready', '2026-11-03T23:58:31Z'],
        ] as const) {
            const row = { component, state, checkedAt };
            expect(managerComponentState(row, now, 1000)).toBe(state);
            expect(managerComponentState(row, now, 1000.000001)).toBe('stale');
        }
        replace(view, { component: 'linux_inventory_step', state: 'succeeded', checkedAt: '2026-11-03T23:59:56Z' });
        expect(managerReadinessStatus(view, 1001)).toBe('stale');
    });
    it('withholds invalid clocks, never treats request duration as a new freshness interval', () => {
        const view = withCertificates();
        for (const elapsed of [-1, Infinity, NaN]) {
            expect(managerReadinessStatus(view, elapsed)).toBe('unknown');
            expect(managerComponentState(view.components[0], now, elapsed)).toBe('unknown');
            expect(managerCertificateState(view.certificateLifetimes![0], now, elapsed)).toBe('unknown');
        }
        expect(managerReadinessStatus(view, 6000)).toBe('stale');
        expect(managerComponentState({ component: 'operator_store', state: 'failed', checkedAt: now }, now, 4000)).toBe('failed');
        expect(managerComponentState({ component: 'linux_inventory_step', state: 'stopped' }, now, 4000)).toBe('stopped');
    });
    it('can worsen remaining lifetime but cannot turn not-yet-valid into success or change stored times', () => {
        const view = certificateView('2026-11-01T00:00:00Z', '2026-11-04T00:00:01Z', 'within_7_days'), row = view.certificateLifetimes![0], before = JSON.stringify(view);
        expect(managerCertificateState(row, now, 999.999999)).toBe('within_7_days');
        expect(managerCertificateState(row, now, 1000)).toBe('expired');
        expect(managerReadinessStatus(view, 1000)).toBe('stale');
        expect(managerCertificateState(row, now, 5001)).toBe('unknown');
        expect(managerCertificateState({ ...row, state: 'not_yet_valid', validFrom: '2026-11-04T00:00:01Z', validUntil: '2027-11-04T00:00:00Z' }, now, 2000)).toBe('not_yet_valid');
        expect(JSON.stringify(view)).toBe(before);
    });
});

describe('manager snapshot clock continuity', () => {
    beforeEach(() => { vi.useFakeTimers({ toFake: ['Date', 'performance'] }); vi.setSystemTime(now); abortProtectedRequests(); });
    afterEach(() => { abortProtectedRequests(); vi.useRealTimers(); });
    it('equal or slowly advancing server reads cannot renew elapsed evidence', () => {
        const view = fixture(), epoch = getProtectedRequestEpoch(), key = 'manager-readiness:model-session';
        expect(acceptWindowsHealthClock(key, epoch, view.serverNow, 100)).toBe(true);
        vi.advanceTimersByTime(3000);
        expect(acceptWindowsHealthClock(key, epoch, view.serverNow, 0)).toBe(true);
        vi.advanceTimersByTime(3000);
        view.serverNow = '2026-11-04T00:00:00.001Z';
        expect(acceptWindowsHealthClock(key, epoch, view.serverNow, 0)).toBe(true);
        expect(windowsHealthElapsed(key, epoch, view.serverNow, 0)).toBe(6099);
        expect(managerReadinessStatus(view, windowsHealthElapsed(key, epoch, view.serverNow, 0))).toBe('stale');
    });
    it('rejects manager rollback and withholds the entire old session epoch', () => {
        const key = 'manager-readiness:model-session', epoch = getProtectedRequestEpoch();
        expect(acceptWindowsHealthClock(key, epoch, '2026-11-04T00:00:00.000000002Z', 0)).toBe(true);
        expect(acceptWindowsHealthClock(key, epoch, '2026-11-04T00:00:00.000000001Z', 0)).toBe(false);
        abortProtectedRequests();
        expect(managerReadinessStatus(fixture(), windowsHealthElapsed(key, epoch, now, 0))).toBe('unknown');
    });
});
