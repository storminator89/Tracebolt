import { describe, expect, it } from 'vitest';
import { deviceReadinessFacts } from './device-readiness-model';
import type { Device } from './types';

const at = '2026-11-03T12:00:00Z';
const device = (): Device => ({ id: 'agent_fixture', source: 'lan', synthetic: false, lastSeen: at, agentCertificate: { source: 'guided-enrollment', checkedAt: at, expiresAt: '2026-11-06T12:00:00Z' } } as Device);
describe('read-only device readiness facts', () => {
    it.each([[0, 'recent', 0], [120000, 'recent', 120], [120001, 'stale', 120], [121000, 'stale', 121]] as const)('uses original capture time at elapsed %s', (elapsed, state, age) => {
        expect(deviceReadinessFacts(device(), [], elapsed, true)).toMatchObject({ report: state, reportAgeSeconds: age, checkedAt: at });
    });
    it.each([Infinity, NaN, -1])('does not invent age or certificate validity from elapsed %s', elapsed => {
        expect(deviceReadinessFacts(device(), [], elapsed, true)).toMatchObject({ report: 'unknown', reportAgeSeconds: null, certificate: 'unknown', checkedAt: null });
    });
    it.each(['0001-01-01T00:00:00Z', '0001-01-01T00:00:00.000000000Z'])('keeps a missing report separate from unknown (%s)', lastSeen => {
        expect(deviceReadinessFacts({ ...device(), lastSeen }, [], 0, true).report).toBe('not_collected');
        expect(deviceReadinessFacts({ ...device(), lastSeen }, [], 0, false).report).toBe('unavailable');
    });
    it.each(['bad', '2026-02-30T12:00:00Z', '2026-11-03T12:00:01Z'])('rejects invalid or future capture time %s', lastSeen => {
        expect(deviceReadinessFacts({ ...device(), lastSeen }, [], 0, true).report).toBe('unknown');
    });
    it('requires a validated manager time and never uses browser time as one', () => {
        const value = device(); delete value.agentCertificate;
        expect(deviceReadinessFacts(value, [], 0, true)).toMatchObject({ report: 'unknown', certificate: 'unknown' });
        value.agentCertificate = { source: 'guided-enrollment', checkedAt: 'bad', expiresAt: '2026-11-06T12:00:00Z' };
        expect(deviceReadinessFacts(value, [], 0, true).report).toBe('unknown');
    });
    it.each(['synthetic', 'sandbox'] as const)('does not promote a %s source to accepted LAN evidence', source => {
        expect(deviceReadinessFacts({ ...device(), source }, [], 0, true).report).toBe('unavailable');
        expect(deviceReadinessFacts({ ...device(), synthetic: true }, [], 0, true).report).toBe('unavailable');
    });
    it('ages certificates past the warning and expiry boundaries without a new GET', () => {
        const value = device();
        expect(deviceReadinessFacts(value, [], 0, true).certificate).toBe('current');
        expect(deviceReadinessFacts(value, [], 24 * 3600000, true).certificate).toBe('expiring');
        expect(deviceReadinessFacts(value, [], 72 * 3600000, true).certificate).toBe('expired');
        expect(deviceReadinessFacts(value, [], 72 * 3600000, false).certificate).toBe('unknown');
    });
    it('preserves revoked renewal evidence instead of reporting a current certificate', () => {
        const value = device();
        value.agentCertificate!.renewal = { status: 'revoked', enabled: false, identityGeneration: 'identity_' + 'a'.repeat(32), credentialGeneration: 1, currentNotAfter: value.agentCertificate!.expiresAt!, authorityExpiresAt: '2026-11-07T12:00:00Z' };
        expect(deviceReadinessFacts(value, [], 0, true).certificate).toBe('revoked');
    });
    it('retains separate status counts without treating support/configuration as collection', () => {
        const facts = deviceReadinessFacts(device(), [{ state: 'scope' }, { state: 'supported' }, { state: 'available' }, { state: 'available' }, { state: 'configured' }, { state: 'denied' }, { state: 'failed' }, { state: 'stale' }, { state: 'unknown' }], 0, true);
        expect(facts.counts).toEqual({ scope: 1, supported: 1, available: 2, configured: 1, denied: 1, failed: 1, stale: 1, unknown: 1 });
        expect(Object.values(facts.counts).reduce((sum, count) => sum + count, 0)).toBe(9);
    });
});
